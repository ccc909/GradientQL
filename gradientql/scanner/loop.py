"""The control loop — the step skeleton, nothing domain-specific."""

from __future__ import annotations

import logging
import time
from collections import Counter
from typing import Any

from ..core.llm import (
    _CIRCUIT_TIMEOUT,
    get_attacker_llm,
    get_circuit_breaker_status,
    invoke_with_circuit_breaker,
)
from ..utils.graphql_client import get_client
from ..utils.reporter import append_vuln_retraction, append_vuln_stream
from .actions import ActionContext, Result, dispatch
from .memory import (
    _ARSENAL_TOOLS,
    _ENDPOINT_TOOLS,
    apply_self_report,
    identity_label,
    primary_root_field,
    unconfirmed_classes,
)
from .coverage import critical_untested, untested_high_value_fields
from .prompt import build_prompt, extract_action
from .schema import (
    _SEMANTIC_INDEX_MIN_FIELDS,
    auth_mutations,
    build_schema_index,
    field_count,
    render_schema_overview,
)
from .tracer import AgentTracer

logger = logging.getLogger("gradientql.scanner")

_NOACTION_ABORT = 5
_LLM_ERROR_ABORT = 8
_MAX_CIRCUIT_WAITS = 3
_NOPROBE_CAP = 4
_NONPROBE_ACTIONS = ("search_schema", "note")
_DEGRADED_AT = 2
_MAX_BACKOFFS = 4
_DONE_DEFERRALS = 2
_HV_DEFERRALS = 2
_COVERAGE_NUDGE_EVERY = 8
_OOB_CHECK_DELAY = 3


def _decision_target(name: str, args: dict) -> str:
    if name in ("graphql", "auth_test"):
        return primary_root_field(str(args.get("query", ""))) or "?"
    if name == "fuzz":
        return str(args.get("field", "?"))
    if name == "search_schema":
        return str(args.get("keyword", "?"))
    if name == "report_finding":
        return str(args.get("vuln_type", ""))[:40]
    return ""


def _decision_summary(name: str, args: dict, ctx: ActionContext, res: Result) -> str:
    obs = " ".join((res.observation or "").split())
    if res.blocked:
        return ("BLOCKED — " + obs)[:160]
    if name == "graphql" and res.touched_target:
        pf = primary_root_field(str(args.get("query", ""))) or "?"
        e = ctx.ledger.get(pf, {})
        if e.get("finding"):
            return f"FINDING {e['finding']}"[:160]
        base = e.get("auto", "") or "sent"
        return (f"{base}: {e['sig']}" if e.get("sig") else base)[:160]
    return obs[:160] or name


def _decision_line(step: int, name: str, args: dict, thought: str, summary: str) -> str:
    tgt = _decision_target(name, args)
    line = f"[{step}] {name}" + (f" {tgt}" if tgt else "") + f" → {summary}"
    th = " ".join(str(thought).split())[:140]
    if th:
        line += f"  «{th}»"
    return line


def _auto_oob_check(ctx: ActionContext) -> None:
    """Reconcile pending OOB callbacks, recording any hit as a confirmed blind-SSRF finding.

    Clears ctx.oob_injected_at so a check fires only once per injection.
    """
    ctx.oob_injected_at = None
    try:
        hits = ctx.oob_sess.reconcile()
    except Exception:  # noqa: BLE001
        return
    for h in hits or []:
        ix = h.get("interaction", {}) if isinstance(h, dict) else {}
        proto = ix.get("protocol", "?")
        if ctx.record(f"Blind SSRF / OOB interaction ({proto}) confirmed", "endpoint",
                      f"OOB {proto} callback from {ix.get('remote-address', '?')}", 3.0):
            ctx.log(f"[{ctx.step}] ⚠ AUTO-OOB: blind SSRF/XXE CONFIRMED ({proto} callback)")


def _accumulate_tokens(acc: dict[str, Any], msg: Any) -> None:
    """Add one LLM response's token usage (and cost, if the provider reports it) to `acc`."""
    try:
        um = getattr(msg, "usage_metadata", None) or {}
        acc["input"] += int(um.get("input_tokens") or 0)
        acc["output"] += int(um.get("output_tokens") or 0)
        acc["total"] += int(um.get("total_tokens") or 0)
        acc["reasoning"] += int((um.get("output_token_details") or {}).get("reasoning") or 0)
        acc["calls"] += 1
        rmeta = getattr(msg, "response_metadata", None) or {}
        cost = rmeta.get("cost")
        if cost is None:
            cost = (rmeta.get("token_usage") or {}).get("cost")
        if cost:
            acc["cost"] += float(cost)
    except Exception:  # noqa: BLE001
        pass


def run(settings: dict[str, Any], schema_map: dict[str, Any], target_url: str, budget: int,
        trace: Any = None, verbose: bool = False, progress_cb: Any = None,
        should_stop: Any = None, steer: Any = None, run_id: str | None = None,
        resume: dict[str, Any] | None = None) -> dict[str, Any]:
    """Drive the attacker LLM's decision loop for up to `budget` steps.

    Streams findings to the reporter as they are confirmed and, when `trace` is
    set, records each step. Returns a result dict with keys vulnerabilities,
    interactions, steps, covered_count, notes, and target_url.
    """
    llm = get_attacker_llm(settings)
    csrf = settings.get("target", {}).get("csrf")
    client = get_client(target_url, csrf_config=csrf)

    from ..utils import oob as _oobmod
    oob_sess = _oobmod.get_session(settings) if _oobmod.is_enabled(settings) else None

    min_fields = settings.get("embeddings", {}).get("min_fields", _SEMANTIC_INDEX_MIN_FIELDS)
    if field_count(schema_map) >= min_fields:
        schema_index = build_schema_index(schema_map, settings.get("embeddings", {}).get("model"))
    else:
        schema_index = None
        logger.info("AGENT: schema small (<%d fields) — lexical schema search only", min_fields)
    schema_overview = render_schema_overview(schema_map)

    ctx = ActionContext(
        client=client, schema_map=schema_map, schema_index=schema_index, settings=settings,
        target_url=target_url, oob_sess=oob_sess,
        identity=dict(settings.get("target", {}).get("headers") or {}),
        _stream=append_vuln_stream, _stream_retract=append_vuln_retraction,
    )

    start_step = 0
    if resume is not None:
        from .checkpoint import restore_ctx
        start_step = restore_ctx(ctx, resume)
        logger.info("AGENT: resumed run %s at step %d with %d prior finding(s)",
                    run_id or "?", start_step, len(ctx.vulns))
    else:
        _am = auth_mutations(schema_map)
        if _am:
            ctx.facts.append("Token-minting mutations exist (" + ", ".join(_am[:6])
                             + ") — the signup/login auth chain is viable here.")
        else:
            ctx.facts.append("NO anonymous token-minting mutation in this schema (no login/register/token "
                             "mutation) — auth is OUT-OF-BAND (REST/OIDC). Do NOT hunt a GraphQL login; focus "
                             "on unauth data exposure, injection, SSRF, DoS.")
        _sub = schema_map.get("_subscription_type")
        if _sub:
            _subf = [f for f in (schema_map.get(_sub) or {}) if not str(f).startswith("_")]
            ctx.facts.append(f"A SUBSCRIPTION root ({_sub}: {', '.join(_subf[:6]) or '?'}) exists — a real "
                             "attack surface (auth-over-subscription, connection DoS) but it needs a WebSocket/"
                             "SSE transport this tool can't drive over HTTP. NOTE it as untested; don't burn "
                             "steps trying to query it over POST.")

    nudge_every = settings.get("scanner", {}).get("tuning", {}).get(
        "coverage_nudge_every", _COVERAGE_NUDGE_EVERY)

    recent_actions: list[str] = []
    recent_targets: list[str] = []
    steering_log: list[dict[str, Any]] = []
    techniques_used: set[str] = set()
    consecutive_dead = 0
    backoffs = 0
    noprobe_streak = 0
    blocked_recon = 0
    consec_noaction = 0
    consec_llm_error = 0
    circuit_waits = 0
    consec_blocked = 0
    done_deferrals = 0
    hv_deferrals = 0

    tracer = AgentTracer(trace, target_url) if trace else None
    ctx.tracing = tracer is not None
    narrate = bool(verbose) or tracer is not None
    pending: dict[str, Any] | None = None

    def _snapshot() -> dict[str, Any]:
        return {
            "identity": list(ctx.identity.keys()), "findings": len(ctx.vulns),
            "facts": list(ctx.facts), "credentials": [dict(c) for c in ctx.credentials],
            "harvested": {k: len(v) for k, v in ctx.harvested.items()}, "searched": list(ctx.searched),
            "ledger": {f: {"auto": e.get("auto"), "verdict": e.get("verdict"),
                           "attempts": e.get("attempts"), "identity": e.get("identity"),
                           "finding": e.get("finding"), "why": e.get("why")}
                       for f, e in ctx.ledger.items()},
            "recent_actions": recent_actions[-12:], "consecutive_dead": consecutive_dead,
        }

    def _finalize_trace() -> None:
        nonlocal pending
        if pending is not None and tracer is not None:
            pending["observations"] = ctx.history[pending.pop("_hl", len(ctx.history)):]
            pending["io"] = ctx.step_io[pending.pop("_io", len(ctx.step_io)):]
            pending["state"] = _snapshot()
            tracer.step(pending)
        pending = None

    from . import checkpoint as _cp
    cp_on = run_id is not None and _cp.is_enabled(settings)
    cp_every = _cp.interval(settings)
    cp_path = _cp.checkpoint_path(settings, run_id) if cp_on else None

    def _save_cp(s: int, complete: bool = False) -> None:
        if not cp_on or s < 0:
            return
        try:
            _cp.save(cp_path, run_id=run_id, ctx=ctx, schema_map=schema_map,
                     target_url=target_url, step=s, budget=budget, complete=complete)
        except Exception as e:  # noqa: BLE001
            logger.warning("AGENT: checkpoint save failed at step %d: %s", s, e)

    if resume is not None:
        # techniques_used is loop-local, not in ctx; rebuild it from the decision log so a resumed
        # run doesn't treat already-used endpoint tools (dos/smuggle/csrf) as unused — which would
        # re-fire them and re-defer a legitimate `done`. Decision lines are "[step] name target ...".
        for _line in ctx.decisions:
            _rest = _line.split("]", 1)[1].strip() if "]" in _line else ""
            _nm = _rest.split(" ", 1)[0] if _rest else ""
            if _nm in _ARSENAL_TOOLS:
                techniques_used.add(_nm)

    run_complete = False
    step = start_step - 1
    last_completed = start_step - 1
    for step in range(start_step, budget):
        if should_stop is not None and should_stop():
            logger.info("AGENT: stop requested — ending scan at step %d", step)
            break
        _finalize_trace()
        ctx.step = step
        if progress_cb is not None:
            try:
                progress_cb(step, budget, ctx)
            except Exception:  # noqa: BLE001
                pass

        if steer is not None:
            try:
                msgs = steer() or []
            except Exception:  # noqa: BLE001
                msgs = []
            for m in (msgs if isinstance(msgs, (list, tuple)) else [msgs]):
                if not m:
                    continue
                steering_log.append({"step": step, "msg": str(m)})
                ctx.log(f"[{step}] operator steering: {m}")
                logger.info("AGENT: operator steering at step %d: %s", step, m)
        active_steer = [x["msg"] for x in steering_log if step - x["step"] <= 3]

        degraded = consecutive_dead >= _DEGRADED_AT
        if degraded:
            backoffs += 1
            time.sleep(min(5 * backoffs + 3, 25))

        nudge: list[str] = []
        recent_t = [t for t in recent_targets[-8:] if t]
        if degraded:
            nudge.append(
                f"TARGET DEGRADED: the last {consecutive_dead} requests errored/timed out — likely "
                f"rate-limiting or load from your probes (especially DoS). Send ONE light query like "
                f"{{__typename}} to check recovery. DO NOT stop — you still have {budget - step} steps.")
        elif len(recent_t) >= 6 and len(set(recent_t)) <= 2:
            nudge.append("You've hammered the same 1-2 fields with little new signal — the MAP shows what's "
                         "already dead. Pivot to a NEW field/vector, or record a verdict/learned and move on.")
        echoed = [f for f, e in ctx.ledger.items()
                  if e.get("echoed") and not e.get("fuzzed") and e.get("verdict") not in ("dead", "exploited")]
        if echoed and not degraded:
            nudge.append(f"(optional) fields that echoed your input — `fuzz` ONLY if the field looks like it "
                         f"renders/interpolates input, otherwise ignore: {', '.join(echoed[:5])}")
        if noprobe_streak >= 2 and not degraded:
            nudge.append(f"You've taken {noprobe_streak} recon/no-probe actions in a row — search & notes "
                         f"DON'T make progress. SEND A REQUEST now (graphql/fuzz/sweep) to actually test something.")
        if step % nudge_every == 0 and not degraded:
            uhv = untested_high_value_fields(schema_map, ctx.ledger)
            if uhv and (budget - step) > 2:
                nudge.append(f"(reminder) high-value fields not yet probed: {', '.join(uhv[:6])}")
            missing = unconfirmed_classes(ctx.vulns)
            if missing and (budget - step) > 2:
                nudge.append("(reminder) untested vuln classes: " + "; ".join(missing[:4]))
            unused_tools = [t for t in _ENDPOINT_TOOLS if t not in techniques_used]
            if unused_tools and (budget - step) > 2:
                nudge.append(f"(reminder) endpoint-level tools not yet run: {', '.join(unused_tools)}")
        fixation = "  ".join(nudge)

        prompt = build_prompt({
            "target_url": target_url, "schema_map": schema_map, "schema_overview": schema_overview,
            "identity": ctx.identity, "remaining": budget - step, "budget": budget,
            "harvested": ctx.harvested,
            "covered": ctx.covered, "credentials": ctx.credentials, "facts": ctx.facts,
            "searched": ctx.searched, "findings": len(ctx.vulns), "vulns": ctx.vulns, "ledger": ctx.ledger,
            "notes": ctx.notes, "history": ctx.history, "decisions": ctx.decisions,
            "fixation": fixation, "steering": active_steer,
        })

        llm_error: str | None = None
        try:
            result_msg = invoke_with_circuit_breaker(llm, prompt)
        except Exception as e:  # noqa: BLE001
            result_msg = None
            llm_error = str(e)[:140]

        if result_msg is None:
            recent_actions.append("llm_error")
            if get_circuit_breaker_status().get("is_open"):
                circuit_waits += 1
                logger.warning("AGENT LLM provider circuit open at step %d (%d/%d) — waiting for recovery",
                               step, circuit_waits, _MAX_CIRCUIT_WAITS)
                ctx.log(f"[{step}] LLM provider circuit open — waiting ~{_CIRCUIT_TIMEOUT}s for recovery")
                if circuit_waits >= _MAX_CIRCUIT_WAITS:
                    logger.warning("AGENT aborting: LLM provider still down after %d circuit waits", circuit_waits)
                    break
                time.sleep(_CIRCUIT_TIMEOUT)
                continue
            detail = llm_error or "provider returned no response"
            low = detail.lower()
            is_rate_limit = "429" in low or "rate limit" in low
            is_length = ("length limit" in low or "completionusage" in low
                         or "finish_reason=length" in low or "'length'" in low)

            if is_length:
                # Deterministic truncation: the model burned its whole output budget (a reasoning
                # model overshooting) without emitting a parseable action. Retrying the identical
                # request just spends another full-length generation, so stop now and keep the
                # findings so far rather than grinding _LLM_ERROR_ABORT identical multi-minute
                # calls. The fix for a recurring case is a higher llm.attacker_max_tokens.
                cap = settings.get("llm", {}).get("attacker_max_tokens", 16384)
                logger.warning("AGENT aborting at step %d: response truncated at the %s-token output limit "
                               "— raise llm.attacker_max_tokens to give the model more room", step, cap)
                ctx.log(f"[{step}] response truncated at the token limit — aborting (raise attacker_max_tokens)")
                break

            consec_llm_error += 1
            logger.warning("AGENT LLM call failed at step %d (%d/%d): %s",
                           step, consec_llm_error, _LLM_ERROR_ABORT, detail)
            ctx.log(f"[{step}] LLM call failed: {detail}")
            if consec_llm_error >= _LLM_ERROR_ABORT:
                logger.warning("AGENT aborting: %d LLM/provider failures in a row", _LLM_ERROR_ABORT)
                break
            time.sleep(min(5 * consec_llm_error, 30) if is_rate_limit else min(2 * consec_llm_error, 10))
            continue

        consec_llm_error = 0
        circuit_waits = 0
        _accumulate_tokens(ctx.tokens, result_msg)
        content = getattr(result_msg, "content", "")
        act = extract_action(content)
        if tracer is not None:
            pending = {"step": step, "prompt": prompt, "raw_response": content,
                       "action": (act.get("action") if act else None),
                       "args": (act.get("args") if act else None),
                       "thought": str(act.get("thought", "")) if act else "",
                       "self_report": "", "_hl": len(ctx.history), "_io": len(ctx.step_io)}
        if act is None:
            consec_noaction += 1
            snippet = " ".join(str(content).split())[:160]
            ctx.log(f"[{step}] (no valid action parsed — reply with ONE JSON object; escape newlines "
                    f"inside string args as \\n: {snippet or 'empty'})")
            recent_actions.append("noop")
            if consec_noaction >= _NOACTION_ABORT:
                logger.warning("AGENT aborting: %d consecutive turns with no usable action. Last: %s",
                               consec_noaction, snippet[:200])
                break
            continue
        consec_noaction = 0

        name = str(act.get("action", "")).lower()
        args = act.get("args") or {}
        thought = str(act.get("thought", ""))[:200]
        recent_actions.append(name)
        recent_targets.append(_decision_target(name, args))
        if name in _ARSENAL_TOOLS:
            techniques_used.add(name)

        reported = apply_self_report(act, ctx.ledger, ctx.facts, identity_label(ctx.identity), step)
        retr = act.get("retract")
        if isinstance(retr, dict) and (retr.get("id") or retr.get("vuln_type") or retr.get("target")):
            n = ctx.retract(finding_id=str(retr.get("id", "")), vuln_type=str(retr.get("vuln_type", "")),
                            target=str(retr.get("target", "")), why=str(retr.get("why", ""))[:160])
            reported = (reported + "; " if reported else "") + \
                f"retracted {n} finding(s): {retr.get('id') or retr.get('vuln_type') or retr.get('target')}"
        if reported:
            ctx.log(f"[{step}] (self-report) {reported}")
        if pending is not None:
            pending["self_report"] = reported
        logger.info("AGENT[%d/%d] %s — %s", step + 1, budget, name,
                    str(act.get("thought", "")) if narrate else thought)

        if name == "done":
            if consecutive_dead >= _DEGRADED_AT and backoffs < _MAX_BACKOFFS:
                recent_actions[-1] = "backoff"
                ctx.log(f"[{step}] done IGNORED — target unresponsive; backing off, "
                        f"continuing ({budget - step} steps left)")
                ctx.decisions.append(_decision_line(step, "done", args, thought,
                                                    "DEFERRED — target unresponsive; backing off, not stopping"))
                continue
            unused = [t for t in _ENDPOINT_TOOLS if t not in techniques_used]
            if unused and (budget - step) > 3 and done_deferrals < _DONE_DEFERRALS:
                done_deferrals += 1
                recent_actions[-1] = "deferred"
                ctx.log(f"[{step}] done DEFERRED — you still have {budget - step} steps and haven't run "
                        f"{', '.join(unused)} (endpoint-level, apply to ANY endpoint). Run them, THEN finish.")
                ctx.decisions.append(_decision_line(step, "done", args, thought,
                                                    f"DEFERRED — endpoint tools unused: {', '.join(unused)}"))
                continue
            crit = critical_untested(schema_map, ctx.ledger)
            if crit and (budget - step) > 3 and hv_deferrals < _HV_DEFERRALS:
                hv_deferrals += 1
                recent_actions[-1] = "deferred"
                ctx.log(f"[{step}] done DEFERRED — CRITICAL high-value fields still untested: {', '.join(crit[:5])}. "
                        f"These are ATO/account-takeover primitives — auth_test them (anon/current/admin), THEN finish.")
                ctx.decisions.append(_decision_line(step, "done", args, thought,
                                                    f"DEFERRED — CRITICAL high-value untested: {', '.join(crit[:5])}"))
                continue
            ctx.log(f"[{step}] done: {str(args.get('reason', ''))[:120]}")
            ctx.decisions.append(_decision_line(step, "done", args, thought,
                                                f"STOP: {str(args.get('reason', ''))[:120]}"))
            logger.info("AGENT done: %s", args.get("reason", ""))
            run_complete = True
            break

        if name in _NONPROBE_ACTIONS and noprobe_streak >= _NOPROBE_CAP and not degraded:
            recent_actions[-1] = "blocked"
            blocked_recon += 1
            ctx.log(f"[{step}] {name} BLOCKED — {noprobe_streak} recon actions with no probe. You have "
                    f"enough schema; SEND A REQUEST now: graphql / fuzz / sweep / dos.")
            ctx.decisions.append(_decision_line(step, name, args, thought,
                                                f"BLOCKED — {noprobe_streak} recon actions, no probe; forced to test"))
            if blocked_recon >= _NOACTION_ABORT:
                logger.warning("AGENT aborting: %d recon actions blocked, model refuses to probe", blocked_recon)
                break
            continue

        try:
            res = dispatch(name, ctx, args)
        except Exception as e:  # noqa: BLE001
            logger.exception("AGENT action %s crashed at step %d", name, step)
            res = Result(observation=f"{name} crashed: {e}", touched_target=False)
        ctx.decisions.append(_decision_line(step, name, args, thought,
                                            _decision_summary(name, args, ctx, res)))
        if narrate and res.observation:
            for ln in str(res.observation).splitlines():
                logger.info("    ↳ %s", ln[:600])
        if res.touched_target:
            consecutive_dead = consecutive_dead + 1 if res.is_dead else 0
        if name in _NONPROBE_ACTIONS:
            noprobe_streak += 1
        elif not (res.blocked or res.is_dead):
            noprobe_streak = 0
            blocked_recon = 0
        if res.blocked:
            recent_actions[-1] = "blocked"
            consec_blocked += 1
            if consec_blocked >= _NOACTION_ABORT:
                logger.warning("AGENT aborting: %d actions blocked in a row (model won't pivot)", consec_blocked)
                break
        else:
            consec_blocked = 0

        if (oob_sess is not None and ctx.oob_injected_at is not None
                and step - ctx.oob_injected_at >= _OOB_CHECK_DELAY):
            _auto_oob_check(ctx)

        last_completed = step
        if cp_on and (step + 1) % cp_every == 0:
            _save_cp(step)
    else:
        run_complete = True  # for-loop exhausted the budget with no early break

    _finalize_trace()
    if tracer is not None:
        tracer.close({
            "steps": min(step + 1, budget), "findings": len(ctx.vulns),
            "action_histogram": dict(Counter(recent_actions)), "facts": list(ctx.facts),
            "searched": list(ctx.searched), "ledger_size": len(ctx.ledger),
            "vuln_types": [v.get("vuln_type") for v in ctx.vulns],
        })

    _save_cp(last_completed, complete=run_complete)

    return {"vulnerabilities": ctx.vulns, "interactions": ctx.interactions,
            "steps": min(step + 1, budget), "covered_count": len(ctx.covered),
            "notes": ctx.notes, "target_url": target_url, "tokens": ctx.tokens,
            "run_id": run_id}
