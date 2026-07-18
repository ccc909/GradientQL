"""Core action handlers: graphql, set_identity, report_finding, done."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from . import action
from .context import ActionContext, Result
from ..harvest import find_reflections, harvest, harvest_request
from ..memory import blank_entry, identity_label, primary_root_field
from ..prevalidate import prevalidate_query
from ..schema import introspection_shortcut
from ..senses import (
    _VALIDATION_ERR_MARKERS,
    classify_outcome,
    empty_response,
    is_dead,
    operation_failed,
    run_detectors,
)

_OBS_DATA_CHARS = 2000
_OBS_QUERY_CHARS = 300
_OBS_ERR_CHARS = 300

_NOTABLE_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*"
    r"|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    r"|\b[A-Fa-f0-9]{32,}\b"
    r"|\b(?:sk|pk|ghp|xox[bap]|AKIA)[-_A-Za-z0-9]{10,}\b")


def _obs_data(full: str, obs_max: int = _OBS_DATA_CHARS) -> str:
    """Truncate a response body for the observation, surfacing secret-like values from the tail.

    When the body is cut, tokens/emails/hashes/keys that would otherwise be lost past the
    cutoff are scanned out of the full text and appended as a NOTABLE note.
    """
    if len(full) <= obs_max:
        return full
    tail = full
    notable: list[str] = []
    for m in _NOTABLE_RE.finditer(tail):
        v = m.group(0)
        if v not in notable:
            notable.append(v)
        if len(notable) >= 5:
            break
    note = f"  …(+{len(full) - obs_max} chars truncated - full body in trace)"
    if notable:
        note += "  ⚠ NOTABLE values further in the response: " + ", ".join(v[:80] for v in notable)
    return full[:obs_max] + note

FIELD_RETRY_CAP = 8
DUP_FAIL_CAP = 2

_VOLATILE_SIG = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|\d{4}-\d{2}-\d{2}[t ][\d:.]+z?"
    r"|0x[0-9a-f]+|\b\d{4,}\b",
    re.IGNORECASE)


def _request_fp(query: str, variables: dict) -> str:
    """Stable fingerprint of a query+variables pair, for detecting an identical resend."""
    blob = " ".join(query.split()) + "|" + json.dumps(variables, sort_keys=True, default=str)
    return hashlib.md5(blob.encode("utf-8", "replace")).hexdigest()[:10]


def _sig_key(sig: str) -> str:
    """Collapse volatile substrings (uuids, timestamps, hex, long ints) so signatures compare stably."""
    return _VOLATILE_SIG.sub("#", sig or "")


_URL_ARG_NAMES = ("url", "uri", "webhook", "callback", "redirect", "fetch", "endpoint", "link",
                  "host", "src", "image", "href", "remote")


def _takes_url_arg(schema_map: dict, field: str) -> str | None:
    """Return the name of the field's URL-like argument (for SSRF), or None if it has none."""
    for root in (schema_map.get("_query_type", "Query"), schema_map.get("_mutation_type", "Mutation")):
        info = (schema_map.get(root) or {}).get(field)
        if isinstance(info, dict):
            for a in info.get("args") or []:
                n = str(a.get("name", "")).lower()
                if any(u == n or u in n for u in _URL_ARG_NAMES):
                    return a.get("name")
    return None


_NOTABLE_CLAIMS = ("iss", "aud", "sub", "exp", "role", "roles", "scope", "scopes", "admin", "base_url",
                   "clientapiurl", "configurl", "merchant_name", "merchantid", "merchant", "environment",
                   "session_type", "session_id", "typ", "name", "email", "version")


def _decode_response_tokens(text: str) -> str:
    """Decode JWT-like blobs found in a response into a one-line summary of notable claims.

    Returns an empty string if nothing decodes to a non-empty claims object.
    """
    seen: list[str] = []
    for m in re.finditer(r"eyJ[A-Za-z0-9_-]{10,}", text or ""):
        blob = m.group(0)
        try:
            claims = json.loads(base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4)))
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(claims, dict) or not claims:
            continue
        keep = {k: v for k, v in claims.items() if str(k).lower() in _NOTABLE_CLAIMS} or claims
        summ = ", ".join(f"{k}={str(v)[:40]}" for k, v in list(keep.items())[:6])
        if summ and summ not in seen:
            seen.append(summ)
        if len(seen) >= 2:
            break
    return ("⚠ TOKEN in response decoded - judge if it's a by-design public client token "
            "(merchant/clientApiUrl present) or a real secret worth chasing: " + " || ".join(seen)) if seen else ""


def _typename_only(val: Any) -> bool:
    """True if a response value carries only __typename (a reachability check, no data)."""
    if isinstance(val, dict):
        return bool(val) and set(val.keys()) == {"__typename"}
    if isinstance(val, list):
        return bool(val) and all(_typename_only(v) for v in val)
    return False


def _mutation_batch_count(query: str) -> int:
    """Count top-level fields in a single-mutation operation; 0 for anything else."""
    try:
        from graphql import parse
        from graphql.language import ast as gast
        ops = [d for d in parse(query).definitions if isinstance(d, gast.OperationDefinitionNode)]
        if len(ops) == 1 and getattr(ops[0].operation, "value", "").lower() == "mutation":
            return sum(1 for s in ops[0].selection_set.selections if isinstance(s, gast.FieldNode))
    except Exception:  # noqa: BLE001
        return 0
    return 0


@action("graphql")
def handle_graphql(ctx: ActionContext, args: dict) -> Result:
    """Execute one GraphQL request, updating the per-field ledger and recording findings.

    Serves introspection and pre-validation locally without a request, enforces the
    dedup/retry backstops (may return a blocked Result), harvests credentials/secrets,
    runs detectors, and mutates the ledger entry for the primary root field in place.
    """
    query = str(args.get("query", "")).strip()
    variables = args.get("variables") if isinstance(args.get("variables"), dict) else {}
    req_headers = args.get("headers") if isinstance(args.get("headers"), dict) else {}
    if not query:
        ctx.log(f"[{ctx.step}] graphql: empty query, skipped")
        return Result(observation="empty query - the GraphQL string must go in args.query "
                      "({\"action\":\"graphql\",\"args\":{\"query\":\"...\"}}); a \"query\" "
                      "placed at the top level, outside \"args\", is dropped.")

    served = introspection_shortcut(query, ctx.schema_map)
    if served is not None:
        ctx.log(f"[{ctx.step}] graphql (introspection served locally) -> {served[:120]}")
        return Result(observation=served)

    synthetic = prevalidate_query(query, variables, ctx.schema_map)
    if synthetic is not None:
        ctx.log(f"[{ctx.step}] graphql PRE-VALIDATED (no request) -> {synthetic}")
        return Result(observation=synthetic)

    scanner = ctx.settings.get("scanner", {})
    tuning = scanner.get("tuning", {})
    cap = tuning.get("field_retry_cap", FIELD_RETRY_CAP)
    dup_cap = tuning.get("dup_fail_cap", DUP_FAIL_CAP)
    obs_max = scanner.get("obs_max_chars", _OBS_DATA_CHARS)

    pf = primary_root_field(query) or "?"
    idlabel = identity_label(ctx.identity)
    led = ctx.ledger.setdefault(pf, blank_entry(pf, idlabel, ctx.step))
    if led.get("identity") != idlabel:
        led.update(attempts=0, identity=idlabel, verdict=None, why=None, confidence=None,
                   dup_fails=0, last_sig=None, stale_fps=[])
    incoming_fp = _request_fp(query, variables)
    same_request = incoming_fp == (led.get("last_sig") or "").rsplit("|", 1)[-1]
    if led.get("dup_fails", 0) >= dup_cap and same_request:
        msg = (f"graphql BLOCKED: this EXACT request to '{pf}' returned the identical failure "
               f"{led['dup_fails']}x under {idlabel} ({led.get('sig') or 'no progress'}). Resending it "
               f"won't help - CHANGE AN ARGUMENT (a different id/value), switch identity, or pivot to a "
               f"different field/vector.")
        ctx.log(f"[{ctx.step}] {msg}")
        return Result(observation=msg, blocked=True)
    stale_fps = led.get("stale_fps") or []
    oscillating = len(stale_fps) >= cap and len(set(stale_fps)) <= 2
    if (led["attempts"] >= cap and same_request) or oscillating:
        msg = (f"graphql BLOCKED (backstop): '{pf}' tried {led['attempts']}x under {idlabel} "
               f"without progress - mark it dead/open and move to a new field or identity.")
        ctx.log(f"[{ctx.step}] {msg}")
        return Result(observation=msg, blocked=True)

    send_headers = {**ctx.identity, **{str(k): str(v) for k, v in req_headers.items()}}
    try:
        resp = ctx.client.execute(query, variables, extra_headers=send_headers or None)
    except Exception as e:  # noqa: BLE001
        ctx.log(f"[{ctx.step}] graphql ERROR: {str(e)[:120]}")
        return Result(observation=f"graphql ERROR: {str(e)[:120]}")

    ctx.trace_io(query, variables, resp, label=pf)
    ctx.covered.add(query[:60])
    status = resp.get("_status_code", 0)
    data = resp.get("data")
    errors = resp.get("errors") or []
    failmsg = operation_failed(data)
    is_empty = empty_response(data)

    led["attempts"] += 1
    led["step"] = ctx.step
    led["auto"] = classify_outcome(status, data, errors)
    # remember THIS field's request so a later report_finding on it reconstructs the right curl,
    # not whatever unrelated probe happened to run last.
    led["req"] = dict(getattr(ctx.client, "last_request", None) or {})
    err_s = "; ".join(str(e.get("message", e))[:_OBS_ERR_CHARS] for e in errors[:4]) if errors else ""
    led["sig"] = failmsg or (err_s[:160] if err_s else ("null" if is_empty else ""))
    full_data_s = json.dumps(data, default=str) if data else "null"
    data_s = _obs_data(full_data_s, obs_max)

    fresh = harvest(resp, ctx.harvested)
    cred = harvest_request(query, variables)
    cred_is_new = bool(cred) and cred not in ctx.credentials
    if cred_is_new:
        ctx.credentials.append(cred)

    obs_bits = [f"HTTP {status}"]
    if is_empty:
        obs_bits.append(f"data=NULL/EMPTY ({pf} returned nothing - null/disabled/auth-gated under {idlabel})")
    elif failmsg:
        obs_bits.append(f"data={data_s}  ⚠ self-reported FAILURE ({failmsg})")
    else:
        obs_bits.append(f"data={data_s}")
    if err_s:
        obs_bits.append(f"errors={err_s}")
    if is_empty and any(m in err_s.lower() for m in _VALIDATION_ERR_MARKERS):
        obs_bits.append("⚠ VALIDATION error: the WHOLE query was REJECTED before running - the "
                        "fields you wanted were NOT tested. Re-run the one you care about ALONE, "
                        "using { __typename } if unsure of its subfields.")
    if _mutation_batch_count(query) >= 2:
        obs_bits.append("⚠ BATCHED MUTATION: you ran 2+ state-changing fields in one request - if any "
                        "errors, the whole result is ENTANGLED and you can't trust the others. For an "
                        "auth-sensitive/destructive mutation, send it ALONE (or use auth_test).")
    if (led["attempts"] > 1 and isinstance(data, dict) and data
            and all(_typename_only(v) for v in data.values())):
        obs_bits.append(f"note: `{pf}` was already probed (x{led['attempts']}) and a bare "
                        "__typename tells you nothing new - select the REAL fields you need "
                        "(search_schema the return type if unsure), or move on.")
    if fresh:
        obs_bits.append("HARVESTED " + ", ".join(fresh[:4]))
    if cred_is_new:
        obs_bits.append("STORED credentials " + ", ".join(f"{k}={v}" for k, v in cred.items())
                        + " (reuse this EXACT pair to log in)")
    for vt, reason in run_detectors(query, resp):
        obs_bits.append(f"⚠ DETECTOR: {vt} ({reason[:80]})")
        ctx.record(vt, query[:60], f"{reason}; resp={data_s}", 3.0)
        led["finding"] = vt
    if ctx.oob_sess is not None and getattr(ctx.oob_sess, "domain", None) and ctx.oob_sess.domain in full_data_s:
        obs_bits.append("⚠ OOB callback domain reflected in response")
        ctx.record("Server-Side Request Forgery (OOB reflected)", query[:60], data_s, 3.0)
    if ctx.oob_sess is not None and getattr(ctx.oob_sess, "domain", None) and (
            ctx.oob_sess.domain in query or ctx.oob_sess.domain in json.dumps(variables, default=str)):
        ctx.oob_injected_at = ctx.step

    if not led.get("finding") and not led.get("fuzzed"):
        refl = find_reflections(query, variables, data)
        if refl:
            led["echoed"] = f"echoes input ({refl[0][:24]})"
            obs_bits.append(f"note: your input ({refl[0][:24]!r}) is echoed back. If this field RENDERS/"
                            f"interpolates input (a template/preview/format/message), `fuzz` it for SSTI/cmdi; "
                            f"if it's just a stored value echoed in a CRUD response, it's a plain echo - your call.")
    if "eyJ" in full_data_s:
        decoded = _decode_response_tokens(full_data_s)
        if decoded:
            obs_bits.append(decoded)
    urlarg = _takes_url_arg(ctx.schema_map, pf)
    oob_dom = getattr(ctx.oob_sess, "domain", "") if ctx.oob_sess is not None else ""
    if (urlarg and ctx.oob_sess is not None and not led.get("fuzzed")
            and (is_empty or not data) and not (oob_dom and oob_dom in query)):
        obs_bits.append(f"blind-SSRF: `{pf}` takes a URL arg ('{urlarg}') and returned no data - that does "
                        f"NOT clear SSRF (a server-side fetch is invisible in the response). To actually test "
                        f"it: `fuzz` field:'{pf}' arg:'{urlarg}' classes:['ssrf'] (auto-injects an OOB callback "
                        f"and the loop auto-confirms a blind hit).")

    progress = (led["auto"] == "DATA"
                or (bool(fresh) and not failmsg and not is_empty)
                or bool(led.get("finding")))
    outcome_sig = f"{led['auto']}|{_sig_key(led['sig'])}|{_request_fp(query, variables)}"
    if progress:
        led["dup_fails"] = 0
        led["stale_fps"] = []
        if led.get("verdict") == "dead":
            led["verdict"] = None
            led["why"] = None
            led["confidence"] = None
    elif outcome_sig == led.get("last_sig"):
        led["dup_fails"] = led.get("dup_fails", 0) + 1
    else:
        led["dup_fails"] = 1
    if not progress:
        led["stale_fps"] = ((led.get("stale_fps") or []) + [incoming_fp])[-cap:]
    led["last_sig"] = outcome_sig
    if led["dup_fails"] >= 2:
        obs_bits.append(f"⚠ SAME failure as last time (x{led['dup_fails']}) - this vector looks dead "
                        f"for {idlabel}; pivot or change identity rather than resending (next resend is blocked).")

    ctx.interactions.append({
        "target_node": query[:80], "query": query[:2000], "variables": variables,
        "response_status": status, "score": 0.0, "reason": "agent_graphql",
        "response_body": data_s, "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    obs = " | ".join(obs_bits)
    qshort = " ".join(query.split())[:_OBS_QUERY_CHARS]
    ctx.log(f"[{ctx.step}] graphql `{qshort}`\n    -> {obs}")
    return Result(observation=obs, touched_target=True, is_dead=is_dead(status))


@action("set_identity")
def handle_set_identity(ctx: ActionContext, args: dict) -> Result:
    hdrs = args.get("headers") or {}
    if not isinstance(hdrs, dict):
        ctx.log(f"[{ctx.step}] set_identity -> headers must be an object")
        return Result(observation="set_identity: headers must be an object")
    new = {str(k): str(v) for k, v in hdrs.items()}
    if new and all(ctx.identity.get(k) == v for k, v in new.items()):
        obs = ("identity UNCHANGED - those headers are already active; stop re-setting. To compare "
               "identities for BOLA, pass the OTHER token via graphql `headers` on a SINGLE call "
               "instead of switching back and forth.")
        ctx.log(f"[{ctx.step}] set_identity -> {obs}")
        return Result(observation=obs)
    ctx.identity.update(new)
    obs = f"identity now: {', '.join(ctx.identity.keys())}"
    ctx.log(f"[{ctx.step}] set_identity -> {obs}")
    return Result(observation=obs)


_SEVERITY_SCORE = {"low": 1.0, "medium": 2.0, "med": 2.0, "high": 3.0, "critical": 4.0, "crit": 4.0}


def _severity_to_score(sev: object) -> float:
    """Map a severity label or number to a 0-4 score; bool or unknown falls back to 2.5."""
    if isinstance(sev, bool):
        return 2.5
    if isinstance(sev, (int, float)):
        return max(0.0, min(float(sev), 4.0))
    return _SEVERITY_SCORE.get(str(sev or "").strip().lower(), 2.5)


def _target_field(target: str) -> str:
    """Reduce a model-written target ('Query.users', 'users(id:)', 'the users field') to a field key."""
    t = (target or "").strip()
    t = t.split()[0] if t else ""
    t = t.split(".")[-1]
    return re.sub(r"[^A-Za-z0-9_].*$", "", t)


@action("report_finding")
def handle_report_finding(ctx: ActionContext, args: dict) -> Result:
    vt = str(args.get("vuln_type", "Finding"))
    target = str(args.get("target", ""))
    # Attach the request for the REPORTED field (from its ledger entry), not client.last_request -
    # the model often reports a finding it confirmed several probes ago, so last_request is unrelated.
    entry = ctx.ledger.get(_target_field(target))
    req = entry.get("req") if isinstance(entry, dict) and isinstance(entry.get("req"), dict) and entry.get("req") else None
    if req is None:
        req = {"url": ctx.target_url, "payload": {}, "headers": dict(ctx.identity or {})}
    ok = ctx.record(vt, target, str(args.get("evidence", "")),
                    _severity_to_score(args.get("severity")), req=req)
    ctx.log(f"[{ctx.step}] report_finding: {vt} on {target}")
    if not ok:
        return Result(observation=(f"NOT recorded - {vt} on {target or 'endpoint'} duplicates an existing "
                                   "finding or was retracted; vary vuln_type/target or leave the retraction."))
    return Result(observation=f"recorded finding: {vt} on {target or 'endpoint'}")


@action("done")
def handle_done(ctx: ActionContext, args: dict) -> Result:
    reason = str(args.get("reason", ""))[:120]
    return Result(observation=f"done: {reason}", stop=True)
