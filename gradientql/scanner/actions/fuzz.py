"""The `fuzz` action: send a battery of payloads at one field argument in a single turn."""

from __future__ import annotations

import copy
import json
import re
from datetime import datetime, timezone

from . import action
from .context import ActionContext, Result
from ..memory import blank_entry, identity_label
from ..payloads import CLASS_PROBES, DEFAULT_CLASSES, ssti_hit
from ..senses import detect_injection_surface, detect_server_error_surface, is_dead

_CANARY = "FZc4n4ry7q"
_MAX_PAYLOADS = 14
_NON_INJECTABLE_SCALARS = {"Int", "Float", "Boolean"}

_COERCION_LITERALS = [
    '"FZcoerce"', "123456789", "true", "null", "[1, 2, 3]", "{}", '{ne: ""}', "{regex: \".*\"}",
    "99999999999999999999999999", "-1", "1.5", "NOTAVALIDENUMVALUE_xyz",
]
_ENUM_LEAK_RE = re.compile(r"did you mean|enum value|not a valid|expected type|cannot represent", re.I)


def _find_root(schema_map: dict, field: str) -> str | None:
    """Return the root type name (Query/Mutation) owning `field`, or None if neither does."""
    for r in (schema_map.get("_query_type", "Query"), schema_map.get("_mutation_type", "Mutation")):
        if isinstance(schema_map.get(r), dict) and field in schema_map[r]:
            return r
    return None


def _arg_type(schema_map: dict, root: str, field: str, arg: str) -> str | None:
    info = (schema_map.get(root) or {}).get(field)
    if not isinstance(info, dict):
        return None
    for a in info.get("args") or []:
        if a.get("name") == arg:
            return str(a.get("type") or "")
    return None


def _base_scalar(type_ref: str) -> str:
    return re.sub(r"[\[\]!]", "", type_ref or "").strip()


def _set_path(obj: dict, path: str, value) -> dict:
    """Set a dot-delimited nested key in `obj`, creating intermediate dicts, and return it."""
    keys = path.split(".")
    cur = obj
    for k in keys[:-1]:
        nxt = cur.get(k)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[k] = nxt
        cur = nxt
    cur[keys[-1]] = value
    return obj


@action("fuzz")
def handle_fuzz(ctx: ActionContext, args: dict) -> Result:
    """Fire a battery of injection payloads at one field argument in a single turn.

    Resolves the arg (top-level scalar or a nested leaf via path+input), skips probe
    classes already exhausted here (tracked in ctx._fuzz_seen), caps the batch, diffs each
    response against a canary baseline, and records any auto-confirmed injection findings.
    """
    field = str(args.get("field", "")).strip()
    arg = str(args.get("arg", "")).strip()
    path = str(args.get("path", "")).strip()
    base_input = args.get("input") if isinstance(args.get("input"), dict) else None
    if not field or not arg:
        msg = ("fuzz needs {field, arg}. For a string field NESTED in an input object also "
               "pass path:'<leaf>' (e.g. 'city') + input:{...base object with valid fillers...}.")
        ctx.log(f"[{ctx.step}] {msg}")
        return Result(observation=msg)
    sm = ctx.schema_map
    root = _find_root(sm, field)
    if root is None:
        msg = f"fuzz: field `{field}` is not a root Query/Mutation field"
        ctx.log(f"[{ctx.step}] {msg}")
        return Result(observation=msg)
    atype = _arg_type(sm, root, field, arg)
    if atype is None:
        msg = f"fuzz: `{field}` has no argument `{arg}`"
        ctx.log(f"[{ctx.step}] {msg}")
        return Result(observation=msg)

    requested0 = [str(c).lower() for c in (args.get("classes") or [])]
    coercion_req = [c for c in requested0 if c in ("coercion", "enum")]
    if coercion_req:
        if path:
            msg = (f"fuzz: classes {coercion_req} (type-coercion/enum) run on a TOP-LEVEL "
                   f"scalar arg only, not a nested leaf. Drop path:'{path}' to coerce `{arg}` directly, "
                   f"or fuzz the nested leaf with injection classes (ssti/cmdi/sqli) + path + input:{{...}}.")
            ctx.log(f"[{ctx.step}] {msg}")
            return Result(observation=msg)
        dropped = [c for c in requested0 if c not in ("coercion", "enum")]
        return _coercion_fuzz(ctx, sm, root, field, arg, dropped)

    nested = bool(path)
    if nested:
        if base_input is None:
            msg = (f"fuzz nested: also pass input:{{...}} - the full base object for `{arg}` "
                   f"with valid fillers, so only `{path}` carries the payload and the rest validates.")
            ctx.log(f"[{ctx.step}] {msg}")
            return Result(observation=msg)
        var_type = atype or "String"
        label = f"{field}({arg}.{path})"
    else:
        if "[" in atype:
            msg = (f"fuzz: `{arg}` is a list type ({atype}); target a scalar string arg "
                   f"(or a nested leaf with path:'<leaf>' + input:{{...}})")
            ctx.log(f"[{ctx.step}] {msg}")
            return Result(observation=msg)
        b = _base_scalar(atype)
        if b in _NON_INJECTABLE_SCALARS or b in (sm.get("_enum_types") or {}):
            msg = (f"fuzz: `{arg}` is {atype} (not string-injectable) - pick a String/ID arg, "
                   f"or fuzz a nested leaf with path:'<leaf>' + input:{{...}}")
            ctx.log(f"[{ctx.step}] {msg}")
            return Result(observation=msg)
        var_type = atype or "String"
        label = f"{field}({arg})"

    attacks = ctx.settings.get("scanner", {}).get("attacks", {})
    custom = [p for p in (args.get("payloads") or []) if isinstance(p, str) and p]
    requested = [str(c).lower() for c in (args.get("classes") or [])]
    if not custom and not requested:
        requested = list(DEFAULT_CLASSES)
    if attacks.get("injection", True) is False:
        requested = [c for c in requested if c not in ("sqli", "cmdi", "ssti")]
    if attacks.get("ssrf", True) is False:
        requested = [c for c in requested if c != "ssrf"]

    buckets: list[tuple[str, int, list[str]]] = []
    for cls in requested:
        probes = CLASS_PROBES.get(cls)
        if not probes:
            continue
        already = ctx._fuzz_seen.get((field, arg, path, cls), 0)
        remaining = probes[already:]
        if remaining:
            buckets.append((cls, already, remaining))

    known = list(dict.fromkeys(c for c in requested if CLASS_PROBES.get(c)))
    if not custom and known and not buckets:
        msg = (f"fuzz {label}: already fuzzed {', '.join(known)} here - whole ladder sent, no new "
               f"signal last time. Use DIFFERENT classes/payloads, or mark it dead and move on.")
        ctx.log(f"[{ctx.step}] {msg}")
        return Result(observation=msg)

    payloads: list[tuple[str, str]] = [("custom", p) for p in custom]
    for i in range(max((len(r) for _, _, r in buckets), default=0)):
        for cls, _already, remaining in buckets:
            if i < len(remaining):
                payloads.append((cls, remaining[i]))
    cap = ctx.settings.get("scanner", {}).get("fuzz", {}).get("max_payloads", _MAX_PAYLOADS)
    payloads = payloads[:cap]

    sent_counts: dict[str, int] = {}
    for cls, _ in payloads:
        if cls == "custom":
            continue
        sent_counts[cls] = sent_counts.get(cls, 0) + 1
    for cls, cnt in sent_counts.items():
        key = (field, arg, path, cls)
        ctx._fuzz_seen[key] = ctx._fuzz_seen.get(key, 0) + cnt

    if "ssrf" in requested and ctx.oob_sess is not None:
        try:
            url, _label = ctx.oob_sess.issue({"approach": "fuzz", "node": label})
            payloads.append(("ssrf", url))
        except Exception:  # noqa: BLE001
            pass
    if not payloads:
        msg = "fuzz: no payloads (unknown classes?) - pass payloads:[...] or classes:[ssti,...]"
        ctx.log(f"[{ctx.step}] {msg}")
        return Result(observation=msg)

    sel = args.get("selection")
    if not (isinstance(sel, str) and sel.strip().startswith("{")):
        from ..schema import fuzz_selection
        sel = fuzz_selection(sm, (sm[root].get(field) or {}).get("return_type", ""))
    op = "mutation" if root == sm.get("_mutation_type", "Mutation") else "query"

    base_resp = _send(ctx, op, field, arg, var_type, sel, _CANARY, path, base_input)
    base_blob = json.dumps(base_resp.get("data"), default=str) if base_resp.get("data") else ""
    dead = is_dead(base_resp.get("_status_code", 0))

    results: list[dict] = []
    confirmed: list[tuple[str, str, str]] = []
    has_ssrf = any(cls == "ssrf" for cls, _ in payloads)

    for cls, payload in payloads:
        resp = _send(ctx, op, field, arg, var_type, sel, payload, path, base_input)
        ctx.trace_io(f"{op} {{ {field}({arg}: {payload!r}) }}", {"p": payload}, resp, label=f"fuzz:{label}")
        dead = is_dead(resp.get("_status_code", 0))
        status = resp.get("_status_code", 0)
        data = resp.get("data")
        errs = resp.get("errors") or []
        blob = json.dumps(data, default=str) if data else ""
        tags: list[str] = []

        det_q = f"{label}: {json.dumps(payload)}"
        vt, reason = detect_injection_surface(det_q, resp)
        if not vt:
            vt, reason = detect_server_error_surface(resp)
        if vt:
            tags.append(f"DETECTOR:{vt}")
            confirmed.append((vt, payload, reason))
        marker = ssti_hit(payload, blob)
        if marker:
            tags.append(f"SSTI-EVAL:{marker}")
            confirmed.append(("Server-Side Template Injection (SSTI)", payload, f"{payload} -> {marker}"))
        if payload in blob:
            tags.append("reflected")
        elif blob and base_blob and blob != base_blob:
            tags.append("changed")
        elif errs:
            tags.append("error")
        snip = (str(errs[0].get("message", ""))[:90] if errs
                else (blob[:90] if "changed" in tags or "reflected" in tags else ""))
        results.append({"cls": cls, "payload": payload, "tags": tags, "status": status, "snip": snip})

    for vt, payload, reason in confirmed:
        ctx.record(vt, label, f"payload={payload!r}; {reason}", 3.0)
    if has_ssrf and ctx.oob_sess is not None:
        ctx.oob_injected_at = ctx.step

    idlabel = identity_label(ctx.identity)
    e = ctx.ledger.setdefault(field, blank_entry(field, idlabel, ctx.step))
    e["fuzzed"] = True
    if confirmed:
        e["finding"] = confirmed[0][0]
    else:
        e["auto"] = "FUZZED"

    def _line(r: dict) -> str:
        tag = "/".join(r["tags"]) if r["tags"] else "no-signal"
        st = "" if r["status"] in (200, 0) else f" HTTP{r['status']}"
        return f"{r['payload']!r}->{tag}{st}" + (f" «{r['snip']}»" if r["snip"] else "")

    if confirmed:
        head = "⚠ CONFIRMED: " + "; ".join(f"{vt} via {payload!r}" for vt, payload, _ in confirmed[:3])
        head += "\n  all payloads: " + " | ".join(_line(r) for r in results)
    elif results and all(r["tags"] == ["reflected"] for r in results):
        head = ("LITERAL REFLECTOR - every payload was echoed back verbatim with NO eval/error/diff. "
                "This is a plain echo, NOT an injection vector. Mark it dead; do not re-fuzz.")
    else:
        signal = [r for r in results if r["tags"]]
        if signal:
            head = "leads (read these - judge if any is a real vuln):\n  " + "\n  ".join(_line(r) for r in signal)
        else:
            head = ("no auto-signal across payloads - per-payload outcomes:\n  "
                    + "\n  ".join(_line(r) for r in results))
    ssrf_note = ("  [ssrf: OOB URL injected - run `oob_url op:check` in a few steps to confirm blind SSRF]"
                 if has_ssrf else "")
    fully_dropped: list[str] = []
    partial: list[tuple[str, int, int]] = []
    for cls in known:
        total = len(CLASS_PROBES[cls])
        done = ctx._fuzz_seen.get((field, arg, path, cls), 0)
        if done == 0:
            fully_dropped.append(cls)
        elif done < total:
            partial.append((cls, done, total))
    notes: list[str] = []
    if fully_dropped:
        notes.append(f"NOT sent: {', '.join(fully_dropped)}; re-fuzz with "
                     f"classes:[{','.join(fully_dropped)}] to cover them")
    for cls, done, total in partial:
        notes.append(f"{cls}: sent {done}/{total} - re-fuzz {label} classes:[{cls}] to send the rest")
    trunc_note = f"  [cap {cap} reached - " + "; ".join(notes) + "]" if notes else ""
    obs = f"fuzz {label} ×{len(payloads)} -> {head}{ssrf_note}{trunc_note}"
    ctx.interactions.append({"target_node": f"fuzz:{label}", "reason": "agent_fuzz",
                             "response_status": 0, "score": 0.0,
                             "timestamp": datetime.now(timezone.utc).isoformat()})
    ctx.log(f"[{ctx.step}] {obs}")
    return Result(observation=obs, touched_target=True, is_dead=dead)


def _coercion_fuzz(ctx: ActionContext, sm: dict, root: str, field: str, arg: str,
                   dropped: list[str] | None = None) -> Result:
    """Run the type-coercion/enum literal battery against a top-level scalar arg once.

    Sends wrong-typed and structural literals to surface type-confusion and enum leaks; the
    battery is deterministic, so it self-blocks on repeat via ctx._fuzz_seen.
    """
    battery_key = (field, arg, "", "coercion-battery")
    if battery_key in ctx._fuzz_seen:
        msg = (f"coercion {field}({arg}): already coerced here - the type-coercion/enum battery is "
               f"deterministic and was fully run, no new signal. Try injection classes "
               f"(ssti/cmdi/sqli), a different arg, or mark it dead.")
        ctx.log(f"[{ctx.step}] {msg}")
        return Result(observation=msg)
    ctx._fuzz_seen[battery_key] = len(_COERCION_LITERALS)
    from ..schema import fuzz_selection
    op = "mutation" if root == sm.get("_mutation_type", "Mutation") else "query"
    sel = fuzz_selection(sm, (sm[root].get(field) or {}).get("return_type", ""))
    label = f"{field}({arg})"
    results: list[dict] = []
    confirmed: list[tuple[str, str, str]] = []
    dead = False
    for lit in _COERCION_LITERALS:
        query = f"{op} {{ {field}({arg}: {lit}) {sel} }}".strip()
        try:
            resp = ctx.client.execute(query, None, extra_headers=ctx.identity or None)
        except Exception as ex:  # noqa: BLE001
            resp = {"data": None, "errors": [{"message": str(ex)[:120]}], "_status_code": 0}
        ctx.trace_io(query, {}, resp, label=f"coerce:{label}")
        dead = dead or is_dead(resp.get("_status_code", 0))
        data = resp.get("data")
        errs = resp.get("errors") or []
        tags: list[str] = []
        det_q = f"{label}: {lit}"
        vt, reason = detect_injection_surface(det_q, resp)
        if not vt:
            vt, reason = detect_server_error_surface(resp)
        if vt:
            tags.append(f"DETECTOR:{vt}")
            confirmed.append((vt, lit, reason))
        errtext = json.dumps(errs, default=str)[:400].lower()
        if errs and _ENUM_LEAK_RE.search(errtext):
            tags.append("type/enum-error")
        if data and not errs:
            tags.append("accepted-structural!" if lit.lstrip().startswith(("{", "[")) else "accepted")
        snip = (str(errs[0].get("message", ""))[:90] if errs
                else (json.dumps(data, default=str)[:90] if data else ""))
        results.append({"payload": lit, "tags": tags, "status": resp.get("_status_code", 0), "snip": snip})

    for vt, lit, reason in confirmed:
        ctx.record(vt, label, f"coercion={lit}; {reason}", 2.5)
    idlabel = identity_label(ctx.identity)
    e = ctx.ledger.setdefault(field, blank_entry(field, idlabel, ctx.step))
    e["fuzzed"] = True
    if confirmed:
        e["finding"] = confirmed[0][0]

    def _line(r: dict) -> str:
        tag = "/".join(r["tags"]) if r["tags"] else "no-signal"
        st = "" if r["status"] in (200, 0) else f" HTTP{r['status']}"
        return f"{r['payload']}->{tag}{st}" + (f" «{r['snip']}»" if r["snip"] else "")

    if confirmed:
        head = "⚠ CONFIRMED: " + "; ".join(f"{vt} via {lit}" for vt, lit, _ in confirmed[:3])
    else:
        head = "type-confusion outcomes (judge if any error leaks internals / a wrong type was accepted):"
    obs = f"coercion {label} ×{len(results)} -> {head}\n  " + "\n  ".join(_line(r) for r in results)
    if dropped:
        obs += (f"\n  [NOT run this turn: {', '.join(dropped)} - re-fuzz {label} with those classes "
                f"(no coercion/enum) to send that injection battery]")
    ctx.interactions.append({"target_node": f"coerce:{label}", "reason": "agent_fuzz_coercion",
                             "response_status": 0, "score": 0.0,
                             "timestamp": datetime.now(timezone.utc).isoformat()})
    ctx.log(f"[{ctx.step}] {obs}")
    return Result(observation=obs, touched_target=True, is_dead=dead)


def _send(ctx: ActionContext, op: str, field: str, arg: str, var_type: str, sel: str, payload: str,
          path: str = "", base_input: dict | None = None) -> dict:
    """Execute one payload-carrying query, returning an error-shaped dict instead of raising."""
    if path and isinstance(base_input, dict):
        variables = {"p": _set_path(copy.deepcopy(base_input), path, payload)}
    else:
        variables = {"p": payload}
    query = f"{op} F($p: {var_type}) {{ {field}({arg}: $p) {sel} }}".strip()
    try:
        return ctx.client.execute(query, variables, extra_headers=ctx.identity or None)
    except Exception as ex:  # noqa: BLE001
        return {"data": None, "errors": [{"message": str(ex)[:120]}], "_status_code": 0}
