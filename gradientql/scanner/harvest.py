"""Extracts and stores values seen in requests and responses."""

from __future__ import annotations

import json
import re
from typing import Any

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")
_TOKEN_KEYS = ("token", "session_token", "secure_token", "access_token", "auth", "jwt", "secret", "otp")
_ID_KEYS = ("id", "uid", "uuid")

_HARVEST_VALUE_CHARS = 48


_RE_INTROSPECTION = re.compile(r"\b__(?:type|schema)\b")


def is_introspection_query(query: str) -> bool:
    """Return True if the query targets `__schema`/`__type` outside string literals."""
    stripped = re.sub(r'"(?:[^"\\]|\\.)*"', '', query or "")
    return bool(_RE_INTROSPECTION.search(stripped))


def walk(obj: Any):
    """Recursively yield (key, value) pairs from nested dicts, descending into lists (whose elements yield no key of their own)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            yield from walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v)


def harvest(response: dict[str, Any], store: dict[str, list[str]]) -> list[str]:
    """Extract JWTs, tokens, and IDs from a response into `store`, in place.

    Mutates `store` (a bucketed ledger of previously seen values) and returns only
    the values newly seen this call, pre-rendered for display.
    """
    fresh: list[str] = []
    blob = json.dumps(response.get("data") or {}, default=str)
    for tok in _JWT_RE.findall(blob):
        if tok not in store.setdefault("jwt", []):
            store["jwt"].append(tok)
            fresh.append(f"jwt={tok[:24]}…")
    for k, v in walk(response.get("data") or {}):
        if not isinstance(v, (str, int)) or v in (None, "", 0):
            continue
        kl = str(k).lower()
        sval = str(v)
        if any(t in kl for t in _TOKEN_KEYS) and len(sval) >= 8:
            b = store.setdefault("token", [])
            if sval not in b:
                b.append(sval)
                fresh.append(f"{k}={sval[:32]}…")
        elif any(kl == i or kl.endswith(i) for i in _ID_KEYS):
            b = store.setdefault("id", [])
            if sval not in b and len(b) < 60:
                b.append(sval)
    return fresh


_PW_NAMES = ("password", "passwd", "pwd", "passphrase")
_ID_SUFFIX = ("email", "username", "login", "user", "phone", "mobile", "msisdn")
_ID_PREFIX = ("email", "username", "phone", "mobile")
_RE_ARG = re.compile(r'([A-Za-z_]\w*)\s*:\s*(?:"((?:[^"\\]|\\.)*)"|\$([A-Za-z_]\w*))')


def _is_secret_name(name: str) -> bool:
    n = name.lower().replace("_", "")
    return any(n == p or n.endswith(p) for p in _PW_NAMES)


def _is_identity_name(name: str) -> bool:
    n = name.lower().replace("_", "")
    return any(n == t or n.endswith(t) for t in _ID_SUFFIX) or any(n.startswith(p) for p in _ID_PREFIX)


def _request_kv_pairs(query: str, variables: dict[str, Any]) -> list[tuple[str, str]]:
    scalars = {str(k).lower(): str(v) for k, v in walk(variables or {})
               if isinstance(v, (str, int)) and str(v) not in ("", "0")}
    pairs: list[tuple[str, str]] = []
    for name, lit, var in _RE_ARG.findall(query or ""):
        if lit:
            pairs.append((name.lower(), lit))
        elif var and var.lower() in scalars:
            pairs.append((name.lower(), scalars[var.lower()]))
    pairs.extend(scalars.items())
    return pairs


def harvest_request(query: str, variables: dict[str, Any]) -> dict[str, str] | None:
    """Pull a credential record from an outgoing auth request, or None if none present.

    Returns None unless a password-like argument is found; otherwise a dict pairing
    the identity arg (email/username/…) with the password.
    """
    pairs = _request_kv_pairs(query, variables)
    secret = next((v for k, v in pairs if _is_secret_name(k)), None)
    if not secret:
        return None
    rec: dict[str, str] = {}
    for k, v in pairs:
        if _is_identity_name(k):
            rec[k] = v
            break
    rec["password"] = secret
    return rec


def find_reflections(query: str, variables: dict[str, Any], data: Any) -> list[str]:
    """Return request argument values that appear reflected in the response data."""
    if is_introspection_query(query):
        return []
    blob = json.dumps(data or {}, default=str)
    if not blob or blob == "{}":
        return []
    out: list[str] = []
    for _name, val in _request_kv_pairs(query, variables):
        if len(val) >= 4 and val in blob and val not in out:
            out.append(val)
    return out


def render_harvested(harvested: dict[str, list[str]]) -> str:
    parts = []
    for k, vals in harvested.items():
        if not vals:
            continue
        full = any(t in str(k).lower() for t in ("token", "jwt", "secret", "auth", "otp"))
        shown = ", ".join(str(v) if full else str(v)[:_HARVEST_VALUE_CHARS] for v in vals[:5])
        parts.append(f"{k}: {shown}" + (f"  (+{len(vals) - 5} more)" if len(vals) > 5 else ""))
    return "\n  ".join(parts) if parts else "none"


def render_credentials(credentials: list[dict[str, str]]) -> str:
    if not credentials:
        return "none"
    return "\n  ".join(", ".join(f"{k}={v}" for k, v in rec.items()) for rec in credentials)
