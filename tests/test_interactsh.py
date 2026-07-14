"""Tests for the interactsh OOB client + OobSession.

The crypto roundtrip simulates the interactsh SERVER encrypting an interaction with our
public key exactly as the Go server does (RSA-OAEP/SHA-256 for the AES key, AES-CTR with a
16-byte IV for the payload), then proves our client.poll() decrypts it. This validates the
decrypt path without a live server.
"""

import base64
import json
import os

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from gradientql.utils import oob as oob_mod
from gradientql.utils.interactsh import InteractshClient


def _server_encrypt(client_pub_pem: bytes, interaction: dict) -> dict:
    """Mirror the interactsh server's response encryption."""
    aes_key = os.urandom(32)
    enc_aes = PKCS1_OAEP.new(RSA.import_key(client_pub_pem), hashAlgo=SHA256).encrypt(aes_key)
    iv = os.urandom(16)
    ct = AES.new(aes_key, AES.MODE_CTR, nonce=b"", initial_value=iv).encrypt(json.dumps(interaction).encode())
    return {
        "data": [base64.b64encode(iv + ct).decode()],
        "aes_key": base64.b64encode(enc_aes).decode(),
    }


class _Resp:
    def __init__(self, payload):
        self._p = payload
        self.status_code = 200

    def json(self):
        return self._p


def test_poll_decrypts_server_interaction(monkeypatch):
    client = InteractshClient(server="oast.fun")
    client.registered = True  # skip the network register
    interaction = {
        "protocol": "http", "unique-id": "abc", "full-id": client.correlation_id + "deadbeef0001",
        "raw-request": "GET / HTTP/1.1", "remote-address": "203.0.113.9", "timestamp": "2026-06-13T00:00:00Z",
    }
    server_payload = _server_encrypt(client.public_key_pem, interaction)
    monkeypatch.setattr("gradientql.utils.interactsh.requests.get", lambda *a, **k: _Resp(server_payload))

    out = client.poll()
    assert len(out) == 1
    assert out[0]["protocol"] == "http"
    assert out[0]["remote-address"] == "203.0.113.9"
    assert out[0]["full-id"].startswith(client.correlation_id)


def test_new_url_is_attributable():
    client = InteractshClient(server="oast.fun")
    url, label = client.new_url()
    assert label.startswith(client.correlation_id)
    assert len(label) == 33  # 20-char correlation-id + 13 random
    assert f"{label}.oast.fun" in url


def test_correlation_id_is_unique_under_seeded_rng():
    # The scanner does random.seed(scanner.seed) for reproducibility; the interactsh
    # correlation-id must NOT derive from that, else every run collides on the server
    # ("correlation-id provided already exists"). secrets-based -> unique per instance.
    import random
    random.seed(1337)
    a = InteractshClient(server="oast.fun")
    random.seed(1337)
    b = InteractshClient(server="oast.fun")
    assert a.correlation_id != b.correlation_id
    assert len(a.correlation_id) == 20
    # per-injection labels are also unique
    assert a.new_url()[1] != a.new_url()[1]


def test_server_parsing_does_not_corrupt_domain():
    assert InteractshClient(server="https://host.fun").server == "host.fun"
    assert InteractshClient(server="oast.pro").server == "oast.pro"


class _FakeClient:
    def __init__(self, corr):
        self.correlation_id = corr
        self.client = None
    def poll(self):
        return [{"protocol": "dns", "full-id": self.correlation_id + "node1payload", "remote-address": "10.0.0.1"}]
    def deregister(self):
        pass


def test_session_reconcile_matches_issued_label(monkeypatch):
    oob_mod.reset_session()
    # Disabled config -> constructor does NO network; then inject a fake registered client.
    sess = oob_mod.OobSession({"scanner": {"oob": {"enabled": False}}})
    fake = _FakeClient("corr12345678abcdefgh")
    sess.client = fake
    label = fake.correlation_id + "node1payload"
    sess.issued = {label: {"approach": "ssrf", "node": "Query.fetchUrl"}}
    hits = sess.reconcile()
    assert len(hits) == 1
    assert hits[0]["context"]["node"] == "Query.fetchUrl"
    assert hits[0]["interaction"]["protocol"] == "dns"


def test_session_disabled_without_config():
    oob_mod.reset_session()
    sess = oob_mod.OobSession({"scanner": {"oob": {"enabled": False}}})
    assert sess.client is None
    assert sess.reconcile() == []
