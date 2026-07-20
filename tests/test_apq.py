"""Automatic Persisted Queries attacks: registration, cache poisoning, allow-list bypass."""

from __future__ import annotations

import hashlib
import json

from gradientql.scanner.actions import ActionContext, dispatch
from gradientql.utils.apq import _sha256, probe_apq


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self.text = body

    def json(self):
        return json.loads(self.text)


class _ApqServer:
    """A minimal APQ endpoint: verify_hash + allowlist toggle the two vulnerabilities."""

    def __init__(self, verify_hash=True, allowlist=False):
        self.verify_hash = verify_hash
        self.allowlist = allowlist
        self.cache: dict[str, str] = {}

    def post(self, url, json=None, headers=None, timeout=None):
        payload = json or {}
        ext = (payload.get("extensions") or {}).get("persistedQuery") or {}
        h = ext.get("sha256Hash")
        q = payload.get("query")
        if q and h:  # registration
            if self.verify_hash and h != hashlib.sha256(q.encode()).hexdigest():
                return _Resp(200, '{"errors":[{"message":"provided sha256Hash does not match the query"}]}')
            self.cache[h] = q
            return _Resp(200, '{"data":{"__typename":"Query"}}')
        if h and not q:  # replay by hash
            if h in self.cache:
                return _Resp(200, '{"data":{"__typename":"Query"}}')
            return _Resp(200, '{"errors":[{"message":"PersistedQueryNotFound"}]}')
        if q and not h:  # plain query
            if self.allowlist:
                return _Resp(200, '{"errors":[{"message":"PersistedQueryOnly: only persisted operations allowed"}]}')
            return _Resp(200, '{"data":{"__typename":"Query"}}')
        return _Resp(400, '{"errors":[{"message":"bad request"}]}')


def _kinds(result):
    return {vt for vt, _ in result["findings"]}


def test_secure_server_no_findings():
    r = probe_apq("http://t/graphql", session=_ApqServer(verify_hash=True, allowlist=False))
    assert r["findings"] == []
    assert any("mismatch REJECTED" in o for o in r["observations"])
    assert any("no persisted-query allow-list" in o for o in r["observations"])


def test_hash_mismatch_cache_poisoning_detected():
    r = probe_apq("http://t/graphql", session=_ApqServer(verify_hash=False))
    assert any("Cache Poisoning" in k for k in _kinds(r))


def test_allowlist_bypass_detected():
    r = probe_apq("http://t/graphql", session=_ApqServer(verify_hash=True, allowlist=True))
    assert any("Allow-list Bypass" in k for k in _kinds(r))
    # a verifying server is NOT poisonable, so that finding must NOT appear
    assert not any("Cache Poisoning" in k for k in _kinds(r))


def test_sha256_helper():
    assert _sha256("{__typename}") == hashlib.sha256(b"{__typename}").hexdigest()


def test_apq_action_records_findings():
    client = type("C", (), {"session": _ApqServer(verify_hash=False)})()
    ctx = ActionContext(client=client, schema_map={}, schema_index=None, settings={},
                        target_url="http://t/graphql")
    res = dispatch("apq", ctx, {})
    assert res.touched_target
    assert any("Cache Poisoning" in v["vuln_type"] for v in ctx.vulns)
    assert "⚠" in res.observation


def test_apq_action_clean_target():
    client = type("C", (), {"session": _ApqServer(verify_hash=True)})()
    ctx = ActionContext(client=client, schema_map={}, schema_index=None, settings={},
                        target_url="http://t/graphql")
    res = dispatch("apq", ctx, {})
    assert ctx.vulns == []
