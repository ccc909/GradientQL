"""GraphQL-over-WebSocket subscription probing."""

from __future__ import annotations

import json

from gradientql.utils import gqlws


def test_ws_url_scheme_swap():
    assert gqlws._ws_url("http://t/graphql") == "ws://t/graphql"
    assert gqlws._ws_url("https://api.x/graphql") == "wss://api.x/graphql"


class _FakeWS:
    def __init__(self, subproto, recvs):
        self._subproto = subproto
        self._recvs = list(recvs)
        self.sent = []

    def getsubprotocol(self):
        return self._subproto

    def send(self, m):
        self.sent.append(m)

    def recv(self):
        if self._recvs:
            return self._recvs.pop(0)
        raise RuntimeError("no more frames")

    def close(self):
        pass


def _patch_connections(monkeypatch, queue):
    it = iter(queue)

    def fake_cc(ws_url, subprotocols=None, header=None, timeout=None):
        item = next(it)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(gqlws, "_WS_AVAILABLE", True)
    monkeypatch.setattr(gqlws.websocket, "create_connection", fake_cc, raising=False)


def test_probe_reports_all_findings(monkeypatch):
    nxt = json.dumps({"type": "next", "payload": {"data": {"secret": 1}}})
    ack = json.dumps({"type": "connection_ack"})
    queue = [
        _FakeWS("graphql-transport-ws", []),   # modern accepted
        _FakeWS("graphql-ws", []),             # legacy accepted -> downgrade
        _FakeWS("graphql-transport-ws", [nxt]),        # pre-init subscribe -> data (bypass)
        _FakeWS("graphql-transport-ws", [ack, nxt]),   # unauth init+subscribe -> data (authz)
    ]
    _patch_connections(monkeypatch, queue)
    res = gqlws.probe_subscriptions("http://t/graphql", {}, sub_field="secret")
    kinds = {vt for vt, _ in res["findings"]}
    assert any("Downgrade" in k for k in kinds)
    assert any("pre-handshake" in k for k in kinds)
    assert any("Broken Authorization" in k for k in kinds)


def test_probe_gated_no_findings(monkeypatch):
    err = json.dumps({"type": "error", "payload": [{"message": "must init first"}]})
    queue = [
        _FakeWS("graphql-transport-ws", []),   # modern accepted
        ConnectionError("legacy rejected"),    # legacy rejected -> no downgrade
        _FakeWS("graphql-transport-ws", [err]),        # pre-init -> error (gated)
        _FakeWS("graphql-transport-ws", [err]),        # init -> error (no ack)
    ]
    _patch_connections(monkeypatch, queue)
    res = gqlws.probe_subscriptions("http://t/graphql", {}, sub_field="secret")
    assert res["findings"] == []
    assert res["observations"]


def test_probe_unavailable(monkeypatch):
    monkeypatch.setattr(gqlws, "_WS_AVAILABLE", False)
    res = gqlws.probe_subscriptions("http://t/graphql", {})
    assert res["available"] is False
    assert any("websocket-client" in o for o in res["observations"])


def test_subscribe_action_records_findings(monkeypatch):
    from gradientql.scanner.actions import ActionContext, dispatch

    def fake_probe(url, headers=None, sub_field=None, timeout=6):
        return {"available": True, "observations": ["x"],
                "findings": [("GraphQL Subscription Auth Bypass (pre-handshake)", "ev")]}

    monkeypatch.setattr(gqlws, "probe_subscriptions", fake_probe)
    sm = {"_subscription_type": "Subscription", "Subscription": {"messageAdded": {}}}
    ctx = ActionContext(client=type("C", (), {"session": None})(), schema_map=sm, schema_index=None,
                        settings={}, target_url="http://t/graphql")
    res = dispatch("subscribe", ctx, {})
    assert any("Auth Bypass" in v["vuln_type"] for v in ctx.vulns)
    assert "⚠" in res.observation
