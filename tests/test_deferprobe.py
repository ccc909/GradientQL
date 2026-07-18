"""@defer/@stream incremental-delivery probing."""

from __future__ import annotations

from gradientql.scanner.actions import ActionContext, dispatch
from gradientql.utils.deferprobe import build_defer_query, probe_defer


class _Resp:
    def __init__(self, status=200, ct="application/json", text=""):
        self.status_code = status
        self.headers = {"Content-Type": ct}
        self.text = text


class _Sess:
    def __init__(self, resp):
        self._resp = resp
        self.sent = []

    def post(self, url, json=None, headers=None, timeout=None):
        self.sent.append({"headers": headers, "json": json})
        return self._resp


def test_probe_detects_multipart():
    body = "--graphql\r\nContent-Type: application/json\r\n\r\n{\"data\":{},\"hasNext\":true}\r\n--graphql--"
    r = probe_defer("http://t/graphql", "query { x { ... @defer { y } } }",
                    session=_Sess(_Resp(200, "multipart/mixed; boundary=graphql", body)))
    assert r["supported"] and r["multipart"]


def test_probe_detects_hasnext_json():
    r = probe_defer("http://t/graphql", "q", session=_Sess(_Resp(200, "application/json", '{"data":{},"hasNext":false}')))
    assert r["supported"]


def test_probe_not_supported_plain_json():
    r = probe_defer("http://t/graphql", "q", session=_Sess(_Resp(200, "application/json", '{"data":{"x":1}}')))
    assert not r["supported"]


def test_probe_sends_incremental_accept_header():
    s = _Sess(_Resp())
    probe_defer("http://t/graphql", "q", session=s)
    assert "multipart/mixed" in s.sent[0]["headers"]["Accept"]


def test_build_defer_query_over_object_field():
    sm = {"_query_type": "Query",
          "Query": {"me": {"args": [], "return_type": "User", "description": ""},
                    "count": {"args": [], "return_type": "Int", "description": ""}},
          "User": {"id": {"args": [], "return_type": "ID", "description": ""}}}
    q = build_defer_query(sm)
    assert q and "@defer" in q and "me" in q


def test_build_defer_query_none_when_no_object_field():
    sm = {"_query_type": "Query", "Query": {"count": {"args": [], "return_type": "Int", "description": ""}}}
    assert build_defer_query(sm) is None


def test_defer_action_records_when_supported(monkeypatch):
    from gradientql.utils import deferprobe
    monkeypatch.setattr(deferprobe, "probe_defer", lambda *a, **k: {
        "supported": True, "multipart": True, "content_type": "multipart/mixed", "markers": ["multipart/mixed"]})
    sm = {"_query_type": "Query", "Query": {"me": {"args": [], "return_type": "User", "description": ""}},
          "User": {"id": {"args": [], "return_type": "ID", "description": ""}}}
    ctx = ActionContext(client=type("C", (), {"session": None})(), schema_map=sm, schema_index=None,
                        settings={}, target_url="http://t/graphql")
    res = dispatch("defer", ctx, {})
    assert any("Incremental Delivery" in v["vuln_type"] for v in ctx.vulns)
    assert "SUPPORTED" in res.observation
