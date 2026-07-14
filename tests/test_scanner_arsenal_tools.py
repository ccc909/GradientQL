"""Tests for src/scanner/arsenal_tools.py — thin arsenal wrappers (mocked network)."""

from __future__ import annotations

from gradientql.scanner import arsenal_tools
from tests.conftest import MockClient


def test_tool_dos_typename_needs_latency():
    fast = MockClient(default={"data": {"a0": "Query"}, "errors": [], "_status_code": 200})
    _, _, vt, _ = arsenal_tools.tool_dos(fast, {}, "aliases")          # __typename, fast -> no finding
    assert vt is None
    slow = MockClient(default={"data": {"a0": "Query"}, "errors": [], "_status_code": 200, "_response_time_ms": 3000})
    _, _, vt, _ = arsenal_tools.tool_dos(slow, {}, "aliases")          # __typename, slow -> finding
    assert vt and "Denial of Service" in vt


def test_tool_dos_aliases_real_field_confirms():
    sm = {"_query_type": "Query", "Query": {"users": {"args": [], "return_type": "String", "description": ""}}}
    client = MockClient(default={"data": {"a0": "x"}, "errors": [], "_status_code": 200})
    q, _, vt, _ = arsenal_tools.tool_dos(client, sm, "aliases", data_field="users")
    assert "users" in q and "__typename" not in q
    assert vt and "Denial of Service" in vt


def test_tool_dos_no_finding_when_limited():
    client = MockClient(default={"errors": [{"message": "query cost limit exceeded"}], "_status_code": 200})
    _, _, vt, _ = arsenal_tools.tool_dos(client, {}, "aliases")
    assert vt is None


def test_tool_csrf_honest_when_get_rejected(monkeypatch):
    class _Resp:
        def __init__(self, status, text="", headers=None):
            self.status_code = status
            self.text = text
            self.headers = headers or {}

    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **k: _Resp(405, "method not allowed"))
    monkeypatch.setattr(requests, "post", lambda *a, **k: _Resp(200, '{"data":{}}',
                                                                {"Access-Control-Allow-Origin": ""}))
    out = arsenal_tools.tool_csrf("http://t/graphql", {}, n_mutations=3)
    joined = " | ".join(out)
    assert "not GET-CSRFable" in joined
    assert "locked down" in joined


def test_tool_csrf_flags_dangerous_cors(monkeypatch):
    class _Resp:
        def __init__(self, status, text="", headers=None):
            self.status_code = status
            self.text = text
            self.headers = headers or {}

    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **k: _Resp(400))
    monkeypatch.setattr(requests, "post", lambda *a, **k: _Resp(
        200, '{"data":{}}', {"Access-Control-Allow-Origin": "https://evil.example",
                            "Access-Control-Allow-Credentials": "true"}))
    out = arsenal_tools.tool_csrf("http://t/graphql", {}, n_mutations=3)
    assert any("EXPLOITABLE" in line for line in out)


def test_tool_smuggle_best_effort_handles_failure(monkeypatch):
    # GraphQLSmuggler probes raw sockets; with an unreachable host every probe raises, so the tool
    # must signal "NOT tested" rather than a false clean bill of health.
    vuln, detail = arsenal_tools.tool_smuggle("http://127.0.0.1:0/graphql")
    assert vuln is False
    assert isinstance(detail, str)
    assert "NOT tested" in detail


def test_tool_smuggle_reports_clean_when_probes_run(monkeypatch):
    # when the probes actually execute and find nothing, the clean-result message stands
    class _Res:
        vulnerable = False

    class _Smuggler:
        def __init__(self, url):
            pass

        def test_cl_te(self):
            return _Res()

        def test_te_cl(self):
            return _Res()

        def test_te_te(self):
            return _Res()

    import gradientql.utils.request_smuggler as rs
    monkeypatch.setattr(rs, "GraphQLSmuggler", _Smuggler)
    vuln, detail = arsenal_tools.tool_smuggle("http://t/graphql")
    assert vuln is False
    assert detail == "no smuggling/desync detected"
