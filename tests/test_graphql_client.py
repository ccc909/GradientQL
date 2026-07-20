"""Tests for gradientql/utils/graphql_client.py — the http config knobs."""

from __future__ import annotations

from gradientql.utils import graphql_client
from gradientql.utils.graphql_client import GraphQLClient, get_client

URL = "https://target.example/graphql"


def test_http_defaults_leave_behavior_unchanged():
    c = GraphQLClient(URL)
    assert c.session.proxies == {}
    assert c.session.verify is True
    assert c._timeout == 30
    assert c._delay == 0.0


def test_configured_proxy_lands_on_session():
    proxy = "http://127.0.0.1:8080"
    c = GraphQLClient(URL, http={"proxy": proxy, "verify_tls": False, "timeout": 5})
    assert c.session.proxies == {"http": proxy, "https": proxy}
    assert c.session.verify is False
    assert c._timeout == 5


def test_get_client_forwards_http(monkeypatch):
    monkeypatch.setattr(graphql_client, "_client_cache", {})
    proxy = "http://127.0.0.1:9999"
    c = get_client(URL, http={"proxy": proxy})
    assert c.session.proxies == {"http": proxy, "https": proxy}


def test_delay_throttles_before_request(monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr(graphql_client.time, "sleep", lambda s: slept.append(s))
    c = GraphQLClient(URL, http={"delay": 0.25})
    c._throttle()
    assert slept == [0.25]


# --- introspection bypass when a naive filter blocks the standard query ------ #

_BLOCKED = {"data": None, "errors": [{"message": "GraphQL introspection is not allowed"}], "_status_code": 200}
_SCHEMA = {"data": {"__schema": {"queryType": {"name": "Query"}, "types": []}}, "_status_code": 200}


def test_introspect_bypass_anonymous_operation(monkeypatch):
    c = GraphQLClient(URL)
    calls = []

    def fake_exec(q, variables=None, extra_headers=None):
        calls.append(q)
        # standard named IntrospectionQuery is blocked; the anonymous "query {" variant works
        return _BLOCKED if "IntrospectionQuery" in q else _SCHEMA

    monkeypatch.setattr(c, "execute", fake_exec)
    r = c.introspect()
    assert r["data"]["__schema"]
    assert any("IntrospectionQuery" not in q for q in calls)  # a bypass variant was tried


def test_introspect_bypass_over_get(monkeypatch):
    c = GraphQLClient(URL)
    monkeypatch.setattr(c, "execute", lambda *a, **k: _BLOCKED)  # POST always blocked

    class _R:
        status_code = 200

        def json(self):
            return {"data": {"__schema": {"queryType": {"name": "Query"}, "types": []}}}

    monkeypatch.setattr(c.session, "get", lambda url, params=None, timeout=None: _R())
    r = c.introspect()
    assert r["data"]["__schema"]


def test_introspect_all_blocked_returns_failure(monkeypatch):
    c = GraphQLClient(URL)
    monkeypatch.setattr(c, "execute", lambda *a, **k: _BLOCKED)

    def _boom(*a, **k):
        raise graphql_client.requests.RequestException("nope")

    monkeypatch.setattr(c.session, "get", _boom)
    r = c.introspect()
    assert r.get("errors") and not r.get("data")  # honest failure, still non-fatal upstream


def test_finding_curl_includes_session_cookies():
    from gradientql.tui import _finding_curl
    f = {"request": {"url": "https://t/graphql", "payload": {"query": "{me{id}}"},
                     "headers": {"Content-Type": "application/json", "Cookie": "stale=1"},
                     "cookies": {"sid": "abc", "csrf": "tok"}}}
    curl = _finding_curl(f)
    assert "-b " in curl and "sid=abc" in curl and "csrf=tok" in curl
    assert "Cookie: stale=1" not in curl   # raw Cookie header dropped; cookies emitted via -b


def test_finding_curl_no_cookies_no_b_flag():
    from gradientql.tui import _finding_curl
    curl = _finding_curl({"request": {"url": "https://t/graphql", "payload": {"query": "{x}"},
                                      "headers": {"Content-Type": "application/json"}}})
    assert "-b " not in curl


def test_execute_captures_session_cookies(monkeypatch):
    c = GraphQLClient(URL)
    c._session_initialized = True                      # skip the csrf/session warm-up network call
    c.session.cookies.set("sid", "abc")

    class _R:
        status_code = 200
        text = '{"data":{"__typename":"Query"}}'
        headers = {"Content-Type": "application/json"}

        def json(self):
            return {"data": {"__typename": "Query"}}

    monkeypatch.setattr(c.session, "post", lambda *a, **k: _R())
    monkeypatch.setattr(c.session, "get", lambda *a, **k: _R())
    c.execute("{ __typename }")
    assert c.last_request["cookies"].get("sid") == "abc"
