"""Tests for the deterministic GraphQL misconfiguration sweep."""

from gradientql.utils.misconfig import run_misconfig_sweep


class _Resp:
    def __init__(self, status=200, text="", payload=None):
        self.status_code = status
        self.text = text
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class _FakeSession:
    """Returns canned responses: an exposed GraphiQL IDE, working GET query, tracing
    extensions, and accepted batching."""

    def get(self, url, params=None, headers=None, timeout=None):
        if headers and headers.get("Accept") == "text/html":
            return _Resp(200, "<html><title>GraphiQL</title></html>")
        if params and "query" in params:
            return _Resp(200, '{"data":{"__typename":"Query"}}')
        return _Resp(404, "")

    def post(self, url, json=None, timeout=None):
        if isinstance(json, list):
            return _Resp(200, payload=[{"data": {}}, {"data": {}}])
        return _Resp(200, payload={"data": {"__typename": "Query"}, "extensions": {"tracing": {"version": 1}}})


def _types(findings):
    return {f["vuln_type"] for f in findings}


def test_sweep_flags_all_misconfigs():
    findings = run_misconfig_sweep("http://t/graphql", introspection_succeeded=True, session=_FakeSession())
    t = _types(findings)
    assert any("Introspection Enabled" in x for x in t)
    assert any("IDE Exposed" in x for x in t)
    assert any("GET-based" in x for x in t)
    assert any("Tracing" in x for x in t)
    assert any("Batching" in x for x in t)


def test_introspection_off_not_flagged():
    findings = run_misconfig_sweep("http://t/graphql", introspection_succeeded=False, session=_FakeSession())
    assert not any("Introspection Enabled" in f["vuln_type"] for f in findings)


class _CleanSession:
    """A hardened endpoint: no IDE, GET disabled, no tracing, no batching."""

    def get(self, url, params=None, headers=None, timeout=None):
        return _Resp(404, "not found")

    def post(self, url, json=None, timeout=None):
        if isinstance(json, list):
            return _Resp(200, payload={"errors": [{"message": "batching disabled"}]})
        return _Resp(200, payload={"data": {"__typename": "Query"}})


def test_hardened_endpoint_only_introspection():
    findings = run_misconfig_sweep("http://t/graphql", introspection_succeeded=False, session=_CleanSession())
    assert findings == []
