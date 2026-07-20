"""GraphQL engine fingerprinting from error signatures (graphw00f port + threat-matrix notes)."""

from __future__ import annotations

from gradientql.utils.engine_fingerprint import (
    engine_dialect,
    engine_note,
    fingerprint_engine,
)


class _Resp:
    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


class _FakeEngine:
    """Returns the given signature response for matching probe queries, a generic error otherwise."""

    def __init__(self, responses):
        self.responses = responses

    def _lookup(self, q):
        for k, v in self.responses.items():
            if q.strip() == k.strip():
                return _Resp(v)
        return _Resp({"errors": [{"message": "generic validation error"}]})

    def post(self, url, json=None, headers=None, timeout=None):
        return self._lookup((json or {}).get("query", ""))

    def get(self, url, params=None, headers=None, timeout=None):
        return self._lookup((params or {}).get("query", ""))


def _detect(responses):
    return fingerprint_engine("http://t/graphql", session=_FakeEngine(responses))


def test_detects_apollo():
    r = _detect({"query @skip { __typename }": {"errors": [
        {"message": 'Directive "@skip" argument "if" of type "Boolean!" is required, but it was not provided.'}]}})
    assert r == "apollo"


def test_detects_graphql_java():
    r = _detect({"queryy { __typename }": {"errors": [
        {"message": "Invalid Syntax : offending token 'queryy' at line 1"}]}})
    assert r == "graphql-java"


def test_detects_hasura():
    r = _detect({"query { aaa }": {"errors": [
        {"message": "field \"aaa\" not found in type: 'query_root'"}]}})
    assert r == "hasura"


def test_detects_strawberry_requires_data():
    # strawberry only matches when data is ALSO present (distinguishes it from apollo's @deprecated)
    r = _detect({"query @deprecated { __typename }": {
        "data": {"__typename": "Query"},
        "errors": [{"message": "Directive '@deprecated' may not be used on query."}]}})
    assert r == "strawberry"


def test_detects_hasura_typename_root():
    r = _detect({"query @cached { __typename }": {"data": {"__typename": "query_root"}}})
    assert r == "hasura"


def test_detects_inigo_via_extensions():
    r = _detect({"query { __typename }": {"data": {"__typename": "Query"}, "extensions": {"inigo": {"v": 1}}}})
    assert r == "inigo"


def test_unknown_engine_returns_none():
    assert _detect({}) is None


def test_probes_are_deduplicated():
    calls = {"n": 0}

    class _Counting(_FakeEngine):
        def post(self, url, json=None, headers=None, timeout=None):
            calls["n"] += 1
            return super().post(url, json=json)

    from gradientql.utils.engine_fingerprint import _ENGINES
    total_rules = sum(len(rules) for _, rules in _ENGINES)
    fingerprint_engine("http://t/graphql", session=_Counting({}))
    # unknown engine exhausts every DISTINCT probe, but shared queries are sent once - so the number
    # of requests is well below the total rule count (proves deduplication)
    assert calls["n"] < total_rules - 10


def test_engine_note_and_dialect():
    assert "Hasura" in engine_note("hasura") and "x-hasura-role" in engine_note("hasura")
    assert engine_note("graphql-java") and "clairvoyance" in engine_note("graphql-java")
    assert engine_note(None) is None
    # an engine with no bespoke note still gets the generic one
    assert "juniper" in engine_note("juniper")
    assert engine_dialect("graphql-java") == "graphql-java"
    assert engine_dialect("apollo") == "graphql-js"
    assert engine_dialect("graphql-ruby") == "graphql-ruby"
