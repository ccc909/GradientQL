"""Tests for src/scanner/schema.py — parsing, search, overview, sweep."""

from __future__ import annotations


from gradientql.scanner import schema
from tests.conftest import MockClient


# --- parse_schema ---------------------------------------------------------- #

def test_parse_schema_roots_and_fields(sample_introspection_result):
    sm = schema.parse_schema(sample_introspection_result)
    assert sm["_query_type"] == "Query"
    assert sm["_mutation_type"] == "Mutation"
    assert "pastes" in sm["Query"]
    assert "createPaste" in sm["Mutation"]
    # arg types resolve through NON_NULL/LIST decoration
    paste = sm["Query"]["paste"]
    assert paste["args"][0]["name"] == "pId"
    assert paste["args"][0]["type"] == "Int!"
    assert sm["Query"]["pastes"]["return_type"] == "[PasteObject]"


def test_parse_schema_skips_introspection_types(sample_introspection_result):
    sm = schema.parse_schema(sample_introspection_result)
    assert "__Schema" not in sm


def test_resolve_type_ref_nested():
    ref = {"kind": "NON_NULL", "ofType": {"kind": "LIST",
           "ofType": {"kind": "SCALAR", "name": "String"}}}
    assert schema._resolve_type_ref(ref) == "[String]!"
    assert schema._resolve_type_ref(None) == "Unknown"


def test_field_count(sample_introspection_result):
    sm = schema.parse_schema(sample_introspection_result)
    assert schema.field_count(sm) == 6  # 2 Query + 1 Mutation + 3 PasteObject


# --- search ---------------------------------------------------------------- #

def test_search_schema_lexical(sample_introspection_result):
    sm = schema.parse_schema(sample_introspection_result)
    hits = schema.search_schema(sm, "paste")
    assert any("pastes" in h for h in hits)
    assert any("createPaste" in h for h in hits)


def test_search_schema_empty_keyword_matches_nothing(sample_introspection_result):
    sm = schema.parse_schema(sample_introspection_result)
    assert schema.search_schema(sm, "") == []


def test_search_schema_hybrid_merges_semantic(sample_introspection_result):
    sm = schema.parse_schema(sample_introspection_result)

    class _Doc:
        def __init__(self, tn, fn):
            self.metadata = {"type_name": tn, "field_name": fn}

    class _Store:
        def similarity_search(self, q, k=20, filter_type=None):
            return [_Doc("Mutation", "createPaste"), _Doc("Stale", "ghost")]

    # 'zzz' has no lexical hit, so the semantic createPaste is surfaced via the store;
    # the stale 'Stale.ghost' (not in the live schema) is dropped.
    hits = schema.search_schema(sm, "zzz", store=_Store())
    assert any("(semantic)" in h and "createPaste" in h for h in hits)
    assert not any("ghost" in h for h in hits)


def test_search_schema_surfaces_enum_despite_field_flood():
    sm = {"_query_type": "Query",
          "Query": {f"colorField{i}": {"args": [], "return_type": "String", "description": ""}
                    for i in range(40)},
          "_enum_types": {"Color": ["RED", "GREEN", "BLUE"]}}
    hits = schema.search_schema(sm, "color", limit=20)
    assert any("enum Color" in h and "RED" in h for h in hits)


def test_search_schema_reports_more_indicator_when_capped():
    sm = {"_query_type": "Query",
          "Query": {f"colorField{i}": {"args": [], "return_type": "String", "description": ""}
                    for i in range(50)}}
    hits = schema.search_schema(sm, "color", limit=20)
    assert len(hits) == 20                                    # slot reserved, not overflowed
    assert any("more - refine keyword" in h for h in hits)
    # 50 matches, 19 shown + 1 indicator -> 31 more
    assert any("(+31 more" in h for h in hits)


def test_search_schema_no_indicator_when_all_shown():
    sm = {"_query_type": "Query",
          "Query": {f"colorField{i}": {"args": [], "return_type": "String", "description": ""}
                    for i in range(5)}}
    hits = schema.search_schema(sm, "color", limit=20)
    assert not any("more - refine keyword" in h for h in hits)


def test_search_schema_finds_field_by_arg_type():
    sm = {"_query_type": "Query",
          "Query": {"createThing": {"args": [{"name": "input", "type": "WidgetInput!"}],
                                    "return_type": "Thing", "description": ""}}}
    hits = schema.search_schema(sm, "widgetinput")
    assert any("createThing" in h for h in hits)


def test_search_schema_semantic_failure_falls_back(sample_introspection_result):
    sm = schema.parse_schema(sample_introspection_result)

    class _Boom:
        def similarity_search(self, *a, **k):
            raise RuntimeError("faiss down")

    hits = schema.search_schema(sm, "paste", store=_Boom())  # must not raise
    assert any("pastes" in h for h in hits)


# --- overview -------------------------------------------------------------- #

def test_render_schema_overview(sample_introspection_result):
    sm = schema.parse_schema(sample_introspection_result)
    ov = schema.render_schema_overview(sm)
    assert "PRODUCT / SEARCH" not in ov or "paste" not in ov.lower()  # pastes isn't a product
    # pastes/paste are uncategorised -> land in "other queries"
    assert "pastes" in ov and "createPaste" in ov


def test_render_schema_overview_other_fields_carry_return_type():
    sm = {"_query_type": "Query", "_mutation_type": "Mutation",
          "Query": {"systemDiagnostics": {"args": [], "return_type": "DiagReport", "description": ""}},
          "Mutation": {}}
    ov = schema.render_schema_overview(sm)
    # no-arg field: bare name + return type, no empty parens
    assert "systemDiagnostics: DiagReport" in ov


def test_render_schema_overview_other_fields_carry_arg_signature():
    sm = {"_query_type": "Query", "_mutation_type": "Mutation",
          "Query": {"systemDiagnostics": {"args": [{"name": "verbose", "type": "Boolean"}],
                                          "return_type": "DiagReport", "description": ""}},
          "Mutation": {}}
    ov = schema.render_schema_overview(sm)
    # non-bucketed field with args now carries its signature, matching the "with signatures" claim
    assert "systemDiagnostics(verbose: Boolean): DiagReport" in ov


# --- sweep ----------------------------------------------------------------- #

def test_sweepable_excludes_required_arg_fields(sample_introspection_result):
    sm = schema.parse_schema(sample_introspection_result)
    sweepable = {f for f, _ in schema._sweepable_query_fields(sm)}
    assert "pastes" in sweepable          # all args optional
    assert "paste" not in sweepable       # pId is Int! (required)


def test_tool_sweep_classifies_per_field(sample_introspection_result):
    sm = schema.parse_schema(sample_introspection_result)
    client = MockClient(default={"data": {"s0": [{"id": 1}]}, "errors": [], "_status_code": 200})
    q, summary, results, resp = schema.tool_sweep(client, sm, exclude=set())
    assert q is not None
    fields = {f: outcome for f, outcome, _ in results}
    assert fields.get("pastes") == "DATA"
    assert "swept" in summary


def test_tool_sweep_binary_split_isolates_bad_field(sample_introspection_result):
    sm = schema.parse_schema(sample_introspection_result)
    # add two more no-arg fields so a split is meaningful
    sm["Query"]["alpha"] = {"args": [], "return_type": "String", "description": ""}
    sm["Query"]["beta"] = {"args": [], "return_type": "String", "description": ""}

    class _SplitClient:
        """Rejects the whole batch (data=null) while it contains 'beta'; otherwise returns data."""
        def __init__(self):
            self.session = None

        def execute(self, query, variables=None, extra_headers=None):
            if "beta" in query:  # any query touching 'beta' is rejected before execution
                return {"data": None, "errors": [{"message": "Cannot query field"}], "_status_code": 200}
            import re as _re
            aliases = _re.findall(r"(s\d+):", query)
            return {"data": {a: "ok" for a in aliases}, "errors": [], "_status_code": 200}

    q, summary, results, resp = schema.tool_sweep(_SplitClient(), sm, exclude=set())
    outcomes = {f: o for f, o, _ in results}
    # beta is isolated as the offender; the good fields still get classified as DATA
    assert outcomes.get("beta") == "ERROR"
    assert outcomes.get("pastes") == "DATA"


def test_tool_sweep_nothing_to_sweep():
    sm = {"_query_type": "Query", "Query": {"needsArg": {"args": [{"name": "id", "type": "ID!"}],
                                                         "return_type": "X", "description": ""}}}
    q, summary, results, resp = schema.tool_sweep(MockClient(), sm, exclude=set())
    assert q is None
    assert "EXHAUSTED" in summary


# --- introspection_shortcut is honest about a recovered (partial) schema ----- #

def test_introspection_shortcut_full_schema_message():
    sm = {"_query_type": "Query", "Query": {"me": {"args": [], "return_type": "User", "description": ""}},
          "User": {"id": {"args": [], "return_type": "ID", "description": ""}}}
    msg = schema.introspection_shortcut("query { __schema { types { name } } }", sm)
    assert msg and "ALREADY hold the full introspected schema" in msg


def test_introspection_shortcut_recovered_schema_message():
    sm = {"_query_type": "Query", "_mutation_type": "Mutation",
          "Query": {"account": {"args": [], "return_type": "Account",
                                "description": "(recovered via clairvoyance)"}}}
    msg = schema.introspection_shortcut("query { __schema { types { name } } }", sm)
    assert msg and "INTROSPECTION IS DISABLED" in msg and "clairvoyance" in msg
    assert "ALREADY hold the full" not in msg


def test_introspection_shortcut_empty_schema_is_recovered_style():
    msg = schema.introspection_shortcut("query { __schema { types { name } } }",
                                        {"_query_type": "Query", "Query": {}})
    assert msg and "DISABLED" in msg
