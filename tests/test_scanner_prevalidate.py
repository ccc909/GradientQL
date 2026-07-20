"""Tests for src/scanner/prevalidate.py — schema-aware query pre-validation.

The cardinal rule: NEVER block a structurally valid query (return None on any uncertainty);
only intercept a query the schema PROVES invalid.
"""

from __future__ import annotations

import pytest

from gradientql.scanner import prevalidate
from gradientql.scanner.schema import parse_schema


@pytest.fixture()
def sm(sample_introspection_result):
    return parse_schema(sample_introspection_result)


# --- must NOT block valid queries ----------------------------------------- #

def test_valid_query_passes(sm):
    assert prevalidate.prevalidate_query("query { pastes { id title content } }", {}, sm) is None


def test_valid_query_with_required_arg_literal(sm):
    assert prevalidate.prevalidate_query("query { paste(pId: 1) { id } }", {}, sm) is None


def test_required_arg_via_variable_passes(sm):
    q = "query Q($p: Int!) { paste(pId: $p) { id } }"
    assert prevalidate.prevalidate_query(q, {"p": 1}, sm) is None


def test_meta_fields_allowed(sm):
    assert prevalidate.prevalidate_query("query { __typename }", {}, sm) is None
    assert prevalidate.prevalidate_query("query { pastes { __typename id } }", {}, sm) is None


def test_batched_array_passes(sm):
    assert prevalidate.prevalidate_query('[{"query":"{__typename}"}]', {}, sm) is None


def test_fragment_query_passes_unjudged(sm):
    q = "query { pastes { ...PasteFields } } fragment PasteFields on PasteObject { id }"
    assert prevalidate.prevalidate_query(q, {}, sm) is None


def test_parse_failure_passes(sm):
    assert prevalidate.prevalidate_query("query { pastes { id ", {}, sm) is None  # unbalanced


def test_scalar_subselection_not_falsely_blocked(sm):
    # selecting subfields on a scalar (id: Int) is invalid GraphQL, but the scalar's "type" is
    # not an object we can resolve -> we stay conservative and let the server reject it.
    assert prevalidate.prevalidate_query("query { pastes { id { nope } } }", {}, sm) is None


def test_empty_schema_passes(sm):
    assert prevalidate.prevalidate_query("query { whatever }", {}, {}) is None


# --- must block proven-invalid queries ------------------------------------ #

def test_unknown_root_field_blocked_with_suggestion(sm):
    obs = prevalidate.prevalidate_query("query { pasts { id } }", {}, sm)
    assert obs is not None
    assert "pasts" in obs and "is not a field of type `Query`" in obs
    assert "Did you mean" in obs and "pastes" in obs


def test_unknown_subfield_blocked(sm):
    obs = prevalidate.prevalidate_query("query { pastes { id bogusField } }", {}, sm)
    assert obs is not None
    assert "bogusField" in obs and "PasteObject" in obs


def test_missing_required_root_arg_blocked(sm):
    obs = prevalidate.prevalidate_query("query { paste { id } }", {}, sm)
    assert obs is not None
    assert "pId" in obs and "requires" in obs


def test_mutation_unknown_field_blocked(sm):
    obs = prevalidate.prevalidate_query("mutation { createPasteX(title: \"a\") { id } }", {}, sm)
    assert obs is not None
    assert "createPasteX" in obs


def test_mutation_missing_required_arg_blocked(sm):
    obs = prevalidate.prevalidate_query("mutation { createPaste(content: \"a\") { id } }", {}, sm)
    assert obs is not None
    assert "title" in obs


def test_prevalidate_rejects_multi_operation_documents():
    sm = {"_query_type": "Query", "_mutation_type": "Mutation",
          "Query": {"me": {"args": [], "return_type": "User", "description": ""}},
          "Mutation": {"deletePaste": {"args": [], "return_type": "T", "description": ""}},
          "User": {"id": {"args": [], "return_type": "Int", "description": ""}}}
    out = prevalidate_query("query { me { id } } mutation { deletePaste { __typename } }", {}, sm)
    assert out and "2 operations" in out


def test_prevalidate_rejects_batched_mutations():
    sm = {"_query_type": "Query", "_mutation_type": "Mutation", "Query": {},
          "Mutation": {"deletePaste": {"args": [], "return_type": "T", "description": ""},
                       "editPaste": {"args": [], "return_type": "T", "description": ""}}}
    out = prevalidate_query(
        "mutation { a: deletePaste { __typename } b: editPaste { __typename } }", {}, sm)
    assert out and "ALONE" in out


def test_prevalidate_allows_batched_query_fields():
    sm = {"_query_type": "Query", "Query": {"me": {"args": [], "return_type": "User", "description": ""}},
          "User": {"id": {"args": [], "return_type": "Int", "description": ""}}}
    assert prevalidate_query("query { a: me { id } b: me { id } }", {}, sm) is None

prevalidate_query = prevalidate.prevalidate_query


def test_recovered_schema_skips_field_validation():
    # a clairvoyance-recovered schema can carry a wrong return_type (here user -> "Query"); pre-validation
    # must NOT reject a valid subfield query against it - the server validates. Only structural checks apply.
    from gradientql.scanner.prevalidate import prevalidate_query
    sm = {"_query_type": "Query", "_mutation_type": "Mutation",
          "Query": {"user": {"args": [{"name": "id", "type": "ID", "default": None}],
                             "return_type": "Query",  # bogus circular type from recovery
                             "description": "(recovered via clairvoyance)"}}}
    assert prevalidate_query("query { user(id: 1) { id email name } }", {}, sm) is None
    # structural checks still fire even on a recovered schema
    multi = prevalidate_query("query { user(id:1){id} } query B { user(id:2){id} }", {}, sm)
    assert multi is not None and "operation" in multi.lower()


def test_real_schema_still_validates_fields():
    # a genuinely-introspected schema (no clairvoyance marker) still rejects unknown fields
    from gradientql.scanner.prevalidate import prevalidate_query
    sm = {"_query_type": "Query", "_mutation_type": "Mutation",
          "Query": {"user": {"args": [], "return_type": "User", "description": ""}},
          "User": {"id": {"args": [], "return_type": "ID", "description": ""}}}
    out = prevalidate_query("query { user { bogusField } }", {}, sm)
    assert out is not None and "bogusField" in out
