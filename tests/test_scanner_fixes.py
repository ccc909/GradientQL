"""Regression tests locking in the 12 fixes from the multi-agent diagnosis of the GitLab run."""

from __future__ import annotations

from gradientql.scanner import memory, prevalidate, schema, senses
from gradientql.scanner.harvest import find_reflections, is_introspection_query
from gradientql.scanner.memory import blank_entry


# --- #3 reflection introspection guard -------------------------------------- #

def test_find_reflections_skips_introspection():
    q = 'query { __type(name: "DevfileValidateInput") { inputFields { name } } }'
    data = {"__type": {"name": "DevfileValidateInput", "inputFields": []}}
    assert find_reflections(q, {}, data) == []


# --- review blocker: __typename must NOT be treated as introspection -------- #

def test_is_introspection_word_boundary():
    assert is_introspection_query('query { __type(name: "X") { x } }')
    assert is_introspection_query("query { __schema { types { name } } }")
    assert not is_introspection_query("query { user { __typename id } }")
    assert not is_introspection_query("query { __typename }")


def test_introspection_shortcut_ignores_typename_selection():
    # the reachability probe `{ __typename }` and any __typename-bearing query must hit the wire
    assert schema.introspection_shortcut("query { user { __typename id } }", {}) is None
    assert schema.introspection_shortcut("query { __typename }", {}) is None


def test_find_reflections_still_fires_on_typename_query():
    refl = find_reflections('query { search(t: "ABCD1234") { __typename } }', {}, {"search": {"r": "ABCD1234"}})
    assert refl == ["ABCD1234"]


# --- review #6: edges-only Relay connection -------------------------------- #

def test_minimal_selection_edges_connection():
    sm = {"Conn": {"edges": {"return_type": "[Edge]"}},
          "Edge": {"node": {"return_type": "User"}},
          "User": {"id": {"return_type": "ID"}}}
    assert schema._minimal_selection(sm, "Conn") == "{ edges { node { id } } }"


# --- review #5: DoS no false-confirm when aliases all errored --------------- #

def test_dos_no_confirm_when_all_aliases_errored():
    q = "query { " + " ".join(f"a{i}: project" for i in range(60)) + " }"
    resp = {"_status_code": 200, "data": None, "errors": [{"message": "argument fullPath is required"}]}
    assert senses.detect_dos_surface(q, resp)[0] is None


# --- review #10: NonNull-with-default is not "required" --------------------- #

def test_prevalidate_nonnull_with_default_not_blocked():
    sm = {"_query_type": "Query", "_mutation_type": "Mutation", "Mutation": {},
          "Query": {"f": {"args": [{"name": "flag", "type": "Boolean!", "default": "false"}],
                          "return_type": "String", "description": ""}}}
    assert prevalidate.prevalidate_query("query { f }", {}, sm) is None


def test_prevalidate_nested_defaulted_leaf_not_required():
    sm = {"_query_type": "Query", "_mutation_type": "Mutation", "Mutation": {},
          "Query": {"g": {"args": [{"name": "input", "type": "In!", "default": None}],
                          "return_type": "String", "description": ""}},
          "_input_types": {"In": [{"name": "a", "type": "String!", "default": None},
                                  {"name": "b", "type": "Boolean!", "default": "false"}]}}
    # missing 'a' (no default) -> blocked; 'b' is defaulted -> not required
    obs = prevalidate.prevalidate_query('query { g(input: {b: true}) }', {}, sm)
    assert obs is not None and "a" in obs
    assert prevalidate.prevalidate_query('query { g(input: {a: "x"}) }', {}, sm) is None


# --- review #12: all-offending sweep handled without a split storm ---------- #

def test_sweep_all_offending_single_request():
    sm = {"_query_type": "Query", "Query": {
        "a": {"args": [], "return_type": "String", "description": ""},
        "b": {"args": [], "return_type": "String", "description": ""}}}

    class _C:
        def __init__(self):
            self.session = None
            self.calls = 0

        def execute(self, query, variables=None, extra_headers=None):
            self.calls += 1
            import re as _re
            aliases = _re.findall(r"(s\d+):", query)
            return {"data": None, "errors": [{"message": "not authorized", "path": [a]} for a in aliases],
                    "_status_code": 200}

    c = _C()
    _q, _s, results, _r = schema.tool_sweep(c, sm, exclude=set())
    assert {f: o for f, o, _ in results} == {"a": "AUTH-BLOCKED", "b": "AUTH-BLOCKED"}
    assert c.calls == 1     # classified from the single response, no binary split


# --- #4 introspection shortcut ---------------------------------------------- #

def test_search_schema_surfaces_enum_values():
    # the agent must be able to GET enum values in one search (was: fixated for ~25 steps on GitLab)
    sm = {"_query_type": "Query", "Query": {}, "_enum_types": {"Color": ["RED", "GREEN", "BLUE"]}}
    hits = schema.search_schema(sm, "color")
    assert any("enum Color" in h and "RED" in h for h in hits)


def test_introspection_shortcut_serves_input_type():
    sm = {"_input_types": {"CiLintInput": [{"name": "content", "type": "String!"},
                                           {"name": "projectPath", "type": "ID!"}]}}
    out = schema.introspection_shortcut('query { __type(name: "CiLintInput") { inputFields { name } } }', sm)
    assert out is not None and "CiLintInput" in out and "projectPath: ID!" in out and "NO request" in out


def test_introspection_shortcut_bare_schema_redirects_to_search():
    out = schema.introspection_shortcut("query { __schema { types { name } } }", {})
    assert out is not None and "search_schema" in out


def test_introspection_shortcut_ignores_normal_query():
    assert schema.introspection_shortcut("query { users { id } }", {}) is None


def test_render_type_shape_input_enum_object():
    sm = {"_input_types": {"In": [{"name": "a", "type": "String!"}]},
          "_enum_types": {"Color": ["RED", "BLUE"]},
          "User": {"id": {"args": [], "return_type": "ID", "description": ""}}}
    assert "input In" in schema.render_type_shape(sm, "In")
    assert "enum Color" in schema.render_type_shape(sm, "Color")
    assert "type User" in schema.render_type_shape(sm, "User")
    assert schema.render_type_shape(sm, "Nope") is None


# --- #9 auth-surface detection ---------------------------------------------- #

def test_auth_mutations_present_and_absent():
    with_tok = {"_mutation_type": "Mutation", "Mutation": {
        "generateCustomerToken": {"args": [], "return_type": "CustomerToken", "description": ""},
        "createPost": {"args": [], "return_type": "Post", "description": ""}}}
    assert "generateCustomerToken" in schema.auth_mutations(with_tok)
    without = {"_mutation_type": "Mutation", "Mutation": {
        "createPost": {"args": [], "return_type": "Post", "description": ""}}}
    assert schema.auth_mutations(without) == []


# --- #6 sweep id-selection + empty-connection ------------------------------- #

def test_minimal_selection_prefers_id_and_connection():
    sm = {"User": {"id": {"return_type": "ID"}, "name": {"return_type": "String"}},
          "UserConn": {"nodes": {"return_type": "[User]"}}}
    assert schema._minimal_selection(sm, "User") == "{ id }"
    assert schema._minimal_selection(sm, "[UserConn]") == "{ nodes { id } }"
    assert schema._minimal_selection(sm, "String") == ""           # scalar/unknown -> no selection


def test_sweep_parse_empty_connection_is_null():
    alias_map = {"s0": "users", "s1": "posts", "s2": "me", "s3": "empty_edges", "s4": "full_edges"}
    data = {"s0": {"nodes": []}, "s1": {"nodes": [{"id": 1}]}, "s2": {"id": None},
            "s3": {"edges": []}, "s4": {"edges": [{"node": {"id": 1}}]}}
    out = {f: o for f, o, _ in schema._sweep_parse(alias_map, data, [])}
    assert out["users"] == "null/empty"        # empty nodes connection != exposure
    assert out["posts"] == "DATA"              # real records
    assert out["me"] == "null/empty"           # {id: null}
    assert out["empty_edges"] == "null/empty"  # empty Relay edges connection
    assert out["full_edges"] == "DATA"         # populated edges connection


# --- #12 sweep targeted removal (no binary-split storm) --------------------- #

def test_sweep_targeted_removal_avoids_split_storm():
    sm = {"_query_type": "Query", "Query": {
        "good": {"args": [], "return_type": "String", "description": ""},
        "bad": {"args": [], "return_type": "String", "description": ""},
        "good2": {"args": [], "return_type": "String", "description": ""}}}

    class _C:
        def __init__(self):
            self.session = None
            self.calls = 0

        def execute(self, query, variables=None, extra_headers=None):
            self.calls += 1
            import re as _re
            aliases = _re.findall(r"(s\d+):\s*(\w+)", query)
            bad_alias = next((a for a, f in aliases if f == "bad"), None)
            if bad_alias:  # NonNull-propagated null + a path-tagged error
                return {"data": None, "errors": [{"message": "not authorized", "path": [bad_alias]}],
                        "_status_code": 200}
            return {"data": {a: "ok" for a, _ in aliases}, "errors": [], "_status_code": 200}

    c = _C()
    _q, _summary, results, _resp = schema.tool_sweep(c, sm, exclude=set())
    outcomes = {f: o for f, o, _ in results}
    assert outcomes["bad"] == "AUTH-BLOCKED"
    assert outcomes["good"] == "DATA" and outcomes["good2"] == "DATA"
    assert c.calls <= 2     # one full attempt + one re-run of the rest, NOT log(n) splits


# --- #2 honest coverage counter + auth-gated line --------------------------- #

def test_render_state_honest_counter():
    led = {"users": {**blank_entry("users", "anon", 0), "auto": "DATA", "attempts": 1}}
    s = memory.render_state(led, [], [], 0, total_root=100, untouched_sweepable=5, require_args=90)
    assert "5 no-arg query fields still un-swept" in s
    assert "90 fields/mutations need args" in s
    assert "STILL UNTOUCHED" not in s        # the old lying instruction is gone


def test_render_state_auth_gated_collapse():
    led = {"adminUsers": {**blank_entry("adminUsers", "anon", 0), "auto": "AUTH-BLOCKED", "attempts": 1}}
    s = memory.render_state(led, [], [], 0, untouched_sweepable=0, require_args=0)
    assert "AUTH-GATED: 1 field" in s


# --- #10 prevalidate nested required input fields --------------------------- #

def _cilint_schema():
    return {
        "_query_type": "Query", "_mutation_type": "Mutation", "Mutation": {},
        "Query": {"ciLint": {"args": [{"name": "input", "type": "CiLintInput!"}],
                             "return_type": "CiLintResult", "description": ""}},
        "CiLintResult": {"valid": {"args": [], "return_type": "Boolean", "description": ""}},
        "_input_types": {"CiLintInput": [{"name": "content", "type": "String!"},
                                         {"name": "projectPath", "type": "ID!"}]},
    }


def test_prevalidate_nested_missing_required_blocked():
    sm = _cilint_schema()
    obs = prevalidate.prevalidate_query('query { ciLint(input: {content: "x"}) { valid } }', {}, sm)
    assert obs is not None and "projectPath" in obs and "CiLintInput" in obs


def test_prevalidate_nested_provided_passes():
    sm = _cilint_schema()
    assert prevalidate.prevalidate_query(
        'query { ciLint(input: {content: "x", projectPath: "p"}) { valid } }', {}, sm) is None


def test_prevalidate_nested_via_variable_not_inspected():
    sm = _cilint_schema()
    # input passed wholly via a $var -> conservative -> do NOT block
    assert prevalidate.prevalidate_query(
        'query Q($i: CiLintInput!) { ciLint(input: $i) { valid } }', {"i": {}}, sm) is None


# --- exit hang: interruptible sleep honors should_stop ---------------------- #

def test_sleep_or_stop_returns_immediately_when_stopped():
    import time
    from gradientql.scanner.loop import _sleep_or_stop
    t0 = time.monotonic()
    _sleep_or_stop(30, lambda: True)          # a 30s wait must return at once
    assert time.monotonic() - t0 < 1.0


def test_sleep_or_stop_waits_when_not_stopped():
    import time
    from gradientql.scanner.loop import _sleep_or_stop
    t0 = time.monotonic()
    _sleep_or_stop(0.4, lambda: False)
    assert time.monotonic() - t0 >= 0.3


# --- report_finding attaches the reported field's request, not last_request - #

def _report_ctx(last_query):
    from gradientql.scanner.actions.context import ActionContext

    class _C:
        session = None
        last_request = {"url": "http://t/graphql",
                        "payload": {"query": last_query}, "headers": {}}

    return ActionContext(client=_C(), schema_map={}, schema_index=None, settings={},
                         target_url="http://t/graphql", identity={})


def test_report_finding_uses_target_field_request():
    from gradientql.scanner.actions import dispatch
    ctx = _report_ctx("query { posts { id } }")          # last probe was posts
    ctx.ledger["users"] = {"req": {"url": "http://t/graphql",
                                   "payload": {"query": "query { users { id email } }"}, "headers": {}}}
    dispatch("report_finding", ctx, {"vuln_type": "BOLA/IDOR", "target": "Query.users",
                                     "evidence": "read another user", "severity": "high"})
    v = ctx.vulns[0]
    assert "users" in v["request"]["payload"]["query"]
    assert "posts" not in v["request"]["payload"]["query"]   # the bug: was grabbing last_request


def test_report_finding_fallback_avoids_unrelated_request():
    import json
    from gradientql.scanner.actions import dispatch
    ctx = _report_ctx("query { posts { id } }")
    dispatch("report_finding", ctx, {"vuln_type": "X", "target": "unknownField", "evidence": "e"})
    v = ctx.vulns[0]
    assert "posts" not in json.dumps(v.get("request") or {})  # no misleading query attached
    assert (v["request"] or {}).get("url") == "http://t/graphql"


def test_target_field_normalization():
    from gradientql.scanner.actions.graphql import _target_field
    assert _target_field("Query.users") == "users"
    assert _target_field("users(id: 5)") == "users"
    assert _target_field("generateCustomerTokenAsAdmin") == "generateCustomerTokenAsAdmin"


# --- map glyph: exploited must render as '!', not '*' ----------------------- #

def test_exploited_glyph_is_bang():
    from gradientql.tui import _GLYPH
    assert _GLYPH["exploited"][0] == "!"
    assert _GLYPH["finding"][0] == "!"
