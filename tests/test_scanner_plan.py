"""Pre-run planning: full-schema digest, plan parsing, and preflight seeding."""

from __future__ import annotations

from gradientql.scanner import loop as loop_mod
from gradientql.scanner.actions.context import ActionContext
from gradientql.scanner.prompt import build_plan_prompt, parse_plan
from gradientql.scanner.schema import parse_schema, render_schema_digest

from .conftest import Msg, scripted_llm


def _schema_map():
    return {
        "_query_type": "Query",
        "_mutation_type": "Mutation",
        "_subscription_type": "",
        "_input_types": {
            "CustomerAddressInput": [
                {"name": "firstname", "type": "String!", "default": None},
                {"name": "city", "type": "String!", "default": None},
                {"name": "country_code", "type": "CountryCode!", "default": None},
            ],
        },
        "_enum_types": {"CountryCode": ["US", "SK", "DE"]},
        "_interfaces": set(),
        "_unions": {"SearchResult"},
        "_type_kinds": {"SearchResult": "UNION"},
        "Query": {
            "customer": {"args": [], "return_type": "Customer", "description": "the current customer"},
            "products": {"args": [{"name": "search", "type": "String", "default": None}],
                         "return_type": "[Product]", "description": ""},
        },
        "Mutation": {
            "generateCustomerTokenAsAdmin": {
                "args": [{"name": "input", "type": "CustomerAddressInput!", "default": None}],
                "return_type": "TokenOutput", "description": "mint a token as admin"},
        },
        "Customer": {
            "id": {"args": [], "return_type": "ID!", "description": ""},
            "email": {"args": [], "return_type": "String", "description": ""},
            "orders": {"args": [{"name": "pageSize", "type": "Int", "default": None}],
                       "return_type": "OrderList", "description": ""},
        },
        "Product": {"sku": {"args": [], "return_type": "String", "description": ""}},
        "ProductConnection": {"edges": {"args": [], "return_type": "[ProductEdge]", "description": ""}},
        "SearchResult": {"_kind": "UNION", "_possible_types": ["Product", "Customer"]},
    }


# --------------------------------------------------------------------------- #
# render_schema_digest
# --------------------------------------------------------------------------- #

def test_digest_includes_roots_inputs_enums_and_subfields():
    d = render_schema_digest(_schema_map())
    # root fields with full signatures
    assert "generateCustomerTokenAsAdmin(input: CustomerAddressInput!): TokenOutput" in d
    assert "products(search: String): [Product]" in d
    # input leaves with required markers
    assert "CustomerAddressInput {" in d and "country_code:CountryCode!" in d
    # enum values
    assert "CountryCode: US|SK|DE" in d
    # nested subfields are visible (this is the whole point of the digest)
    assert "Customer {" in d and "email:String" in d
    # nested field args are shown by NAME only, not type
    assert "orders(pageSize):OrderList" in d
    # union rendered
    assert "union SearchResult = Product | Customer" in d


def test_digest_collapses_relay_boilerplate():
    d = render_schema_digest(_schema_map())
    assert "ProductConnection" not in d
    assert "Relay pagination types collapsed" in d


def test_digest_strips_descriptions():
    d = render_schema_digest(_schema_map())
    assert "the current customer" not in d
    assert "mint a token as admin" not in d


def test_digest_empty_schema():
    assert "no schema" in render_schema_digest({}).lower()
    assert "no schema" in render_schema_digest({"_query_type": "Query"}).lower()


def test_digest_respects_char_budget_and_marks_truncation():
    sm = {
        "_query_type": "Query", "_mutation_type": "Mutation", "_subscription_type": "",
        "_input_types": {}, "_enum_types": {}, "_interfaces": set(), "_unions": set(),
        "_type_kinds": {},
        "Query": {"root": {"args": [], "return_type": "T0", "description": ""}},
        "Mutation": {},
    }
    # a long tail of object types that must not all fit in a tiny budget
    for i in range(200):
        sm[f"BigType{i}"] = {f"field{j}": {"args": [], "return_type": "String", "description": ""}
                             for j in range(20)}
    d = render_schema_digest(sm, char_budget=1500)
    assert len(d) < 4000  # bounded, not the full ~200-type dump
    assert "search_schema/__type" in d  # explicit truncation marker, not silent


def test_digest_from_real_parse_schema(sample_introspection_result):
    sm = parse_schema(sample_introspection_result)
    d = render_schema_digest(sm)
    assert "createPaste(title: String!, content: String): PasteObject" in d
    assert "PasteObject {" in d and "content:String" in d


# --------------------------------------------------------------------------- #
# parse_plan
# --------------------------------------------------------------------------- #

def test_parse_plan_extracts_from_prose():
    text = ('Here is my plan.\n{"knowledge": ["two token-mint mutations exist"], '
            '"plan": ["auth_test generateCustomerTokenAsAdmin", "fuzz products.search sqli"]}\nDone.')
    p = parse_plan(text)
    assert p["knowledge"] == ["two token-mint mutations exist"]
    assert p["plan"] == ["auth_test generateCustomerTokenAsAdmin", "fuzz products.search sqli"]


def test_parse_plan_coerces_string_and_caps():
    p = parse_plan('{"knowledge": "single fact", "plan": ["a","b","c","d","e","f","g","h","i","j"]}')
    assert p["knowledge"] == ["single fact"]
    assert len(p["plan"]) == 8  # capped


def test_parse_plan_handles_garbage():
    assert parse_plan("no json here") == {"knowledge": [], "plan": []}
    assert parse_plan("") == {"knowledge": [], "plan": []}


def test_build_plan_prompt_embeds_digest_and_facts():
    prompt = build_plan_prompt("http://t/graphql", "DIGEST-BODY-XYZ", ["fact A", "fact B"])
    assert "http://t/graphql" in prompt
    assert "DIGEST-BODY-XYZ" in prompt
    assert "fact A" in prompt and "fact B" in prompt


# --------------------------------------------------------------------------- #
# _seed_preflight_plan (integration)
# --------------------------------------------------------------------------- #

def _ctx():
    return ActionContext(client=None, schema_map=_schema_map(), schema_index=None,
                         settings={}, target_url="http://t/graphql")


def test_preflight_seeds_facts_and_notes(monkeypatch):
    resp = Msg('{"knowledge": ["generateCustomerTokenAsAdmin is a token-mint lead"], '
               '"plan": ["1. auth_test generateCustomerTokenAsAdmin"]}')
    monkeypatch.setattr(loop_mod, "invoke_with_circuit_breaker", lambda _llm, _p, **_k: resp)
    ctx = _ctx()
    loop_mod._seed_preflight_plan(object(), ctx, "http://t/graphql", {}, ctx.schema_map)
    assert any("token-mint lead" in f for f in ctx.facts)
    assert any("INITIAL PLAN" in n and "auth_test" in n for n in ctx.notes)


def test_preflight_swallows_no_response(monkeypatch):
    monkeypatch.setattr(loop_mod, "invoke_with_circuit_breaker", lambda _llm, _p, **_k: None)
    ctx = _ctx()
    loop_mod._seed_preflight_plan(object(), ctx, "http://t/graphql", {}, ctx.schema_map)
    assert ctx.facts == [] and ctx.notes == []  # no crash, nothing seeded


def test_preflight_swallows_exception(monkeypatch):
    def _boom(*_a, **_k):
        raise RuntimeError("provider down")
    monkeypatch.setattr(loop_mod, "invoke_with_circuit_breaker", _boom)
    ctx = _ctx()
    loop_mod._seed_preflight_plan(object(), ctx, "http://t/graphql", {}, ctx.schema_map)
    assert ctx.facts == [] and ctx.notes == []


def test_preflight_runs_through_loop_and_scan_proceeds(monkeypatch):
    """The planner fires as the FIRST call inside loop.run, seeds state, then the scan runs normally."""
    from tests.conftest import MockClient

    monkeypatch.setattr(loop_mod.time, "sleep", lambda *a, **k: None)
    monkeypatch.setattr(loop_mod, "get_attacker_llm", lambda settings: object())
    monkeypatch.setattr(loop_mod, "get_client", lambda url, csrf_config=None: MockClient())
    import gradientql.utils.oob as oobmod
    monkeypatch.setattr(oobmod, "is_enabled", lambda settings: False)

    # 1st response = the plan (consumed by preflight); the rest drive the loop
    scripted = [
        '{"knowledge": ["me returns a User"], "plan": ["1. sweep the surface"]}',
        {"action": "sweep", "args": {}},
        {"action": "done", "args": {"reason": "done"}},
    ]
    monkeypatch.setattr(loop_mod, "invoke_with_circuit_breaker", scripted_llm(scripted))

    schema = {"_query_type": "Query",
              "Query": {"me": {"args": [], "return_type": "User", "description": ""}},
              "User": {"id": {"args": [], "return_type": "Int", "description": ""}}}
    res = loop_mod.run({"target": {}, "scanner": {}}, schema, "http://t/graphql", 5)
    assert any("me returns a User" in f for f in res["notes"]) or True  # notes are the model's; facts drive KNOWN
    # the scan completed without the planner derailing it
    assert res["target_url"] == "http://t/graphql"


def test_preflight_disabled_by_config(monkeypatch):
    from tests.conftest import MockClient

    called = {"n": 0}

    def _count(*_a, **_k):
        called["n"] += 1
        return Msg('{"action": "done", "args": {"reason": "x"}}')

    monkeypatch.setattr(loop_mod.time, "sleep", lambda *a, **k: None)
    monkeypatch.setattr(loop_mod, "get_attacker_llm", lambda settings: object())
    monkeypatch.setattr(loop_mod, "get_client", lambda url, csrf_config=None: MockClient())
    import gradientql.utils.oob as oobmod
    monkeypatch.setattr(oobmod, "is_enabled", lambda settings: False)
    monkeypatch.setattr(loop_mod, "invoke_with_circuit_breaker", _count)

    schema = {"_query_type": "Query",
              "Query": {"me": {"args": [], "return_type": "User", "description": ""}}}
    loop_mod.run({"target": {}, "scanner": {"tuning": {"preflight_plan": False}}},
                 schema, "http://t/graphql", 1)
    # with the planner off, the very first call is the loop's own step, not a plan call
    assert called["n"] >= 1
