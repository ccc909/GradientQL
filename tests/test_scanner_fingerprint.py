"""Framework fingerprinting -> targeted attack-guidance facts."""

from __future__ import annotations

from gradientql.scanner.fingerprint import detect_frameworks


def _base(query=None, mutation=None, extra=None):
    sm = {"_query_type": "Query", "_mutation_type": "Mutation",
          "Query": query or {}, "Mutation": mutation or {}}
    sm.update(extra or {})
    return sm


def test_detects_apollo_federation():
    sm = _base(query={"_entities": {}, "_service": {}, "me": {}}, extra={"_Service": {}})
    facts = detect_frameworks(sm)
    assert any("FEDERATION" in f for f in facts)
    assert any("_entities" in f and "representations" in f for f in facts)


def test_detects_hasura():
    sm = {"_query_type": "query_root", "_mutation_type": "mutation_root",
          "query_root": {"users": {}, "users_aggregate": {}},
          "mutation_root": {"insert_users": {}, "delete_users": {}},
          "users_bool_exp": {}}
    facts = detect_frameworks(sm)
    assert any("HASURA" in f for f in facts)
    assert any("x-hasura-role" in f and "run_sql" in f for f in facts)


def test_detects_wpgraphql():
    sm = _base(query={"contentNodes": {}, "mediaItems": {}, "users": {}}, extra={"MediaItem": {}, "Post": {}})
    sm["_query_type"] = "RootQuery"
    sm["RootQuery"] = sm.pop("Query")
    facts = detect_frameworks(sm)
    assert any("WPGRAPHQL" in f for f in facts)


def test_plain_schema_no_false_positive():
    sm = _base(query={"me": {}, "products": {}}, mutation={"login": {}})
    assert detect_frameworks(sm) == []


def test_empty_schema():
    assert detect_frameworks({}) == []


def test_detects_strapi():
    sm = _base(query={"usersPermissionsUser": {}, "process": {}},
               extra={"ProcessEntityResponse": {}, "UsersPermissionsUser": {}})
    facts = detect_frameworks(sm)
    assert any("STRAPI" in f for f in facts)
    assert any("NOT BOLA" in f and "mass assignment" in f.lower() for f in facts)


def test_strapi_via_register_input():
    sm = _base(query={"me": {}}, extra={"_input_types": {"UsersPermissionsRegisterInput": []}})
    assert any("STRAPI" in f for f in detect_frameworks(sm))
