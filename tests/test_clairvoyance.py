"""Clairvoyance schema recovery across graphql-js and graphql-java validation dialects."""

from __future__ import annotations

import re

from gradientql.scanner.actions import ActionContext, dispatch
from gradientql.utils.clairvoyance import _analyze, merge_into_schema, recover_schema


# --------------------------------------------------------------------------- #
# _analyze: dialect-aware classification
# --------------------------------------------------------------------------- #

def test_analyze_graphql_java_undefined_is_invalid():
    resp = {"errors": [
        {"message": "Validation error (FieldUndefined@[audit]) : Field 'audit' in type 'Query' is undefined"},
        {"message": "Validation error (FieldUndefined@[log]) : Field 'log' in type 'Query' is undefined"},
        {"message": "Validation error (MissingFieldArgument@[notification]) : Missing field argument 'messageId'"},
        {"message": "Validation error (SubselectionRequired@[notification]) : Subselection required for type 'Notification'"},
    ]}
    out = _analyze(resp, ["audit", "log", "notification"])
    assert "audit" not in out and "log" not in out          # undefined -> dropped
    assert out["notification"]["return_type"] == "Notification"
    assert out["notification"]["args"] == ["messageId"]
    assert out["notification"]["scalar"] is False


def test_analyze_graphql_js_dialect():
    resp = {"errors": [
        {"message": 'Cannot query field "bogus" on type "Query".'},
        {"message": 'Field "customer" of type "Customer" must have a selection of subfields.'},
        {"message": 'Field "order" argument "id" of type "ID!" is required.'},
    ]}
    out = _analyze(resp, ["bogus", "customer", "order"])
    assert "bogus" not in out
    assert out["customer"]["return_type"] == "Customer"
    assert out["order"]["args"] == ["id"]


def test_analyze_no_signal_returns_empty():
    # a wholesale failure with no per-field validation detail must NOT mark everything valid
    assert _analyze({"errors": [{"message": "Something went wrong"}]}, ["a", "b", "c"]) == {}
    assert _analyze({"data": None, "errors": []}, ["a", "b"]) == {}


def test_analyze_valid_is_chunk_minus_undefined():
    # validation is exhaustive: fields not flagged undefined are valid (scalar leaves included)
    resp = {"errors": [
        {"message": "Validation error (FieldUndefined@[x]) : Field 'x' in type 'T' is undefined"},
    ], "data": None}
    out = _analyze(resp, ["x", "title", "id"])
    assert "x" not in out and "title" in out and "id" in out
    assert out["title"]["scalar"] is True


# --------------------------------------------------------------------------- #
# recover_schema: a graphql-java server like Netflix (no "did you mean")
# --------------------------------------------------------------------------- #

_SCHEMA = {
    "Query": {"notification": ("Notification", ["messageId"]), "version": ("", [])},
    "Notification": {"id": ("", []), "title": ("", []), "text": ("NotificationText", [])},
    "NotificationText": {"key": ("", []), "value": ("", [])},
}


class _JavaServer:
    """Simulates graphql-java exhaustive validation for the crawler's query shapes."""

    def __init__(self):
        self.session = None

    def execute(self, query, variables=None, extra_headers=None):
        cur = ("NotificationText" if "text {" in query or "text{" in query
               else "Notification" if re.search(r"notification\s*\(", query)
               else "Mutation" if query.lstrip().startswith("mutation") else "Query")
        prefix = {"Notification": "notification/", "NotificationText": "notification/text/"}.get(cur, "")
        last = query.rfind("{")
        inner = query[last + 1:query.find("}", last)]
        cands = re.findall(r"[A-Za-z_]\w*", inner)
        known = _SCHEMA.get(cur, {})
        errors, data = [], {}
        for c in cands:
            if c not in known:
                errors.append({"message": f"Validation error (FieldUndefined@[{prefix}{c}]) : "
                                          f"Field '{c}' in type '{cur}' is undefined"})
                continue
            rtype, args = known[c]
            if args:
                errors.append({"message": f"Validation error (MissingFieldArgument@[{prefix}{c}]) : "
                                          f"Missing field argument '{args[0]}'"})
            if rtype:
                errors.append({"message": f"Validation error (SubselectionRequired@[{prefix}{c}]) : "
                                          f"Subselection required for type '{rtype}'"})
            elif not args:
                data[c] = None
        return {"data": data or None, "errors": errors, "_status_code": 200}


def test_recover_schema_crawls_types_and_ignores_garbage():
    schema = recover_schema(_JavaServer(), max_requests=40, batch=40, max_depth=2)
    q = schema["Query"]
    assert "notification" in q and "version" in q
    assert q["notification"]["return_type"] == "Notification"
    assert [a["name"] for a in q["notification"]["args"]] == ["messageId"]
    assert "audit" not in q and "log" not in q and "person" not in q   # the old false positives
    # recursion recovered the object types, not just root names
    assert "Notification" in schema and {"id", "title", "text"} <= set(schema["Notification"])
    assert schema["Notification"]["text"]["return_type"] == "NotificationText"
    assert "NotificationText" in schema and {"key", "value"} <= set(schema["NotificationText"])


def test_merge_into_schema_populates_map():
    sm = {"_query_type": "Query", "_mutation_type": "Mutation", "Query": {}, "Mutation": {}}
    recovered = recover_schema(_JavaServer(), max_requests=40, batch=40)
    added = merge_into_schema(sm, recovered)
    assert added > 0
    assert "notification" in sm["Query"] and "Notification" in sm


def test_clairvoyance_action_recovers_map():
    sm = {"_query_type": "Query", "_mutation_type": "Mutation", "Query": {}, "Mutation": {}}
    ctx = ActionContext(client=_JavaServer(), schema_map=sm, schema_index=None, settings={},
                        target_url="http://t/graphql")
    res = dispatch("clairvoyance", ctx, {})
    assert res.touched_target and "recovered" in res.observation
    assert "notification" in sm["Query"] and sm["Query"]["notification"]["return_type"] == "Notification"


def test_clairvoyance_action_no_signal_message():
    class _Silent:
        session = None

        def execute(self, query, variables=None, extra_headers=None):
            return {"data": None, "errors": [{"message": "Bad request"}], "_status_code": 400}

    ctx = ActionContext(client=_Silent(), schema_map={"_query_type": "Query", "Query": {}},
                        schema_index=None, settings={}, target_url="http://t/graphql")
    res = dispatch("clairvoyance", ctx, {})
    assert "no fields recovered" in res.observation


# --------------------------------------------------------------------------- #
# argument-type recovery (WrongType / required-arg errors)
# --------------------------------------------------------------------------- #

def test_parse_arg_type_graphql_java_list():
    from gradientql.utils.clairvoyance import _parse_arg_type
    r = _parse_arg_type("Validation error (WrongType@[videos]) : argument 'videoIds[0]' with value "
                        "'StringValue{value='1'}' is not a valid 'Int' - Expected an AST type of 'Int'")
    assert r == ("videos", "videoIds", "[Int]")


def test_parse_arg_type_graphql_js_required():
    from gradientql.utils.clairvoyance import _parse_arg_type
    assert _parse_arg_type('Field "order" argument "id" of type "ID!" is required.') == ("order", "id", "ID")


def test_placeholder_by_type():
    from gradientql.utils.clairvoyance import _placeholder
    assert _placeholder("Int") == "1"
    assert _placeholder("[Int]") == "[1]"
    assert _placeholder("String") == '"1"'
    assert _placeholder("") == '"1"'
    assert _placeholder("Boolean") == "true"


def test_arg_segment_uses_typed_placeholder():
    from gradientql.utils.clairvoyance import _arg_segment
    assert _arg_segment("videos", [{"name": "videoIds", "type": "[Int]"}]) == "videos(videoIds: [1])"


def test_learn_arg_types_fills_type_from_wrongtype():
    from gradientql.utils.clairvoyance import _learn_arg_types

    class _C:
        def execute(self, q, extra_headers=None):
            return {"errors": [{"message": "Validation error (WrongType@[videos]) : argument "
                                "'videoIds[0]' with value 'x' is not a valid 'Int' - Expected an AST "
                                "type of 'Int'"}]}

    fields = {"videos": {"args": [{"name": "videoIds", "type": "", "default": None}],
                         "return_type": "VideoList"}}
    budget = [5]
    _learn_arg_types(_C(), "query", [], fields, None, budget)
    assert fields["videos"]["args"][0]["type"] == "[Int]"
    assert budget[0] == 4  # consumed one probe request


def test_analyze_guards_against_non_exhaustive_errors():
    # a server that reports only ONE "Cannot query field" for a big batch (error cap / WAF) must NOT
    # make clairvoyance mark the other 39 as valid - that produced the 1337 junk fields on riverside.
    chunk = [f"w{i}" for i in range(40)]
    resp = {"errors": [{"message": 'Cannot query field "w0" on type "Query".'}], "data": None}
    out = _analyze(resp, chunk)
    assert out == {}                       # no positive signals -> nothing recovered (not 39 junk)


def test_analyze_guard_keeps_positively_signalled_fields():
    # even on a capped server, a field the server explicitly typed (SubselectionRequired) is kept
    chunk = [f"w{i}" for i in range(40)] + ["user"]
    resp = {"errors": [
        {"message": 'Cannot query field "w0" on type "Query".'},
        {"message": "Validation error (SubselectionRequired@[user]) : Subselection required for type 'User'"},
    ], "data": None}
    out = _analyze(resp, chunk)
    assert set(out) == {"user"} and out["user"]["return_type"] == "User"


def test_analyze_exhaustive_server_still_recovers_scalars():
    # a normal exhaustive server flags most of the chunk undefined -> guard OFF, scalars recovered
    chunk = [f"w{i}" for i in range(40)]
    errs = [{"message": f'Cannot query field "w{i}" on type "Query".'} for i in range(2, 40)]
    out = _analyze({"errors": errs, "data": None}, chunk)
    assert set(out) == {"w0", "w1"}        # the 2 not flagged are the real scalars
