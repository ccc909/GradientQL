"""Clairvoyance schema recovery via the validation-error suggestion oracle."""

from __future__ import annotations

from gradientql.scanner.actions import ActionContext, dispatch
from gradientql.utils.clairvoyance import _parse_message, recover_root_fields


def test_parse_message_suggestions():
    found = set()
    _parse_message('Cannot query field "usr" on type "Query". Did you mean "user" or "users"?',
                   {"usr"}, found)
    assert found == {"user", "users"}


def test_parse_message_self_named_valid_field():
    found = set()
    _parse_message('Field "orders" of type "[Order!]!" must have a selection of subfields.',
                   {"orders"}, found)
    assert "orders" in found


def test_parse_message_ignores_cannot_query_without_suggestion():
    found = set()
    _parse_message('Cannot query field "zzz" on type "Query".', {"zzz"}, found)
    assert found == set()


class _OracleClient:
    """Simulates a server with introspection off but suggestions on."""

    def __init__(self, valid):
        self.valid = set(valid)
        self.session = None

    def execute(self, query, variables=None, extra_headers=None):
        # parse aliased candidates: "cN: name"
        import re
        errors = []
        data = {}
        for alias, name in re.findall(r"(c\d+):\s*(\w+)", query):
            if name in self.valid:
                # pretend valid fields need a selection (so they surface via the error, not data)
                errors.append({"message": f'Field "{name}" of type "T" must have a selection of subfields.'})
            else:
                errors.append({"message": f'Cannot query field "{name}" on type "Query". '
                                          f'Did you mean "{sorted(self.valid)[0]}"?'})
        return {"data": data or None, "errors": errors, "_status_code": 200}


def test_recover_root_fields_finds_valid_and_suggested():
    client = _OracleClient(valid={"user", "orders", "adminPanel"})
    found = recover_root_fields(client, "query", ["user", "orders", "adminPanel", "bogus"], max_requests=5)
    assert {"user", "orders", "adminPanel"} <= found


def test_clairvoyance_action_merges_into_schema_map():
    client = _OracleClient(valid={"user", "secretConfig"})
    sm = {"_query_type": "Query", "_mutation_type": "Mutation", "Query": {}, "Mutation": {}}
    ctx = ActionContext(client=client, schema_map=sm, schema_index=None, settings={},
                        target_url="http://t/graphql")
    res = dispatch("clairvoyance", ctx, {"wordlist": ["user", "secretConfig", "nope"]})
    assert res.touched_target
    assert "recovered" in res.observation
    # discovered fields are merged so later steps can drill them
    assert "user" in sm["Query"] and "secretConfig" in sm["Query"]
    assert sm["Query"]["user"]["description"].startswith("(recovered")


def test_clairvoyance_no_leak_message():
    class _Silent:
        session = None

        def execute(self, query, variables=None, extra_headers=None):
            return {"data": None, "errors": [{"message": "Bad request"}], "_status_code": 400}

    ctx = ActionContext(client=_Silent(), schema_map={"_query_type": "Query", "Query": {}},
                        schema_index=None, settings={}, target_url="http://t/graphql")
    res = dispatch("clairvoyance", ctx, {"wordlist": ["user"]})
    assert "no field names" in res.observation or "leaked no" in res.observation
