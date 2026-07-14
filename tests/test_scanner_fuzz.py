"""Tests for the `fuzz` action — the free-form payload battery."""

from __future__ import annotations

from gradientql.scanner.actions import ActionContext, dispatch


def _ctx(client, schema_map):
    return ActionContext(client=client, schema_map=schema_map, schema_index=None,
                         settings={"target": {}}, target_url="http://t/graphql")


def _schema(field="echo", arg="text", ret="String"):
    return {
        "_query_type": "Query", "_mutation_type": "Mutation", "_enum_types": {},
        "Query": {field: {"args": [{"name": arg, "type": "String"}], "return_type": ret, "description": ""}},
    }


class _VarClient:
    """A client that responds based on the injected variable (payload), with an optional
    transform simulating a vulnerable resolver."""
    def __init__(self, transform):
        self.session = None
        self.calls = []
        self._transform = transform

    def execute(self, query, variables=None, extra_headers=None):
        self.calls.append((query, dict(variables or {})))
        p = (variables or {}).get("p", "")
        return self._transform(p)


def test_fuzz_confirms_ssti_eval():
    # a Ruby-interpolating echo: evaluates #{...}/{{...}} markers
    def t(p):
        out = (p.replace("#{1337*1337}", "1787569").replace("{{1337*1337}}", "1787569")
               .replace("<%= 1337*1337 %>", "1787569").replace("${1337*1337}", "1787569")
               .replace("{{7*'7'}}", "7777777").replace("#{'7'*7}", "7777777")
               .replace("{{99*99}}", "9801"))
        return {"data": {"echo": f"nil says: {out}"}, "errors": [], "_status_code": 200}

    client = _VarClient(t)
    ctx = _ctx(client, _schema())
    res = dispatch("fuzz", ctx, {"field": "echo", "arg": "text", "classes": ["ssti"]})
    assert res.touched_target
    assert any("SSTI" in v["vuln_type"] for v in ctx.vulns)
    assert "CONFIRMED" in res.observation
    assert ctx.ledger["echo"]["fuzzed"] is True
    assert ctx.ledger["echo"]["finding"]


def test_fuzz_confirms_command_injection():
    def t(p):
        if any(sep in p for sep in (";", "|", "$(", "`", "&")) and "id" in p:
            return {"data": {"run": "uid=33(www-data) gid=33(www-data) groups=33(www-data)"},
                    "errors": [], "_status_code": 200}
        return {"data": {"run": "ok"}, "errors": [], "_status_code": 200}

    client = _VarClient(t)
    ctx = _ctx(client, _schema(field="run", arg="cmd"))
    res = dispatch("fuzz", ctx, {"field": "run", "arg": "cmd", "classes": ["cmdi"]})
    assert any("Command Injection" in v["vuln_type"] for v in ctx.vulns)


def test_fuzz_literal_reflector_flagged_not_confirmed():
    # a plain echo that reflects every payload verbatim -> LITERAL REFLECTOR, not a finding
    client = _VarClient(lambda p: {"data": {"echo": f"you said {p}"}, "errors": [], "_status_code": 200})
    ctx = _ctx(client, _schema())
    res = dispatch("fuzz", ctx, {"field": "echo", "arg": "text", "payloads": ["MYCANARYxyz"]})
    assert "REFLECTOR" in res.observation
    assert ctx.vulns == []                       # reflection alone is not a confirmed finding
    assert ctx.ledger["echo"]["fuzzed"] is True


def test_fuzz_selection_does_not_subselect_a_scalar_nodes_field():
    # a field literally named `nodes` that returns a SCALAR must NOT get `{ nodes { ... } }` forced on
    # it (invalid GraphQL -> whole query rejected -> every payload silently fails)
    from gradientql.scanner.schema import fuzz_selection
    sm = {"_query_type": "Query", "Query": {},
          "W": {"nodes": {"args": [], "return_type": "Int", "description": ""}}}
    sel = fuzz_selection(sm, "W")
    assert "{ nodes {" not in sel and "nodes" in sel    # requests the scalar leaf, no sub-selection


def test_fuzz_selection_requests_sibling_scalar_fields():
    # the schema-derived selection must request scalar SIBLING fields (output/message), not just {id},
    # so an injection result that surfaces in another field is actually returned + detectable
    sm = {"_query_type": "Query", "_mutation_type": "Mutation", "_enum_types": {},
          "Query": {"run": {"args": [{"name": "cmd", "type": "String"}], "return_type": "RunResult", "description": ""}},
          "RunResult": {"id": {"args": [], "return_type": "ID", "description": ""},
                        "output": {"args": [], "return_type": "String", "description": ""},
                        "message": {"args": [], "return_type": "String", "description": ""}}}
    captured = []

    class _C:
        session = None

        def execute(self, query, variables=None, extra_headers=None):
            captured.append(query)
            return {"data": {"run": {"id": "1", "output": "ok", "message": ""}}, "errors": [], "_status_code": 200}

    ctx = _ctx(_C(), sm)
    dispatch("fuzz", ctx, {"field": "run", "arg": "cmd", "payloads": ["x"]})
    assert captured and all("output" in q and "message" in q for q in captured)   # siblings requested, not just id


def test_fuzz_shows_every_payload_outcome():
    # per-payload visibility: the obs surfaces EACH payload's outcome, not a collapsed 6-tag digest
    def t(p):
        if "ERR" in p:
            return {"data": None, "errors": [{"message": f"boom-{p}"}], "_status_code": 200}
        return {"data": {"echo": f"val-{p}"}, "errors": [], "_status_code": 200}

    ctx = _ctx(_VarClient(t), _schema())
    res = dispatch("fuzz", ctx, {"field": "echo", "arg": "text", "payloads": ["ERRa", "okb", "okc"]})
    assert "ERRa" in res.observation and "okb" in res.observation and "okc" in res.observation


def test_fuzz_coercion_mode_targets_numeric_arg_and_flags_enum_leak():
    # coercion mode works on a non-string (Int) arg the normal path rejects, and flags a
    # "did you mean" enum/field-suggestion leak as schema disclosure
    sm = {"_query_type": "Query", "_mutation_type": "Mutation", "_enum_types": {},
          "Query": {"paste": {"args": [{"name": "id", "type": "Int"}], "return_type": "Paste", "description": ""}},
          "Paste": {"id": {"args": [], "return_type": "ID", "description": ""}}}

    class _C:
        session = None

        def execute(self, query, variables=None, extra_headers=None):
            return {"data": None, "errors": [{"message": "Enum value invalid; did you mean ACTIVE, INACTIVE?"}],
                    "_status_code": 200}

    ctx = _ctx(_C(), sm)
    res = dispatch("fuzz", ctx, {"field": "paste", "arg": "id", "classes": ["coercion"]})
    assert res.touched_target and "coercion paste(id)" in res.observation
    # a "did you mean" enum suggestion is surfaced as a LEAD tag, NOT recorded as a finding (it's
    # graphql-core's benign default, and the agent already has the schema via introspection)
    assert "type/enum-error" in res.observation
    assert not any("Suggestion Leak" in v["vuln_type"] for v in ctx.vulns)


def test_fuzz_connection_selection_is_wrapped():
    # model passes a BARE selection -> the handler must not emit the invalid `field(arg) __typename`
    sm = {"_query_type": "Query", "_mutation_type": "Mutation", "_enum_types": {},
          "Query": {"items": {"args": [{"name": "search", "type": "String"}], "return_type": "ItemConn", "description": ""}},
          "ItemConn": {"nodes": {"args": [], "return_type": "[Item]", "description": ""}},
          "Item": {"id": {"args": [], "return_type": "ID", "description": ""}}}
    captured = []

    class _C:
        session = None

        def execute(self, query, variables=None, extra_headers=None):
            captured.append(query)
            return {"data": {"items": {"nodes": []}}, "errors": [], "_status_code": 200}

    ctx = _ctx(_C(), sm)
    dispatch("fuzz", ctx, {"field": "items", "arg": "search", "payloads": ["x"], "selection": "__typename"})
    assert captured and all("search: $p) { nodes { id } }" in q for q in captured)
    assert not any("$p) __typename" in q for q in captured)


def test_fuzz_nested_input_field_injects_at_leaf():
    sm = {"_query_type": "Query", "_mutation_type": "Mutation", "Query": {},
          "Mutation": {"createCustomerAddress": {"args": [{"name": "input", "type": "CustomerAddressInput!"}],
                                                 "return_type": "CustomerAddress", "description": ""}},
          "CustomerAddress": {"id": {"args": [], "return_type": "ID", "description": ""}},
          "_input_types": {"CustomerAddressInput": [{"name": "city", "type": "String"},
                                                    {"name": "firstname", "type": "String"}]}}
    captured = []

    class _C:
        session = None

        def execute(self, query, variables=None, extra_headers=None):
            captured.append((query, variables))
            city = ((variables or {}).get("p") or {}).get("city", "")
            out = city.replace("#{1337*1337}", "1787569").replace("{{1337*1337}}", "1787569")
            return {"data": {"createCustomerAddress": {"id": out}}, "errors": [], "_status_code": 200}

    ctx = _ctx(_C(), sm)
    res = dispatch("fuzz", ctx, {"field": "createCustomerAddress", "arg": "input", "path": "city",
                                 "input": {"firstname": "Test", "city": "x"}, "classes": ["ssti"]})
    # the whole input object is sent as the variable: filler preserved, payload injected at the leaf
    assert all((v.get("p") or {}).get("firstname") == "Test" for _q, v in captured)
    assert any((v.get("p") or {}).get("city") in ("#{1337*1337}", "{{1337*1337}}") for _q, v in captured)
    assert any("SSTI" in x["vuln_type"] for x in ctx.vulns)


def test_fuzz_nested_requires_input_object():
    sm = {"_query_type": "Query", "_mutation_type": "Mutation", "Query": {},
          "Mutation": {"createX": {"args": [{"name": "input", "type": "XInput!"}], "return_type": "X", "description": ""}}}
    res = dispatch("fuzz", _ctx(_VarClient(lambda p: {}), sm), {"field": "createX", "arg": "input", "path": "city"})
    assert "input:" in res.observation       # nudges the model to supply the base object


def test_fuzz_rejects_non_string_arg():
    sm = _schema()
    sm["Query"]["echo"]["args"] = [{"name": "n", "type": "Int!"}]
    res = dispatch("fuzz", _ctx(_VarClient(lambda p: {}), sm), {"field": "echo", "arg": "n"})
    assert "not string-injectable" in res.observation


def test_fuzz_unknown_field():
    res = dispatch("fuzz", _ctx(_VarClient(lambda p: {}), _schema()), {"field": "nope", "arg": "x"})
    assert "not a root" in res.observation


def test_fuzz_dedup_skips_identical_battery():
    # ssti's 7-probe ladder fits under the cap, so one turn sends it WHOLE; only then is a repeat blocked
    client = _VarClient(lambda p: {"data": {"echo": f"says {p}"}, "errors": [], "_status_code": 200})
    ctx = _ctx(client, _schema())
    dispatch("fuzz", ctx, {"field": "echo", "arg": "text", "classes": ["ssti"]})
    sent = [v.get("p") for _q, v in client.calls]
    assert "{{1337*1337}}" in sent and "{{99*99}}" in sent   # the full ssti ladder went out
    n = len(client.calls)
    res = dispatch("fuzz", ctx, {"field": "echo", "arg": "text", "classes": ["ssti"]})
    assert "already fuzzed" in res.observation
    assert len(client.calls) == n           # the repeat sent ZERO requests


def test_fuzz_clean_field_marked_done_not_open():
    from gradientql.scanner.memory import effective_state
    client = _VarClient(lambda p: {"data": {"echo": f"says {p}"}, "errors": [], "_status_code": 200})
    ctx = _ctx(client, _schema())
    dispatch("fuzz", ctx, {"field": "echo", "arg": "text", "payloads": ["abcd"]})
    e = ctx.ledger["echo"]
    assert e["auto"] == "FUZZED"
    assert effective_state(e) == "dead"     # fuzzed-clean -> done, not 'open' forever


def test_fuzz_sends_payloads_as_variables():
    client = _VarClient(lambda p: {"data": {"echo": p}, "errors": [], "_status_code": 200})
    ctx = _ctx(client, _schema())
    dispatch("fuzz", ctx, {"field": "echo", "arg": "text", "payloads": ["a' OR '1'='1"]})
    # the payload travels in variables, never inlined into the query string (no quote-breaking)
    assert any(v.get("p") == "a' OR '1'='1" for _q, v in client.calls)
    assert all("$p" in q for q, _v in client.calls)


class _FakeOOB:
    def __init__(self):
        self.issued = []

    def issue(self, meta):
        self.issued.append(meta)
        return ("http://oob.example/abc", "oob-abc")


def test_fuzz_default_classes_round_robin_includes_sqli():
    # the default battery interleaves ssti/cmdi/sqli so sqli fires before the cap (was silently dropped)
    client = _VarClient(lambda p: {"data": {"echo": f"v-{p}"}, "errors": [], "_status_code": 200})
    ctx = _ctx(client, _schema())
    dispatch("fuzz", ctx, {"field": "echo", "arg": "text"})
    sent = [v.get("p") for _q, v in client.calls]
    assert "' OR '1'='1" in sent
    assert "; id" in sent
    assert "{{1337*1337}}" in sent


def test_fuzz_ssrf_oob_url_survives_truncation_when_combined():
    # combining ssti+cmdi+ssrf keeps ssrf reachable: static probes round-robined in, OOB URL appended past the cap
    client = _VarClient(lambda p: {"data": {"echo": f"v-{p}"}, "errors": [], "_status_code": 200})
    ctx = _ctx(client, _schema())
    ctx.oob_sess = _FakeOOB()
    res = dispatch("fuzz", ctx, {"field": "echo", "arg": "text", "classes": ["ssti", "cmdi", "ssrf"]})
    sent = [v.get("p") for _q, v in client.calls]
    assert "http://oob.example/abc" in sent
    assert "http://169.254.169.254/latest/meta-data/" in sent
    assert "OOB URL injected" in res.observation


def test_fuzz_honors_max_payloads_override():
    # scanner.fuzz.max_payloads shrinks the per-turn battery cap (default 14 -> 3 here)
    client = _VarClient(lambda p: {"data": {"echo": f"v-{p}"}, "errors": [], "_status_code": 200})
    ctx = _ctx(client, _schema())
    ctx.settings = {"target": {}, "scanner": {"fuzz": {"max_payloads": 3}}}
    customs = [f"c{i}" for i in range(10)]
    res = dispatch("fuzz", ctx, {"field": "echo", "arg": "text", "payloads": customs})
    assert len(client.calls) == 4          # 1 baseline canary + 3 capped payloads
    assert "×3" in res.observation


def test_fuzz_injection_disabled_drops_ssti():
    # scanner.attacks.injection:false strips sqli/cmdi/ssti from the requested classes
    client = _VarClient(lambda p: {"data": {"echo": f"v-{p}"}, "errors": [], "_status_code": 200})
    ctx = _ctx(client, _schema())
    ctx.settings = {"target": {}, "scanner": {"attacks": {"injection": False}}}
    res = dispatch("fuzz", ctx, {"field": "echo", "arg": "text", "classes": ["ssti"]})
    sent = [v.get("p") for _q, v in client.calls]
    assert "{{1337*1337}}" not in sent     # the ssti ladder never went out
    assert "no payloads" in res.observation


def test_fuzz_truncation_note_names_fully_dropped_class():
    client = _VarClient(lambda p: {"data": {"echo": f"v-{p}"}, "errors": [], "_status_code": 200})
    ctx = _ctx(client, _schema())
    customs = [f"c{i}" for i in range(14)]
    res = dispatch("fuzz", ctx, {"field": "echo", "arg": "text", "payloads": customs, "classes": ["sqli"]})
    sent = [v.get("p") for _q, v in client.calls]
    assert "' OR '1'='1" not in sent
    assert "NOT sent: sqli" in res.observation


def test_fuzz_dropped_class_not_locked_out():
    # a class truncated away is NOT marked seen, so a later focused re-fuzz actually runs its whole ladder
    client = _VarClient(lambda p: {"data": {"echo": f"v-{p}"}, "errors": [], "_status_code": 200})
    ctx = _ctx(client, _schema())
    customs = [f"c{i}" for i in range(14)]
    dispatch("fuzz", ctx, {"field": "echo", "arg": "text", "payloads": customs, "classes": ["sqli"]})
    res = dispatch("fuzz", ctx, {"field": "echo", "arg": "text", "classes": ["sqli"]})
    assert "already fuzzed" not in res.observation
    sent = [v.get("p") for _q, v in client.calls]
    assert "' OR '1'='1" in sent
    assert "' UNION SELECT NULL-- -" in sent      # the deep sqli probe is now reachable on re-fuzz


def test_fuzz_resumes_ladder_across_refuzz():
    # the default battery is longer than the 14-cap, so a class is only half-sent the first turn.
    # a re-fuzz must RESUME the ladder (send the deep RCE/SQLi probes), not be blocked as "seen".
    client = _VarClient(lambda p: {"data": {"echo": f"v-{p}"}, "errors": [], "_status_code": 200})
    ctx = _ctx(client, _schema())
    res1 = dispatch("fuzz", ctx, {"field": "echo", "arg": "text"})
    sent1 = [v.get("p") for _q, v in client.calls]
    assert "; cat /etc/passwd" not in sent1        # deep cmdi probe truncated the first turn
    assert "' UNION SELECT NULL-- -" not in sent1  # deep sqli probe truncated too
    assert "sent" in res1.observation and "re-fuzz" in res1.observation  # within-class truncation note

    res2 = dispatch("fuzz", ctx, {"field": "echo", "arg": "text"})
    assert "already fuzzed" not in res2.observation
    sent2 = [v.get("p") for _q, v in client.calls]
    assert "; cat /etc/passwd" in sent2            # resumed ladder now sends the deep probes
    assert "' UNION SELECT NULL-- -" in sent2

    # once the whole ladder is exhausted, a further re-fuzz IS blocked (nothing new to send)
    res3 = dispatch("fuzz", ctx, {"field": "echo", "arg": "text"})
    assert "already fuzzed" in res3.observation


def test_fuzz_coercion_battery_deduped_across_coercion_and_enum():
    # the coercion/enum battery is deterministic; a repeat (even under the OTHER class name that
    # runs the same battery) is blocked instead of re-firing identical requests
    sm = {"_query_type": "Query", "_mutation_type": "Mutation", "_enum_types": {},
          "Query": {"paste": {"args": [{"name": "id", "type": "Int"}], "return_type": "Paste", "description": ""}},
          "Paste": {"id": {"args": [], "return_type": "ID", "description": ""}}}

    class _C:
        session = None

        def __init__(self):
            self.n = 0

        def execute(self, query, variables=None, extra_headers=None):
            self.n += 1
            return {"data": None, "errors": [{"message": "invalid"}], "_status_code": 200}

    client = _C()
    ctx = _ctx(client, sm)
    dispatch("fuzz", ctx, {"field": "paste", "arg": "id", "classes": ["coercion"]})
    fired = client.n
    res = dispatch("fuzz", ctx, {"field": "paste", "arg": "id", "classes": ["enum"]})
    assert "already coerced" in res.observation
    assert client.n == fired      # the repeat (as enum) sent ZERO requests


def test_fuzz_coercion_nested_leaf_returns_guidance():
    res = dispatch("fuzz", _ctx(_VarClient(lambda p: {}), _schema()),
                   {"field": "echo", "arg": "text", "path": "city", "classes": ["coercion"]})
    assert "TOP-LEVEL" in res.observation
    assert "unknown classes" not in res.observation


def test_fuzz_coercion_with_injection_class_flags_dropped():
    sm = {"_query_type": "Query", "_mutation_type": "Mutation", "_enum_types": {},
          "Query": {"paste": {"args": [{"name": "id", "type": "Int"}], "return_type": "Paste", "description": ""}},
          "Paste": {"id": {"args": [], "return_type": "ID", "description": ""}}}

    class _C:
        session = None

        def execute(self, query, variables=None, extra_headers=None):
            return {"data": None, "errors": [{"message": "Enum value invalid; did you mean ACTIVE?"}],
                    "_status_code": 200}

    res = dispatch("fuzz", _ctx(_C(), sm), {"field": "paste", "arg": "id", "classes": ["coercion", "ssti"]})
    assert "coercion paste(id)" in res.observation
    assert "NOT run this turn" in res.observation and "ssti" in res.observation
