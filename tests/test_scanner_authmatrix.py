"""Tests for the `auth_test` action — multi-identity isolated testing + BFLA/priv-esc detection."""

from __future__ import annotations

from gradientql.scanner.actions import ActionContext, dispatch


def _ctx(client, schema_map=None, **over):
    ctx = ActionContext(client=client, schema_map=schema_map if schema_map is not None else {},
                        schema_index=None, settings={"target": {}}, target_url="http://t/graphql")
    for k, v in over.items():
        setattr(ctx, k, v)
    return ctx


class _IdentityClient:
    """Responds based on the Authorization header so the identity matrix is observable."""
    def __init__(self, fn):
        self.fn = fn
        self.session = None
        self.calls = []

    def execute(self, query, variables=None, extra_headers=None):
        hdrs = dict(extra_headers or {})
        self.calls.append(hdrs)
        return self.fn(hdrs)


def _sm(mutation):
    return {"_query_type": "Query", "_mutation_type": "Mutation", "Query": {}, "Mutation": mutation}


def test_auth_test_records_bfla_when_anon_reaches_sensitive_field():
    sm = _sm({"generateCustomerTokenAsAdmin": {"args": [], "return_type": "T", "description": ""}})

    def fn(h):
        if h.get("Authorization"):  # authed -> correctly blocked
            return {"data": None, "errors": [{"message": "not authorized"}], "_status_code": 200}
        return {"data": {"generateCustomerTokenAsAdmin": {"customer_token": "LEAKED"}}, "errors": [], "_status_code": 200}

    ctx = _ctx(_IdentityClient(fn), sm, identity={"Authorization": "Bearer cust"})
    dispatch("auth_test", ctx, {"query": "mutation { generateCustomerTokenAsAdmin(input:{customer_email:\"x\"}) { customer_token } }"})
    assert any("Broken Function-Level Authorization" in v["vuln_type"] for v in ctx.vulns)
    assert ctx.ledger["generateCustomerTokenAsAdmin"]["authmatrix"]   # matrix recorded on the ledger
    assert {"anon", "current"} <= set(ctx.ledger["generateCustomerTokenAsAdmin"]["authmatrix"])


def test_auth_test_no_false_positive_on_public_field():
    # a non-high-value field returning data anonymously is NOT flagged
    sm = {"_query_type": "Query", "_mutation_type": "Mutation",
          "Query": {"products": {"args": [], "return_type": "Y", "description": ""}}, "Mutation": {}}
    ctx = _ctx(_IdentityClient(lambda h: {"data": {"products": {"items": []}}, "errors": [], "_status_code": 200}), sm)
    dispatch("auth_test", ctx, {"query": "query { products { items { id } } }"})
    assert ctx.vulns == []


def test_auth_test_no_bfla_on_uniform_public_payment_list():
    # paymentMethods returns the SAME public data to every identity (no authed identity blocked) ->
    # not a differential, must NOT record (regression: rank-agnostic anon==DATA fired here)
    sm = {"_query_type": "Query", "_mutation_type": "Mutation",
          "Query": {"paymentMethods": {"args": [], "return_type": "Y", "description": ""}}, "Mutation": {}}
    ctx = _ctx(_IdentityClient(lambda h: {"data": {"paymentMethods": [{"code": "checkmo"}]},
                                          "errors": [], "_status_code": 200}),
               sm, identity={"Authorization": "Bearer cust"})
    dispatch("auth_test", ctx, {"query": "query { paymentMethods { code } }"})
    assert ctx.vulns == []


def test_auth_test_no_bfla_on_anon_reset_request_ack():
    # requestPasswordResetEmail is anonymous-by-design and returns a bare {ok:true} ACK to anon while
    # an authed identity is blocked -> the differential holds but the ACK guard suppresses it
    sm = _sm({})
    sm["Query"] = {"requestPasswordResetEmail": {"args": [], "return_type": "Boolean", "description": ""}}

    def fn(h):
        if h.get("Authorization"):
            return {"data": None, "errors": [{"message": "not authorized"}], "_status_code": 200}
        return {"data": {"requestPasswordResetEmail": True}, "errors": [], "_status_code": 200}

    ctx = _ctx(_IdentityClient(fn), sm, identity={"Authorization": "Bearer cust"})
    dispatch("auth_test", ctx, {"query": 'query { requestPasswordResetEmail(email:"x@y.io") }'})
    assert ctx.vulns == []


def test_auth_test_no_privesc_on_anon_reachable_field():
    # cancelOrder: current blocked (own-resource BOLA), forged DATA, but anon ALSO DATA -> the forged
    # token just fell back to anon, NOT an elevation. Must record NEITHER priv-esc nor BFLA.
    sm = _sm({"cancelOrder": {"args": [], "return_type": "Z", "description": ""}})

    def fn(h):
        a = h.get("Authorization", "")
        if "cust" in a and "forged" not in a:    # the real customer is blocked on this order
            return {"data": None, "errors": [{"message": "not authorized for this order"}], "_status_code": 200}
        return {"data": {"cancelOrder": {"state": "CANCELED"}}, "errors": [], "_status_code": 200}

    ctx = _ctx(_IdentityClient(fn), sm, identity={"Authorization": "Bearer cust"},
               harvested={"forged_jwt": ["forgedTOKEN"]})
    dispatch("auth_test", ctx, {"query": "mutation { cancelOrder(id:1) { state } }"})
    assert ctx.vulns == []


def test_auth_test_records_privilege_escalation_via_forged_token():
    sm = _sm({"deletePaymentToken": {"args": [], "return_type": "Z", "description": ""}})

    def fn(h):
        a = h.get("Authorization", "")
        if "forged" in a:           # forged admin token elevates
            return {"data": {"deletePaymentToken": {"result": True}}, "errors": [], "_status_code": 200}
        return {"data": None, "errors": [{"message": "not authorized"}], "_status_code": 200}

    ctx = _ctx(_IdentityClient(fn), sm, identity={"Authorization": "Bearer cust"},
               harvested={"forged_jwt": ["forgedTOKEN"]})
    dispatch("auth_test", ctx, {"query": "mutation { deletePaymentToken(public_hash:\"x\") { result } }"})
    assert any("Privilege Escalation" in v["vuln_type"] for v in ctx.vulns)


def test_auth_test_needs_query():
    res = dispatch("auth_test", _ctx(_IdentityClient(lambda h: {}), {}), {})
    assert "needs {query}" in res.observation


def test_batch_brute_flags_rate_limit_bypass_and_hit():
    # the server processes all aliased attempts in one request (no per-request limit) and one succeeds
    def fn(_h):
        # every alias present in data; the "1337" attempt yields a token, others null
        return {"data": {"b0": None, "b1": {"token": "WON"}, "b2": None}, "errors": [], "_status_code": 200}

    ctx = _ctx(_IdentityClient(fn), {})
    res = dispatch("batch_brute", ctx, {"template": 'login(p:"{V}"){token}', "values": ["a", "1337", "c"]})
    assert "processed 3/3" in res.observation
    assert any("Rate-Limit Bypass" in v["vuln_type"] for v in ctx.vulns)
    assert any("brute-force hit" in v["vuln_type"] for v in ctx.vulns)
    assert "1337" in res.observation     # the winning value surfaced


def test_batch_brute_needs_template_and_values():
    res = dispatch("batch_brute", _ctx(_IdentityClient(lambda h: {}), {}), {"values": ["x"]})
    assert "needs {template" in res.observation


def test_batch_brute_no_bypass_when_all_validation_rejected():
    # every alias fails with a VALIDATION error (no execution-time path) -> nothing ran -> NOT a bypass
    ctx = _ctx(_IdentityClient(lambda h: {"data": None, "errors": [{"message": "Cannot query field"}],
                                          "_status_code": 200}), {})
    res = dispatch("batch_brute", ctx, {"template": 'x(p:"{V}")', "values": ["a", "b", "c"]})
    assert ctx.vulns == [] and "processed 0/3" in res.observation


def test_batch_brute_notes_truncated_values():
    # >50 candidates: only 50 are sent, but the observation must flag how many were dropped so the
    # agent doesn't read a clean 50/50 negative as "secret not in list"
    ctx = _ctx(_IdentityClient(lambda h: {"data": {}, "errors": [], "_status_code": 200}), {})
    res = dispatch("batch_brute", ctx, {"template": 'login(p:"{V}"){token}',
                                        "values": [str(i) for i in range(200)]})
    assert "processed 0/50" in res.observation
    assert "150 value(s) NOT sent" in res.observation


def test_batch_brute_no_note_under_cap():
    ctx = _ctx(_IdentityClient(lambda h: {"data": {}, "errors": [], "_status_code": 200}), {})
    res = dispatch("batch_brute", ctx, {"template": 'login(p:"{V}"){token}', "values": ["a", "b"]})
    assert "NOT sent" not in res.observation


def test_batch_brute_refuses_destructive_template():
    ctx = _ctx(_IdentityClient(lambda h: {"data": {}, "errors": [], "_status_code": 200}), {})
    res = dispatch("batch_brute", ctx, {"template": 'deleteUser(id:"{V}")', "values": ["1", "2"]})
    assert "REFUSED" in res.observation and ctx.vulns == []


def test_auth_test_records_bfla_when_sensitive_field_open_to_everyone():
    # the textbook BFLA: a sensitive field returns real data to anon AND to a customer token
    # (nothing blocked - it's just open). The old rule needed a blocked identity and missed it.
    sm = _sm({"deleteCustomer": {"args": [], "return_type": "T", "description": ""}})

    def fn(h):
        return {"data": {"deleteCustomer": {"customer": {"email": "victim@x.io", "name": "V"}}},
                "errors": [], "_status_code": 200}

    ctx = _ctx(_IdentityClient(fn), sm, identity={"Authorization": "Bearer cust"})
    dispatch("auth_test", ctx, {"query": "mutation { deleteCustomer(id: 2) { customer { email } } }"})
    assert any("Broken Function-Level Authorization" in v["vuln_type"] for v in ctx.vulns)


def test_batch_brute_escapes_quotes_in_values():
    # a candidate containing a double quote must not break the batched query string
    sent = []

    class _C:
        session = None

        def execute(self, query, variables=None, extra_headers=None):
            sent.append(query)
            return {"data": {"b0": None, "b1": None}, "errors": [], "_status_code": 200}

    ctx = _ctx(_C(), _sm({"login": {"args": [], "return_type": "T", "description": ""}}))
    dispatch("batch_brute", ctx, {"template": 'login(user:"admin", password:"{V}") { token }',
                                  "values": ['pa"ss', 'x\y']})
    assert '\\"' in sent[0] and 'pa\\"ss' in sent[0]
    assert "x\\\\y" in sent[0]  # single backslash in the value must be doubled in the query


def test_batch_brute_partial_processing_is_not_a_bypass():
    # only 2 of 3 aliases came back - an alias cap/validation reject proves nothing about rate
    # limits, so no bypass finding may be recorded
    class _C:
        session = None

        def execute(self, query, variables=None, extra_headers=None):
            return {"data": {"b0": None, "b1": None}, "errors": [], "_status_code": 200}

    ctx = _ctx(_C(), _sm({"login": {"args": [], "return_type": "T", "description": ""}}))
    res = dispatch("batch_brute", ctx, {"template": 'login(user:"a", password:"{V}") { token }',
                                        "values": ["1", "2", "3"]})
    assert "BYPASSED" not in res.observation
    assert not any("Rate-Limit Bypass" in v["vuln_type"] for v in ctx.vulns)
