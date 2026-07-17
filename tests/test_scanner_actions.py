"""Tests for src/scanner/actions/* — the registry and each handler over ActionContext."""

from __future__ import annotations

import json


from gradientql.scanner.actions import ACTIONS, ActionContext, dispatch
from gradientql.scanner.schema import parse_schema
from tests.conftest import MockClient


def make_ctx(client=None, schema_map=None, **over):
    ctx = ActionContext(
        client=client or MockClient(), schema_map=schema_map if schema_map is not None else {},
        schema_index=None, settings={"target": {}}, target_url="http://t/graphql",
    )
    for k, v in over.items():
        setattr(ctx, k, v)
    return ctx


# --- registry -------------------------------------------------------------- #

def test_all_actions_registered():
    expected = {"graphql", "set_identity", "report_finding", "done", "sweep", "search_schema",
                "note", "forge_jwt", "oob_url", "temp_mail", "dos", "smuggle", "csrf"}
    assert expected <= set(ACTIONS)


def test_dispatch_unknown_action():
    res = dispatch("nonsense", make_ctx(), {})
    assert "unknown action" in res.observation


def test_new_attack_toggles_gate_dispatch():
    # jwt / brute / bola gate forge_jwt, batch_brute, authmatrix+auth_test before the handler runs
    ctx = make_ctx(settings={"target": {}, "scanner": {"attacks": {"jwt": False}}})
    r = dispatch("forge_jwt", ctx, {})
    assert r.blocked and "disabled" in r.observation
    assert dispatch("batch_brute", make_ctx(settings={"target": {}, "scanner": {"safe_mode": True}}), {}).blocked
    bola_off = make_ctx(settings={"target": {}, "scanner": {"attacks": {"bola": False}}})
    assert dispatch("auth_test", bola_off, {}).blocked


# --- forge_jwt auto-test against token-arg sinks --------------------------- #

_JWT_SM = {"_query_type": "Query", "_mutation_type": "Mutation", "Mutation": {},
           "Query": {"me": {"args": [{"name": "token", "type": "String"}],
                            "return_type": "User", "description": ""}},
           "User": {"id": {"args": [], "return_type": "Int", "description": ""}}}


def test_forge_jwt_autotests_token_field_and_records_bypass():
    # forged token is submitted INTO me(token:) by the tool; a data response == accepted == bypass
    client = MockClient(default={"data": {"me": {"id": 1}}, "errors": [], "_status_code": 200})
    ctx = make_ctx(client, schema_map=_JWT_SM)
    res = dispatch("forge_jwt", ctx, {"approach": "none"})
    assert res.touched_target
    assert any("Auth Bypass" in v["vuln_type"] and "me(token)" in v["target_node"] for v in ctx.vulns)
    assert "ACCEPTED" in res.observation


def test_forge_jwt_autotest_rejected_token_records_nothing():
    client = MockClient(default={"data": {"me": None},
                                 "errors": [{"message": "Not enough segments"}], "_status_code": 200})
    ctx = make_ctx(client, schema_map=_JWT_SM)
    dispatch("forge_jwt", ctx, {"approach": "none"})
    assert not any("Auth Bypass" in v["vuln_type"] for v in ctx.vulns)


def test_forge_jwt_no_token_field_points_at_header():
    ctx = make_ctx(schema_map={"_query_type": "Query", "Query": {"x": {"args": [], "return_type": "Int"}}})
    res = dispatch("forge_jwt", ctx, {"approach": "none"})
    assert not ctx.vulns
    assert "set_identity" in res.observation


# --- graphql --------------------------------------------------------------- #

def test_graphql_records_detector_finding():
    client = MockClient(default={"data": {"x": "uid=0(root) gid=0(root)"}, "errors": [], "_status_code": 200})
    ctx = make_ctx(client)
    res = dispatch("graphql", ctx, {"query": "query { x }"})
    assert res.touched_target
    assert any("Command Injection" in v["vuln_type"] for v in ctx.vulns)
    assert ctx.ledger["x"]["finding"]


def test_graphql_harvests_submitted_credential():
    client = MockClient(default={"data": {"register": {"id": 1}}, "errors": [], "_status_code": 200})
    ctx = make_ctx(client)
    res = dispatch("graphql", ctx, {"query": 'mutation { register(email:"a@b.com", password:"P@ss123!") { id } }'})
    assert {"email": "a@b.com", "password": "P@ss123!"} in ctx.credentials
    assert "STORED credentials" in res.observation


def test_graphql_retry_cap_blocks():
    # the backstop is argument-aware: it blocks only a RESEND of the same request (matching fingerprint)
    ctx = make_ctx()
    from gradientql.scanner.memory import blank_entry
    from gradientql.scanner.actions.graphql import _request_fp
    q = "query { me { id } }"
    ctx.ledger["me"] = {**blank_entry("me", "anon", 0), "attempts": 8,
                        "last_sig": f"DATA||{_request_fp(q, {})}"}
    res = dispatch("graphql", ctx, {"query": q})
    assert res.blocked and "BLOCKED" in res.observation


def test_graphql_lowered_field_retry_cap_blocks_sooner():
    # a lowered scanner.tuning.field_retry_cap makes the backstop bite before the default 8:
    # attempts at 3 is under the default (would pass) but at/over a configured cap of 3 -> blocked
    from gradientql.scanner.memory import blank_entry
    from gradientql.scanner.actions.graphql import _request_fp
    q = "query { me { id } }"
    entry = lambda: {**blank_entry("me", "anon", 0), "attempts": 3,  # noqa: E731
                     "last_sig": f"DATA||{_request_fp(q, {})}"}
    default_ctx = make_ctx(MockClient(default={"data": {"me": {"id": 1}}, "errors": [], "_status_code": 200}))
    default_ctx.ledger["me"] = entry()
    assert not dispatch("graphql", default_ctx, {"query": q}).blocked   # 3 < default cap 8
    tuned_ctx = make_ctx(settings={"target": {}, "scanner": {"tuning": {"field_retry_cap": 3}}})
    tuned_ctx.ledger["me"] = entry()
    res = dispatch("graphql", tuned_ctx, {"query": q})
    assert res.blocked and "backstop" in res.observation


def test_graphql_retry_cap_lets_a_different_request_through():
    # a diligent BOLA sweep past the cap must NOT be guillotined: a distinct-argument request
    # (different fingerprint) falls through to the network even with attempts at the cap
    client = MockClient(default={"data": {"user": None}, "errors": [], "_status_code": 200})
    ctx = make_ctx(client)
    from gradientql.scanner.memory import blank_entry
    from gradientql.scanner.actions.graphql import _request_fp
    prev = "query { user(id:1000) { email } }"
    ctx.ledger["user"] = {**blank_entry("user", "anon", 0), "attempts": 8,
                          "last_sig": f"null||{_request_fp(prev, {})}"}
    res = dispatch("graphql", ctx, {"query": "query { user(id:9999) { email } }"})
    assert not res.blocked
    assert len(client.calls) == 1


def test_graphql_dup_block_releases_on_argument_change():
    # dup-lock (dup_fails>=cap) must honour the "CHANGE AN ARGUMENT" advice it prints: a request with
    # a NEW fingerprint is not blocked, only a resend of the identical failing request is
    client = MockClient(default={"data": {"user": None},
                                 "errors": [{"message": "not found"}], "_status_code": 200})
    ctx = make_ctx(client)
    from gradientql.scanner.memory import blank_entry
    from gradientql.scanner.actions.graphql import _request_fp
    prev = "query { user(id:1000) { email } }"
    ctx.ledger["user"] = {**blank_entry("user", "anon", 0), "attempts": 2, "dup_fails": 2,
                          "sig": "not found", "last_sig": f"AUTH-BLOCKED|not found|{_request_fp(prev, {})}"}
    resend = dispatch("graphql", ctx, {"query": prev})
    assert resend.blocked and "identical failure" in resend.observation
    changed = dispatch("graphql", ctx, {"query": "query { user(id:2000) { email } }"})
    assert not changed.blocked


def test_graphql_empty_query():
    res = dispatch("graphql", make_ctx(), {"query": "  "})
    assert "empty query" in res.observation


def test_graphql_small_response_shown_whole():
    client = MockClient(default={"data": {"x": "short value"}, "errors": [], "_status_code": 200})
    res = dispatch("graphql", make_ctx(client), {"query": "query { x }"})
    assert "short value" in res.observation and "truncated" not in res.observation


def test_graphql_big_response_surfaces_notable_values_past_the_head():
    # a JWT/email buried PAST the 2000-char display cap must still reach the model (not silently dropped).
    # keys 'blob'/'addr' don't trigger harvest, so the values are surfaced ONLY by the NOTABLE scan.
    from gradientql.scanner.actions.graphql import _OBS_DATA_CHARS
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsZWFrZWQifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    filler = {"pad": "A" * (_OBS_DATA_CHARS + 200), "deep": {"blob": jwt, "addr": "victim@corp.io"}}
    client = MockClient(default={"data": filler, "errors": [], "_status_code": 200})
    res = dispatch("graphql", make_ctx(client), {"query": "query { stuff }"})
    assert "truncated" in res.observation and "NOTABLE" in res.observation
    assert jwt[:60] in res.observation and "victim@corp.io" in res.observation


def test_finding_evidence_stored_up_to_2000():
    ctx = make_ctx()
    ctx.record("X", "t", "E" * 3000, 2.5)
    assert len(ctx.vulns[0]["evidence"]) == 2000     # widened from 500 so detail isn't lost


def test_graphql_prevalidation_blocks_without_request(sample_introspection_result):
    sm = parse_schema(sample_introspection_result)
    client = MockClient()
    ctx = make_ctx(client, schema_map=sm)
    res = dispatch("graphql", ctx, {"query": "query { pastes { bogusField } }"})
    assert "PRE-VALIDATION" in res.observation
    assert client.calls == []           # no request was sent
    assert res.touched_target is False


def test_graphql_suggests_but_does_not_push_on_reflection():
    client = MockClient(default={"data": {"echo": "nil says: reflectme123"}, "errors": [], "_status_code": 200})
    ctx = make_ctx(client)
    res = dispatch("graphql", ctx, {"query": 'query { echo(text: "reflectme123") }'})
    # a soft, take-it-or-leave-it suggestion — NOT the old "EVALUATE … don't move on" directive
    assert "echoed back" in res.observation and "your call" in res.observation
    assert "don't move on" not in res.observation
    assert ctx.ledger["echo"].get("echoed")          # remembered as echoed (for the optional nudge)
    from gradientql.scanner.memory import effective_state
    assert effective_state(ctx.ledger["echo"]) == "data"   # NOT forced "open"


def test_retract_by_id_blocks_readd_but_not_a_different_finding():
    ctx = make_ctx()
    ctx.record("Server-Side Template Injection (SSTI)", "paxList", "9801 seen", 3.0)
    fid = ctx.vulns[0]["id"]                      # the model retracts by the id it sees in the prompt
    assert ctx.retract(finding_id=fid, why="1337*1337 did not evaluate") == 1
    assert ctx.vulns == []
    # a detector must NOT resurrect the SAME disproven finding…
    assert ctx.record("Server-Side Template Injection (SSTI)", "paxList", "again", 3.0) is False
    # …but a genuinely DIFFERENT finding on the same field is NOT class-blocked
    assert ctx.record("SQL Injection (error-based)", "paxList", "real sqli", 3.0) is True


def test_retract_exact_signature_fallback():
    # retract without an id still works via an EXACT full-vuln_type+target match (what report_finding gives)
    ctx = make_ctx()
    ctx.record("User Enumeration", "userExists", "diff", 2.5)
    assert ctx.retract(vuln_type="User Enumeration", target="userExists", why="same to all") == 1
    assert ctx.vulns == []


def test_vuln_stream_tombstone_filters_retracted(tmp_path, monkeypatch):
    # a crash-rebuild from the stream must drop a retracted finding (tombstone honored)
    import gradientql.utils.reporter as rep
    monkeypatch.setattr(rep, "_VULN_STREAM_PATH", tmp_path / "vs.jsonl")
    rep.init_vuln_stream("t")
    rep.append_vuln_stream({"vuln_type": "SSTI", "target_node": "paxList", "score": 3.0})
    rep.append_vuln_stream({"vuln_type": "User Enumeration", "target_node": "userExists", "score": 2.5})
    rep.append_vuln_retraction("SSTI", "paxList")
    out = rep.read_vuln_stream()
    assert [v["vuln_type"] for v in out] == ["User Enumeration"]     # SSTI tombstoned away


def test_graphql_identity_change_resets_attempts():
    client = MockClient(default={"data": {"me": {"id": 1}}, "errors": [], "_status_code": 200})
    ctx = make_ctx(client)
    from gradientql.scanner.memory import blank_entry
    ctx.ledger["me"] = {**blank_entry("me", "anon", 0), "attempts": 8, "verdict": "dead"}
    ctx.identity = {"Authorization": "Bearer newtoken123456"}
    res = dispatch("graphql", ctx, {"query": "query { me { id } }"})
    # under a new identity it's a fresh attempt: not blocked, verdict cleared, counts as 1
    assert not res.blocked
    assert ctx.ledger["me"]["attempts"] == 1
    assert ctx.ledger["me"]["verdict"] is None


# --- other core handlers --------------------------------------------------- #

def test_set_identity():
    ctx = make_ctx()
    dispatch("set_identity", ctx, {"headers": {"Authorization": "Bearer t"}})
    assert ctx.identity["Authorization"] == "Bearer t"


def test_set_identity_redundant_is_noop():
    ctx = make_ctx(identity={"Authorization": "Bearer t"})
    res = dispatch("set_identity", ctx, {"headers": {"Authorization": "Bearer t"}})
    assert "UNCHANGED" in res.observation     # re-setting an active token is flagged, not silently repeated


def test_report_finding_records():
    ctx = make_ctx()
    dispatch("report_finding", ctx, {"vuln_type": "BOLA", "target": "addressFilter", "evidence": "leaked"})
    assert ctx.vulns and ctx.vulns[0]["vuln_type"] == "BOLA"


def test_report_finding_honest_on_dedup():
    # a silently deduped re-report must NOT claim success — mirror the dos action's honest observation
    ctx = make_ctx()
    args = {"vuln_type": "BOLA", "target": "addressFilter", "evidence": "leaked"}
    first = dispatch("report_finding", ctx, args)
    assert "recorded finding" in first.observation
    second = dispatch("report_finding", ctx, args)
    assert "NOT recorded" in second.observation
    assert len(ctx.vulns) == 1        # the duplicate was dropped, and the model was told so


def test_done_returns_stop():
    res = dispatch("done", make_ctx(), {"reason": "covered"})
    assert res.stop


def test_graphql_nudges_oob_on_null_url_field():
    # a url-taking field returning null must NOT be read as "no SSRF" — point at the OOB/fuzz path
    sm = {"_query_type": "Query", "_mutation_type": "Mutation",
          "Query": {"route": {"args": [{"name": "url", "type": "String!"}], "return_type": "RoutableInterface",
                              "description": ""}}, "Mutation": {}}
    client = MockClient(default={"data": {"route": None}, "errors": [], "_status_code": 200})
    ctx = make_ctx(client, schema_map=sm)
    ctx.oob_sess = type("O", (), {"domain": "x.oast.fun"})()   # OOB available
    res = dispatch("graphql", ctx, {"query": 'query { route(url: "../../etc/passwd") { __typename } }'})
    assert "blind-SSRF" in res.observation and "classes:['ssrf']" in res.observation


def test_graphql_no_oob_nudge_when_field_has_no_url_arg():
    sm = {"_query_type": "Query", "Query": {"me": {"args": [], "return_type": "User", "description": ""}}}
    client = MockClient(default={"data": {"me": None}, "errors": [], "_status_code": 200})
    ctx = make_ctx(client, schema_map=sm)
    ctx.oob_sess = type("O", (), {"domain": "x.oast.fun"})()
    res = dispatch("graphql", ctx, {"query": "query { me { id } }"})
    assert "blind-SSRF" not in res.observation


def test_graphql_decodes_token_in_response():
    # a returned token is DECODED so the model can judge it (Braintree/Klarna = public client token)
    import base64
    braintree = base64.urlsafe_b64encode(json.dumps({
        "version": 2, "merchantId": "vbs2tkzg3r47gnjy", "environment": "production",
        "clientApiUrl": "https://api.braintreegateway.com/merchants/x/client_api",
    }).encode()).decode().rstrip("=")
    client = MockClient(default={"data": {"createBraintreeClientToken": braintree},
                                 "errors": [], "_status_code": 200})
    res = dispatch("graphql", make_ctx(client), {"query": "mutation { createBraintreeClientToken }"})
    assert "TOKEN in response decoded" in res.observation
    assert "merchantId" in res.observation and "braintreegateway" in res.observation


def test_graphql_batched_mutation_warns():
    client = MockClient(default={"data": {"a": None, "b": None}, "errors": [], "_status_code": 200})
    res = dispatch("graphql", make_ctx(client),
                   {"query": "mutation { deactivateAccount(id:1){__typename} addProductsToWishlist(id:1){__typename} }"})
    assert "BATCHED MUTATION" in res.observation


def test_graphql_single_mutation_no_batch_warn():
    client = MockClient(default={"data": {"x": {"ok": True}}, "errors": [], "_status_code": 200})
    res = dispatch("graphql", make_ctx(client), {"query": "mutation { deactivateAccount(id:1){__typename} }"})
    assert "BATCHED MUTATION" not in res.observation


def test_graphql_blocks_repeated_identical_failure():
    # the exact live waste: same failing login resent — after DUP_FAIL_CAP identical failures the
    # 3rd resend is hard-blocked (no request sent), telling the model to pivot/change identity
    client = MockClient(default={"data": {"loginUser": None},
                                 "errors": [{"message": "The email or password provided is incorrect."}],
                                 "_status_code": 200})
    ctx = make_ctx(client)
    q = {"query": 'mutation { loginUser(email:"a@b.io", password:"x") { token } }'}
    r1 = dispatch("graphql", ctx, q)
    r2 = dispatch("graphql", ctx, q)
    r3 = dispatch("graphql", ctx, q)
    assert not r1.blocked and not r2.blocked
    assert r3.blocked and "BLOCKED" in r3.observation and "identical failure" in r3.observation
    assert len(client.calls) == 2          # the 3rd never hit the network


def test_progress_clears_stale_dead_verdict():
    # a field the model marked dead that later returns data has its stale verdict cleared,
    # so a field that becomes productive stops reading as dead
    from gradientql.scanner.memory import blank_entry, effective_state
    client = MockClient(default={"data": {"me": {"email": "a@b.c"}}, "errors": [], "_status_code": 200})
    ctx = make_ctx(client)
    ctx.ledger["me"] = {**blank_entry("me", "anon", 0), "attempts": 2,
                        "verdict": "dead", "why": "looked empty"}
    res = dispatch("graphql", ctx, {"query": "query { me { email } }"})
    assert not res.blocked
    assert ctx.ledger["me"]["verdict"] is None
    assert effective_state(ctx.ledger["me"]) == "data"


def test_graphql_progress_resets_dup_fail_guard():
    # a field that returns DATA (progress) must NOT accrue the dup-fail counter -> never falsely blocked
    client = MockClient(default={"data": {"me": {"id": 1}}, "errors": [], "_status_code": 200})
    ctx = make_ctx(client)
    res = None
    for _ in range(5):
        res = dispatch("graphql", ctx, {"query": "query { me { id } }"})
    assert not res.blocked
    assert ctx.ledger["me"]["dup_fails"] == 0
    assert len(client.calls) == 5


def test_graphql_dup_guard_is_argument_aware_bola_sweep_not_blocked():
    # BOLA/IDOR enumeration: same root field, DIFFERENT ids, all returning null -> NOT blocked, every
    # probe hits the network (the dup signature folds a request fingerprint, so distinct ids != repeat)
    client = MockClient(default={"data": {"user": None}, "errors": [], "_status_code": 200})
    ctx = make_ctx(client)
    for i in range(6):
        res = dispatch("graphql", ctx, {"query": f'query {{ user(id:{1000 + i}) {{ email }} }}'})
        assert not res.blocked
    assert len(client.calls) == 6          # none short-circuited


def test_graphql_backstop_blocks_two_variant_oscillation():
    # a dead field cycled among only two argument variants (id:1, id:2, id:1, ...) all returning null
    # must still hit the backstop: each fingerprint differs from the immediately-previous one, so the
    # same-request resend guard never fires, but low argument diversity over many attempts should
    client = MockClient(default={"data": {"user": None}, "errors": [], "_status_code": 200})
    ctx = make_ctx(client)
    ids = [1, 2]
    blocked = None
    for i in range(12):
        res = dispatch("graphql", ctx, {"query": f'query {{ user(id:{ids[i % 2]}) {{ email }} }}'})
        if res.blocked:
            blocked = res
            break
    assert blocked is not None and "BLOCKED" in blocked.observation


def test_auth_test_clears_dup_fail_streak(monkeypatch):
    # an interleaved auth_test on a field resets its graphql dup-failure streak (distinct work)
    from gradientql.scanner.actions.authmatrix import handle_auth_test  # noqa: F401  (registers the action)
    client = MockClient(default={"data": {"resetPassword": None},
                                 "errors": [{"message": "Token is invalid"}], "_status_code": 200})
    ctx = make_ctx(client)
    q = {"query": 'mutation { resetPassword(token:"x") { __typename } }'}
    dispatch("graphql", ctx, q)
    dispatch("graphql", ctx, q)
    assert ctx.ledger["resetPassword"]["dup_fails"] == 2
    dispatch("auth_test", ctx, q)
    assert ctx.ledger["resetPassword"]["dup_fails"] == 0      # streak cleared
    res = dispatch("graphql", ctx, q)                          # so the very next graphql isn't blocked
    assert not res.blocked


# --- recon ----------------------------------------------------------------- #

def test_sweep_populates_ledger(sample_introspection_result):
    sm = parse_schema(sample_introspection_result)
    client = MockClient(default={"data": {"s0": [{"id": 1}]}, "errors": [], "_status_code": 200})
    ctx = make_ctx(client, schema_map=sm)
    res = dispatch("sweep", ctx, {})
    assert res.touched_target
    assert "pastes" in ctx.ledger       # a no-arg field got swept


def test_search_schema_records_keyword(sample_introspection_result):
    sm = parse_schema(sample_introspection_result)
    ctx = make_ctx(schema_map=sm)
    dispatch("search_schema", ctx, {"keyword": "paste"})
    assert "paste" in ctx.searched


def test_note_appends():
    ctx = make_ctx()
    dispatch("note", ctx, {"text": "hypothesis"})
    assert ctx.notes == ["hypothesis"]


# --- arsenal --------------------------------------------------------------- #

def test_forge_jwt_returns_and_stores_token():
    ctx = make_ctx()
    res = dispatch("forge_jwt", ctx, {"approach": "none", "claims": {"role": "admin"}})
    assert ctx.harvested.get("forged_jwt")
    assert "Bearer" in res.observation


def test_oob_url_unconfigured():
    res = dispatch("oob_url", make_ctx(oob_sess=None), {})
    assert "not configured" in res.observation


def test_dos_records_on_accept():
    # the handler aliases a REAL data-returning field from the ledger (not zero-cost __typename)
    client = MockClient(default={"data": {"a0": [{"id": 1}]}, "errors": [], "_status_code": 200})
    sm = {"_query_type": "Query", "Query": {"users": {"args": [], "return_type": "UserConn", "description": ""}}}
    ctx = make_ctx(client, schema_map=sm,
                   settings={"target": {}, "scanner": {"attacks": {"dos": True}}})
    from gradientql.scanner.memory import blank_entry
    ctx.ledger["users"] = {**blank_entry("users", "anon", 0), "auto": "DATA"}
    res = dispatch("dos", ctx, {"type": "aliases"})
    assert res.touched_target
    assert any("Denial of Service" in v["vuln_type"] for v in ctx.vulns)


def test_dos_blocked_by_config():
    # scanner.attacks.dos:false gates the technique before the handler runs — no request, no finding
    client = MockClient(default={"data": {"a0": [{"id": 1}]}, "errors": [], "_status_code": 200})
    sm = {"_query_type": "Query", "Query": {"users": {"args": [], "return_type": "UserConn", "description": ""}}}
    ctx = make_ctx(client, schema_map=sm, settings={"target": {}, "scanner": {"attacks": {"dos": False}}})
    res = dispatch("dos", ctx, {"type": "aliases"})
    assert res.blocked and "disabled by config" in res.observation
    assert client.calls == []
    assert ctx.vulns == []


def test_dos_blocked_by_safe_mode():
    # safe_mode gates the destructive techniques (dos/smuggle) even with attacks left at default
    client = MockClient(default={"data": {"a0": [{"id": 1}]}, "errors": [], "_status_code": 200})
    ctx = make_ctx(client, settings={"target": {}, "scanner": {"safe_mode": True}})
    res = dispatch("dos", ctx, {"type": "aliases"})
    assert res.blocked and client.calls == []


def test_dos_forwards_identity():
    # an authenticated overload must carry ctx.identity, not be sent anonymously
    client = MockClient(default={"data": {"a0": [{"id": 1}]}, "errors": [], "_status_code": 200})
    sm = {"_query_type": "Query", "Query": {"users": {"args": [], "return_type": "UserConn", "description": ""}}}
    ctx = make_ctx(client, schema_map=sm,
                   settings={"target": {}, "scanner": {"attacks": {"dos": True}}})
    ctx.identity["Authorization"] = "Bearer tok"
    dispatch("dos", ctx, {"type": "aliases"})
    assert client.calls and client.calls[-1][2].get("Authorization") == "Bearer tok"


def test_dos_fragment_sends_real_generator_not_alias_dup():
    # 'fragment' must produce a real circular-fragment query (was: silently fell through to alias-dup)
    from gradientql.scanner.arsenal_tools import tool_dos

    class _C:
        def execute(self, query, variables=None, extra_headers=None):
            self.q = query
            return {"data": {"__typename": "Query"}, "errors": [], "_status_code": 200}

    q, resp, vt, reason = tool_dos(_C(), {"_query_type": "Query", "Query": {}}, "fragment")
    assert "fragment" in q.lower() and "..." in q     # a real fragment-spread query, not a0:__typename×120


def test_dos_directive_overload_detected_only_with_slowdown():
    # a stacked-directive flood is a DoS only if the server SLOWED (the flood is on zero-cost
    # __typename) — and it must not be mis-counted as field-duplication
    from gradientql.scanner.senses import detect_dos_surface
    q = "query { __typename " + " ".join("@skip(if: false)" for _ in range(100)) + " }"
    slow = detect_dos_surface(q, {"data": {"__typename": "Query"}, "errors": [], "_status_code": 200,
                                  "_response_time_ms": 3000})
    assert slow[0] and "directive" in slow[1].lower()
    fast = detect_dos_surface(q, {"data": {"__typename": "Query"}, "errors": [], "_status_code": 200})
    assert fast[0] is None         # accepted-but-fast (cheap directives) is not a DoS


def test_dos_pagination_builds_huge_page_and_detects_when_honored():
    # confirmed only when the server HONORS the huge page (returns a big collection or slows) —
    # a silent cap (few rows) is a defense and must NOT confirm
    from gradientql.scanner.arsenal_tools import tool_dos
    sm = {"_query_type": "Query",
          "Query": {"pastes": {"args": [{"name": "limit", "type": "Int"}], "return_type": "[Paste]", "description": ""}},
          "Paste": {"id": {"args": [], "return_type": "ID", "description": ""}}}
    big = [{"id": str(i)} for i in range(1500)]   # server honored the huge page

    class _Honored:
        def execute(self, query, variables=None, extra_headers=None):
            return {"data": {"pastes": big}, "errors": [], "_status_code": 200}

    q, resp, vt, reason = tool_dos(_Honored(), sm, "pagination")
    assert "1000000" in q and "limit" in q
    assert vt and "pagination" in reason.lower()

    class _Capped:
        def execute(self, query, variables=None, extra_headers=None):
            return {"data": {"pastes": [{"id": "1"}, {"id": "2"}]}, "errors": [], "_status_code": 200}

    _q, _r, vt2, _reason = tool_dos(_Capped(), sm, "pagination")
    assert vt2 is None              # silently capped -> defended, not a finding


def test_csrf_confirms_get_executable_mutation(monkeypatch):
    class _Resp:
        def __init__(self, status, text="", headers=None):
            self.status_code = status; self.text = text; self.headers = headers or {}

        def json(self):
            import json as _j
            return _j.loads(self.text)
    import requests
    monkeypatch.setattr(requests, "get",
                        lambda *a, **k: _Resp(200, '{"data":{"__typename":"Mutations"}}'))
    monkeypatch.setattr(requests, "post", lambda *a, **k: _Resp(200, "{}", {}))
    ctx = make_ctx(schema_map={"_mutation_type": "Mutations", "Mutations": {"createPaste": {}}})
    res = dispatch("csrf", ctx, {})
    assert "GET-MUTATION CONFIRMED" in res.observation
    assert any("Cross-Site Request Forgery" in v["vuln_type"] for v in ctx.vulns)


def test_subscription_root_is_surfaced():
    from gradientql.scanner.schema import parse_schema
    intro = {"data": {"__schema": {
        "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
        "subscriptionType": {"name": "Subscription"},
        "types": [{"kind": "OBJECT", "name": "Subscription", "description": None,
                   "fields": [{"name": "pasteCreated", "args": [],
                               "type": {"kind": "OBJECT", "name": "Paste"}, "description": None}]}]}}}
    sm = parse_schema(intro)
    assert sm["_subscription_type"] == "Subscription"


def test_misconfig_detects_apq(monkeypatch):
    import gradientql.utils.misconfig as mc

    class _Resp:
        def __init__(self, status, text):
            self.status_code = status; self.text = text

        def json(self):
            import json as _j
            return _j.loads(self.text)

    class _Sess:
        def get(self, *a, **k):
            return _Resp(404, "nope")

        def post(self, url, json=None, **k):
            if isinstance(json, dict) and "extensions" in json:
                return _Resp(200, '{"errors":[{"message":"PersistedQueryNotFound"}]}')
            return _Resp(200, '{"data":{"__typename":"Query"}}')

    findings = mc.run_misconfig_sweep("http://t/graphql", introspection_succeeded=False, session=_Sess())
    assert any("apq" in f["vuln_type"].lower() for f in findings)


def test_visit_opens_activation_link_in_session(monkeypatch):
    # opening a link-based activation: GET in-session, detect "activated", harvest a token, report cookies
    class _Resp:
        status_code = 200
        url = "https://t/account/activated?welcome=1"
        text = "Your account is now activated. Welcome!"

    class _Sess:
        def __init__(self): self.cookies = {"SESSION": "abc"}
        def get(self, url, **k): return _Resp()

    client = MockClient()
    client.session = _Sess()
    ctx = make_ctx(client)
    res = dispatch("visit", ctx, {"url": "https://t/customer/account/confirm?key=ZZ&id=5"})
    assert res.touched_target
    assert "ACTIVATED" in res.observation and "SESSION" in res.observation


def test_visit_requires_http_url():
    res = dispatch("visit", make_ctx(), {"url": "ftp://nope"})
    assert "needs {url}" in res.observation


def test_temp_mail_creates_inbox(monkeypatch):
    import gradientql.utils.tempmail as tm

    class _Fake:
        address = "throwaway@mail.tm"
        def create(self):
            return self.address
        def poll(self):
            return []

    monkeypatch.setattr(tm, "TempMailClient", _Fake)
    ctx = make_ctx()
    res = dispatch("temp_mail", ctx, {"op": "new"})
    assert "throwaway@mail.tm" in res.observation
    assert ctx.tempmail is not None


def test_csrf_honest(monkeypatch):
    class _Resp:
        def __init__(self, status, text="", headers=None):
            self.status_code = status; self.text = text; self.headers = headers or {}
    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **k: _Resp(405))
    monkeypatch.setattr(requests, "post", lambda *a, **k: _Resp(200, "{}", {}))
    res = dispatch("csrf", make_ctx(schema_map={"_mutation_type": "Mutation", "Mutation": {}}), {})
    assert "GET-exec" in res.observation


def test_disabled_actions_defaults_and_safe_mode():
    # dos defaults OFF with no config (matches the shipped settings.yaml); safe_mode offs the
    # destructive trio regardless
    from gradientql.scanner.actions import disabled_actions
    assert disabled_actions({}) == {"dos"}
    assert disabled_actions({"scanner": {"attacks": {"dos": True}}}) == set()
    assert {"dos", "smuggle", "batch_brute"} <= disabled_actions(
        {"scanner": {"safe_mode": True, "attacks": {"dos": True}}})


def test_forge_jwt_weak_secret_tries_dictionary(monkeypatch):
    # approach weak_secret with no explicit secret must work through the common-secret list in
    # ONE action (was: only "secret" was ever tried) and stop at the first acceptance
    from gradientql.scanner.actions import dispatch
    from gradientql.utils import jwt_attacks
    monkeypatch.setattr(jwt_attacks.time, "time", lambda: 1700000000)  # deterministic iat/exp
    monkeypatch.setattr(jwt_attacks, "WEAK_SECRETS", ("zzz", "opensesame", "third"))
    accepted = jwt_attacks.forge_hs256("opensesame", jwt_attacks._escalated({}))

    sm = {"_query_type": "Query", "_mutation_type": "Mutation",
          "Query": {"me": {"args": [{"name": "token", "type": "String"}], "return_type": "User",
                           "description": ""}},
          "User": {"id": {"args": [], "return_type": "Int", "description": ""}},
          "Mutation": {}}

    class _JWTMock:
        session = None

        def execute(self, query, variables=None, extra_headers=None):
            if accepted in query:
                return {"data": {"me": {"id": 1}}, "errors": [], "_status_code": 200}
            return {"data": {"me": None}, "errors": [{"message": "invalid token"}], "_status_code": 200}

    ctx = make_ctx(_JWTMock(), schema_map=sm)
    res = dispatch("forge_jwt", ctx, {"approach": "weak_secret"})
    assert "weak-secret WIN" in res.observation and "opensesame" in res.observation
    assert any("hs256:opensesame" in v["vuln_type"] for v in ctx.vulns)
    assert len(ctx.harvested["forged_jwt"]) == 2  # stopped at the first acceptance, not all 3


def test_forge_jwt_weak_secret_dictionary_all_rejected(monkeypatch):
    from gradientql.scanner.actions import dispatch
    from gradientql.utils import jwt_attacks
    monkeypatch.setattr(jwt_attacks.time, "time", lambda: 1700000000)
    monkeypatch.setattr(jwt_attacks, "WEAK_SECRETS", ("aaa", "bbb"))

    sm = {"_query_type": "Query", "_mutation_type": "Mutation",
          "Query": {"me": {"args": [{"name": "token", "type": "String"}], "return_type": "User",
                           "description": ""}},
          "User": {"id": {"args": [], "return_type": "Int", "description": ""}},
          "Mutation": {}}

    class _RejectAll:
        session = None

        def execute(self, query, variables=None, extra_headers=None):
            return {"data": {"me": None}, "errors": [{"message": "invalid token"}], "_status_code": 200}

    ctx = make_ctx(_RejectAll(), schema_map=sm)
    res = dispatch("forge_jwt", ctx, {"approach": "weak_secret"})
    assert "none of the 2 common secrets" in res.observation
    assert ctx.vulns == []
    assert len(ctx.harvested["forged_jwt"]) == 2
