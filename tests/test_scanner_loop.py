"""Tests for src/scanner/loop.py — the control loop + backstops, driven by a scripted LLM."""

from __future__ import annotations

import pytest

from gradientql.scanner import loop
from tests.conftest import MockClient, scripted_llm


@pytest.fixture()
def patch_loop(monkeypatch):
    """Patch the loop's external deps; return a runner(actions, client, **kw) -> result."""
    monkeypatch.setattr(loop.time, "sleep", lambda *a, **k: None)
    monkeypatch.setattr(loop, "get_attacker_llm", lambda settings: object())
    import gradientql.utils.oob as oobmod
    monkeypatch.setattr(oobmod, "is_enabled", lambda settings: False)

    def _run(actions, client, settings=None, budget=12):
        monkeypatch.setattr(loop, "get_client", lambda url, csrf_config=None: client)
        monkeypatch.setattr(loop, "invoke_with_circuit_breaker", scripted_llm(actions))
        settings = settings or {"target": {}, "scanner": {}}
        return loop.run(settings, {"_query_type": "Query", "Query": {"me": {"args": [], "return_type": "User", "description": ""}},
                                   "User": {"id": {"args": [], "return_type": "Int", "description": ""}}},
                        "http://t/graphql", budget)

    return _run


def test_should_stop_halts_before_any_action(monkeypatch):
    monkeypatch.setattr(loop.time, "sleep", lambda *a, **k: None)
    monkeypatch.setattr(loop, "get_attacker_llm", lambda settings: object())
    import gradientql.utils.oob as oobmod
    monkeypatch.setattr(oobmod, "is_enabled", lambda settings: False)
    client = MockClient(default={"data": {"me": {"id": 1}}, "errors": [], "_status_code": 200})
    monkeypatch.setattr(loop, "get_client", lambda url, csrf_config=None: client)
    calls = {"n": 0}
    monkeypatch.setattr(loop, "invoke_with_circuit_breaker",
                        lambda *a, **k: calls.__setitem__("n", calls["n"] + 1))
    schema = {"_query_type": "Query",
              "Query": {"me": {"args": [], "return_type": "User", "description": ""}},
              "User": {"id": {"args": [], "return_type": "Int", "description": ""}}}
    res = loop.run({"target": {}, "scanner": {}}, schema, "http://t/graphql", 10,
                   should_stop=lambda: True)
    assert res["steps"] == 1            # broke on the first iteration
    assert calls["n"] == 0             # the model was never invoked
    assert res["vulnerabilities"] == []


def test_accumulate_tokens():
    from types import SimpleNamespace

    from gradientql.scanner.loop import _accumulate_tokens
    acc = {"input": 0, "output": 0, "reasoning": 0, "total": 0, "cost": 0.0, "calls": 0}
    msg = SimpleNamespace(
        usage_metadata={"input_tokens": 30, "output_tokens": 291, "total_tokens": 321,
                        "output_token_details": {"reasoning": 274}},
        response_metadata={"cost": 0.0021})
    _accumulate_tokens(acc, msg)
    assert acc["input"] == 30 and acc["output"] == 291 and acc["total"] == 321
    assert acc["reasoning"] == 274 and acc["calls"] == 1
    assert abs(acc["cost"] - 0.0021) < 1e-9
    _accumulate_tokens(acc, SimpleNamespace(usage_metadata=None, response_metadata=None))  # tolerant
    assert acc["input"] == 30 and acc["total"] == 321      # token counts unchanged on empty usage


def test_steer_message_reaches_the_prompt(monkeypatch):
    monkeypatch.setattr(loop.time, "sleep", lambda *a, **k: None)
    monkeypatch.setattr(loop, "get_attacker_llm", lambda settings: object())
    import gradientql.utils.oob as oobmod
    monkeypatch.setattr(oobmod, "is_enabled", lambda settings: False)
    client = MockClient(default={"data": {"me": {"id": 1}}, "errors": [], "_status_code": 200})
    monkeypatch.setattr(loop, "get_client", lambda url, csrf_config=None: client)
    prompts = []
    base = scripted_llm([{"action": "sweep", "args": {}}, {"action": "done", "args": {}}])

    def capture(llm, prompt_text, **k):
        prompts.append(prompt_text)
        return base(llm, prompt_text, **k)

    monkeypatch.setattr(loop, "invoke_with_circuit_breaker", capture)
    calls = {"n": 0}

    def steer():
        calls["n"] += 1
        return ["search for DoS now"] if calls["n"] == 1 else []

    schema = {"_query_type": "Query",
              "Query": {"me": {"args": [], "return_type": "User", "description": ""}},
              "User": {"id": {"args": [], "return_type": "Int", "description": ""}}}
    loop.run({"target": {}, "scanner": {}}, schema, "http://t/graphql", 5, steer=steer)
    assert any("OPERATOR STEERING" in p and "search for DoS now" in p for p in prompts)


def test_recon_report_done(patch_loop):
    client = MockClient(default={"data": {"me": {"id": 1}}, "errors": [], "_status_code": 200})
    actions = [{"action": "sweep", "args": {}},
               {"action": "report_finding", "args": {"vuln_type": "BOLA", "target": "me", "evidence": "x"}},
               {"action": "done", "args": {"reason": "covered"}}]
    res = patch_loop(actions, client, budget=4)
    assert any(v["vuln_type"] == "BOLA" for v in res["vulnerabilities"])
    assert res["steps"] == 3


def test_done_deferred_until_deferrals_exhausted(patch_loop):
    # _response_time_ms makes the __typename DoS probe confirm (zero-cost aliases now need latency)
    client = MockClient(default={"data": {"a0": "Query"}, "errors": [], "_status_code": 200,
                                 "_response_time_ms": 3000})
    # done at step0 is deferred (ample budget, endpoint tools unused), dos runs, done deferred
    # again, then honoured on the 2nd deferral cap.
    actions = [{"action": "done", "args": {"reason": "x"}},
               {"action": "dos", "args": {"type": "aliases"}},
               {"action": "done", "args": {"reason": "x"}}]
    res = patch_loop(actions, client, budget=20)
    assert res["steps"] == 4               # done deferred twice, honoured on the 3rd
    assert any("Denial of Service" in v["vuln_type"] for v in res["vulnerabilities"])


def test_abort_on_consecutive_no_action(patch_loop):
    res = patch_loop(["not json"] * 6, MockClient(), budget=20)
    assert res["steps"] == 5               # aborts after 5 unusable turns
    assert res["vulnerabilities"] == []


def test_survives_bad_then_good_output(patch_loop):
    # garbage then a valid done — consec_noaction resets, the run ends cleanly
    actions = ["garbage", "garbage", {"action": "done", "args": {"reason": "ok"}}]
    res = patch_loop(actions, MockClient(), budget=4)
    assert res["steps"] == 3


def test_repeated_identical_failure_blocks_fast(patch_loop):
    # a field that returns the SAME null/failure every time is confirmed-dead after DUP_FAIL_CAP(2)
    # identical results -> only 2 requests sent, then hard-blocked (no more wasted sends)
    client = MockClient(default={"data": {"me": None}, "errors": [], "_status_code": 200})
    patch_loop([{"action": "graphql", "args": {"query": "query { me { id } }"}}], client, budget=10)
    assert len(client.calls) == 2


def test_field_retry_cap_blocks_at_8_when_returning_data(patch_loop):
    # a field that keeps returning DATA isn't "dead" (dup-fail never trips) — the absolute attempts
    # backstop (8) still bounds a model that re-queries the same data-returning field forever
    client = MockClient(default={"data": {"me": {"id": 1}}, "errors": [], "_status_code": 200})
    patch_loop([{"action": "graphql", "args": {"query": "query { me { id } }"}}], client, budget=12)
    assert len(client.calls) == 8


def test_identity_chain_applies_token(patch_loop):
    client = MockClient(default={"data": {"me": {"id": 1}}, "errors": [], "_status_code": 200})
    actions = [{"action": "set_identity", "args": {"headers": {"Authorization": "Bearer captured123456"}}},
               {"action": "graphql", "args": {"query": "query { me { id } }"}},
               {"action": "done", "args": {"reason": "done"}}]
    patch_loop(actions, client, budget=4)
    # the graphql call after set_identity must carry the adopted auth header
    graphql_calls = [c for c in client.calls if "me" in c[0]]
    assert graphql_calls
    assert graphql_calls[-1][2].get("Authorization") == "Bearer captured123456"


def test_recon_spiral_blocks_and_aborts(patch_loop):
    # the recon backstop is now REACHABLE: an all-search run blocks searches after the no-probe cap
    # and ABORTS (was: the old unreachable guard let it burn the whole budget)
    res = patch_loop([{"action": "search_schema", "args": {"keyword": "x"}}], MockClient(), budget=30)
    assert res["steps"] < 30


def test_note_spiral_also_aborts(patch_loop):
    # `note` is a non-probe action too — an all-note run can't dodge the backstop
    res = patch_loop([{"action": "note", "args": {"text": "thinking"}}], MockClient(), budget=30)
    assert res["steps"] < 30


def test_oob_auto_reconcile_records_blind_hit(monkeypatch):
    import gradientql.utils.oob as oobmod

    class _Oob:
        domain = "oast.example"
        client = object()

        def reconcile(self):
            return [{"interaction": {"protocol": "dns", "remote-address": "9.9.9.9"}}]

    monkeypatch.setattr(oobmod, "is_enabled", lambda s: True)
    monkeypatch.setattr(oobmod, "get_session", lambda s: _Oob())
    monkeypatch.setattr(loop.time, "sleep", lambda *a, **k: None)
    monkeypatch.setattr(loop, "get_attacker_llm", lambda s: object())
    client = MockClient(default={"data": {"x": "ok"}, "errors": [], "_status_code": 200})
    monkeypatch.setattr(loop, "get_client", lambda url, csrf_config=None: client)

    actions = [
        {"action": "graphql", "args": {"query": 'query { x(u: "http://oast.example/p") }'}},  # injects domain
        {"action": "note", "args": {"text": "wait"}},
        {"action": "note", "args": {"text": "wait"}},
        {"action": "note", "args": {"text": "wait"}},   # >= _OOB_CHECK_DELAY steps later -> auto-reconcile
        {"action": "done", "args": {"reason": "x"}},
    ]
    monkeypatch.setattr(loop, "invoke_with_circuit_breaker", scripted_llm(actions))
    sm = {"_query_type": "Query", "_mutation_type": "Mutation",
          "Query": {"x": {"args": [{"name": "u", "type": "String"}], "return_type": "String", "description": ""}}}
    res = loop.run({"target": {}, "scanner": {}}, sm, "http://t/graphql", 10)
    assert any("OOB" in v["vuln_type"] for v in res["vulnerabilities"])


def test_done_gate_defers_on_critical_high_value(monkeypatch):
    # a schema exposing a critical untested high-value field (generateCustomerTokenAsAdmin) must
    # add extra `done` deferrals on top of the endpoint-tool ones
    import gradientql.utils.oob as oobmod
    monkeypatch.setattr(oobmod, "is_enabled", lambda s: False)
    monkeypatch.setattr(loop.time, "sleep", lambda *a, **k: None)
    monkeypatch.setattr(loop, "get_attacker_llm", lambda s: object())
    client = MockClient(default={"data": {"x": 1}, "errors": [], "_status_code": 200})
    monkeypatch.setattr(loop, "get_client", lambda url, csrf_config=None: client)

    done_only = [{"action": "done", "args": {"reason": "x"}}]
    sm_crit = {"_query_type": "Query", "_mutation_type": "Mutation", "Query": {},
               "Mutation": {"generateCustomerTokenAsAdmin": {"args": [], "return_type": "T", "description": ""}}}
    monkeypatch.setattr(loop, "invoke_with_circuit_breaker", scripted_llm(done_only))
    crit = loop.run({"target": {}, "scanner": {}}, sm_crit, "http://t/graphql", 20)

    sm_none = {"_query_type": "Query", "_mutation_type": "Mutation",
               "Query": {"x": {"args": [], "return_type": "String", "description": ""}}, "Mutation": {}}
    monkeypatch.setattr(loop, "invoke_with_circuit_breaker", scripted_llm(done_only))
    none = loop.run({"target": {}, "scanner": {}}, sm_none, "http://t/graphql", 20)

    assert crit["steps"] > none["steps"]   # the high-value gate held `done` longer


def test_loop_records_decision_log_with_reasoning(patch_loop, monkeypatch):
    # every dispatched action lands in the unbounded run log WITH the model's own thought, so the
    # next prompt carries the reasoning chain (the fix for re-deriving / repeating dead ends)
    captured = {}
    real = loop.build_prompt
    monkeypatch.setattr(loop, "build_prompt",
                        lambda c: (captured.update(decisions=list(c.get("decisions") or [])), real(c))[1])
    client = MockClient(default={"data": {"me": {"id": 1}}, "errors": [], "_status_code": 200})
    actions = [{"action": "graphql", "args": {"query": "query { me { id } }"}, "thought": "probing me"},
               {"action": "note", "args": {"text": "hmm"}, "thought": "thinking"},
               {"action": "done", "args": {"reason": "ok"}}]
    patch_loop(actions, client, budget=5)
    log = captured["decisions"]
    assert any("graphql me" in d and "probing me" in d for d in log)   # action + target + reasoning
    assert any("note" in d and "thinking" in d for d in log)


def test_aborts_on_consecutive_blocked_actions(patch_loop):
    # a model that keeps re-issuing a dup-blocked graphql can't burn the whole budget — abort kicks in
    client = MockClient(default={"data": {"me": None},
                                 "errors": [{"message": "nope"}], "_status_code": 200})
    res = patch_loop([{"action": "graphql", "args": {"query": "query { me { id } }"}}], client, budget=40)
    assert res["steps"] < 40               # _NOACTION_ABORT consecutive blocks ends the run early
    assert len(client.calls) == 2          # only the first two sends reached the network


def test_retract_side_channel_drops_finding_mid_run(patch_loop):
    # the model records a finding, then DISPROVES it and attaches `retract` to a later action —
    # the finding must be gone from the final report (retraction works on any step, not just at the end)
    client = MockClient(default={"data": {"x": 1}, "errors": [], "_status_code": 200})
    actions = [
        {"action": "report_finding", "args": {"vuln_type": "SSTI", "target": "echo", "evidence": "9801 seen"}},
        {"action": "note", "args": {"text": "coincidence"},
         "retract": {"vuln_type": "SSTI", "target": "echo", "why": "1337*1337 did not evaluate"}},
        {"action": "done", "args": {"reason": "done"}},
    ]
    res = patch_loop(actions, client, budget=8)
    assert not any("SSTI" in v["vuln_type"] for v in res["vulnerabilities"])


def test_llm_none_returns_back_off_and_bounded_abort(monkeypatch):
    # a transient provider blip (invoke returns None) must NOT be treated as a model no-action:
    # it uses its own counter with backoff and a higher bounded abort, so a healthy scan isn't
    # killed by the 5-strike no-action limit.
    import gradientql.core.llm as llmmod
    import gradientql.utils.oob as oobmod
    llmmod.reset_circuit()
    sleeps: list = []
    monkeypatch.setattr(loop.time, "sleep", lambda s=0, *a, **k: sleeps.append(s))
    monkeypatch.setattr(loop, "get_attacker_llm", lambda settings: object())
    monkeypatch.setattr(oobmod, "is_enabled", lambda settings: False)
    monkeypatch.setattr(loop, "get_client", lambda url, csrf_config=None: MockClient())
    monkeypatch.setattr(loop, "invoke_with_circuit_breaker", lambda llm, prompt, **k: None)
    sm = {"_query_type": "Query", "Query": {"me": {"args": [], "return_type": "Int", "description": ""}}}
    res = loop.run({"target": {}, "scanner": {}}, sm, "http://t/graphql", 30)
    assert res["steps"] == loop._LLM_ERROR_ABORT
    assert res["steps"] > loop._NOACTION_ABORT
    assert len([s for s in sleeps if s > 0]) >= loop._LLM_ERROR_ABORT - 1


def test_llm_circuit_open_waits_then_aborts(monkeypatch):
    # while the circuit is open the loop waits for provider recovery instead of burning iterations,
    # and gives up only after a bounded number of waits so a truly dead provider still terminates.
    import gradientql.utils.oob as oobmod
    sleeps: list = []
    monkeypatch.setattr(loop.time, "sleep", lambda s=0, *a, **k: sleeps.append(s))
    monkeypatch.setattr(loop, "get_attacker_llm", lambda settings: object())
    monkeypatch.setattr(oobmod, "is_enabled", lambda settings: False)
    monkeypatch.setattr(loop, "get_client", lambda url, csrf_config=None: MockClient())
    monkeypatch.setattr(loop, "invoke_with_circuit_breaker", lambda llm, prompt, **k: None)
    monkeypatch.setattr(loop, "get_circuit_breaker_status", lambda: {"is_open": True})
    sm = {"_query_type": "Query", "Query": {"me": {"args": [], "return_type": "Int", "description": ""}}}
    res = loop.run({"target": {}, "scanner": {}}, sm, "http://t/graphql", 30)
    assert res["steps"] == loop._MAX_CIRCUIT_WAITS
    assert any(s == loop._CIRCUIT_TIMEOUT for s in sleeps)


def test_degraded_target_does_not_quit_early(patch_loop):
    # every request 500s; 'done' on a degraded target is deferred until backoffs accumulate
    client = MockClient(default={"data": None, "errors": [{"message": "boom"}], "_status_code": 500})
    actions = [{"action": "graphql", "args": {"query": "query { me { id } }"}},
               {"action": "graphql", "args": {"query": "query { me { id } }"}},
               {"action": "done", "args": {"reason": "give up"}}]
    res = patch_loop(actions, client, budget=10)
    assert res["steps"] > 3                # it kept going past the premature 'done'
