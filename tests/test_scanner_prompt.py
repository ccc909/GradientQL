"""Tests for src/scanner/prompt.py — prompt assembly + action parsing."""

from __future__ import annotations

from gradientql.scanner import prompt
from gradientql.scanner.schema import parse_schema


def test_extract_action_tolerant_of_prose():
    txt = 'Sure, here is my move:\n{"thought":"x","action":"sweep","args":{}}\nThanks!'
    act = prompt.extract_action(txt)
    assert act["action"] == "sweep"


def test_extract_action_none_on_garbage():
    assert prompt.extract_action("no json here") is None
    assert prompt.extract_action("{not valid}") is None


def test_extract_action_recovers_multiline_query():
    # a pretty-printed multi-line GraphQL query carries literal newlines inside the string arg;
    # the tolerant decoder must recover the action instead of dropping the whole turn
    txt = '{"thought":"probe","action":"graphql","args":{"query":"query {\n  users { id }\n}"}}'
    act = prompt.extract_action(txt)
    assert act is not None
    assert act["action"] == "graphql"
    assert "users { id }" in act["args"]["query"]


def _ctx(sm, **over):
    base = {
        "target_url": "http://t/graphql", "schema_map": sm, "schema_overview": "",
        "identity": {}, "remaining": 10, "harvested": {}, "covered": set(),
        "credentials": [], "facts": [], "searched": [], "findings": 0, "ledger": {},
        "notes": [], "history": [], "decisions": [], "fixation": "",
    }
    base.update(over)
    return base


def test_build_prompt_contains_methodology(sample_introspection_result):
    sm = parse_schema(sample_introspection_result)
    p = prompt.build_prompt(_ctx(sm))
    assert "BOLA/IDOR" in p          # methodology present
    assert "sweep" in p              # action menu present


def test_build_prompt_surfaces_operator_steering(sample_introspection_result):
    sm = parse_schema(sample_introspection_result)
    assert "OPERATOR STEERING" not in prompt.build_prompt(_ctx(sm))
    p = prompt.build_prompt(_ctx(sm, steering=["search for DoS now", "you missed importPaste"]))
    assert "OPERATOR STEERING" in p
    assert "search for DoS now" in p and "you missed importPaste" in p
    assert "__typename" in p         # reachability guidance present
    # injection playbook + fuzz action are surfaced
    assert "fuzz" in p
    assert "INJECTION" in p
    assert "#{7*7}" in p             # Ruby SSTI engine called out


def test_build_prompt_renders_full_run_log(sample_introspection_result):
    # within the generous tail window every line appears, oldest to newest, with its own reasoning
    sm = parse_schema(sample_introspection_result)
    decisions = [f"[{i}] graphql f{i} → null/empty  «trying field {i}»" for i in range(40)]
    p = prompt.build_prompt(_ctx(sm, decisions=decisions))
    assert "YOUR RUN LOG" in p
    assert "[0] graphql f0" in p      # under the cap -> oldest retained
    assert "[39] graphql f39" in p    # newest present
    assert "trying field 0" in p      # the model's own reasoning is fed back


def test_build_prompt_windows_long_run_log(sample_introspection_result):
    # the run log is the one section that grew with budget; it is now tail-windowed so a very long
    # run drops only the oldest lines while keeping the recent reasoning chain
    sm = parse_schema(sample_introspection_result)
    decisions = [f"[{i}] graphql f{i} → null/empty  «trying field {i}»" for i in range(80)]
    p = prompt.build_prompt(_ctx(sm, decisions=decisions))
    assert "[0] graphql f0" not in p    # oldest beyond the window dropped
    assert "[20] graphql f20" in p      # last 60 retained
    assert "[79] graphql f79" in p      # newest present


def test_build_prompt_run_log_window_scales_with_budget(sample_introspection_result):
    # on a long-budget profile (DVGA budget=250) the window grows past the default 60 up to the
    # 120-line cap, so far more of the run log reaches the model than the old flat 60
    sm = parse_schema(sample_introspection_result)
    decisions = [f"[{i}] graphql f{i} → null/empty  «trying field {i}»" for i in range(200)]
    p = prompt.build_prompt(_ctx(sm, decisions=decisions, budget=250))
    assert "[80] graphql f80" in p       # inside the 120-line budget-scaled window
    assert "[199] graphql f199" in p     # newest present
    assert "[70] graphql f70" not in p   # window is capped at 120, so oldest still drop


def test_build_prompt_lists_recorded_findings_with_ids(sample_introspection_result):
    # the model must SEE its findings (with ids) to retract the right one — esp. auto-recorded FPs
    sm = parse_schema(sample_introspection_result)
    vulns = [{"id": "f1", "vuln_type": "SSTI", "target_node": "paxList"},
             {"id": "f2", "vuln_type": "CORS Misconfiguration", "target_node": "endpoint"}]
    p = prompt.build_prompt(_ctx(sm, vulns=vulns))
    assert "FINDINGS YOU'VE RECORDED" in p
    assert "[f1] SSTI on paxList" in p and "[f2] CORS Misconfiguration on endpoint" in p
    assert 'retract' in p and '"id"' in p              # the retract-by-id instruction is present


def test_build_prompt_tolerates_missing_decisions(sample_introspection_result):
    # back-compat: a ctx without the decisions key must not KeyError
    sm = parse_schema(sample_introspection_result)
    ctx = _ctx(sm)
    del ctx["decisions"]
    p = prompt.build_prompt(ctx)
    assert "nothing yet" in p
