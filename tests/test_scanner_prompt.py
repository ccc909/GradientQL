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
    # the run log no longer drops older steps outright: they are compacted (thoughts stripped,
    # repeats merged) while the recent window stays verbatim
    sm = parse_schema(sample_introspection_result)
    decisions = [f"[{i}] graphql f{i} → null/empty  «trying field {i}»" for i in range(80)]
    p = prompt.build_prompt(_ctx(sm, decisions=decisions))
    assert "[0] graphql f0" in p           # oldest compacted, not dropped
    assert "«trying field 0»" not in p     # ... but its thought is stripped
    assert "— recent steps, verbatim —" in p
    assert "«trying field 79»" in p        # recent window keeps thoughts
    assert "[79] graphql f79" in p


def test_build_prompt_run_log_compaction_drops_oldest_with_marker(sample_introspection_result):
    # when even the compacted older segment overflows its cap, the earliest lines drop WITH a
    # marker (nothing is silently truncated) and the recent window stays complete
    sm = parse_schema(sample_introspection_result)
    decisions = [f"[{i}] graphql f{i} → null/empty  «trying field {i}»" for i in range(200)]
    p = prompt.build_prompt(_ctx(sm, decisions=decisions))
    assert "[199] graphql f199" in p     # newest present
    assert "[0] graphql f0" not in p     # earliest dropped after compaction...
    assert "earliest compacted line(s) dropped" in p  # ... explicitly, not silently
    assert "[150] graphql f150" in p     # recent compacted lines survive


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


def test_prompt_drops_config_disabled_actions():
    # with dos disabled, its bullet must not appear (the model can't use the tool); the
    # DISABLED note must name it instead so the model doesn't waste a step discovering it
    sm = {"_query_type": "Query", "Query": {"me": {"args": [], "return_type": "User", "description": ""}},
          "User": {"id": {"args": [], "return_type": "Int", "description": ""}}}
    p = prompt.build_prompt(_ctx(sm, disabled_tools=["dos"]))
    assert "\n- dos:" not in p
    assert "DISABLED by the operator's config" in p and "dos" in p.split("DISABLED", 1)[1]
    p_all = prompt.build_prompt(_ctx(sm, disabled_tools=[]))
    assert "\n- dos:" in p_all


def test_render_decisions_compacts_old_steps():
    from gradientql.scanner.prompt import _render_decisions
    lines = ["[0] sweep → 4 DATA  «t0»", "[1] sweep → 4 DATA  «t1»",
             "[2] sweep → 4 DATA  «t2»"]
    lines += [f"[{i}] graphql me → DATA x1  «thought{i}»" for i in range(3, 60)]
    out = _render_decisions(lines)
    assert "— recent steps, verbatim —" in out
    assert "«thought59»" in out          # recent window keeps thoughts
    assert "«thought10»" not in out      # older steps lose theirs
    assert "sweep → 4 DATA (x3)" in out  # consecutive repeats merge with a count
    assert "graphql me → DATA x1" in out  # knowledge is compacted, not dropped


def test_render_decisions_short_passthrough():
    from gradientql.scanner.prompt import _render_decisions
    assert _render_decisions(["[0] done → STOP  «x»"]) == "[0] done → STOP  «x»"
    assert _render_decisions([]) == "(nothing yet)"


def test_prompt_teaches_results_not_intent_for_learned():
    sm = {"_query_type": "Query", "Query": {"me": {"args": [], "return_type": "User", "description": ""}},
          "User": {"id": {"args": [], "return_type": "Int", "description": ""}}}
    p = " ".join(prompt.build_prompt(_ctx(sm)).split())  # normalize line wraps
    assert "never a plan or intention" in p
    assert "batch_brute` with a dictionary" in p  # no single-guess logins
