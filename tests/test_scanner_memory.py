"""Tests for src/scanner/memory.py — the ledger/state model + self-report."""

from __future__ import annotations

from gradientql.scanner import memory


def test_primary_root_field_plain_and_alias():
    assert memory.primary_root_field("query { me { id } }") == "me"
    assert memory.primary_root_field("{ alias: realField { x } }") == "realField"


def test_primary_root_field_named_op_with_vars():
    # the variable-declaration block must be skipped, not collapsed to None
    assert memory.primary_root_field("mutation Login($email: String!) { generateToken { token } }") \
        == "generateToken"


def test_effective_state_verdict_wins_over_ambiguous_auto_but_not_data():
    # a verdict overrides an ambiguous auto-read...
    e = memory.blank_entry("f", "anon", 0)
    e["attempts"] = 1
    e["auto"] = "null/empty"
    e["verdict"] = "open"
    assert memory.effective_state(e) == "open"
    # ...but a "dead" verdict cannot erase an objective DATA return
    e["auto"] = "DATA"
    e["verdict"] = "dead"
    assert memory.effective_state(e) == "data"


def test_effective_state_auth_blocked_is_open_not_dead():
    e = memory.blank_entry("f", "anon", 0)
    e["auto"] = "AUTH-BLOCKED"
    assert memory.effective_state(e) == "open"
    e["auto"] = "null/empty"
    assert memory.effective_state(e) == "dead"
    e["auto"] = "HTTP500"
    assert memory.effective_state(e) == "open"


def test_echo_does_not_force_field_open():
    # an echoed field returning data is just "data" — echoes no longer force "open"/pressure a fuzz;
    # whether it's worth fuzzing is the model's call (a plain CRUD echo usually isn't)
    e = memory.blank_entry("echo", "anon", 0)
    e["auto"] = "DATA"
    e["echoed"] = "echoes input"
    assert memory.effective_state(e) == "data"      # NOT forced "open"


def test_echoed_does_not_override_model_dead_verdict():
    e = memory.blank_entry("echo", "anon", 0)
    e["attempts"] = 1            # probed first, so the dead verdict has evidence
    e["echoed"] = "echoes input"
    e["verdict"] = "dead"        # the model explicitly killed it
    assert memory.effective_state(e) == "dead"


def test_dead_verdict_on_unprobed_field_is_ignored():
    # a "dead" verdict with no attempts behind it carries no evidence and stays open
    e = memory.blank_entry("f", "anon", 0)
    e["verdict"] = "dead"
    assert memory.effective_state(e) == "open"


def test_access_control_codes_stay_open():
    e = memory.blank_entry("f", "anon", 0)
    for code in ("HTTP401", "HTTP403"):
        e["auto"] = code
        assert memory.effective_state(e) == "open"


def test_effective_state_finding_trumps_all():
    e = memory.blank_entry("f", "anon", 0)
    e["finding"] = "BOLA"
    assert memory.effective_state(e) == "finding"


def test_apply_self_report_banks_fact_and_verdict():
    ledger: dict = {}
    facts: list = []
    note = memory.apply_self_report(
        {"action": "graphql", "learned": "self-reg needs email confirm",
         "verdict": {"field": "addressFilter", "state": "open", "why": "needs token", "confidence": 0.7}},
        ledger, facts, "anon", 3)
    assert "self-reg needs email confirm" in facts
    assert ledger["addressFilter"]["verdict"] == "open"
    assert ledger["addressFilter"]["confidence"] == 0.7
    assert "banked fact" in note and "verdict" in note


def test_apply_self_report_dedupes_facts():
    facts = ["known"]
    memory.apply_self_report({"learned": "known"}, {}, facts, "anon", 0)
    assert facts.count("known") == 1


def test_identity_label():
    assert memory.identity_label({}) == "anon"
    assert memory.identity_label({"Authorization": "Bearer abcdef123456"}).startswith("auth:")
    assert memory.identity_label({"X-Custom": "v"}) == "hdr"


def test_dedup_findings_collapses_endpoint_class_and_field():
    vulns = [
        {"vuln_type": "Denial of Service (No Query Cost Limiting)", "target_node": "q1"},
        {"vuln_type": "Denial of Service (No Query Cost Limiting)", "target_node": "q2"},
        {"vuln_type": "BOLA", "target_node": "query { user(id:1){id} }"},
        {"vuln_type": "BOLA", "target_node": "query { user(id:2){id} }"},
    ]
    out = memory.dedup_findings(vulns)
    # DoS collapses to one (endpoint-wide); BOLA collapses by root field 'user'
    assert len(out) == 2


def test_dedup_findings_collapses_oob_wording_variants():
    # the in-loop auto-OOB finding and the end-of-run reconcile finding differ only in casing —
    # they must collapse to one (run.py re-dedups after _reconcile_oob)
    out = memory.dedup_findings([
        {"vuln_type": "Blind SSRF / OOB interaction (dns) confirmed", "target_node": "endpoint"},
        {"vuln_type": "Blind SSRF / OOB Interaction (dns) confirmed", "target_node": "endpoint"},
    ])
    assert len(out) == 1


def test_unconfirmed_classes():
    missing = memory.unconfirmed_classes([{"vuln_type": "Denial of Service"}])
    assert "denial-of-service" not in missing
    assert "ssrf" in missing


def test_render_state_seed_message_when_empty():
    s = memory.render_state({}, [], [], 0, total_root=10)
    assert "sweep" in s.lower()


def test_render_state_shows_coverage_and_findings():
    ledger = {"me": {**memory.blank_entry("me", "anon", 0), "auto": "DATA", "attempts": 1}}
    s = memory.render_state(ledger, ["a fact"], ["login"], 1, total_root=5)
    assert "COVERAGE" in s and "findings recorded" in s
    assert "a fact" in s and "login" in s


def test_render_state_tried_table_marks_overflow_past_20():
    # >20 fields at data/open state: the TRIED table caps at 20 rows and must
    # signal the dropped rows, mirroring the facts-list overflow marker
    ledger = {f"f{i}": {**memory.blank_entry(f"f{i}", "anon", 0), "auto": "DATA", "attempts": 1}
              for i in range(25)}
    s = memory.render_state(ledger, [], [], 0, total_root=25)
    assert "(+5 more fields in ledger" in s
