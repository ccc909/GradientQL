"""Tests for src/scanner/payloads.py — the attack-payload catalog."""

from __future__ import annotations

from gradientql.scanner import payloads


def test_classes_present():
    for cls in ("ssti", "cmdi", "sqli", "nosql", "traversal", "ssrf"):
        assert payloads.CLASS_PROBES.get(cls), f"missing class {cls}"


def test_ssti_covers_ruby_and_erb():
    blob = " ".join(payloads.CLASS_PROBES["ssti"])
    assert "#{1337*1337}" in blob        # Ruby interpolation (Rails)
    assert "<%= 1337*1337 %>" in blob     # ERB
    assert "{{1337*1337}}" in blob        # Jinja/Twig


def test_sqli_probes_drop_inert_pg_sleep():
    # a zero-second pg_sleep emits no timing signal and no detector reads response time -> removed
    blob = " ".join(payloads.CLASS_PROBES["sqli"])
    assert "pg_sleep(0)" not in blob


def test_ssti_hit_confirms_eval_only():
    # marker present + payload not echoed -> evaluated
    assert payloads.ssti_hit("#{1337*1337}", "got 1787569 back") == "1787569"
    # payload echoed verbatim -> reflected, NOT evaluated
    assert payloads.ssti_hit("#{1337*1337}", "you sent #{1337*1337}") is None
    # unknown/custom payload -> not in the catalog map
    assert payloads.ssti_hit("{{custom}}", "anything 1787569") is None
