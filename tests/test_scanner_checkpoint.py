"""Tests for scanner/checkpoint.py - defaults and the save/restore round-trip."""

from __future__ import annotations

from gradientql.scanner import checkpoint as cp
from gradientql.scanner.actions import ActionContext


def _ctx(**over):
    ctx = ActionContext(client=None, schema_map={}, schema_index=None, settings={},
                        target_url="http://t/graphql")
    for k, v in over.items():
        setattr(ctx, k, v)
    return ctx


def test_defaults_match_shipped_config():
    # checkpointing is on by default (a Ctrl-C'd run stays resumable) and snapshots every 5 steps
    assert cp.is_enabled({}) is True
    assert cp.interval({}) == 5
    assert cp.is_enabled({"scanner": {"checkpoint": {"enabled": False}}}) is False


def test_save_restore_round_trip(tmp_path):
    ctx = _ctx()
    ctx.identity["Authorization"] = "Bearer tok"
    ctx.harvested["jwt"] = ["eyJ.x.y"]
    ctx.credentials.append({"email": "a@b.c", "password": "pw"})
    ctx.ledger["me"] = {"field": "me", "attempts": 2, "auto": "DATA", "sig": "",
                        "identity": "anon", "verdict": "open", "why": "w", "confidence": 0.5,
                        "finding": None, "step": 1, "dup_fails": 0, "last_sig": None,
                        "stale_fps": []}
    ctx.facts.append("fact one")
    ctx.notes.append("a note")
    ctx.decisions.append("[0] sweep -> 1 DATA")
    ctx.vulns.append({"id": "f1", "vuln_type": "BOLA", "target_node": "me"})
    ctx.covered.add("query { me }")
    ctx._seen_finding_keys.add("bola|me")
    ctx._retracted_sigs.add("x|y")
    ctx._fid = 1
    ctx._fuzz_seen[("pastes", "filter", "", "sqli")] = 4
    schema_map = {"_query_type": "Query", "_interfaces": {"Node", "Entity"},  # sets must survive
                  "Query": {"me": {"args": [], "return_type": "User", "description": ""}}}

    path = tmp_path / "gql-test.json"
    cp.save(path, run_id="gql-test", ctx=ctx, schema_map=schema_map,
            target_url="http://t/graphql", step=4, budget=30)

    data = cp.load(path)
    assert sorted(data["schema_map"]["_interfaces"]) == ["Entity", "Node"]  # set -> list

    fresh = _ctx()
    next_step = cp.restore_ctx(fresh, data)
    assert next_step == 5
    assert fresh.identity == {"Authorization": "Bearer tok"}
    assert fresh.ledger["me"]["verdict"] == "open"
    assert fresh.vulns == ctx.vulns
    assert fresh.covered == {"query { me }"}
    assert fresh._fuzz_seen == {("pastes", "filter", "", "sqli"): 4}  # tuple keys rebuilt
    assert fresh._seen_finding_keys == {"bola|me"} and fresh._retracted_sigs == {"x|y"}
    assert fresh._fid == 1
