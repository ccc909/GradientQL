"""Tests for src/scanner/tracer.py."""

from __future__ import annotations

from gradientql.scanner.tracer import AgentTracer


def test_tracer_writes_step_and_summary(tmp_path):
    dest = str(tmp_path / "trace")
    tr = AgentTracer(dest, "http://t/graphql")
    tr.step({"step": 0, "prompt": "P", "raw_response": "R", "action": "sweep",
             "thought": "map it", "self_report": "", "observations": ["swept 3 fields"],
             "state": {"identity": [], "findings": 0, "facts": [], "credentials": [],
                       "harvested": {}, "ledger": {}}})
    tr.close({"steps": 1, "findings": 0})

    jsonl = (tmp_path / "trace.jsonl").read_text(encoding="utf-8")
    md = (tmp_path / "trace.md").read_text(encoding="utf-8")
    assert '"action": "sweep"' in jsonl
    assert "summary" in jsonl
    assert "map it" in md and "Step 0" in md


def test_tracer_renders_full_wire_io_and_args(tmp_path):
    # the .md digest must surface the FULL untruncated response + the action args (operator ground truth)
    tr = AgentTracer(str(tmp_path / "t"), "http://t/graphql")
    tr.step({"step": 1, "action": "graphql", "thought": "probe me",
             "args": {"query": "query { me { id } }"},
             "io": [{"label": "me", "query": "query { me { id } }", "variables": {},
                     "status": 200, "data": {"me": {"id": 1, "secret": "LEAKED_TOKEN_VALUE"}}, "errors": []}],
             "raw_response": "{}", "observations": ["HTTP 200 | data=..."],
             "state": {"identity": [], "findings": 0, "facts": [], "credentials": [], "harvested": {}, "ledger": {}}})
    tr.close({"steps": 1})
    md = (tmp_path / "t.md").read_text(encoding="utf-8")
    assert "Wire I/O" in md
    assert "LEAKED_TOKEN_VALUE" in md      # full response body is present, untruncated by model caps
    assert "Action args" in md and "query { me { id } }" in md


def test_trace_io_is_noop_unless_tracing():
    from gradientql.scanner.actions import ActionContext
    ctx = ActionContext(client=None, schema_map={}, schema_index=None, settings={}, target_url="x")
    ctx.trace_io("q", {}, {"data": {"x": 1}, "_status_code": 200})
    assert ctx.step_io == []                # tracing off -> zero overhead, nothing recorded
    ctx.tracing = True
    ctx.trace_io("q", {"v": 1}, {"data": {"x": 1}, "_status_code": 200}, label="x")
    assert len(ctx.step_io) == 1 and ctx.step_io[0]["data"] == '{"x": 1}'   # stored as bounded JSON string
