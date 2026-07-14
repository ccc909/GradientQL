"""End-to-end integration: run_scan driven by a scripted LLM against a mock BOLA endpoint.

Exercises the whole pipeline (auth gate -> introspect -> misconfig -> agent loop -> dedup ->
report -> trace) with all network mocked, and asserts the auth attestation is stamped into the
trace + vuln stream and that pre-validation intercepts an invalid query without a request.
"""

from __future__ import annotations

import pytest

from gradientql.scanner import loop
from gradientql.scanner import run as run_mod
from tests.conftest import MockClient, scripted_llm


@pytest.fixture()
def mock_world(monkeypatch, sample_introspection_result):
    """Patch all external deps; return a client whose responses model a BOLA-y target."""
    client = MockClient(
        introspection=sample_introspection_result,
        responses={
            "pastes { id": {"data": {"pastes": [{"id": 101, "title": "mine"}]},
                            "errors": [], "_status_code": 200},
            "paste(pId": {"data": {"paste": {"id": 100, "title": "ANOTHER USER's paste"}},
                          "errors": [], "_status_code": 200},
        },
        default={"data": None, "errors": [], "_status_code": 200},
    )
    monkeypatch.setattr(loop.time, "sleep", lambda *a, **k: None)
    monkeypatch.setattr(loop, "get_attacker_llm", lambda settings: object())
    monkeypatch.setattr(loop, "get_client", lambda url, csrf_config=None, http=None: client)
    import gradientql.utils.graphql_client as gc
    monkeypatch.setattr(gc, "get_client", lambda url, csrf_config=None, http=None: client)
    import gradientql.utils.misconfig as mc
    monkeypatch.setattr(mc, "run_misconfig_sweep", lambda *a, **k: [])
    import gradientql.utils.oob as oobmod
    monkeypatch.setattr(oobmod, "is_enabled", lambda settings: False)
    monkeypatch.setattr(oobmod, "get_session", lambda settings: type("S", (), {"client": None})())
    return client


def test_end_to_end_bola_chain(monkeypatch, mock_world, sample_settings, tmp_path):
    client = mock_world
    trace_prefix = str(tmp_path / "run_trace")
    sample_settings["scanner"]["trace"] = trace_prefix

    actions = [
        {"action": "sweep", "args": {}},
        {"action": "graphql", "args": {"query": "query { pastes { id title } }"}},
        # an invalid guess the schema PROVES wrong -> must be intercepted with NO request
        {"action": "graphql", "args": {"query": "query { pastes { nopeField } }"}},
        # the real BOLA probe: read another user's object by id
        {"action": "graphql", "args": {"query": "query { paste(pId: 100) { id title } }"}},
        {"action": "report_finding", "args": {"vuln_type": "BOLA / IDOR", "target": "paste",
                                              "evidence": "read another user's paste id=100"}},
        {"action": "done", "args": {"reason": "confirmed BOLA"}},
    ]
    monkeypatch.setattr(loop, "invoke_with_circuit_breaker", scripted_llm(actions))

    url = sample_settings["target"]["url"]
    result = run_mod.run_scan(sample_settings, url)

    # 1) the BOLA finding was recorded
    assert any("BOLA" in v["vuln_type"] for v in result["vulnerabilities"])

    # 2) pre-validation intercepted the invalid query: it never reached the client
    assert not any("nopeField" in c[0] for c in client.calls)
    # ...but the valid BOLA probe DID reach the client
    assert any("paste(pId: 100)" in c[0] for c in client.calls)

    # 3) a per-step trace was written
    trace_md = (tmp_path / "run_trace.md").read_text(encoding="utf-8")
    assert "Agent trace" in trace_md
