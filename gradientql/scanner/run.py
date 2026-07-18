"""Agent-only run orchestration."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from ..core.llm import (
    clear_llm_cache,
    clear_response_memo_cache,
    configure_cache,
    configure_circuit,
    reset_circuit,
)
from ..utils.reporter import append_vuln_stream, init_vuln_stream
from . import loop
from .memory import dedup_findings
from .schema import parse_schema

logger = logging.getLogger("gradientql.scanner")


def run_scan(settings: dict[str, Any], target_url: str, progress_cb: Any = None,
             report: bool = True, should_stop: Any = None, steer: Any = None,
             run_id: str | None = None, resume: dict[str, Any] | None = None) -> dict[str, Any]:
    """Introspect the target, run the agent loop, and return deduplicated findings.

    Resets the shared LLM caches, circuit breaker, and OOB session as a side
    effect. Prints a plain report unless `report` is False (the TUI renders its
    own). `progress_cb(step, budget, ctx)` is invoked once per loop step. Every
    run gets a unique `run_id`; pass a loaded checkpoint as `resume` to continue
    it (introspection is skipped and the saved schema/state are reused). Returns
    the loop result dict; if introspection fails, returns an empty result.
    """
    from . import checkpoint as _cp
    if resume is not None:
        run_id = resume.get("run_id") or run_id or _cp.new_run_id()
    elif run_id is None:
        run_id = _cp.new_run_id()
    configure_cache(settings)
    configure_circuit(settings)
    clear_llm_cache()
    clear_response_memo_cache()
    reset_circuit()
    from ..utils.oob import reset_session as _reset_oob
    _reset_oob()
    init_vuln_stream(target_url)
    if resume is not None:  # re-emit prior findings so the stream feed isn't truncated to post-resume only
        for v in (resume.get("ctx") or {}).get("vulns", []) or []:
            try:
                append_vuln_stream(v)
            except Exception:  # noqa: BLE001
                pass

    from ..utils.graphql_client import clear_client_cache, get_client
    clear_client_cache()
    csrf = settings.get("target", {}).get("csrf")
    client = get_client(target_url, csrf_config=csrf, http=settings.get("http", {}))
    introspection_ok = True
    if resume is not None:
        schema_map = resume.get("schema_map") or {}
        try:  # introspection normally primes the session (CSRF token/cookies); warm it up on resume
            client.execute("{__typename}")
        except Exception:  # noqa: BLE001
            pass
        logger.info("AGENT MODE: resuming run %s from step %d (skipping introspection, %d types cached)",
                    run_id, int(resume.get("step", -1)) + 1,
                    len([k for k in schema_map if not k.startswith("_")]))
    else:
        logger.info("AGENT MODE: introspecting %s", target_url)
        raw = client.introspect()
        introspection_ok = not (raw.get("errors") and not raw.get("data"))
        if introspection_ok:
            schema_map = parse_schema(raw)
            logger.info("AGENT MODE: schema parsed (%d types). Handing control to the model.",
                        len([k for k in schema_map if not k.startswith("_")]))
        else:
            # Introspection is disabled/blocked - do NOT abort. Endpoint-level probes (misconfig sweep,
            # SDL/run_sql) still run, and the agent recovers the surface with `clairvoyance` (suggestion
            # oracle) and query-name probing. Start from empty roots.
            errs = raw.get("errors")
            detail = str(errs[0].get("message", ""))[:160] if isinstance(errs, list) and errs and isinstance(errs[0], dict) else ""
            logger.warning("AGENT MODE: introspection blocked (%s) - proceeding schema-less; the agent "
                           "will recover the surface via clairvoyance / obfuscated introspection.", detail or errs)
            schema_map = {"_query_type": "Query", "_mutation_type": "Mutation",
                          "_subscription_type": "", "Query": {}, "Mutation": {}}

    vulns: list[dict[str, Any]] = []
    try:
        from ..utils.misconfig import run_misconfig_sweep
        for f in run_misconfig_sweep(target_url, introspection_succeeded=introspection_ok,
                                     session=getattr(client, "session", None)):
            v = {"vuln_type": f["vuln_type"], "target_node": f.get("target_node", "endpoint"),
                 "query": "", "variables": {}, "evidence": f.get("evidence", ""), "score": 2.0,
                 "timestamp": datetime.now(timezone.utc).isoformat()}
            vulns.append(v)
            try:
                append_vuln_stream(v)
            except Exception:  # noqa: BLE001
                pass
    except Exception as e:  # noqa: BLE001
        logger.debug("misconfig sweep skipped: %s", e)

    budget = int(settings.get("scanner", {}).get("budget", 60))
    if resume is not None:  # never resume into an already-finished step space; allow extending
        budget = max(budget, int(resume.get("budget", 0)))
        if resume.get("complete"):
            _start = int(resume.get("step", -1)) + 1
            if _start >= budget:
                logger.warning("Checkpoint %s already used its full budget of %d steps - raise scanner.budget "
                               "to explore further; returning the saved findings unchanged.", run_id, budget)
            else:
                logger.warning("Checkpoint %s ended naturally (done/budget); resuming re-scans the remaining "
                               "%d step(s).", run_id, budget - _start)
    trace = settings.get("scanner", {}).get("trace")
    verbose = bool(settings.get("scanner", {}).get("verbose"))
    result = loop.run(settings, schema_map, target_url, budget, trace=trace, verbose=verbose,
                      progress_cb=progress_cb, should_stop=should_stop, steer=steer,
                      run_id=run_id, resume=resume)
    result["vulnerabilities"] = dedup_findings(vulns + result.get("vulnerabilities", []))
    result.setdefault("run_id", run_id)

    _reconcile_oob(settings, result)
    result["vulnerabilities"] = dedup_findings(result["vulnerabilities"])

    if report:
        _print_report(result)
    return result


def _reconcile_oob(settings: dict[str, Any], result: dict[str, Any]) -> None:
    try:
        from ..utils import oob as _oob
        sess = _oob.get_session(settings)
        if getattr(sess, "client", None) is None:
            return
        seen: set = set()
        for _ in range(2):
            for hit in sess.reconcile():
                ix = hit["interaction"]
                key = (ix.get("full-id"), ix.get("timestamp"))
                if key in seen:
                    continue
                seen.add(key)
                v = {"vuln_type": f"Blind SSRF / OOB Interaction ({ix.get('protocol', '?')}) confirmed",
                     "target_node": "endpoint", "query": "", "variables": {},
                     "evidence": f"OOB {ix.get('protocol', '?')} callback from {ix.get('remote-address', '?')}",
                     "score": 3.0, "timestamp": datetime.now(timezone.utc).isoformat()}
                result["vulnerabilities"].append(v)
                try:
                    append_vuln_stream(v)
                except Exception:  # noqa: BLE001
                    pass
            time.sleep(6)
        sess.client.deregister()
    except Exception:  # noqa: BLE001
        pass


def _print_report(result: dict[str, Any]) -> None:
    vulns = result.get("vulnerabilities", [])
    line = "=" * 66
    print(f"\n{line}\n  GradientQL - AGENT MODE Report\n{line}")
    print(f"\nTarget:   {result.get('target_url')}")
    print(f"Steps:    {result.get('steps')}")
    print(f"Requests: {len(result.get('interactions', []))}")
    tok = result.get("tokens") or {}
    if tok.get("calls"):
        reasoning = f", {tok['reasoning']:,} reasoning" if tok.get("reasoning") else ""
        cost = f"  ~${tok['cost']:.3f}" if tok.get("cost") else ""
        print(f"Tokens:   {tok.get('total', 0):,} total "
              f"({tok.get('input', 0):,} in / {tok.get('output', 0):,} out{reasoning}) "
              f"over {tok['calls']} calls{cost}")
    print(f"Findings: {len(vulns)}")
    if vulns:
        print("\n--- Findings ---")
        for v in vulns:
            print(f"  [{v.get('score', 0):.1f}] {v.get('vuln_type')} on {v.get('target_node')}")
            ev = str(v.get("evidence", ""))[:1000]
            if ev:
                print(f"        {ev}")
    notes = result.get("notes", [])
    if notes:
        print("\n--- Agent notes (final state of its working memory) ---")
        for n in notes[-12:]:
            print(f"  - {str(n)[:300]}")
    print(f"\n{line}\n  Scan complete.\n{line}")
