"""Deterministic GraphQL misconfiguration sweep (graphql-cop parity)."""

from __future__ import annotations

import logging
from typing import Any

import requests

logger = logging.getLogger("gradientql.misconfig")

_IDE_MARKERS = (
    "graphiql", "graphql playground", "playground", "apollo sandbox",
    "embeddedsandbox", "altair", "graphql voyager",
)


def run_misconfig_sweep(
    target_url: str,
    introspection_succeeded: bool,
    session: requests.Session | None = None,
) -> list[dict[str, Any]]:
    """Probe an endpoint for GraphQL misconfigurations; introspection_succeeded=True emits a finding without re-probing.

    Returns one finding dict (vuln_type/target_node/evidence/severity) per issue.
    """
    sess = session or requests.Session()
    findings: list[dict[str, Any]] = []

    def add(vuln_type: str, evidence: str, severity: str = "low") -> None:
        findings.append({
            "vuln_type": vuln_type,
            "target_node": "endpoint",
            "evidence": evidence[:500],
            "severity": severity,
        })

    if introspection_succeeded:
        add(
            "Introspection Enabled (information_disclosure)",
            "The __schema introspection query returned the full schema; disable or "
            "restrict introspection in production (OWASP GraphQL Cheat Sheet).",
            "medium",
        )

    try:
        r = sess.get(target_url, headers={"Accept": "text/html"}, timeout=10)
        body = (r.text or "")[:20000].lower()
        hit = next((m for m in _IDE_MARKERS if m in body), None)
        if hit and r.status_code == 200:
            add(
                "GraphQL IDE Exposed (information_disclosure)",
                f"GET {target_url} serves an interactive GraphQL IDE (matched '{hit}') — "
                f"self-documenting attack console in production.",
                "medium",
            )
    except requests.RequestException:
        pass

    try:
        r = sess.get(target_url, params={"query": "{__typename}"}, timeout=10)
        if r.status_code == 200 and "__typename" in (r.text or ""):
            add(
                "GET-based Queries Allowed (csrf surface)",
                "The endpoint executes GraphQL over HTTP GET; combined with state-changing "
                "operations this is a CSRF and web-cache-deception vector.",
                "low",
            )
    except requests.RequestException:
        pass

    try:
        r = sess.post(target_url, json={"query": "{__typename}"}, timeout=10)
        j = r.json()
        ext = j.get("extensions") if isinstance(j, dict) else None
        if isinstance(ext, dict) and any(k in ext for k in ("tracing", "metrics", "apolloTracing")):
            add(
                "Apollo Tracing / Verbose Extensions (information_disclosure)",
                "Responses include performance tracing in `extensions` — leaks resolver "
                "timing and internal structure; disable tracing in production.",
                "low",
            )
    except (requests.RequestException, ValueError):
        pass

    try:
        r = sess.post(
            target_url,
            json=[{"query": "{__typename}"}, {"query": "{__typename}"}],
            timeout=10,
        )
        j = r.json()
        if isinstance(j, list) and len(j) == 2 and all(isinstance(e, dict) for e in j):
            add(
                "Query Batching Enabled (resource_exhaustion surface)",
                "The endpoint accepts JSON-array batches; enables alias/batch brute-force "
                "(rate-limit & 2FA bypass) and DoS amplification.",
                "low",
            )
    except (requests.RequestException, ValueError):
        pass

    try:
        r = sess.post(
            target_url,
            json={"extensions": {"persistedQuery": {"version": 1, "sha256Hash": "0" * 64}}},
            timeout=10,
        )
        if "persistedquerynotfound" in (r.text or "").lower():
            add(
                "Automatic Persisted Queries Enabled (apq)",
                "The endpoint supports Apollo APQ (responded PersistedQueryNotFound to a fake hash) — "
                "an attacker can register/cache queries by hash (cache poisoning, Apollo fingerprint, "
                "and a bypass of allow-listed persisted-query controls).",
                "low",
            )
    except (requests.RequestException, ValueError):
        pass

    logger.info("Misconfig sweep: %d finding(s)", len(findings))
    return findings
