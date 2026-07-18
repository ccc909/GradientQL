"""Race-condition engine: fire N identical GraphQL operations simultaneously (TOCTOU).

A single barrier releases every worker at once so the requests hit the resolver in the tiny window
before any commits - the way limit-overrun / double-spend / single-use-token races are exploited
(redeem a one-time coupon twice, withdraw past a balance, reuse an OTP, overrun a stock/quota check).
"""

from __future__ import annotations

import concurrent.futures
import json
import threading
from typing import Any

import requests

_RACE_BLOCK_MARKERS = (
    "rate limit", "too many", "duplicate", "already", "unique", "conflict", "insufficient",
    "exceeded", "not enough", "out of stock", "sold out", "limit reached", "throttl", "locked",
)


def run_race(url: str, query: str, variables: dict | None = None, headers: dict | None = None,
             n: int = 20, timeout: int = 15, verify: bool = True,
             proxies: dict | None = None) -> list[dict[str, Any]]:
    """Fire the same operation `n` times concurrently (all released by one barrier). Returns per-request results."""
    payload: dict[str, Any] = {"query": query}
    if variables:
        payload["variables"] = variables
    barrier = threading.Barrier(n)
    sessions = []
    for _ in range(n):
        s = requests.Session()
        s.verify = verify
        if proxies:
            s.proxies = proxies
        if headers:
            s.headers.update(headers)
        s.headers.setdefault("Content-Type", "application/json")
        sessions.append(s)

    def worker(i: int) -> dict[str, Any]:
        try:
            barrier.wait(timeout=timeout)
        except threading.BrokenBarrierError:
            pass
        try:
            r = sessions[i].post(url, json=payload, timeout=timeout)
            try:
                body = r.json()
            except ValueError:
                body = None
            data = body.get("data") if isinstance(body, dict) else None
            errors = body.get("errors") if isinstance(body, dict) else None
            return {"status": r.status_code, "data": data, "errors": errors, "text": (r.text or "")[:200]}
        except requests.RequestException as e:
            return {"status": 0, "data": None, "errors": [{"message": str(e)[:120]}], "text": ""}
        finally:
            sessions[i].close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
        return list(ex.map(worker, range(n)))


def analyze_race(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Bucket race results and decide whether concurrency control appears ABSENT.

    `possible_race` is True when >=2 operations succeeded concurrently with no rate-limit / duplicate /
    insufficient-funds style error - i.e. nothing serialized them. Whether that is a *vuln* depends on
    the operation being single-use (coupon/withdrawal/unique signup), which the caller/LLM judges.
    """
    total = len(results)
    succeeded = [r for r in results if r.get("status") == 200 and r.get("data") and not r.get("errors")]
    blocked = []
    for r in results:
        blob = json.dumps(r.get("errors") or [], default=str).lower()
        if r.get("status") == 429 or any(mk in blob for mk in _RACE_BLOCK_MARKERS):
            blocked.append(r)
    return {
        "total": total,
        "succeeded": len(succeeded),
        "blocked": len(blocked),
        "errored": sum(1 for r in results if r.get("errors")),
        "possible_race": len(succeeded) >= 2 and len(blocked) == 0,
    }
