"""Probe GraphQL @defer/@stream incremental delivery - a DoS-amplification and response-desync surface.

@defer/@stream split one operation into an initial payload plus streamed multipart/mixed patches. A
server that honours them can be pushed to fan a single query into many chunks (amplification), can
leak deferred fields whose auth runs only on the initial selection, and streams a multipart body that
intermediaries may mis-frame (desync). This module just detects support + reports the surface.
"""

from __future__ import annotations

from typing import Any

import requests

_INCREMENTAL_MARKERS = ("multipart/mixed", "\r\n--", "\"hasnext\"", "\"incremental\"", "\"pending\"")


def probe_defer(url: str, query: str, session: Any = None, headers: dict | None = None,
                timeout: int = 15) -> dict[str, Any]:
    """Send a @defer query with an incremental-delivery Accept header; report whether it streamed."""
    http = session or requests
    h = dict(headers or {})
    h["Accept"] = "multipart/mixed, application/json"
    h["Content-Type"] = "application/json"
    try:
        r = http.post(url, json={"query": query}, headers=h, timeout=timeout)
    except requests.RequestException as e:
        return {"supported": False, "status": 0, "detail": f"request failed: {str(e)[:80]}"}
    ct = (r.headers.get("Content-Type", "") or "").lower()
    body = (r.text or "")
    low = body.lower()
    multipart = "multipart/mixed" in ct
    markers = [m for m in _INCREMENTAL_MARKERS if m in ct or m in low]
    supported = multipart or "\"hasnext\"" in low or "\"incremental\"" in low
    chunks = low.count("content-type: application/json") or (body.count("\r\n--") if multipart else 0)
    return {
        "supported": supported,
        "multipart": multipart,
        "status": r.status_code,
        "content_type": ct[:60],
        "markers": markers,
        "chunks": chunks,
        "detail": body[:300],
    }


def build_defer_query(schema_map: dict[str, Any]) -> str | None:
    """Build a minimal @defer query over the first object-returning root Query field, or None."""
    import re
    qroot = schema_map.get("_query_type", "Query")
    fields = schema_map.get(qroot)
    if not isinstance(fields, dict):
        return None
    for fname, info in fields.items():
        if str(fname).startswith("_") or not isinstance(info, dict):
            continue
        if info.get("args"):
            continue  # keep it arg-free so the query validates
        base = re.sub(r"[\[\]!]", "", str(info.get("return_type", ""))).strip()
        if isinstance(schema_map.get(base), dict):
            return f"query {{ {fname} {{ ... @defer {{ __typename }} }} }}"
    return None
