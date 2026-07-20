"""ActionContext and Result: the state and return types shared with action handlers."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from ..memory import _finding_key, _retract_sig

logger = logging.getLogger("gradientql.scanner")


@dataclass
class Result:
    """Outcome of one action handler, returned to the control loop."""

    observation: str = ""
    touched_target: bool = False
    is_dead: bool = False
    stop: bool = False
    blocked: bool = False
    # blocked because the technique is disabled in config, not because the model is stuck;
    # the loop never counts these toward the blocked-action abort.
    config_blocked: bool = False


@dataclass
class ActionContext:
    """Mutable per-run state shared across every action handler for one target."""

    client: Any
    schema_map: dict[str, Any]
    schema_index: Any
    settings: dict[str, Any]
    target_url: str
    oob_sess: Any = None

    identity: dict[str, str] = field(default_factory=dict)
    harvested: dict[str, list[str]] = field(default_factory=dict)
    credentials: list[dict[str, str]] = field(default_factory=list)
    ledger: dict[str, dict] = field(default_factory=dict)
    facts: list[str] = field(default_factory=list)
    searched: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    history: list[str] = field(default_factory=list)
    decisions: list[str] = field(default_factory=list)
    step_io: list[dict[str, Any]] = field(default_factory=list)
    tracing: bool = False
    vulns: list[dict[str, Any]] = field(default_factory=list)
    interactions: list[dict[str, Any]] = field(default_factory=list)
    covered: set[str] = field(default_factory=set)

    tempmail: Any = None
    step: int = 0
    oob_injected_at: int | None = None
    oob_injected_req: dict[str, Any] | None = None
    tokens: dict[str, Any] = field(default_factory=lambda: {
        "input": 0, "output": 0, "reasoning": 0, "total": 0, "cost": 0.0, "calls": 0})

    _seen_finding_keys: set[str] = field(default_factory=set)
    _retracted_sigs: set[str] = field(default_factory=set)
    _fid: int = 0
    _fuzz_seen: dict = field(default_factory=dict)
    _prevalidate_fails: dict[str, int] = field(default_factory=dict)
    _stream: Callable[[dict[str, Any]], None] | None = None
    _stream_retract: Callable[[str, str], None] | None = None

    def log(self, line: str) -> None:
        self.history.append(line)

    def trace_io(self, query: str, variables: Any, resp: dict | None, label: str = "") -> None:
        """Append a truncated request/response record to the trace; no-op unless tracing is on."""
        if not self.tracing:
            return
        r = resp or {}
        data = r.get("data")
        errors = r.get("errors") or []
        self.step_io.append({
            "label": label, "query": str(query)[:3000], "variables": variables or {},
            "status": r.get("_status_code"),
            "data": json.dumps(data, default=str)[:12000] if data is not None else None,
            "errors": json.dumps(errors, default=str)[:4000] if errors else "",
        })

    def record(self, vuln_type: str, target: str, evidence: str, score: float = 2.5,
               req: dict[str, Any] | None = None) -> bool:
        """Store a new finding, returning False if it duplicates one or was previously retracted.

        On success appends to vulns, assigns an id, captures the triggering request (so the UI can
        reconstruct a curl), and streams it to any live subscriber. `req` defaults to the client's
        most recent request when not given.
        """
        key = _finding_key(vuln_type, target)
        if _retract_sig(vuln_type, target) in self._retracted_sigs:
            return False
        if key in self._seen_finding_keys:
            return False
        self._seen_finding_keys.add(key)
        self._fid += 1
        if req is None:
            req = getattr(self.client, "last_request", None)
        payload = req.get("payload") if isinstance(req, dict) else None
        v = {
            "id": f"f{self._fid}",
            "vuln_type": vuln_type, "target_node": target or "endpoint",
            "query": (payload or {}).get("query", "") if isinstance(payload, dict) else "",
            "variables": (payload or {}).get("variables", {}) if isinstance(payload, dict) else {},
            "evidence": str(evidence)[:2000],
            "request": req if isinstance(req, dict) else None,
            "score": score, "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.vulns.append(v)
        if self._stream is not None:
            try:
                self._stream(v)
            except Exception:  # noqa: BLE001
                pass
        logger.warning("AGENT finding: %s on %s", vuln_type, target)
        return True

    def retract(self, finding_id: str = "", vuln_type: str = "", target: str = "", why: str = "") -> int:
        """Remove matching findings and block their re-recording; return how many were removed.

        Matches by finding_id when given, else by vuln_type/target signature.
        """
        fid = str(finding_id).strip()
        if fid:
            matched = [v for v in self.vulns if v.get("id") == fid]
        elif vuln_type or target:
            sig = _retract_sig(vuln_type, target)
            matched = [v for v in self.vulns
                       if _retract_sig(str(v.get("vuln_type", "")), str(v.get("target_node", ""))) == sig]
        else:
            matched = []
        for v in matched:
            self._retracted_sigs.add(_retract_sig(str(v.get("vuln_type", "")), str(v.get("target_node", ""))))
            if self._stream_retract is not None:
                try:
                    self._stream_retract(str(v.get("vuln_type", "")), str(v.get("target_node", "")))
                except Exception:  # noqa: BLE001
                    pass
            logger.warning("AGENT retracted finding: %s on %s (%s)",
                           v.get("vuln_type"), v.get("target_node"), why[:80])
        self.vulns = [v for v in self.vulns if v not in matched]
        return len(matched)
