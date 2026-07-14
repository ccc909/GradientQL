"""Report generation for scan results."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_VULN_STREAM_PATH = Path("output") / "vuln_stream.jsonl"


def init_vuln_stream(target_url: str = "") -> Path:
    """Truncate the stream file and write its header record; return the path."""
    _VULN_STREAM_PATH.parent.mkdir(exist_ok=True)
    header = {"_target": target_url, "timestamp": datetime.now(timezone.utc).isoformat()}
    _VULN_STREAM_PATH.write_text(json.dumps(header, default=str) + "\n", encoding="utf-8")
    return _VULN_STREAM_PATH


def append_vuln_stream(vuln: dict[str, Any]) -> None:
    try:
        rec = {
            "vuln_type": vuln.get("vuln_type"),
            "target_node": vuln.get("target_node"),
            "score": vuln.get("score"),
            "timestamp": vuln.get("timestamp"),
        }
        with _VULN_STREAM_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
    except OSError:
        pass


def append_vuln_retraction(vuln_type: str, target_node: str) -> None:
    """Append a retraction marker that suppresses the matching vuln on read."""
    try:
        with _VULN_STREAM_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"_retracted": True, "vuln_type": vuln_type,
                                "target_node": target_node}, default=str) + "\n")
    except OSError:
        pass


def read_vuln_stream() -> list[dict[str, Any]]:
    """Load live vulns, dropping the header and any retracted (type, node) pairs."""
    raw: list[dict[str, Any]] = []
    try:
        for line in _VULN_STREAM_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                raw.append(json.loads(line))
    except (OSError, json.JSONDecodeError):
        pass
    retracted = {(r.get("vuln_type"), r.get("target_node")) for r in raw if r.get("_retracted")}
    return [r for r in raw if not r.get("_retracted") and "_target" not in r
            and (r.get("vuln_type"), r.get("target_node")) not in retracted]
