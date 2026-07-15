"""Run checkpointing — serialize the recoverable slice of a run so it can be resumed.

A checkpoint is a JSON snapshot of the agent's working state (findings, per-field ledger,
harvested secrets, identity, run-log, token tally) plus the parsed schema and the step index,
written atomically every few steps and once at the end. `--resume <run-id>` rebuilds the
context from it and continues from the next step. The live GraphQL client, schema index, and
OOB session are rebuilt fresh on resume. A few live, external-bound sessions cannot be
serialized and are lost on resume: unreconciled OOB callbacks and any open temp-mail inbox
(a mid-flight email-activation chain would need to be restarted). The within-session
degraded-target throttle (consecutive dead-response counters) also resets on resume.
"""
from __future__ import annotations

import json
import logging
import os
import pathlib
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("gradientql.scanner")

_VERSION = 1
_DEFAULT_DIR = "output/checkpoints"


def new_run_id() -> str:
    """A unique, lexically sortable run id, e.g. gql-20260715-213045-a3f9."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"gql-{ts}-{os.urandom(2).hex()}"


def _cfg(settings: dict[str, Any]) -> dict[str, Any]:
    return (settings.get("scanner", {}) or {}).get("checkpoint", {}) or {}


def is_enabled(settings: dict[str, Any]) -> bool:
    return bool(_cfg(settings).get("enabled", False))


def interval(settings: dict[str, Any]) -> int:
    return max(1, int(_cfg(settings).get("every", 5)))


def checkpoint_dir(settings: dict[str, Any]) -> pathlib.Path:
    return pathlib.Path(_cfg(settings).get("dir", _DEFAULT_DIR))


def checkpoint_path(settings: dict[str, Any], run_id: str) -> pathlib.Path:
    return checkpoint_dir(settings) / f"{run_id}.json"


def resolve(settings: dict[str, Any], ref: str) -> pathlib.Path | None:
    """Turn a --resume value (a run id or a path) into an existing checkpoint file, or None."""
    for cand in (pathlib.Path(ref), checkpoint_path(settings, ref), pathlib.Path(f"{ref}.json")):
        if cand.is_file():
            return cand
    return None


def latest(settings: dict[str, Any]) -> pathlib.Path | None:
    """The most recently modified checkpoint in the configured directory, or None."""
    d = checkpoint_dir(settings)
    files = sorted(d.glob("gql-*.json"), key=lambda p: p.stat().st_mtime, reverse=True) if d.is_dir() else []
    return files[0] if files else None


def save(path: Any, *, run_id: str, ctx: Any, schema_map: dict[str, Any],
         target_url: str, step: int, budget: int, complete: bool = False) -> None:
    """Atomically write a checkpoint of the recoverable run state (last completed step = `step`).

    `complete` marks a checkpoint written after the run ended naturally (the agent said `done`
    or the budget was exhausted), so resume can warn rather than silently re-scanning.
    """
    # parse_schema stores a few keys (_interfaces, _unions) as sets; json.dump would stringify
    # them via default=str, so a resumed schema_map wouldn't match a fresh parse. Emit as lists.
    safe_schema = {k: (sorted(v) if isinstance(v, set) else v) for k, v in schema_map.items()}
    data = {
        "version": _VERSION,
        "run_id": run_id,
        "target_url": target_url,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "step": step,            # last completed step; resume starts at step + 1
        "budget": budget,
        "complete": bool(complete),
        "schema_map": safe_schema,
        "ctx": {
            "identity": ctx.identity,
            "harvested": ctx.harvested,
            "credentials": ctx.credentials,
            "ledger": ctx.ledger,
            "facts": ctx.facts,
            "searched": ctx.searched,
            "notes": ctx.notes,
            "history": ctx.history,
            "decisions": ctx.decisions,
            "vulns": ctx.vulns,
            "interactions": ctx.interactions,
            "covered": sorted(ctx.covered),
            "tokens": ctx.tokens,
            "seen_finding_keys": sorted(ctx._seen_finding_keys),
            "retracted_sigs": sorted(ctx._retracted_sigs),
            "fid": ctx._fid,
            # _fuzz_seen is keyed by tuples (field, arg, path, cls); JSON keys must be strings,
            # so store it as [key, count] pairs (list-encoded tuples) and rebuild on restore.
            "fuzz_seen": [[list(k) if isinstance(k, tuple) else k, v]
                          for k, v in ctx._fuzz_seen.items()],
        },
    }
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, default=str)
        os.replace(tmp, path)  # atomic on the same filesystem
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    logger.info("AGENT: checkpoint saved at step %d -> %s", step, path)


def load(path: Any) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def restore_ctx(ctx: Any, data: dict[str, Any]) -> int:
    """Re-seed a fresh ctx from a checkpoint's `ctx` blob. Returns the next step to run."""
    c = data.get("ctx", {}) or {}
    ctx.identity = dict(c.get("identity", {}) or {})
    ctx.harvested = {k: list(v) for k, v in (c.get("harvested", {}) or {}).items()}
    ctx.credentials = list(c.get("credentials", []) or [])
    ctx.ledger = dict(c.get("ledger", {}) or {})
    ctx.facts = list(c.get("facts", []) or [])
    ctx.searched = list(c.get("searched", []) or [])
    ctx.notes = list(c.get("notes", []) or [])
    ctx.history = list(c.get("history", []) or [])
    ctx.decisions = list(c.get("decisions", []) or [])
    ctx.vulns = list(c.get("vulns", []) or [])
    ctx.interactions = list(c.get("interactions", []) or [])
    ctx.covered = set(c.get("covered", []) or [])
    ctx.tokens = dict(c.get("tokens", None) or ctx.tokens)
    ctx._seen_finding_keys = set(c.get("seen_finding_keys", []) or [])
    ctx._retracted_sigs = set(c.get("retracted_sigs", []) or [])
    ctx._fid = int(c.get("fid", 0) or 0)
    fs = c.get("fuzz_seen", []) or []
    ctx._fuzz_seen = (dict(fs) if isinstance(fs, dict)  # tolerate a legacy dict form
                      else {tuple(k) if isinstance(k, list) else k: v for k, v in fs})
    return int(data.get("step", -1)) + 1
