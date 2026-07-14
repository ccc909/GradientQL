"""Tracing — full per-step observability into what the model SAW and DID."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("gradientql.scanner")


class AgentTracer:
    """Streams every agent step to a JSONL log and a readable Markdown digest."""

    def __init__(self, dest: Any, target_url: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base = dest if (isinstance(dest, str) and dest not in ("1", "true", "True", "__default__")) \
            else os.path.join("output", f"agent_trace_{ts}")
        if os.path.isdir(base):
            base = os.path.join(base, f"agent_trace_{ts}")
        parent = os.path.dirname(base)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.jsonl_path = base + ".jsonl"
        self.md_path = base + ".md"
        self._jf = open(self.jsonl_path, "w", encoding="utf-8")
        self._mf = open(self.md_path, "w", encoding="utf-8")
        self._mf.write(f"# Agent trace — {target_url}\n\n_started {ts} UTC_\n\n"
                       f"Per-step **full** prompts/responses are in `{os.path.basename(self.jsonl_path)}`; "
                       f"this file is a readable digest.\n")
        self.count = 0
        logger.info("AGENT: tracing every step to %s (+ .md digest)", self.jsonl_path)

    def step(self, rec: dict[str, Any]) -> None:
        self.count += 1
        try:
            self._jf.write(json.dumps(rec, default=str) + "\n")
            self._jf.flush()
            self._write_md(rec)
        except Exception as e:  # noqa: BLE001
            logger.debug("trace write failed: %s", e)

    def _write_md(self, rec: dict[str, Any]) -> None:
        st = rec.get("state", {}) or {}
        m = self._mf
        m.write(f"\n---\n\n## Step {rec.get('step')} — `{rec.get('action') or '(no valid action)'}`\n\n")
        if rec.get("thought"):
            m.write(f"**Thought:** {rec['thought']}\n\n")
        args = rec.get("args")
        if args not in (None, {}):
            m.write("**Action args:**\n\n```json\n" + json.dumps(args, indent=2, default=str)[:4000] + "\n```\n\n")
        io = rec.get("io") or []
        if io:
            m.write(f"**Wire I/O — {len(io)} request(s) this step (FULL response, not the model's bounded view):**\n\n")
            for i, e in enumerate(io):
                lbl = e.get("label") or "?"
                m.write(f"<details><summary>req {i + 1}: `{lbl}` → HTTP {e.get('status')}</summary>\n\n```graphql\n"
                        + str(e.get("query", ""))[:2000] + "\n```\n")
                if e.get("variables"):
                    m.write("vars: `" + json.dumps(e["variables"], default=str)[:1500] + "`\n\n")
                dat, err = e.get("data"), e.get("errors")
                if dat is not None:
                    dat = dat if isinstance(dat, str) else json.dumps(dat, default=str)
                    m.write("data:\n```json\n" + dat[:6000] + "\n```\n")
                if err:
                    err = err if isinstance(err, str) else json.dumps(err, default=str)
                    m.write("errors:\n```json\n" + err[:3000] + "\n```\n")
                m.write("\n</details>\n\n")
        m.write("**Model raw output:**\n\n```\n" + str(rec.get("raw_response", ""))[:8000] + "\n```\n\n")
        if rec.get("self_report"):
            m.write(f"**Self-report applied:** {rec['self_report']}\n\n")
        obs = rec.get("observations") or []
        if obs:
            m.write("**Observation(s) the model actually saw next turn (bounded):**\n\n```\n"
                    + "\n".join(str(o) for o in obs)[:6000] + "\n```\n\n")
        led = st.get("ledger", {}) or {}
        led_lines = "; ".join(
            f"{f}:{e.get('verdict') or e.get('auto') or '?'}(x{e.get('attempts', 0)})"
            + ("⚠" if e.get("finding") else "")
            for f, e in list(led.items())[:25])
        m.write(f"**State after** — identity={st.get('identity')} · findings={st.get('findings')} · "
                f"creds={len(st.get('credentials', []))} · harvested={st.get('harvested')}\n\n")
        if st.get("searched"):
            m.write("  searched: " + ", ".join(st["searched"]) + "\n\n")
        if st.get("facts"):
            m.write("  facts: " + " | ".join(st["facts"]) + "\n\n")
        m.write(f"  ledger: {led_lines or '(empty)'}\n\n")
        if self.count == 1:
            m.write("<details><summary>full prompt (step 1 — later prompts in the .jsonl)</summary>\n\n```\n"
                    + str(rec.get("prompt", ""))[:40000] + "\n```\n\n</details>\n\n")

    def close(self, summary: dict[str, Any]) -> None:
        try:
            self._jf.write(json.dumps({"summary": summary}, default=str) + "\n")
            self._mf.write("\n---\n\n## Summary\n\n```json\n" + json.dumps(summary, indent=2, default=str) + "\n```\n")
        except Exception:  # noqa: BLE001
            pass
        finally:
            for fh in (self._jf, self._mf):
                try:
                    fh.close()
                except Exception:  # noqa: BLE001
                    pass
