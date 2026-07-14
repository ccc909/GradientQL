"""Recon action handlers: sweep (bulk surface mapping), search_schema, note."""

from __future__ import annotations

from . import action
from .context import ActionContext, Result
from ..harvest import harvest
from ..memory import blank_entry, identity_label
from ..schema import search_schema, tool_sweep
from ..senses import is_dead, run_detectors


@action("sweep")
def handle_sweep(ctx: ActionContext, args: dict) -> Result:
    """Probe many not-yet-tried root fields in one batch, recording each outcome in the ledger."""
    idlabel = identity_label(ctx.identity)
    swept_here = {f for f, e in ctx.ledger.items() if e.get("identity") == idlabel}
    try:
        q, summary, results, resp = tool_sweep(ctx.client, ctx.schema_map, swept_here,
                                                extra_headers=ctx.identity or None)
    except Exception as e:  # noqa: BLE001
        ctx.log(f"[{ctx.step}] sweep ERROR: {str(e)[:120]}")
        return Result(observation=f"sweep ERROR: {str(e)[:120]}")
    if q is None:
        ctx.log(f"[{ctx.step}] sweep -> {summary}")
        return Result(observation=summary)

    ctx.trace_io(q, {}, resp, label="sweep")
    dead = is_dead(resp.get("_status_code", 0))
    data_fields: list[str] = []
    for fld, outcome, snip in results:
        e = ctx.ledger.setdefault(fld, blank_entry(fld, idlabel, ctx.step))
        e.update(attempts=e.get("attempts", 0) + 1, auto=outcome, step=ctx.step, identity=idlabel)
        if snip:
            e["sig"] = snip
        if outcome == "DATA":
            data_fields.append(fld)
    harvest(resp, ctx.harvested)
    for vt, reason in run_detectors(q, resp):
        ctx.record(vt, "sweep", reason, 3.0)
    ctx.covered.add(q[:60])
    obs = summary + (f" | DATA from: {', '.join(data_fields[:18])}" if data_fields else "")
    ctx.log(f"[{ctx.step}] sweep -> {obs}")
    return Result(observation=obs, touched_target=True, is_dead=dead)


@action("search_schema")
def handle_search_schema(ctx: ActionContext, args: dict) -> Result:
    kw = str(args.get("keyword", ""))
    nkw = kw.strip().lower()
    if nkw and nkw not in (s.lower() for s in ctx.searched):
        ctx.searched.append(kw.strip())
    hits = search_schema(ctx.schema_map, kw, store=ctx.schema_index)
    obs = "\n   ".join(hits[:20]) or "(no matches)"
    ctx.log(f"[{ctx.step}] search_schema '{kw}' ->\n   {obs}")
    return Result(observation=obs)


@action("note")
def handle_note(ctx: ActionContext, args: dict) -> Result:
    text = str(args.get("text", ""))[:300]
    ctx.notes.append(text)
    ctx.log(f"[{ctx.step}] note: {text[:120]}")
    return Result(observation="noted")
