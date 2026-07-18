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


@action("clairvoyance")
def handle_clairvoyance(ctx: ActionContext, args: dict) -> Result:
    """Recover root field names from validation-error suggestions when introspection is disabled.

    Fires a wordlist (or the caller's) at the endpoint and mines "did you mean"/needs-selection
    errors, then merges any newly-discovered fields into schema_map so the rest of the loop can
    drill them with graphql/search_schema.
    """
    from ..schema import _minimal_selection  # noqa: F401  (kept for parity; recovery is name-level)
    from ...utils.clairvoyance import DEFAULT_WORDLIST, recover_root_fields

    wl = args.get("wordlist") if isinstance(args.get("wordlist"), list) and args.get("wordlist") else DEFAULT_WORDLIST
    extra = ctx.identity or None
    try:
        q_fields = recover_root_fields(ctx.client, "query", wl, extra)
        m_fields = recover_root_fields(ctx.client, "mutation", wl, extra)
    except Exception as e:  # noqa: BLE001
        ctx.log(f"[{ctx.step}] clairvoyance ERROR: {str(e)[:120]}")
        return Result(observation=f"clairvoyance ERROR: {str(e)[:120]}", touched_target=True)

    added = 0
    for root_key, default, names in (("_query_type", "Query", q_fields),
                                     ("_mutation_type", "Mutation", m_fields)):
        root = ctx.schema_map.get(root_key, default)
        bucket = ctx.schema_map.setdefault(root, {})
        ctx.schema_map.setdefault(root_key, root)
        if not isinstance(bucket, dict):
            continue
        for n in names:
            if n not in bucket:
                bucket[n] = {"args": [], "return_type": "", "description": "(recovered via clairvoyance)"}
                added += 1

    total = len(q_fields) + len(m_fields)
    if not total:
        obs = ("clairvoyance: the suggestion oracle leaked no field names (server returns generic "
               "errors with no 'did you mean' - suggestions are off, or introspection is actually open: "
               "just query __schema).")
    else:
        obs = (f"clairvoyance recovered {total} root field name(s) via the suggestion oracle "
               f"({added} new, merged into the schema map):\n  query: {', '.join(sorted(q_fields)) or '-'}\n"
               f"  mutation: {', '.join(sorted(m_fields)) or '-'}\n"
               "  Drill these with graphql { __typename } to confirm, then add real subfields.")
    ctx.log(f"[{ctx.step}] clairvoyance -> recovered {total} ({added} new)")
    return Result(observation=obs, touched_target=True)
