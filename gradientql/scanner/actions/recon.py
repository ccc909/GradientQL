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
    """Recover a schema map from validation errors when introspection is disabled.

    Crawls the endpoint - marking undefined fields invalid, reading each valid field's return type
    and required args, and recursing into the object types they return - then merges the recovered
    fields, types, and args into schema_map so the rest of the loop drills real fields, not guesses.
    """
    from ...utils.clairvoyance import merge_into_schema, recover_schema

    wl = args.get("wordlist") if isinstance(args.get("wordlist"), list) and args.get("wordlist") else None
    try:
        recovered = recover_schema(ctx.client, ctx.identity or None, wordlist=wl)
    except Exception as e:  # noqa: BLE001
        ctx.log(f"[{ctx.step}] clairvoyance ERROR: {str(e)[:120]}")
        return Result(observation=f"clairvoyance ERROR: {str(e)[:120]}", touched_target=True)

    added = merge_into_schema(ctx.schema_map, recovered)
    n_types = len([k for k in recovered if not k.startswith("_") and recovered[k]])
    q = recovered.get("Query") or {}
    m = recovered.get("Mutation") or {}
    if not added and not q and not m:
        obs = ("clairvoyance: no fields recovered - the server returns generic errors with no per-field "
               "validation detail (no 'undefined'/'must have a selection'/'missing argument'). "
               "Introspection may actually be open (try __schema), or field-name probing is blocked.")
    else:
        def _fmt(fields):
            return ", ".join(f"{f}{'(' + ','.join(a['name'] for a in i['args']) + ')' if i.get('args') else ''}"
                             f"{':' + i['return_type'] if i.get('return_type') else ''}"
                             for f, i in list(fields.items())[:20]) or "-"
        obs = (f"clairvoyance recovered {added} field(s) across {n_types} type(s) and merged them into "
               f"the schema map - drill these directly now, no more guessing:\n"
               f"  Query: {_fmt(q)}\n  Mutation: {_fmt(m)}\n"
               f"  types: {', '.join(k for k in recovered if not k.startswith('_') and k not in ('Query', 'Mutation') and recovered[k]) or '-'}")
    ctx.log(f"[{ctx.step}] clairvoyance -> {added} fields, {n_types} types")
    return Result(observation=obs, touched_target=True)
