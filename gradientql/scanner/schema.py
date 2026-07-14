"""Schema — introspection parsing, schema search, the attack-surface overview, and `sweep`."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from .harvest import is_introspection_query
from .senses import _AUTH_ERR_MARKERS

logger = logging.getLogger("gradientql.scanner")

_SEMANTIC_INDEX_MIN_FIELDS = 80


def _resolve_type_ref(type_info: dict[str, Any] | None) -> str:
    if type_info is None:
        return "Unknown"
    kind = type_info.get("kind", "")
    name = type_info.get("name")
    of_type = type_info.get("ofType")
    if kind == "NON_NULL":
        return f"{_resolve_type_ref(of_type) if of_type else 'Unknown'}!"
    if kind == "LIST":
        return f"[{_resolve_type_ref(of_type) if of_type else 'Unknown'}]"
    if name:
        return name
    return "Unknown"


def parse_schema(introspection_data: dict[str, Any]) -> dict[str, Any]:
    """Flatten an introspection result into a schema_map keyed by type name.

    Root/meta entries live under underscore keys (`_query_type`, `_mutation_type`,
    `_input_types`, `_enum_types`, `_interfaces`, `_unions`, `_type_kinds`); every
    other key maps a type name to its field map.
    """
    schema = introspection_data.get("data", {}).get("__schema", {})
    types = schema.get("types", [])

    query_type_name = (schema.get("queryType") or {}).get("name", "Query")
    mutation_type_name = (schema.get("mutationType") or {}).get("name", "Mutation")
    subscription_type_name = (schema.get("subscriptionType") or {}).get("name") or ""

    input_types: dict[str, list[dict[str, str]]] = {}
    for t in types:
        if t.get("kind") == "INPUT_OBJECT" and t.get("inputFields"):
            input_types[t["name"]] = [
                {"name": f["name"], "type": _resolve_type_ref(f.get("type", {})),
                 "default": f.get("defaultValue")}
                for f in t["inputFields"]
            ]

    enum_types: dict[str, list[str]] = {}
    for t in types:
        if t.get("kind") == "ENUM" and t.get("enumValues"):
            values = [v["name"] for v in t["enumValues"] if not v.get("isDeprecated")]
            if values:
                enum_types[t["name"]] = values

    schema_map: dict[str, Any] = {}
    interface_types: set[str] = set()
    union_types: set[str] = set()
    type_kinds: dict[str, str] = {}

    for t in types:
        type_name = t.get("name", "")
        kind = t.get("kind", "")
        if kind == "INTERFACE":
            interface_types.add(type_name)
            type_kinds[type_name] = "INTERFACE"
        elif kind == "UNION":
            union_types.add(type_name)
            type_kinds[type_name] = "UNION"

    for t in types:
        type_name = t.get("name", "")
        if type_name.startswith("__"):
            continue
        kind = t.get("kind", "")
        fields = t.get("fields")

        if kind == "UNION":
            possible_types = [pt.get("name") for pt in t.get("possibleTypes", []) if pt.get("name")]
            schema_map[type_name] = {"_kind": "UNION", "_possible_types": possible_types}
            continue
        if kind not in ("OBJECT", "INTERFACE") or not fields:
            continue

        field_map: dict[str, Any] = {}
        for field in fields:
            args_list = [
                {"name": arg["name"], "type": _resolve_type_ref(arg.get("type", {})),
                 "default": arg.get("defaultValue")}
                for arg in field.get("args", [])
            ]
            field_map[field["name"]] = {
                "args": args_list,
                "return_type": _resolve_type_ref(field.get("type", {})),
                "description": field.get("description") or "",
            }
        if kind == "INTERFACE":
            field_map["_kind"] = "INTERFACE"
            field_map["_possible_types"] = [
                pt.get("name") for pt in t.get("possibleTypes", []) if pt.get("name")
            ]
        schema_map[type_name] = field_map

    schema_map["_input_types"] = input_types
    schema_map["_enum_types"] = enum_types
    schema_map["_query_type"] = query_type_name
    schema_map["_mutation_type"] = mutation_type_name
    schema_map["_subscription_type"] = subscription_type_name
    schema_map["_interfaces"] = interface_types
    schema_map["_unions"] = union_types
    schema_map["_type_kinds"] = type_kinds
    return schema_map


def _create_chunks(schema_map: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    chunks: list[str] = []
    metadatas: list[dict[str, Any]] = []
    input_types = schema_map.get("_input_types", {})

    for type_name, fields in schema_map.items():
        if type_name.startswith("_") or not isinstance(fields, dict):
            continue
        for field_name, field_info in fields.items():
            if not isinstance(field_info, dict):
                continue
            args = field_info.get("args", [])
            return_type = field_info.get("return_type", "Unknown")
            description = field_info.get("description", "")

            args_parts = []
            for arg in args:
                arg_str = f"{arg['name']}: {arg['type']}"
                base_type = arg["type"].rstrip("!").strip("[]").rstrip("!")
                if base_type in input_types:
                    nested = ", ".join(f"{f['name']}: {f['type']}" for f in input_types[base_type])
                    arg_str += f" {{ {nested} }}"
                args_parts.append(arg_str)
            args_str = ", ".join(args_parts) if args_parts else "none"

            chunk = (f"Type: {type_name}\nField: {field_name}\n"
                     f"Args: {args_str}\nReturns: {return_type}\n")
            if description:
                chunk += f"Description: {description}\n"
            chunks.append(chunk)
            metadatas.append({"type": "schema", "type_name": type_name,
                              "field_name": field_name, "node_path": f"{type_name}.{field_name}"})
    return chunks, metadatas


def build_schema_index(schema_map: dict[str, Any], model_name: str | None = None) -> Any:
    """Build a semantic vector index over schema fields, or None if unavailable.

    Returns None (and logs) when embeddings can't be built, signalling callers to
    fall back to lexical search.
    """
    try:
        from ..core.rag import SchemaVectorStore
        chunks, metadatas = _create_chunks(schema_map)
        if not chunks:
            return None
        store = SchemaVectorStore(model_name) if model_name else SchemaVectorStore()
        logger.info("AGENT: building semantic schema index (%d fields)…", len(chunks))
        store.build_from_chunks(chunks, metadatas)
        logger.info("AGENT: semantic schema index ready")
        return store
    except Exception as e:  # noqa: BLE001
        logger.info("AGENT: semantic index unavailable (%s) — using lexical schema search", e)
        return None


def field_count(schema_map: dict[str, Any]) -> int:
    return sum(len(v) for k, v in schema_map.items()
               if not k.startswith("_") and isinstance(v, dict))


def _fmt_field(schema_map: dict[str, Any], type_name: str, field: str) -> str:
    info = (schema_map.get(type_name, {}) or {}).get(field, {})
    args = ", ".join(f'{a.get("name")}: {a.get("type")}' for a in (info.get("args") or []))
    ret = info.get("return_type", "")
    return f"{type_name}.{field}({args}): {ret}"


def _lexical_hits(schema_map: dict[str, Any], keyword: str) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    kw = (keyword or "").lower()
    if not kw:
        return [], []
    field_hits: list[tuple[str, str]] = []
    for type_name, fields in schema_map.items():
        if type_name.startswith("_") or not isinstance(fields, dict):
            continue
        for field, info in fields.items():
            if not isinstance(info, dict):
                continue
            arg_bits = " ".join(f"{a.get('name', '')} {a.get('type', '')}"
                                for a in (info.get("args") or []))
            hay = f"{type_name}.{field} {info.get('return_type', '')} {arg_bits}"
            if kw in hay.lower():
                field_hits.append((_fmt_field(schema_map, type_name, field), f"{type_name}.{field}"))
    typed_hits: list[tuple[str, str]] = []
    for itype, leaves in (schema_map.get("_input_types", {}) or {}).items():
        if kw in itype.lower():
            ls = ", ".join(f'{f.get("name")}: {f.get("type")}' for f in leaves)
            typed_hits.append((f"input {itype} {{ {ls} }}", f"input:{itype}"))
    for etype, values in (schema_map.get("_enum_types", {}) or {}).items():
        if kw in etype.lower():
            vs = ", ".join(values[:40]) + (" …" if len(values) > 40 else "")
            typed_hits.append((f"enum {etype} {{ {vs} }}", f"enum:{etype}"))
    return field_hits, typed_hits


def _cap_hits(fields: list[str], typed: list[str], sem: list[str], total: int, limit: int) -> list[str]:
    need_more = total > limit
    budget = (limit - 1) if need_more else limit
    typed_keep = typed[:budget]
    room = budget - len(typed_keep)
    field_keep = fields[:room]
    room -= len(field_keep)
    items = field_keep + typed_keep + sem[:room]
    if need_more:
        items.append(f"(+{total - len(items)} more — refine keyword)")
    return items


def search_schema(schema_map: dict[str, Any], keyword: str, limit: int = 20, store: Any = None) -> list[str]:
    """Search the schema by keyword, merging lexical hits with optional semantic ones.

    Semantic hits from `store` fill the remaining budget after lexical field/type
    hits, deduped against them.
    """
    field_hits, typed_hits = _lexical_hits(schema_map, keyword)
    total = len(field_hits) + len(typed_hits)
    fields = [rendered for rendered, _ in field_hits]
    typed = [rendered for rendered, _ in typed_hits]
    if store is None or not keyword:
        return _cap_hits(fields, typed, [], total, limit)

    seen = {key for _, key in field_hits} | {key for _, key in typed_hits}
    try:
        docs = store.similarity_search(keyword, k=limit, filter_type="schema")
    except Exception:  # noqa: BLE001
        return _cap_hits(fields, typed, [], total, limit)
    sem: list[str] = []
    for doc in docs:
        if len(sem) >= limit:
            break
        md = getattr(doc, "metadata", {}) or {}
        tn, fn = md.get("type_name"), md.get("field_name")
        if not tn or not fn:
            continue
        if fn not in (schema_map.get(tn) or {}):
            continue
        key = f"{tn}.{fn}"
        if key in seen:
            continue
        seen.add(key)
        sem.append("~ " + _fmt_field(schema_map, tn, fn) + "  (semantic)")
    return _cap_hits(fields, typed, sem, total, limit)


_SURFACE_BUCKETS = (
    ("AUTH / TOKEN / SESSION", ("token", "login", "sign", "sso", "oauth", "session", "password",
                                "confirm", "auth", "bearer", "otp", "2fa", "mfa", "revoke", "credential")),
    ("ADMIN / PRIVILEGED", ("admin", "internal", "manage", "privileg", "staff", "backoffice", "impersonat")),
    ("CUSTOMER / PII", ("customer", "address", "wishlist", "profile", "account", "subscriber", "contact")),
    ("ORDER / CART / CHECKOUT", ("order", "cart", "checkout", "quote", "invoice", "shipment", "return", "rma")),
    ("PAYMENT", ("payment", "adyen", "paypal", "klarna", "refund", "vault", "card", "stripe",
                 "braintree", "transaction", "giftcard", "reward")),
    ("FILE / URL / SSRF", ("url", "image", "file", "upload", "redirect", "webhook", "route",
                           "resolver", "import", "media", "attachment")),
    ("PRODUCT / SEARCH", ("product", "search", "category", "catalog", "review", "compare")),
)


def _surface_bucket(name: str, ret: str) -> str | None:
    low = f"{name} {ret}".lower()
    for label, kws in _SURFACE_BUCKETS:
        if any(k in low for k in kws):
            return label
    return None


def render_schema_overview(schema_map: dict[str, Any], sig_cap: int = 24, other_cap: int = 50) -> str:
    qroot = schema_map.get("_query_type", "Query")
    mroot = schema_map.get("_mutation_type", "Mutation")
    buckets: dict[str, list[str]] = {label: [] for label, _ in _SURFACE_BUCKETS}
    other: dict[str, list[str]] = {"Q": [], "M": []}
    for root, tag in ((qroot, "Q"), (mroot, "M")):
        fields = schema_map.get(root)
        if not isinstance(fields, dict):
            continue
        for fname, info in fields.items():
            if fname.startswith("_") or not isinstance(info, dict):
                continue
            ret = info.get("return_type", "")
            args = ", ".join(f"{a.get('name')}: {a.get('type')}" for a in (info.get("args") or [])[:6])
            sig = f"{fname}({args})" if args else fname
            label = _surface_bucket(fname, ret)
            if label:
                buckets[label].append(f"{tag}:{fname}({args}): {ret}")
            else:
                other[tag].append(f"{sig}: {ret}" if ret else sig)
    out: list[str] = []
    for label, _ in _SURFACE_BUCKETS:
        items = buckets[label]
        if not items:
            continue
        extra = f"  (+{len(items) - sig_cap} more — search to see)" if len(items) > sig_cap else ""
        out.append(f"  {label}:\n    " + "\n    ".join(items[:sig_cap]) + extra)
    for tag, kind in (("Q", "other queries"), ("M", "other mutations")):
        names = other[tag]
        if names:
            tail = f" (+{len(names) - other_cap})" if len(names) > other_cap else ""
            out.append(f"  {kind}: " + ", ".join(names[:other_cap]) + tail)
    return "\n".join(out) if out else "  (no root fields)"


def _sweepable_query_fields(schema_map: dict[str, Any]) -> list[tuple[str, dict]]:
    qroot = schema_map.get("_query_type", "Query")
    fields = schema_map.get(qroot)
    out: list[tuple[str, dict]] = []
    if not isinstance(fields, dict):
        return out
    for fname, info in fields.items():
        if fname.startswith("_") or not isinstance(info, dict):
            continue
        if any(str(a.get("type", "")).rstrip().endswith("!") for a in (info.get("args") or [])):
            continue
        out.append((fname, info))
    return out


def _base_type_name(type_ref: str) -> str:
    return re.sub(r"[\[\]!]", "", str(type_ref or "")).strip()


def _minimal_selection(schema_map: dict[str, Any], return_type: str) -> str:
    base = _base_type_name(return_type)
    inner = schema_map.get(base)
    if not isinstance(inner, dict):
        return ""
    nodes = inner.get("nodes")
    if isinstance(nodes, dict):
        node_t = schema_map.get(_base_type_name(nodes.get("return_type", "")))
        return "{ nodes { id } }" if isinstance(node_t, dict) and "id" in node_t else "{ nodes { __typename } }"
    edges = inner.get("edges")
    if isinstance(edges, dict):
        edge_t = schema_map.get(_base_type_name(edges.get("return_type", "")))
        node_field = edge_t.get("node") if isinstance(edge_t, dict) else None
        node_t = (schema_map.get(_base_type_name(node_field.get("return_type", "")))
                  if isinstance(node_field, dict) else None)
        return ("{ edges { node { id } } }" if isinstance(node_t, dict) and "id" in node_t
                else "{ edges { node { __typename } } }")
    if "id" in inner:
        return "{ id }"
    return "{ __typename }"


def _scalar_leaves(schema_map: dict[str, Any], type_ref: str, cap: int = 8) -> list[str]:
    fields = schema_map.get(_base_type_name(type_ref))
    if not isinstance(fields, dict):
        return []
    out: list[str] = []
    for fname, finfo in fields.items():
        if str(fname).startswith("_") or not isinstance(finfo, dict):
            continue
        if any(str(a.get("type", "")).rstrip().endswith("!") for a in (finfo.get("args") or [])):
            continue
        if not isinstance(schema_map.get(_base_type_name(finfo.get("return_type", ""))), dict):
            out.append(fname)
        if len(out) >= cap:
            break
    return out


def fuzz_selection(schema_map: dict[str, Any], return_type: str, cap: int = 8) -> str:
    """Build a wide selection set of scalar leaves for fuzzing a field's return type.

    Unwraps Relay `nodes`/`edges { node }` connections; falls back to a minimal
    selection when no scalar leaves exist.
    """
    inner = schema_map.get(_base_type_name(return_type))
    if not isinstance(inner, dict):
        return ""

    def _is_object(type_ref: str) -> bool:
        return isinstance(schema_map.get(_base_type_name(type_ref)), dict)

    nodes = inner.get("nodes")
    if isinstance(nodes, dict) and _is_object(nodes.get("return_type", "")):
        leaves = _scalar_leaves(schema_map, nodes.get("return_type", ""), cap)
        return "{ nodes { " + " ".join(leaves or ["__typename"]) + " } }"
    edges = inner.get("edges")
    if isinstance(edges, dict) and _is_object(edges.get("return_type", "")):
        edge_t = schema_map.get(_base_type_name(edges.get("return_type", "")))
        node_field = edge_t.get("node") if isinstance(edge_t, dict) else None
        if isinstance(node_field, dict) and _is_object(node_field.get("return_type", "")):
            leaves = _scalar_leaves(schema_map, node_field.get("return_type", ""), cap)
            return "{ edges { node { " + " ".join(leaves or ["__typename"]) + " } } }"
    leaves = _scalar_leaves(schema_map, return_type, cap)
    return "{ " + " ".join(leaves) + " }" if leaves else _minimal_selection(schema_map, return_type)


def _sweep_query(schema_map: dict[str, Any], fields: list[tuple[str, dict]]) -> tuple[str, dict[str, str]]:
    alias_map: dict[str, str] = {}
    parts: list[str] = []
    for idx, (fname, info) in enumerate(fields):
        alias = f"s{idx}"
        alias_map[alias] = fname
        sel = _minimal_selection(schema_map, info.get("return_type", ""))
        parts.append(f"{alias}: {fname} {sel}".strip())
    return "query { " + " ".join(parts) + " }", alias_map


def _is_empty_record(val: Any) -> bool:
    if not isinstance(val, dict):
        return False
    if "nodes" in val or "edges" in val:
        return not val.get("nodes") and not val.get("edges")
    keys = set(val.keys()) - {"__typename"}
    if keys <= {"id"}:
        return not val.get("id")
    return False


def _sweep_parse(alias_map: dict[str, str], data: dict, errors: list) -> list[tuple[str, str, str]]:
    err_by_alias: dict[str, str] = {}
    for e in errors:
        path = e.get("path") or []
        if path and isinstance(path[0], str):
            err_by_alias.setdefault(path[0], str(e.get("message", "")))
    out: list[tuple[str, str, str]] = []
    for alias, field in alias_map.items():
        if alias in err_by_alias:
            msg = err_by_alias[alias]
            outcome = "AUTH-BLOCKED" if any(m in msg.lower() for m in _AUTH_ERR_MARKERS) else "ERROR"
            out.append((field, outcome, msg[:60]))
        elif data.get(alias) in (None, [], {}, "") or _is_empty_record(data.get(alias)):
            out.append((field, "null/empty", ""))
        else:
            out.append((field, "DATA", json.dumps(data.get(alias), default=str)[:60]))
    return out


def _sweep_recurse(client: Any, schema_map: dict[str, Any], fields: list[tuple[str, dict]],
                   extra_headers: dict | None, budget: list[int]) -> tuple[list[tuple[str, str, str]], dict]:
    """Execute a batched sweep, bisecting to isolate fields that reject the whole query.

    A partial (non-null data) response is read per-alias directly; a hard error
    triggers binary splitting to find the offending field(s). `budget` is a
    one-element list acting as a shared decrementing request counter.
    """
    if not fields or budget[0] <= 0:
        return [(f, "ERROR", "sweep budget exhausted") for f, _ in fields], {}
    budget[0] -= 1
    query, alias_map = _sweep_query(schema_map, fields)
    resp = client.execute(query, extra_headers=extra_headers)
    data = resp.get("data")
    errors = resp.get("errors") or []
    if isinstance(data, dict):
        return _sweep_parse(alias_map, data, errors), resp
    bad = [str(e["path"][0]) for e in errors
           if e.get("path") and isinstance(e["path"][0], str) and e["path"][0] in alias_map]
    if bad:
        bad_results: list[tuple[str, str, str]] = []
        offending: set[str] = set()
        for a in dict.fromkeys(bad):
            fld = alias_map[a]
            offending.add(fld)
            msg = next((str(e.get("message", "")) for e in errors if (e.get("path") or [None])[0] == a), "")
            outcome = "AUTH-BLOCKED" if any(m in msg.lower() for m in _AUTH_ERR_MARKERS) else "ERROR"
            bad_results.append((fld, outcome, msg[:60]))
        remaining = [(f, i) for f, i in fields if f not in offending]
        if remaining:
            rest, rest_resp = _sweep_recurse(client, schema_map, remaining, extra_headers, budget)
            return bad_results + rest, (rest_resp or resp)
        return bad_results, resp
    if len(fields) == 1:
        msg = (errors or [{}])[0].get("message") if errors else None
        return [(fields[0][0], "ERROR", str(msg or "query rejected")[:60])], resp
    mid = len(fields) // 2
    left, lr = _sweep_recurse(client, schema_map, fields[:mid], extra_headers, budget)
    right, rr = _sweep_recurse(client, schema_map, fields[mid:], extra_headers, budget)
    return left + right, (rr or lr or resp)


def tool_sweep(client: Any, schema_map: dict[str, Any], exclude: set[str], limit: int = 40,
               extra_headers: dict | None = None) -> tuple[str | None, str, list[tuple[str, str, str]], dict]:
    """Batch-probe every no-arg query field (minus `exclude`) to tally reachability.

    Returns (batched_query, summary, per-field results, last raw response), or a
    None query with a guidance string when the sweep surface is exhausted.
    """
    fields = [(f, i) for f, i in _sweepable_query_fields(schema_map) if f not in exclude][:limit]
    if not fields:
        return None, ("SWEEP EXHAUSTED — every no-arg query field has been swept. STOP sweeping; it will "
                      "keep returning this. Drill required-arg fields & mutations individually with "
                      "graphql/fuzz, and pivot to injection/SSRF/DoS/auth."), [], {}
    full_query, _ = _sweep_query(schema_map, fields)
    results, resp = _sweep_recurse(client, schema_map, fields, extra_headers, budget=[16])
    tally: dict[str, int] = {}
    for _, outcome, _ in results:
        tally[outcome] = tally.get(outcome, 0) + 1
    summary = (f"swept {len(fields)} fields -> {tally.get('DATA', 0)} DATA, "
               f"{tally.get('AUTH-BLOCKED', 0)} auth-blocked, {tally.get('null/empty', 0)} null, "
               f"{tally.get('ERROR', 0)} error")
    return full_query, summary, results, resp


def render_type_shape(schema_map: dict[str, Any], name: str) -> str | None:
    """Render a known input/enum/object type's shape, or None if the name is unknown."""
    it = (schema_map.get("_input_types") or {}).get(name)
    if it:
        leaves = ", ".join(f'{f.get("name")}: {f.get("type")}' for f in it)
        return f"input {name} {{ {leaves} }}"
    enums = (schema_map.get("_enum_types") or {}).get(name)
    if enums:
        return f"enum {name} {{ {', '.join(enums)} }}"
    obj = schema_map.get(name)
    if isinstance(obj, dict):
        names = [f for f in obj if not f.startswith("_")]
        sig = ", ".join(_fmt_field(schema_map, name, f) for f in names[:30])
        more = f"  (+{len(names) - 30} more — search_schema)" if len(names) > 30 else ""
        return f"type {name} {{ {sig} }}{more}"
    return None


_RE_INTROSPECT_TYPE = re.compile(r'__type\s*\(\s*name\s*:\s*"([^"]+)"')


def introspection_shortcut(query: str, schema_map: dict[str, Any]) -> str | None:
    """Answer an introspection query from the cached schema without sending a request.

    Returns None when the query isn't introspection; otherwise a message (type
    shapes for `__type(name:)`, or a nudge to use search_schema) served with no
    HTTP call.
    """
    if not is_introspection_query(query):
        return None
    names = _RE_INTROSPECT_TYPE.findall(query)
    if names:
        lines = [render_type_shape(schema_map, n) or f"{n}: not a known composite type (scalar/enum/typo?)"
                 for n in dict.fromkeys(names)]
        return ("served from the already-introspected schema (NO request sent — __type queries return the "
                "whole schema dump on many servers, so use this):\n  " + "\n  ".join(lines))
    return ("you ALREADY hold the full introspected schema — do NOT re-introspect with __schema/__type "
            "(it returns the entire multi-thousand-field schema and tells you nothing new). Use "
            "`search_schema <keyword>` to find fields/types/inputs, or query a concrete field.")


_AUTH_MUT_KEYWORDS = ("login", "signin", "sign_in", "token", "register", "signup", "sign_up",
                      "session", "authenticate", "oauth", "credential", "jwt")


def auth_mutations(schema_map: dict[str, Any]) -> list[str]:
    mroot = schema_map.get("_mutation_type", "Mutation")
    fields = schema_map.get(mroot)
    if not isinstance(fields, dict):
        return []
    out: list[str] = []
    for fname, info in fields.items():
        if fname.startswith("_") or not isinstance(info, dict):
            continue
        low = fname.lower()
        ret = str(info.get("return_type", "")).lower()
        if any(k in low for k in _AUTH_MUT_KEYWORDS) or "token" in ret or "session" in ret:
            out.append(fname)
    return out
