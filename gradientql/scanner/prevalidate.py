"""Reject queries the schema proves invalid before sending."""

from __future__ import annotations

import difflib
import re
from typing import Any

from .schema import _fmt_field, _schema_recovered

_MAX_DEPTH = 8


def _base_type(type_ref: str) -> str:
    return re.sub(r"[\[\]!]", "", str(type_ref or "")).strip()


def _field_names(fields: dict[str, Any]) -> list[str]:
    return [f for f in fields if not str(f).startswith("_")]


def _is_object_type(fields: Any) -> bool:
    if not isinstance(fields, dict):
        return False
    if fields.get("_kind") in ("UNION", "INTERFACE"):
        return False
    return bool(_field_names(fields))


def prevalidate_query(query: str, variables: dict[str, Any], schema_map: dict[str, Any]) -> str | None:
    """Reject a query the schema already proves invalid, before any request is sent.

    Returns None when nothing is provably wrong (send it) or graphql isn't
    available; otherwise an error string naming the bad field or missing required
    argument.
    """
    if not query or not schema_map:
        return None
    q = query.strip()
    if q.startswith("["):
        return None
    if "..." in q or "fragment " in q:
        return None

    try:
        from graphql import parse
        from graphql.language import ast as gast
    except Exception:  # noqa: BLE001
        return None
    try:
        doc = parse(query)
    except Exception:  # noqa: BLE001
        return None

    ops = [d for d in doc.definitions if isinstance(d, gast.OperationDefinitionNode)]
    if len(ops) > 1:
        return ("PRE-VALIDATION (no request sent): your document has "
                f"{len(ops)} operations - servers reject multi-operation documents, and mixing "
                "reads and writes entangles the outcomes. Send ONE operation per request.")
    if not ops:
        return None
    op = ops[0]
    op_type = getattr(op.operation, "value", str(op.operation)).lower()
    if op_type == "mutation" and op.selection_set is not None:
        n_mut_fields = sum(1 for s in op.selection_set.selections
                       if isinstance(s, gast.FieldNode))
        if n_mut_fields >= 2:
            return ("PRE-VALIDATION (no request sent): you batched "
                    f"{n_mut_fields} state-changing fields in one mutation - if any errors, "
                    "every result is ENTANGLED and untrustworthy. Send each state-changing "
                    "mutation ALONE (or use auth_test, which isolates them).")
    if op_type == "query":
        root_type = schema_map.get("_query_type", "Query")
    elif op_type == "mutation":
        root_type = schema_map.get("_mutation_type", "Mutation")
    else:
        return None
    root_fields = schema_map.get(root_type)
    if not _is_object_type(root_fields):
        return None

    # A clairvoyance-recovered schema is PARTIAL and its return types can be wrong (a field the
    # crawler couldn't resolve may point at the root type), so field/subselection checks here would
    # FALSELY reject valid queries. The multi-operation / batched-mutation checks above still apply;
    # for everything else, trust the server's own validation.
    if _schema_recovered(schema_map):
        return None

    errors: list[str] = []
    _validate_selection(op.selection_set, root_type, schema_map, variables or {}, 0, errors,
                        gast, check_args=True)
    if not errors:
        return None
    head = "PRE-VALIDATION (no request sent): "
    body = " ".join(errors[:2])
    tail = (" Re-run with valid fields; use { __typename } to confirm a field is reachable "
            "before adding subfields.")
    return head + body + tail


def _validate_selection(sel_set: Any, type_name: str, schema_map: dict[str, Any],
                        variables: dict[str, Any], depth: int, errors: list[str], gast: Any,
                        check_args: bool) -> None:
    if sel_set is None or depth > _MAX_DEPTH or errors:
        return
    fields = schema_map.get(type_name)
    if not _is_object_type(fields):
        return
    valid_names = _field_names(fields)

    for sel in sel_set.selections:
        if not isinstance(sel, gast.FieldNode):
            return
        name = sel.name.value
        if name.startswith("__"):
            continue
        if name not in fields:
            suggestions = difflib.get_close_matches(name, valid_names, n=3, cutoff=0.5)
            sg = f" Did you mean: {', '.join(suggestions)}?" if suggestions else ""
            valid_list = ", ".join(valid_names[:25]) + (" …" if len(valid_names) > 25 else "")
            errors.append(f"field `{name}` is not a field of type `{type_name}`.{sg} "
                          f"Valid fields of {type_name}: {valid_list}.")
            return
        info = fields[name]
        if check_args:
            missing = _missing_required_args(info, sel, gast, schema_map)
            if missing:
                arg_name, arg_type, parent = missing
                where = f"input `{parent}`" if parent else f"`{_fmt_field(schema_map, type_name, name)}`"
                errors.append(f"{where} requires `{arg_name}: {arg_type}` which you did not provide.")
                return
        if sel.selection_set is not None:
            base = _base_type(info.get("return_type", ""))
            _validate_selection(sel.selection_set, base, schema_map, variables, depth + 1, errors,
                                gast, check_args=False)


def _missing_required_args(info: dict[str, Any], field_node: Any, gast: Any,
                           schema_map: dict[str, Any]) -> tuple[str, str, str | None] | None:
    supplied = {a.name.value: a for a in (field_node.arguments or [])}
    input_types = schema_map.get("_input_types") or {}
    for arg in (info.get("args") or []):
        atype = str(arg.get("type", ""))
        name = arg.get("name", "")
        if atype.endswith("!") and name and name not in supplied and arg.get("default") is None:
            return name, atype, None
        base = re.sub(r"[\[\]!]", "", atype).strip()
        if name in supplied and base in input_types:
            node = supplied[name].value
            if isinstance(node, gast.ObjectValueNode):
                provided = {f.name.value for f in node.fields}
                for leaf in input_types[base]:
                    ltype = str(leaf.get("type", ""))
                    lname = leaf.get("name", "")
                    if ltype.endswith("!") and lname and lname not in provided and leaf.get("default") is None:
                        return f"{name}.{lname}", ltype, base
    return None
