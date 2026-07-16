"""Schema-driven coverage of under-tested high-value field classes."""

from __future__ import annotations

import re
from typing import Any

_HIGH_VALUE_CLASSES: list[tuple[str, int, tuple[str, ...]]] = [
    ("auth-token-mint / impersonation", 0,
     ("tokenasadmin", "generatetokenas", "impersonat", "admintoken", "loginas", "switchuser")),
    ("password-reset / ATO", 0,
     ("resetpassword", "requestpasswordreset", "forgotpassword")),
    ("account destruction", 0,
     ("deactivateaccount", "deletecustomer", "deleteaccount", "closeaccount", "deleteuser",
      "removeaccount")),
    ("password change (self-service)", 1,
     ("changecustomerpassword", "changepassword", "setpassword", "updatepassword")),
    ("guest-order / order IDOR", 1,
     ("guestorder", "orderbytoken", "ordersbyemail", "orderbynumber", "getorder")),
    ("payment vault", 1,
     ("paymenttoken", "deletepaymenttoken", "vaultcard", "storedcard", "deletecard")),
    ("order-state BFLA", 1,
     ("cancelorder", "completeorder", "placeorder", "refundorder", "internalorderid", "shiporder")),
    ("cart takeover", 1,
     ("mergecarts", "assigncustomertoguestcart", "assigncart")),
    ("coupon / gift-card brute-force", 2,
     ("applycoupon", "applygiftcard", "giftcardaccount", "redeemgiftcard", "giftcard")),
]
CRITICAL_RANK = 0

_BFLA_AUTORECORD = {"auth-token-mint / impersonation", "password-reset / ATO",
                    "account destruction", "payment vault"}


def _root_fields(schema_map: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for r in (schema_map.get("_query_type", "Query"), schema_map.get("_mutation_type", "Mutation")):
        fields = schema_map.get(r)
        if isinstance(fields, dict):
            out += [f for f in fields if not str(f).startswith("_")]
    return out


def high_value_targets(schema_map: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Map each high-value attack class present in the schema to its rank and fields.

    Only classes with at least one matching root field are included; rank 0 is
    critical.
    """
    roots = _root_fields(schema_map)
    out: dict[str, dict[str, Any]] = {}
    for label, rank, kws in _HIGH_VALUE_CLASSES:
        hits = [f for f in roots if any(k in f.lower() for k in kws)]
        if hits:
            out[label] = {"rank": rank, "fields": hits}
    return out


def high_value_fields(schema_map: dict[str, Any]) -> set[str]:
    return {f for info in high_value_targets(schema_map).values() for f in info["fields"]}


def bfla_sensitive_fields(schema_map: dict[str, Any]) -> set[str]:
    return {f for label, info in high_value_targets(schema_map).items()
            if label in _BFLA_AUTORECORD for f in info["fields"]}


def _tested(entry: dict | None) -> bool:
    if not entry:
        return False
    return bool(entry.get("attempts") or entry.get("auto")
                or entry.get("finding") or entry.get("authmatrix"))


def _attacked(entry: dict | None) -> bool:
    if not entry:
        return False
    return bool(entry.get("authmatrix") or entry.get("fuzzed") or entry.get("finding")
                or entry.get("attempts", 0) >= 3)


def untested_high_value_fields(schema_map: dict[str, Any], ledger: dict[str, dict]) -> list[str]:
    return [f for info in high_value_targets(schema_map).values()
            for f in info["fields"] if not _attacked(ledger.get(f))]


def critical_untested(schema_map: dict[str, Any], ledger: dict[str, dict]) -> list[str]:
    out: list[str] = []
    for info in high_value_targets(schema_map).values():
        if info["rank"] == CRITICAL_RANK:
            out += [f for f in info["fields"] if not _attacked(ledger.get(f))]
    return out


_NON_INJECTABLE = {"Int", "Float", "Boolean"}
_TOKEN_ARG_HINTS = ("token", "jwt", "auth", "session", "bearer")


def _arg_scalar(type_ref: Any) -> str:
    return re.sub(r"[\[\]!]", "", str(type_ref or "")).strip()


def unfuzzed_string_args(schema_map: dict[str, Any], fuzz_seen: dict, cap: int = 6) -> list[str]:
    """Root Query fields with a string arg that has not had the sqli ladder yet.

    List-returning fields come first: a filter/search arg on a normal-looking list read
    is a classic SQLi sink that gets skipped because the field 'works' on a plain read.
    """
    qroot = schema_map.get("_query_type", "Query")
    fields = schema_map.get(qroot) or {}
    enums = schema_map.get("_enum_types") or {}
    listy: list[str] = []
    other: list[str] = []
    for field, info in fields.items():
        if str(field).startswith("_") or not isinstance(info, dict):
            continue
        is_list = "[" in str(info.get("return_type", ""))
        for a in info.get("args") or []:
            base = _arg_scalar(a.get("type"))
            if not base or base in _NON_INJECTABLE or base in enums:
                continue
            arg = str(a.get("name", ""))
            if not arg or fuzz_seen.get((field, arg, "", "sqli"), 0):
                continue
            (listy if is_list else other).append(f"{field}({arg})")
    return (listy + other)[:cap]


def token_arg_fields(schema_map: dict[str, Any], cap: int = 4) -> list[str]:
    """Query/Mutation fields whose argument is a JWT/token sink read from the field itself.

    e.g. me(token:) - a server that reads the JWT from a field argument rather than the
    Authorization header, so a forged/captured token must be passed INTO the field.
    """
    out: list[str] = []
    for r in (schema_map.get("_query_type", "Query"), schema_map.get("_mutation_type", "Mutation")):
        fields = schema_map.get(r)
        if not isinstance(fields, dict):
            continue
        for field, info in fields.items():
            if str(field).startswith("_") or not isinstance(info, dict):
                continue
            for a in info.get("args") or []:
                if any(h in str(a.get("name", "")).lower() for h in _TOKEN_ARG_HINTS):
                    out.append(f"{field}({a.get('name')})")
    return out[:cap]


def render_high_value(schema_map: dict[str, Any], ledger: dict[str, dict] | None = None,
                      cap: int = 5) -> str:
    hv = high_value_targets(schema_map)
    if not hv:
        return ""
    led = ledger or {}

    def _mark(f: str) -> str:
        e = led.get(f)
        if not _tested(e):
            return "★" + f
        if e.get("authmatrix"):
            return "✓" + f
        return "◐" + f

    lines = []
    for label, info in sorted(hv.items(), key=lambda kv: kv[1]["rank"]):
        shown = [_mark(f) for f in info["fields"][:cap]]
        more = f" (+{len(info['fields']) - cap})" if len(info["fields"]) > cap else ""
        lines.append(f"  [{label}] " + ", ".join(shown) + more)
    return "\n".join(lines)
