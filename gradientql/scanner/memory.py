"""Situational state the agent keeps across steps."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

_CLASS_KEYWORDS = {
    "injection (SQLi/cmd/SSTI/...)": ("inject", "sqli", "sql ", "command", "ssti", "xpath", "ldap", "nosql", "rce"),
    "denial-of-service": ("denial of service", "dos", "resource exhaust"),
    "broken access control (BOLA/BFLA/auth)": ("bola", "idor", "access control", "authoriz", "auth bypass", "authbypass"),
    "information disclosure": ("disclosure", "introspection", "leak", "sensitive", "info"),
    "ssrf": ("ssrf",),
    "server error / crash": ("server error", "crash", "5xx"),
}

# A vuln class the scanner can be configured not to test; nudges skip it when its toggle is off.
_CLASS_TOGGLE = {
    "injection (SQLi/cmd/SSTI/...)": "injection",
    "denial-of-service": "dos",
    "broken access control (BOLA/BFLA/auth)": "bola",
    "ssrf": "ssrf",
}

_ARSENAL_TOOLS = ("sweep", "dos", "smuggle", "csrf", "oob_url", "forge_jwt", "temp_mail")
_ENDPOINT_TOOLS = ("dos", "smuggle", "csrf")

_ENDPOINT_CLASSES = ("denial", "introspection", "batching", "csrf", "smuggl", "rate-limit",
                     "rate limit", "tracing", "cors", "cache")

_STATE_SYM = {"finding": "⚠", "exploited": "⚠", "data": "✓", "open": "?", "dead": "✗"}


def primary_root_field(query: str) -> str | None:
    """Return the first root field of a GraphQL op, resolving an alias to its field.

    Accepts dotted paths too ("Query.users" -> "users"), as models often write
    verdicts/targets in that form. Returns None if no field can be parsed out.
    """
    s = query.strip()
    if re.fullmatch(r"[A-Za-z_]\w*(\.[A-Za-z_]\w*)+", s):
        s = s.rsplit(".", 1)[-1]
    m = re.match(r"(query|mutation|subscription)\b\s*\w*\s*(\([^)]*\))?\s*", s)
    if m:
        s = s[m.end():]
    s = s.lstrip()
    if s.startswith("{"):
        s = s[1:].lstrip()
    m = re.match(r"([A-Za-z_]\w*)\s*(:\s*([A-Za-z_]\w*))?", s)
    if not m:
        return None
    return m.group(3) or m.group(1)


def blank_entry(field: str, idlabel: str, step: int) -> dict[str, Any]:
    return {"field": field, "attempts": 0, "auto": "", "sig": "", "identity": idlabel,
            "verdict": None, "why": None, "confidence": None, "finding": None, "step": step,
            "dup_fails": 0, "last_sig": None, "stale_fps": []}


def identity_label(identity: dict[str, str]) -> str:
    """Return a short tag for an identity: "anon", "auth:<last6>", or "hdr"."""
    if not identity:
        return "anon"
    authish = [str(v) for k, v in identity.items()
               if any(t in str(k).lower() for t in ("auth", "token", "cookie", "session", "api", "bearer"))]
    if authish:
        v = authish[0]
        return "auth:" + v[-6:] if len(v) >= 6 else "auth"
    return "hdr"


def effective_state(e: dict[str, Any]) -> str:
    """Collapse a ledger entry to one state.

    The model's verdict overrides the auto-read, except a "dead" verdict is
    ignored when it would erase an objective DATA/AUTH-BLOCKED signal or has no
    attempts behind it. Access-control HTTP codes (401/403) stay "open".
    """
    if e.get("finding"):
        return "finding"
    a = str(e.get("auto", ""))
    v = e.get("verdict")
    if v == "dead" and (a in ("DATA", "AUTH-BLOCKED") or not e.get("attempts")):
        v = None
    if v in ("dead", "open", "exploited"):
        return v
    if a == "DATA":
        return "data"
    if a in ("AUTH-BLOCKED", "ERROR", "HTTP401", "HTTP403", "RATE-LIMITED") or a.startswith("HTTP5"):
        return "open"
    return "dead" if a else "open"


def unconfirmed_classes(vulns: list[dict[str, Any]], skip_toggles: set[str] | None = None) -> list[str]:
    """Return the vuln classes not represented in `vulns`, minus disabled-technique classes."""
    skip_toggles = skip_toggles or set()
    found: set[str] = set()
    for v in vulns:
        t = str(v.get("vuln_type", "")).lower()
        for cls, kws in _CLASS_KEYWORDS.items():
            if any(k in t for k in kws):
                found.add(cls)
    return [c for c in _CLASS_KEYWORDS
            if c not in found and _CLASS_TOGGLE.get(c) not in skip_toggles]


def render_state(ledger: dict[str, dict], facts: list[str], searched: list[str], n_findings: int,
                 total_root: int = 0, untouched_sweepable: int = 0, require_args: int = 0) -> str:
    if not ledger and not facts and not searched:
        n = untouched_sweepable or total_root
        seed = f" ({n} no-arg fields await - `sweep` maps many at once)" if n else ""
        return f"  (nothing tried yet - START with `sweep` to map the surface{seed})"
    tally = Counter(effective_state(e) for e in ledger.values())
    auth_gated = sum(1 for e in ledger.values()
                     if e.get("auto") == "AUTH-BLOCKED" and effective_state(e) == "open")
    parts: list[str] = []
    if untouched_sweepable > 0:
        parts.append(f"{untouched_sweepable} no-arg query fields still un-swept (`sweep`)")
    if require_args > 0:
        parts.append(f"{require_args} fields/mutations need args - DRILL individually (graphql/fuzz), can't sweep")
    if not parts:
        parts.append("no-arg surface fully swept - pivot to required-arg fields, injection, SSRF, DoS")
    cov = (f"  COVERAGE: {tally.get('finding', 0) + tally.get('exploited', 0)} finding/exploited, "
           f"{tally.get('data', 0)} data, {tally.get('open', 0)} open, {tally.get('dead', 0)} dead "
           f"({len(ledger)} fields tried) - {'; '.join(parts)} | {n_findings} findings recorded")
    if auth_gated:
        cov += (f"\n  AUTH-GATED: {auth_gated} field(s) need a token. If KNOWN says there's no way to mint "
                f"one, STOP retrying them - they stay blocked while anonymous; pivot to unauth vectors.")
    sr = "  SEARCHED: " + (", ".join(searched[:30]) if searched else "(nothing yet)")

    opens = [e for e in ledger.values() if effective_state(e) == "open"]
    if opens:
        ot = "\n  OPEN THREADS (worth another angle):\n" + "\n".join(
            f"    • {e.get('field', '?')} @{e.get('identity', '?')} - "
            f"{e.get('why') or e.get('echoed') or e.get('auto') or 'untested angle'}"
            for e in opens[:6])
    else:
        ot = "\n  OPEN THREADS: (none flagged - mark one with verdict:{state:\"open\"} if you want to revisit it)"

    if facts:
        shown = "\n".join(f"    - {f}" for f in facts[:20])
        if len(facts) > 20:
            shown += f"\n    (+{len(facts) - 20} more banked facts)"
        kn = "\n  KNOWN (facts you've recorded):\n" + shown
    else:
        kn = "\n  KNOWN: (nothing yet - add \"learned\":\"...\" to ANY action to bank what you discover)"

    def _rank(e: dict) -> int:
        st = effective_state(e)
        return 0 if e.get("finding") else (1 if st in ("data", "open") else 2)

    rows = sorted(ledger.values(), key=lambda e: (_rank(e), -e.get("attempts", 0)))
    lines = []
    for e in rows[:20]:
        st = effective_state(e)
        if e.get("finding"):
            extra = f"  FINDING: {e['finding']}"
        elif e.get("why"):
            extra = f'  "{e["why"]}"'
        elif e.get("sig"):
            extra = f"  {e['sig']}"
        else:
            extra = ""
        conf = f" (conf {e['confidence']:.1f})" if isinstance(e.get("confidence"), (int, float)) else ""
        idl = f" @{e['identity']}" if e.get("identity") and e["identity"] != "anon" else ""
        lines.append(f"    {_STATE_SYM.get(st, '?')} {e.get('field', '?')}{idl} {e.get('auto', '')} "
                     f"x{e.get('attempts', 0)}{extra}{conf}")
    if len(ledger) > 20:
        lines.append(f"    (+{len(ledger) - 20} more fields in ledger - lower priority)")
    tried = "\n  TRIED (✓data ⚠finding ✗dead ?open):\n" + "\n".join(lines)
    return cov + "\n" + sr + ot + kn + tried


# `learned` facts are long-term memory; plans are not facts. A fact phrased as an intention
# ("Testing X...", "I need to check...") describes what the model is ABOUT to do - it can't stop
# a repeat later, because it records no outcome. Rejected at the door with a correction the
# model sees in its next observation.
_INTENT_PREFIXES = (
    "testing", "trying", "test ", "try ", "starting", "to test", "to check", "checking",
    "i need", "need to", "let me", "i will", "i'll", "going to", "plan to", "next",
    "time to", "i should", "now i", "i'm going", "attempting", "attempt to", "about to",
    "planning", "aiming", "want to", "let's",
)


def _is_intent(fact: str) -> bool:
    low = fact.strip().lower()
    return any(low.startswith(p) for p in _INTENT_PREFIXES)


def apply_self_report(action: dict[str, Any], ledger: dict[str, dict], facts: list[str],
                      idlabel: str, step: int) -> str:
    """Fold an action's optional `learned`/`verdict` into the ledger and facts.

    Mutates `ledger` and `facts` in place; returns a summary of what was
    recorded, or an empty string if the action carried neither.
    """
    bits: list[str] = []
    learned = action.get("learned")
    if isinstance(learned, str) and learned.strip():
        f = learned.strip()[:200]
        if _is_intent(f):
            bits.append(f'NOT banked (a plan, not a result): "{f[:50]}" - `learned` is for what a '
                        'response SHOWED (e.g. "me(token) masks passwords"), not for what you '
                        'intend to do next')
        elif f not in facts:
            facts.append(f)
            bits.append(f'banked fact: "{f[:60]}"')
    v = action.get("verdict")
    if isinstance(v, dict) and v.get("field"):
        field = primary_root_field(str(v["field"])) or str(v["field"])[:40]
        e = ledger.setdefault(field, blank_entry(field, idlabel, step))
        st = str(v.get("state", "")).lower()
        if st in ("dead", "open", "exploited"):
            e["verdict"] = st
        if v.get("why"):
            e["why"] = str(v["why"])[:120]
        if isinstance(v.get("confidence"), (int, float)):
            e["confidence"] = float(v["confidence"])
        bits.append(f"verdict {field}={st or 'noted'}")
    return "; ".join(bits)


def _retract_sig(vuln_type: str, target: str) -> str:
    vt = " ".join(str(vuln_type).lower().split())
    pf = primary_root_field(str(target)) or str(target).lower()[:40]
    return f"{vt}|{pf}"


def _finding_key(vuln_type: str, target: str) -> str:
    low = str(vuln_type).lower()
    for c in _ENDPOINT_CLASSES:
        if c in low:
            return c
    pf = primary_root_field(str(target)) or str(target)[:30]
    return f"{' '.join(low.split()[:3])}|{pf}"


def dedup_findings(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop duplicate findings, keeping the first per (class-or-type, target) key.

    Endpoint-level classes (DoS, CSRF, CORS, smuggling, ...) collapse to one
    finding each regardless of target.
    """
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for v in vulns:
        k = _finding_key(str(v.get("vuln_type", "")), str(v.get("target_node", "")))
        if k in seen:
            continue
        seen.add(k)
        out.append(v)
    return out
