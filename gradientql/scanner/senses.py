"""Senses — deterministic, signature-based confirmation of vulns + response classification."""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

from .harvest import is_introspection_query, walk
from .payloads import SSTI_PROBES

_DOS_LIMIT_MARKERS = (
    "depth", "complex", "cost", "too many", "maximum", "exceed", "limit",
    "not allowed", "too large", "too deep", "throttl", "rate limit", "node limit",
)


def _max_brace_depth(s: str) -> int:
    depth = best = 0
    for ch in s:
        if ch == "{":
            depth += 1
            best = max(best, depth)
        elif ch == "}":
            depth = max(0, depth - 1)
    return best


def _max_list_len(obj: Any) -> int:
    best = 0
    stack = [obj]
    while stack:
        x = stack.pop()
        if isinstance(x, list):
            best = max(best, len(x))
            stack.extend(x)
        elif isinstance(x, dict):
            stack.extend(x.values())
    return best


_DOS_SLOW_MS = 1500


def detect_dos_surface(query: str, response: dict) -> tuple[str | None, str]:
    """Flag a resource-exhaustion query the server accepted without cost limits.

    Returns (vuln_type, reason), or (None, "") when the overload was rejected,
    rate-limited, or the server surfaced a cost/depth/complexity/batch limit.
    """
    if not query:
        return None, ""
    q = query.strip()

    is_batch = q.startswith("[") or bool(response.get("_batch_responses"))
    depth = _max_brace_depth(q)
    rt = response.get("_response_time_ms", 0)
    n_directives = len(re.findall(r"@\w+", q))
    aliased = re.findall(r"\b[A-Za-z_]\w*\s*:\s*([A-Za-z_]\w*)", q)
    top_field, top_n = (Counter(aliased).most_common(1)[0] if aliased else ("", 0))

    if is_batch:
        overload = "large query batch"
    elif n_directives >= 20:
        if not (isinstance(rt, (int, float)) and rt >= _DOS_SLOW_MS):
            return None, ""
        overload = f"{n_directives} stacked directives ({rt}ms — server slowed, no directive limit)"
    elif top_n >= 50:
        if top_field.startswith("__"):
            if not (isinstance(rt, (int, float)) and rt >= _DOS_SLOW_MS):
                return None, ""
            overload = f"{top_n}× {top_field} ({rt}ms — server slowed under load)"
        else:
            overload = f"{top_n}× {top_field} field duplication"
    elif depth >= 20:
        overload = f"{depth}-level deep nesting"
    elif re.search(r"\b(first|limit|last|count|take|perPage|pageSize)\s*:\s*\d{6,}", q, re.IGNORECASE):
        biggest = _max_list_len(response.get("data"))
        if not (biggest >= 1000 or (isinstance(rt, (int, float)) and rt >= _DOS_SLOW_MS)):
            return None, ""
        overload = f"uncapped pagination (server returned {biggest} records to a 6+ digit page request)"
    else:
        return None, ""

    errors = response.get("errors") or []
    err_text = json.dumps(errors).lower() if errors else ""
    if any(m in err_text for m in _DOS_LIMIT_MARKERS):
        return None, ""
    if is_batch and response.get("_batch_not_supported"):
        return None, ""

    status = response.get("_status_code", 0)
    accepted = (bool(response.get("data")) or bool(response.get("_batch_responses"))
                or (status == 200 and not errors))
    if not accepted:
        return None, ""

    return (
        "Denial of Service (No Query Cost Limiting)",
        f"dos_overload_accepted: {overload} accepted (HTTP {status}, {rt}ms) "
        f"with no cost/depth/complexity/batch limiting",
    )


_CMD_OUTPUT_MARKERS = (
    r"uid=\d+\([\w.-]+\)\s+gid=\d+",
    r"\broot:.*?:0:0:",
    r"\b(?:Linux|Darwin)\s+\S+\s+\d+\.\d+",
    r"\b[A-Z]:\\Windows\\system32",
)
_SQL_ERROR_MARKERS = (
    "sql syntax", "sqlite3.", "unrecognized token", "you have an error in your sql",
    "psycopg2", "near \"", "mysql_fetch", "ora-0", "sqlstate", "operationalerror",
    "incorrect syntax near", "warning: pg_", "quoted string not properly terminated",
)
_NOSQL_ERROR_MARKERS = (
    "mongoerror", "mongoservererror", "bsonerror", "cast to objectid failed", "e11000",
    "unknown operator", "couchbase", "n1ql", "topology was destroyed",
    "must be an object", "$where is not allowed",
)
_XPATH_ERROR_MARKERS = (
    "xpatheval", "saxon", "xpst0003", "xqst", "javax.xml.xpath",
    "invalid expression token", "system.xml.xpath",
)
_LDAP_ERROR_MARKERS = (
    "javax.naming", "invalid dn syntax", "bad search filter", "com.sun.jndi",
    "ldapexception", "error code 87", "invalid attribute syntax",
)


def detect_injection_surface(query: str, response: dict) -> tuple[str | None, str]:
    """Fingerprint injection (RCE/SSTI/SQL/NoSQL/XPath/LDAP) from response signatures.

    Returns (vuln_type, reason), or (None, "") when no signature matched.
    """
    if is_introspection_query(query):
        return None, ""

    data = response.get("data")
    data_text = json.dumps(data, default=str) if data else ""
    err_text = json.dumps(response.get("errors") or [], default=str)

    for pat in _CMD_OUTPUT_MARKERS:
        m = re.search(pat, data_text, re.IGNORECASE)
        if m:
            return ("OS Command Injection (RCE)",
                    f"command_output_in_response: matched {m.group(0)[:60]!r}")

    for expr, marker in SSTI_PROBES:
        if expr in query and marker in data_text and expr not in data_text:
            return ("Server-Side Template Injection (SSTI)",
                    f"template_evaluated: {expr} -> {marker} in response data")

    low = (data_text + " " + err_text).lower()
    for label, markers in (
        ("SQL Injection (error-based)", _SQL_ERROR_MARKERS),
        ("NoSQL Injection (error-based)", _NOSQL_ERROR_MARKERS),
        ("XPath Injection (error-based)", _XPATH_ERROR_MARKERS),
        ("LDAP Injection (error-based)", _LDAP_ERROR_MARKERS),
    ):
        for marker in markers:
            if marker in low:
                return (label, f"{label.split()[0].lower()}_error_in_response: {marker!r}")

    return None, ""


_SERVER_EXC_MARKERS = (
    "positional argument", "traceback (most recent call last)", "object has no attribute",
    "is not subscriptable", "is not iterable", "unhashable type",
    "referenced before assignment", "maximum recursion depth",
    "cannot destructure property", "cannot read property", "cannot read properties",
    "is not a function", "is not defined", "undefined is not",
)
_5XX_LEAK_MARKERS = (
    "stack trace", "stacktrace", "/var/www", "/app/code", ".php on line", " on line ",
    "fatal error", "sqlstate", "exception", "warning:", "notice:", "in /",
)


def detect_server_error_surface(response: dict) -> tuple[str | None, str]:
    """Detect leaked internals from an exception or a non-generic HTTP 5xx body.

    Returns (vuln_type, reason), or (None, "") for clean errors or generic
    maintenance/HTML 5xx pages that leak nothing.
    """
    err_text = json.dumps(response.get("errors") or [], default=str).lower()
    for m in _SERVER_EXC_MARKERS:
        if m in err_text:
            return ("Server Error / Crash (Internal Exception Leak)",
                    f"server_error_exception_leak: {m!r}")

    status = response.get("_status_code", 0)
    if isinstance(status, int) and status >= 500:
        is_generic_html = ("<!doctype" in err_text or "<html" in err_text
                           or "maintenance" in err_text or "<title>" in err_text)
        leaks = any(m in err_text for m in _5XX_LEAK_MARKERS)
        if leaks and not is_generic_html:
            return ("Server Error / Crash (HTTP 5xx, internals leaked)",
                    f"server_error_5xx_leak: status {status}")
    return None, ""


def run_detectors(query: str, response: dict[str, Any]) -> list[tuple[str, str]]:
    hits = []
    for fn, fn_args in ((detect_injection_surface, (query, response)),
                        (detect_dos_surface, (query, response)),
                        (detect_server_error_surface, (response,))):
        try:
            vt, reason = fn(*fn_args)
        except Exception:  # noqa: BLE001
            vt, reason = None, ""
        if vt:
            hits.append((vt, reason))
    return hits


_AUTH_ERR_MARKERS = ("authoriz", "unauthor", "unauthenticated", "not authenticated",
                     "forbidden", "logged in", "must be logged", "permission")
_SIGNIN_FAIL_MARKERS = ("sign-in was incorrect", "sign in was incorrect", "account is disabled",
                        "invalid login", "invalid credentials", "incorrect or your account")
_VALIDATION_ERR_MARKERS = ("cannot query field", "argument is required", "was not provided",
                           "unknown argument", "cannot represent", "must be", "of required type",
                           "no subfields", "did you mean", "is not defined by")
_FAIL_MSG_KEYS = ("error_message", "errormessage", "error", "message")


def is_dead(status: Any) -> bool:
    """Return True if the HTTP status marks the endpoint dead (0/None or 5xx)."""
    return status in (0, None) or (isinstance(status, int) and status >= 500)


def empty_response(data: Any) -> bool:
    """Return True if `data` carries no usable values (also True when not a dict)."""
    if not isinstance(data, dict):
        return True
    return all(v in (None, [], {}, "") for v in data.values())


def operation_failed(data: Any) -> str | None:
    """Return a failure message mined from response data, or None if it looks ok.

    Scans nested keys for an error/message string or a `success: false` flag.
    """
    if not isinstance(data, (dict, list)):
        return None
    saw_success_false = False
    for k, v in walk(data):
        kl = str(k).lower()
        if kl in _FAIL_MSG_KEYS and isinstance(v, str) and v.strip():
            return v.strip()[:80]
        if kl == "success" and v is False:
            saw_success_false = True
    return "success=false" if saw_success_false else None


def classify_outcome(status: Any, data: Any, errors: list[Any]) -> str:
    """Classify a response into a coarse outcome label (auth/login/HTTP/empty/DATA).

    Precedence matters: auth and login-failure signatures win over status codes,
    which win over empty-data and operation-failure checks.
    """
    estr = json.dumps(errors or [], default=str).lower()
    if any(m in estr for m in _SIGNIN_FAIL_MARKERS):
        return "LOGIN-FAILED"
    if any(m in estr for m in _AUTH_ERR_MARKERS):
        return "AUTH-BLOCKED"
    if isinstance(status, int) and status >= 500:
        return f"HTTP{status}"
    if isinstance(status, int) and status in (400, 401, 403, 406):
        return f"HTTP{status}"
    if empty_response(data):
        return "null/empty"
    if operation_failed(data):
        return "FAILED"
    return "DATA"
