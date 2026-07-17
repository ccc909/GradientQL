"""Tests for src/scanner/senses.py — detectors + response classification."""

from __future__ import annotations

from gradientql.scanner import senses


# --- DoS ------------------------------------------------------------------- #

def test_dos_typename_aliases_need_latency_to_confirm():
    # 120 zero-cost __typename aliases accepted FAST proves nothing (the false-positive fix)
    q = "query { " + " ".join(f"a{i}: __typename" for i in range(120)) + " }"
    assert senses.detect_dos_surface(q, {"_status_code": 200, "data": {"a0": "Query"}})[0] is None
    # ...but a real slowdown under that load does confirm
    vt, _ = senses.detect_dos_surface(
        q, {"_status_code": 200, "data": {"a0": "Query"}, "_response_time_ms": 3000})
    assert vt and "Denial of Service" in vt


def test_dos_real_field_aliasing_confirms_on_accept():
    # aliasing a REAL resolver-touching field 60x and being accepted IS a cost-limiting finding
    q = "query { " + " ".join(f"a{i}: users {{ id }}" for i in range(60)) + " }"
    vt, _ = senses.detect_dos_surface(q, {"_status_code": 200, "data": {"a0": []}})
    assert vt and "Denial of Service" in vt


def test_dos_rejected_overload_is_not_a_finding():
    q = "query { " + " ".join(f"a{i}: __typename" for i in range(120)) + " }"
    resp = {"_status_code": 200, "errors": [{"message": "query is too complex / cost limit exceeded"}]}
    vt, _ = senses.detect_dos_surface(q, resp)
    assert vt is None


def test_dos_ignores_ordinary_query():
    vt, _ = senses.detect_dos_surface("query { me { id } }", {"_status_code": 200, "data": {"me": {}}})
    assert vt is None


# --- injection ------------------------------------------------------------- #

def test_injection_command_output():
    resp = {"data": {"x": "uid=1000(svc) gid=1000(svc) groups=1000(svc)"}}
    vt, _ = senses.detect_injection_surface("query{x}", resp)
    assert vt == "OS Command Injection (RCE)"


def test_injection_ssti_eval():
    resp = {"data": {"render": "9801"}}
    vt, _ = senses.detect_injection_surface('mutation{render(t:"{{99*99}}")}', resp)
    assert vt and "SSTI" in vt


def test_injection_ssti_literal_echo_is_not_eval():
    resp = {"data": {"render": "{{99*99}} 9801"}}  # echoes raw payload -> NOT evaluated
    vt, _ = senses.detect_injection_surface('mutation{render(t:"{{99*99}}")}', resp)
    assert vt is None


def test_injection_ssti_ruby_and_erb():
    # Ruby #{...} interpolation evaluated to 1787569 (= 1337²)
    vt, _ = senses.detect_injection_surface('q { echo(text: "#{1337*1337}") }',
                                            {"data": {"echo": "1787569"}})
    assert vt and "SSTI" in vt
    # ERB <%= %>
    vt, _ = senses.detect_injection_surface('q { r(t: "<%= 1337*1337 %>") }',
                                            {"data": {"r": "1787569"}})
    assert vt and "SSTI" in vt


def test_injection_sql_error_fingerprint():
    resp = {"errors": [{"message": "You have an error in your SQL syntax near '\"'"}]}
    vt, _ = senses.detect_injection_surface("query{x}", resp)
    assert vt and "SQL Injection" in vt


def test_sql_unique_constraint_error_is_not_injection():
    # a UNIQUE/IntegrityError from a normal write (registering a duplicate username) is a DB
    # validation error, not injection - the bare engine name must not trip the SQLi fingerprint
    resp = {"errors": [{"message": "(sqlite3.IntegrityError) UNIQUE constraint failed: users.username"}]}
    vt, _ = senses.detect_injection_surface("mutation{createUser}", resp)
    assert vt is None


def test_sql_syntax_error_still_flags_despite_engine_name():
    # a real metacharacter-induced syntax error is still SQLi even though it also names the engine
    resp = {"errors": [{"message": "(sqlite3.OperationalError) near \"'\": syntax error"}]}
    vt, _ = senses.detect_injection_surface("query{pastes(filter)}", resp)
    assert vt and "SQL Injection" in vt


def test_injection_introspection_response_is_not_scanned():
    # a schema dump whose field names contain "ldap"/"xpath" must NOT false-positive
    resp = {"data": {"__schema": {"types": [{"name": "ldapAdminRoleLinks"},
                                            {"name": "xpathQuery"}]}}}
    vt, _ = senses.detect_injection_surface("{ __schema { types { name } } }", resp)
    assert vt is None


def test_injection_bare_ldap_word_no_longer_false_positives():
    # the literal word "ldap" in ordinary data is not a driver error anymore
    vt, _ = senses.detect_injection_surface("{ x }", {"data": {"x": "configure your ldap server"}})
    assert vt is None


# --- server error ---------------------------------------------------------- #

def test_server_error_exception_leak():
    resp = {"errors": [{"message": "resolve_user() missing 1 required positional argument: 'id'"}]}
    vt, _ = senses.detect_server_error_surface(resp)
    assert vt and "Internal Exception Leak" in vt


def test_server_error_generic_5xx_html_is_not_a_finding():
    resp = {"_status_code": 502, "errors": [{"message": "<html><title>502 Bad Gateway</title></html>"}]}
    vt, _ = senses.detect_server_error_surface(resp)
    assert vt is None


def test_server_error_5xx_with_leak():
    resp = {"_status_code": 500, "errors": [{"message": "Traceback (most recent call last): in /app/code/x.py"}]}
    vt, _ = senses.detect_server_error_surface(resp)
    assert vt is not None


def test_run_detectors_aggregates_and_never_raises():
    hits = senses.run_detectors("query{x}", {"data": {"x": "uid=0(root) gid=0(root)"}})
    assert any("Command Injection" in vt for vt, _ in hits)
    # malformed input must not raise
    assert senses.run_detectors(None, {}) == [] or isinstance(senses.run_detectors(None, {}), list)


# --- classification -------------------------------------------------------- #

def test_classify_outcome():
    assert senses.classify_outcome(200, {"me": {"id": 1}}, []) == "DATA"
    assert senses.classify_outcome(200, {"me": None}, []) == "null/empty"
    assert senses.classify_outcome(200, {}, [{"message": "Not authorized"}]) == "AUTH-BLOCKED"
    assert senses.classify_outcome(200, {}, [{"message": "the sign-in was incorrect"}]) == "LOGIN-FAILED"
    assert senses.classify_outcome(500, None, []) == "HTTP500"
    assert senses.classify_outcome(200, {"ok": {"success": False}}, []) == "FAILED"


def test_operation_failed_detects_self_reported_failure():
    assert senses.operation_failed({"r": {"success": False}}) == "success=false"
    assert senses.operation_failed({"r": {"error_message": "not enabled"}}) == "not enabled"
    assert senses.operation_failed({"r": {"id": 1}}) is None


def test_is_dead():
    assert senses.is_dead(0) and senses.is_dead(None) and senses.is_dead(503)
    assert not senses.is_dead(200) and not senses.is_dead(404)


def test_429_is_rate_limited_not_empty_and_counts_as_unresponsive():
    # a 429 must read as RATE-LIMITED (never as a null/empty "dead" field) and must feed the
    # loop's degraded-target backoff via is_dead
    from gradientql.scanner.senses import classify_outcome, is_dead
    from gradientql.scanner.memory import effective_state
    assert is_dead(429) is True
    assert classify_outcome(429, None, []) == "RATE-LIMITED"
    assert effective_state({"auto": "RATE-LIMITED", "attempts": 1}) == "open"
