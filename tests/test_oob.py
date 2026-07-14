"""Tests for the out-of-band (OOB) interaction scaffolding."""

from gradientql.utils import oob


def test_disabled_without_domain():
    assert oob.is_enabled({"scanner": {"oob": {"enabled": True}}}) is False
    assert oob.is_enabled({"scanner": {"oob": {"enabled": False, "collaborator_domain": "x.oast.fun"}}}) is False
    assert oob.is_enabled({"scanner": {"oob": {"enabled": True, "collaborator_domain": "x.oast.fun"}}}) is True


def test_token_is_deterministic_and_attributable():
    a = oob.make_token("ssrf", "Query.fetchUrl")
    b = oob.make_token("ssrf", "Query.fetchUrl")
    c = oob.make_token("ssrf", "Query.other")
    assert a == b and a != c
    assert a.isalnum()


def test_callback_url_embeds_token():
    url = oob.callback_url("oast.fun", "ptoken")
    assert url == "http://ptoken.oast.fun/"


def test_oob_payloads_carry_callback():
    p = oob.oob_payloads("oast.fun", "ptoken")
    assert "ptoken.oast.fun" in p["ssrf"]
    assert "ptoken.oast.fun" in p["xxe"] and "ENTITY" in p["xxe"]
    assert p["dns"] == "ptoken.oast.fun"


def test_reflection_detection():
    assert oob.detect_reflection('{"data":{"x":"...ptoken.oast.fun..."}}', "ptoken") is True
    assert oob.detect_reflection('{"data":{"x":"nothing"}}', "ptoken") is False


def test_poll_is_stubbed_until_wired():
    assert oob.poll_interactions({}, ["ptoken"]) == []
