"""Tests for src/scanner/harvest.py — token/id/credential extraction."""

from __future__ import annotations

from gradientql.scanner import harvest


def test_harvest_jwt_and_token_and_id():
    store: dict = {}
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturepart"
    resp = {"data": {"login": {"access_token": "abcdef1234567890", "jwt": jwt, "userId": "15255542"}}}
    fresh = harvest.harvest(resp, store)
    assert jwt in store["jwt"]
    assert "abcdef1234567890" in store["token"]
    assert "15255542" in store["id"]
    assert any("jwt=" in f for f in fresh)


def test_harvest_ignores_short_tokens():
    store: dict = {}
    harvest.harvest({"data": {"x": {"token": "short"}}}, store)  # < 8 chars
    assert "short" not in store.get("token", [])


def test_harvest_request_inline_literal():
    rec = harvest.harvest_request('mutation { login(email: "a@b.com", password: "Secr3t!") { ok } }', {})
    assert rec == {"email": "a@b.com", "password": "Secr3t!"}


def test_harvest_request_resolves_variable():
    q = "mutation Reg($pwd: String!) { register(email: \"u@x.io\", password: $pwd) { id } }"
    rec = harvest.harvest_request(q, {"pwd": "P@ssw0rd"})
    assert rec["password"] == "P@ssw0rd"
    assert rec["email"] == "u@x.io"


def test_harvest_request_variables_input_object():
    q = "mutation($input: RegInput!) { register(input: $input) { id } }"
    rec = harvest.harvest_request(q, {"input": {"email": "v@y.io", "password": "hunter2!"}})
    assert rec["password"] == "hunter2!"
    assert rec["email"] == "v@y.io"


def test_harvest_request_no_secret_returns_none():
    assert harvest.harvest_request("query { me { id } }", {}) is None


def test_harvest_request_does_not_match_lookalike_names():
    # clientSecret / userAgent / loginUrl must NOT be mistaken for credentials
    q = 'mutation { config(clientSecret: "x", userAgent: "ua", loginUrl: "http://x") { ok } }'
    assert harvest.harvest_request(q, {}) is None


def test_find_reflections_detects_echoed_input():
    refl = harvest.find_reflections('query { echo(text: "test1234") }', {}, {"echo": "nil says: test1234"})
    assert refl == ["test1234"]


def test_find_reflections_ignores_short_and_absent():
    assert harvest.find_reflections('query { echo(text: "ab") }', {}, {"echo": "ab"}) == []   # too short
    assert harvest.find_reflections('query { echo(text: "zzzz") }', {}, {"echo": "other"}) == []  # absent


def test_find_reflections_resolves_variable():
    q = "query F($p: String!) { echo(text: $p) }"
    assert harvest.find_reflections(q, {"p": "canary99"}, {"echo": "got canary99"}) == ["canary99"]


def test_render_credentials_untruncated():
    out = harvest.render_credentials([{"email": "a@b.com", "password": "VeryLongPasswordValue123456789"}])
    assert "VeryLongPasswordValue123456789" in out


def test_render_harvested_tokens_in_full_ids_truncated():
    long_id = "x" * 80
    out = harvest.render_harvested({"token": ["t" * 60], "id": [long_id]})
    assert "t" * 60 in out                       # token shown in full
    assert long_id not in out                    # id truncated
