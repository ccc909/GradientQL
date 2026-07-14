"""Tests for gradientql/utils/graphql_client.py — the http config knobs."""

from __future__ import annotations

from gradientql.utils import graphql_client
from gradientql.utils.graphql_client import GraphQLClient, get_client

URL = "https://target.example/graphql"


def test_http_defaults_leave_behavior_unchanged():
    c = GraphQLClient(URL)
    assert c.session.proxies == {}
    assert c.session.verify is True
    assert c._timeout == 30
    assert c._delay == 0.0


def test_configured_proxy_lands_on_session():
    proxy = "http://127.0.0.1:8080"
    c = GraphQLClient(URL, http={"proxy": proxy, "verify_tls": False, "timeout": 5})
    assert c.session.proxies == {"http": proxy, "https": proxy}
    assert c.session.verify is False
    assert c._timeout == 5


def test_get_client_forwards_http(monkeypatch):
    monkeypatch.setattr(graphql_client, "_client_cache", {})
    proxy = "http://127.0.0.1:9999"
    c = get_client(URL, http={"proxy": proxy})
    assert c.session.proxies == {"http": proxy, "https": proxy}


def test_delay_throttles_before_request(monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr(graphql_client.time, "sleep", lambda s: slept.append(s))
    c = GraphQLClient(URL, http={"delay": 0.25})
    c._throttle()
    assert slept == [0.25]
