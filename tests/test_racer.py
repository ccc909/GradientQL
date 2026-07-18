"""Race-condition engine: concurrent dispatch + result analysis + the `race` action."""

from __future__ import annotations

import gradientql.utils.racer as racer
from gradientql.scanner.actions import ActionContext, dispatch


class _Resp:
    def __init__(self, status=200, body=None, text=""):
        self.status_code = status
        self._body = body
        self.text = text

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


def test_run_race_fires_n_concurrently(monkeypatch):
    calls = []

    def fake_post(self, url, json=None, timeout=None):
        calls.append(url)
        return _Resp(200, {"data": {"redeem": {"ok": True}}})

    monkeypatch.setattr(racer.requests.Session, "post", fake_post, raising=True)
    results = racer.run_race("http://t/graphql", "mutation { redeem }", n=4)
    assert len(results) == 4 and len(calls) == 4
    assert all(r["status"] == 200 and r["data"] for r in results)


def test_analyze_flags_possible_race():
    ok = {"status": 200, "data": {"x": 1}, "errors": None}
    a = racer.analyze_race([ok, ok, ok])
    assert a["possible_race"] and a["succeeded"] == 3 and a["blocked"] == 0


def test_analyze_blocked_is_not_a_race():
    ok = {"status": 200, "data": {"x": 1}, "errors": None}
    dup = {"status": 200, "data": None, "errors": [{"message": "duplicate key value violates unique"}]}
    rl = {"status": 429, "data": None, "errors": None}
    a = racer.analyze_race([ok, dup, rl])
    assert not a["possible_race"]
    assert a["blocked"] == 2 and a["succeeded"] == 1


def _ctx():
    class _C:
        session = None

    return ActionContext(client=_C(), schema_map={}, schema_index=None, settings={},
                         target_url="http://t/graphql")


def test_race_action_reports_possible(monkeypatch):
    monkeypatch.setattr(racer, "run_race",
                        lambda *a, **k: [{"status": 200, "data": {"redeem": 1}, "errors": None}] * 6)
    res = dispatch("race", _ctx(), {"query": 'mutation { redeemCoupon(code:"X"){ok} }', "n": 6})
    assert res.touched_target and "POSSIBLE RACE" in res.observation


def test_race_action_serialized(monkeypatch):
    monkeypatch.setattr(racer, "run_race", lambda *a, **k: (
        [{"status": 200, "data": {"redeem": 1}, "errors": None}]
        + [{"status": 200, "data": None, "errors": [{"message": "coupon already redeemed"}]}] * 5))
    res = dispatch("race", _ctx(), {"query": "mutation { redeemCoupon }", "n": 6})
    assert "POSSIBLE RACE" not in res.observation
    assert "serialize" in res.observation.lower() or "blocked" in res.observation.lower()


def test_race_action_needs_query():
    res = dispatch("race", _ctx(), {})
    assert "needs" in res.observation


def test_race_action_from_template(monkeypatch):
    seen = {}

    def capture(url, query, variables=None, headers=None, n=20, **k):
        seen["query"] = query
        return [{"status": 200, "data": None, "errors": [{"message": "x"}]}]

    monkeypatch.setattr(racer, "run_race", capture)
    dispatch("race", _ctx(), {"template": 'redeem(code:"{V}")', "values": ["ABC"]})
    assert "ABC" in seen["query"]  # {V} substituted from values
