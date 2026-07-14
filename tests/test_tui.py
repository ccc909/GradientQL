from __future__ import annotations

from types import SimpleNamespace

from gradientql import tui


def _ctx():
    sm = {"_query_type": "Query", "_mutation_type": "Mutation",
          "Query": {"me": {}, "orders": {}, "products": {}},
          "Mutation": {"resetPassword": {}, "deleteAccount": {}}}
    ledger = {
        "me": {"attempts": 2, "auto": "DATA"},
        "orders": {"attempts": 1, "auto": "null/empty"},
        "resetPassword": {"attempts": 4, "auto": "null/empty"},
    }
    return SimpleNamespace(schema_map=sm, ledger=ledger, identity={}, vulns=[], interactions=[],
                           decisions=["1 sweep -> mapped"])


def test_field_state_transitions():
    assert tui._field_state(None) == "untested"
    assert tui._field_state({"attempts": 2, "auto": "DATA"}) == "data"
    assert tui._field_state({"attempts": 1, "auto": "null/empty"}) == "shallow"
    assert tui._field_state({"attempts": 4, "auto": "null/empty"}) == "dead"
    assert tui._field_state({"attempts": 1, "auto": "HTTP403"}) == "open"
    assert tui._field_state({"attempts": 1, "auto": "DATA", "finding": "x"}) == "finding"


def test_coverage_text_is_ascii_only():
    txt = tui.coverage_text(_ctx()).plain
    assert "Query" in txt and "Mutation" in txt
    assert "untested" in txt and "high-value" in txt
    for ascii_glyph in (". ", "+ ", "o ", "x "):
        assert ascii_glyph in txt
    for emoji in ("★", "◐", "✓", "✗", "⚠", "⚑", "◆", "…", "›"):
        assert emoji not in txt


def test_coverage_text_handles_no_context():
    assert "waiting" in tui.coverage_text(None).plain


def test_loot_text_renders_credentials_tokens_facts():
    ctx = SimpleNamespace(
        credentials=[{"email": "victim@x.com", "password": "hunter2"}],
        identity={"authorization": "Bearer eyJhbGciOi.PAYLOAD.sig"},
        harvested={"token": ["eyJ1", "eyJ2"], "forged_jwt": ["fff"]},
        facts=["Token-minting mutation exists"])
    txt = tui.loot_text(ctx).plain
    assert "victim@x.com" in txt and "hunter2" in txt
    assert "Bearer" in txt
    assert "token (2)" in txt and "forged_jwt" in txt
    assert "Token-minting" in txt


def test_loot_text_handles_no_context():
    assert "waiting" in tui.loot_text(None).plain


def test_logo_text_loads():
    assert tui._logo_text().plain


def test_activity_text_severity_colors():
    assert tui.ERR_RED in str(tui._activity_text("LLM error: provider timed out").style)
    assert tui.GOLD_HI in str(tui._activity_text("fuzz arg -> CONFIRMED Injection (RCE)").style)
    assert tui.OK_GREEN in str(tui._activity_text("login -> authenticated as admin").style)
    assert "grey" in str(tui._activity_text("orders -> null/empty").style)
    assert "grey" in str(tui._activity_text("plain recon line").style)


def test_activity_text_has_severity_glyph():
    assert tui._activity_text("LLM error here").plain.startswith("x ")
    assert tui._activity_text("CONFIRMED RCE").plain.startswith("! ")
    assert tui._activity_text("login -> authenticated").plain.startswith("+ ")
    assert tui._activity_text("orders -> dead").plain.startswith("- ")


def test_attack_labels_are_descriptive():
    for name, _ in tui._ATTACK_DEFAULTS:
        assert name in tui._ATTACK_LABELS
        assert len(tui._ATTACK_LABELS[name]) > len(name)
    assert "broken object-level auth" in tui._ATTACK_LABELS["bola"]


def test_coverage_legend_uses_plain_terms():
    txt = tui.coverage_text(_ctx()).plain
    assert "probed" in txt and "auth-gated" in txt and "exhausted" in txt
    assert "shallow" not in txt      # old jargon gone


def test_attack_defaults_cover_all_techniques():
    names = [n for n, _ in tui._ATTACK_DEFAULTS]
    for a in ("injection", "ssrf", "dos", "smuggle", "csrf", "jwt", "brute", "bola"):
        assert a in names


async def test_app_mounts_menu_and_navigates_to_settings():
    app = tui.GradientQLApp({"target": {"url": ""}, "scanner": {}, "llm": {}, "http": {}})
    async with app.run_test() as pilot:
        assert isinstance(app.screen, tui.MenuScreen)
        await pilot.click("#settings")
        await pilot.pause()
        assert isinstance(app.screen, tui.SettingsScreen)
        await pilot.click("#attacks")
        await pilot.pause()
        assert isinstance(app.screen, tui.AttacksScreen)


async def test_dashboard_screen_composes(monkeypatch):
    monkeypatch.setattr("gradientql.core.llm.verify_key", lambda s: (True, "ok"))
    monkeypatch.setattr(
        "gradientql.scanner.run.run_scan",
        lambda *a, **k: {"vulnerabilities": [], "target_url": "http://t", "steps": 0, "interactions": []})
    app = tui.GradientQLApp({"target": {"url": "http://t/graphql"}, "scanner": {}, "llm": {}, "http": {}},
                            "http://t/graphql")
    async with app.run_test() as pilot:
        app.push_screen(tui.DashboardScreen())
        await pilot.pause()
        assert isinstance(app.screen, tui.DashboardScreen)
        assert app.screen.query_one("#coverage") is not None


async def test_dashboard_uses_current_settings_url(monkeypatch):
    captured: dict = {}
    monkeypatch.setattr("gradientql.core.llm.verify_key", lambda s: (True, "ok"))
    monkeypatch.setattr(
        "gradientql.scanner.run.run_scan",
        lambda settings, url, **k: captured.__setitem__("url", url)
        or {"vulnerabilities": [], "target_url": url, "steps": 0, "interactions": []})
    app = tui.GradientQLApp({"target": {"url": ""}, "scanner": {}, "llm": {}, "http": {}})
    async with app.run_test() as pilot:
        app.settings["target"]["url"] = "http://set-in-settings/graphql"
        app.push_screen(tui.DashboardScreen())
        await pilot.pause()
        await pilot.pause()
    assert captured.get("url") == "http://set-in-settings/graphql"


async def test_dashboard_blocks_on_bad_key(monkeypatch):
    scanned = {"called": False}
    monkeypatch.setattr("gradientql.core.llm.verify_key", lambda s: (False, "API key rejected by the provider."))
    monkeypatch.setattr(
        "gradientql.scanner.run.run_scan",
        lambda *a, **k: scanned.__setitem__("called", True) or {"vulnerabilities": []})
    app = tui.GradientQLApp({"target": {"url": "http://t/graphql"}, "scanner": {}, "llm": {}, "http": {}},
                            "http://t/graphql")
    async with app.run_test() as pilot:
        app.push_screen(tui.DashboardScreen())
        await pilot.pause()
        await pilot.pause()
        header = app.screen.query_one("#dash_header", tui.Static).render()
    assert scanned["called"] is False
    assert "CANNOT START" in str(header)
    assert app.result is None


async def test_dashboard_surfaces_scan_error(monkeypatch):
    monkeypatch.setattr("gradientql.core.llm.verify_key", lambda s: (True, "ok"))
    monkeypatch.setattr(
        "gradientql.scanner.run.run_scan",
        lambda *a, **k: {"vulnerabilities": [], "steps": 0, "target_url": "x",
                         "error": "introspection failed: Read timed out"})
    app = tui.GradientQLApp({"target": {"url": "http://t/graphql"}, "scanner": {}, "llm": {}, "http": {}},
                            "http://t/graphql")
    async with app.run_test() as pilot:
        app.push_screen(tui.DashboardScreen())
        await pilot.pause()
        await pilot.pause()
        header = str(app.screen.query_one("#dash_header", tui.Static).render())
    assert "FAILED" in header
    assert "introspection failed" in header


def test_menu_key_status_reflects_presence(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert tui._has_key({"llm": {"api_key": "sk-xyz"}}) is True
    assert tui._has_key({"llm": {"api_key": "", "api_key_env": "OPENROUTER_API_KEY"}}) is False


def test_verify_key_reports_missing(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    from gradientql.core.llm import verify_key
    ok, msg = verify_key({"llm": {"api_key": "", "api_key_env": "OPENROUTER_API_KEY"}})
    assert ok is False
    assert "No API key" in msg


async def test_settings_clamps_and_sanitizes_numbers():
    from textual.widgets import Input
    app = tui.GradientQLApp({"target": {"url": "http://t/graphql"}, "scanner": {"budget": 60},
                             "llm": {}, "http": {"delay": 0.0}})
    async with app.run_test() as pilot:
        await pilot.click("#settings")
        await pilot.pause()
        app.screen.query_one("#f_budget", Input).value = "-5"
        app.screen.query_one("#f_delay", Input).value = "-1"
        app.screen.query_one("#f_timeout", Input).value = "0"
        await pilot.click("#back")
        await pilot.pause()
    assert app.settings["scanner"]["budget"] == 1      # negative clamped to min 1
    assert app.settings["http"]["delay"] == 0.0        # negative clamped to 0
    assert app.settings["http"]["timeout"] == 1        # zero clamped to min 1


async def test_settings_budget_accepts_decimal():
    from textual.widgets import Input
    app = tui.GradientQLApp({"target": {"url": "http://t/graphql"}, "scanner": {"budget": 60},
                             "llm": {}, "http": {}})
    async with app.run_test() as pilot:
        await pilot.click("#settings")
        await pilot.pause()
        app.screen.query_one("#f_budget", Input).value = "8.9"
        await pilot.click("#back")
        await pilot.pause()
    assert app.settings["scanner"]["budget"] == 8      # truncated, not silently reverted


async def test_settings_url_scheme_prepended_and_model_fallback():
    from textual.widgets import Input
    app = tui.GradientQLApp({"target": {"url": "http://old/graphql"}, "scanner": {"budget": 60},
                             "llm": {"attacker_model": "z-ai/glm-5.2"}, "http": {}})
    async with app.run_test() as pilot:
        await pilot.click("#settings")
        await pilot.pause()
        app.screen.query_one("#f_url", Input).value = "example.com/graphql"   # no scheme
        app.screen.query_one("#f_model", Input).value = ""                     # cleared
        await pilot.click("#back")
        await pilot.pause()
    assert app.settings["target"]["url"] == "https://example.com/graphql"
    assert app.settings["llm"]["attacker_model"] == "z-ai/glm-5.2"      # empty reverted, not blanked


async def test_start_rejects_whitespace_url():
    app = tui.GradientQLApp({"target": {"url": "   "}, "scanner": {}, "llm": {"api_key": "x"}, "http": {}})
    async with app.run_test() as pilot:
        await pilot.click("#start")
        await pilot.pause()
        assert isinstance(app.screen, tui.SettingsScreen)


async def test_menu_summary_does_not_interpret_markup():
    app = tui.GradientQLApp({"target": {"url": "http://x/g?q=[bold red]PWN[/]"}, "scanner": {},
                             "llm": {}, "http": {}})
    async with app.run_test() as pilot:
        summ = str(app.screen.query_one("#summary", tui.Static).render())
    assert "[bold red]" in summ      # shown literally, markup not parsed


async def test_dashboard_update_safe_after_escape(monkeypatch):
    monkeypatch.setattr("gradientql.core.llm.verify_key", lambda s: (True, "ok"))
    monkeypatch.setattr(
        "gradientql.scanner.run.run_scan",
        lambda *a, **k: {"vulnerabilities": [], "target_url": "x", "steps": 0, "interactions": []})
    app = tui.GradientQLApp({"target": {"url": "http://t/graphql"}, "scanner": {}, "llm": {}, "http": {}},
                            "http://t/graphql")
    async with app.run_test() as pilot:
        app.push_screen(tui.DashboardScreen())
        await pilot.pause()
        scr = app.screen
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, tui.MenuScreen)
        # late worker callbacks on the now-unmounted dashboard must not raise
        scr._update(2, 12, _ctx())
        scr._done({"vulnerabilities": [], "target_url": "x"})
