"""Generate the TUI screenshots used in the README, filled with illustrative data.

Writes docs/menu.svg, docs/settings.svg, and docs/dashboard.svg. The output is SVG so it
renders crisply on GitHub without a rasterizer. Run with `python scripts/generate_screenshots.py`.
Only `textual` and `rich` are required (no target, no model calls).
"""
from __future__ import annotations

import asyncio
import pathlib
import warnings
from types import SimpleNamespace

from gradientql import tui

DOCS = pathlib.Path(__file__).resolve().parent.parent / "docs"
SIZE = (150, 42)

DEMO_SETTINGS = {
    "target": {"url": "https://api.example.shop/graphql"},
    "scanner": {"budget": 60},
    "llm": {"api_key": "sk-demo", "attacker_model": "qwen/qwen3.7-max"},
    "http": {},
}


def _demo_ctx() -> SimpleNamespace:
    sm = {"_query_type": "Query", "_mutation_type": "Mutation",
          "Query": {n: {} for n in ["me", "orders", "cart", "products", "customer",
                                    "wishlist", "invoices", "reviews"]},
          "Mutation": {n: {} for n in ["login", "resetPassword", "deleteAccount",
                                       "generateCustomerTokenAsAdmin", "changeCustomerPassword",
                                       "applyCoupon"]}}
    ledger = {"me": {"attempts": 2, "auto": "DATA"},
              "orders": {"attempts": 1, "auto": "null/empty"},
              "cart": {"attempts": 1, "auto": "HTTP403"},
              "products": {"attempts": 2, "auto": "DATA"},
              "resetPassword": {"attempts": 4, "auto": "null/empty"},
              "generateCustomerTokenAsAdmin": {"attempts": 3, "auto": "DATA",
                                               "finding": "admin token minted"}}
    return SimpleNamespace(
        schema_map=sm, ledger=ledger,
        identity={"authorization": "Bearer eyJhbGci.PAYLOAD.sig"},
        credentials=[{"email": "victim@example.shop", "password": "Summer2024!"}],
        harvested={"token": ["eyJ1", "eyJ2", "eyJ3"], "forged_jwt": ["forged.jwt.tok"]},
        facts=["Token-minting mutations exist (login)",
               "me returns the caller's email without auth"],
        vulns=[{"score": 4.0, "vuln_type": "Auth token mint (impersonation)",
                "target_node": "generateCustomerTokenAsAdmin"},
               {"score": 3.0, "vuln_type": "BOLA on orders", "target_node": "orders"}],
        interactions=[{}] * 34,
        decisions=["12 sweep -> 40 query fields mapped",
                   "18 graphql login -> authenticated as customer",
                   "21 graphql me -> DATA (email leaked, no auth)",
                   "23 fuzz resetPassword arg:token -> null/empty",
                   "27 graphql systemDebug -> LLM error: provider timed out (retry)",
                   "29 auth_test orders id=2 -> another user's order (BOLA confirmed)",
                   "33 forge_jwt admin -> generateCustomerTokenAsAdmin minted a token"],
        tokens={"total": 142600, "cost": 0.221, "input": 118400, "output": 24200,
                "reasoning": 9800, "calls": 18})


async def main() -> None:
    warnings.filterwarnings("ignore")
    DOCS.mkdir(exist_ok=True)
    # No-op the scan worker: no target or model calls, we drive the dashboard panes by hand.
    tui.DashboardScreen.run_scan = lambda self: None

    app = tui.GradientQLApp(DEMO_SETTINGS, DEMO_SETTINGS["target"]["url"])
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        app.save_screenshot(str(DOCS / "menu.svg"))

        await pilot.click("#settings")
        await pilot.pause()
        app.save_screenshot(str(DOCS / "settings.svg"))
        await pilot.press("escape")
        await pilot.pause()

        app.push_screen(tui.DashboardScreen())
        await pilot.pause()
        scr = app.screen
        scr._start = tui.time.monotonic() - 105
        scr._update(33, 60, _demo_ctx())
        scr._set_header("SCANNING", f"bold {tui.GOLD_HI}", DEMO_SETTINGS["target"]["url"])
        await pilot.pause()
        app.save_screenshot(str(DOCS / "dashboard.svg"))

    print("wrote menu.svg, settings.svg, dashboard.svg to", DOCS)


if __name__ == "__main__":
    asyncio.run(main())
