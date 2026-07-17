"""Generate the TUI screenshots used in the README.

Menu and settings are drawn from illustrative demo state. The dashboard is rendered from the
newest real run checkpoint in output/checkpoints (an actual DVGA scan), so the live screen shows
real findings, loot, and coverage; it falls back to demo state when no checkpoint is present. The
output is SVG so it renders crisply on GitHub without a rasterizer. Run with
`python scripts/generate_screenshots.py`; only textual and rich are required.
"""
from __future__ import annotations

import asyncio
import glob
import json
import os
import pathlib
import warnings
from types import SimpleNamespace

from gradientql import tui

DOCS = pathlib.Path(__file__).resolve().parent.parent / "docs"
ROOT = DOCS.parent
MENU_SIZE = (150, 42)   # menu and settings read well at a standard terminal
DASH_SIZE = (200, 46)   # the live dashboard packs four panels, so give it a real fullscreen width
TARGET_URL = "http://dvga.local/graphql"

DEMO_SETTINGS = {
    "target": {"url": TARGET_URL},
    "scanner": {"budget": 60, "checkpoint": {"enabled": True, "every": 5}},
    "llm": {"api_key": "sk-demo", "attacker_model": "z-ai/glm-5.2", "attacker_max_tokens": 64000},
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


def _checkpoint_ctx() -> tuple[SimpleNamespace, int, int] | None:
    """The newest real run checkpoint as a render ctx plus (step, budget), or None if absent."""
    files = sorted(glob.glob(str(ROOT / "output" / "checkpoints" / "gql-*.json")), key=os.path.getmtime)
    if not files:
        return None
    with open(files[-1], encoding="utf-8") as fh:
        d = json.load(fh)
    c = d.get("ctx", {})
    ctx = SimpleNamespace(
        schema_map=d.get("schema_map", {}), ledger=c.get("ledger", {}),
        identity=c.get("identity", {}), credentials=c.get("credentials", []),
        harvested=c.get("harvested", {}), facts=c.get("facts", []),
        vulns=c.get("vulns", []), interactions=c.get("interactions", []),
        decisions=c.get("decisions", []), tokens=c.get("tokens", {}))
    return ctx, int(d.get("step", 39)), int(d.get("budget", 40))


async def main() -> None:
    warnings.filterwarnings("ignore")
    DOCS.mkdir(exist_ok=True)
    # No-op the scan worker: we drive the dashboard panes by hand, no target or model calls.
    tui.DashboardScreen.run_scan = lambda self: None

    app = tui.GradientQLApp(DEMO_SETTINGS, TARGET_URL)
    async with app.run_test(size=MENU_SIZE) as pilot:
        await pilot.pause()
        app.save_screenshot(str(DOCS / "menu.svg"))
        await pilot.click("#settings")
        await pilot.pause()
        app.save_screenshot(str(DOCS / "settings.svg"))

    real = _checkpoint_ctx()
    if real is not None:
        ctx, step, budget = real
        run_line = "run gql-20260717-0737-ddad · auto-checkpoint every step"
    else:
        ctx, step, budget = _demo_ctx(), 33, 60
        run_line = "run gql-20260715-2130-a3f9 · auto-checkpoint every 5 steps"

    app = tui.GradientQLApp(DEMO_SETTINGS, TARGET_URL)
    async with app.run_test(size=DASH_SIZE) as pilot:
        await pilot.pause()
        app.scan_active = True  # so the "thinking" indicator renders like a live run
        app.push_screen(tui.DashboardScreen())
        await pilot.pause()
        scr = app.screen
        scr._start = tui.time.monotonic() - 598  # elapsed ~09:58
        scr._log(run_line, f"bold {tui.GOLD}")
        scr._update(step, budget, ctx)
        scr._set_header("SCANNING", f"bold {tui.GOLD_HI}", TARGET_URL)
        scr._last_step_ts = tui.time.monotonic() - 2.0  # idle > 0.6s, so _pulse shows "thinking"
        await asyncio.sleep(0.5)  # let the 0.35s pulse timer fire
        await pilot.pause()
        app.save_screenshot(str(DOCS / "dashboard.svg"))

    print("wrote menu.svg, settings.svg, dashboard.svg to", DOCS)


if __name__ == "__main__":
    asyncio.run(main())
