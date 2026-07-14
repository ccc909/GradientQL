"""CLI entry point for the agent-only scanner."""

from __future__ import annotations

import warnings

warnings.filterwarnings("ignore", category=UserWarning, module="google.protobuf")
warnings.filterwarnings("ignore", category=FutureWarning, module="keras")
warnings.filterwarnings("ignore", message=r".*np\.object.*", category=FutureWarning)

import argparse
import sys
from typing import Any

from ..core.config import load_settings
from ..utils.logger import setup_logging
from .run import run_scan


def main(settings_path: str | None = None, target_url: str | None = None,
         trace: Any = None, verbose: bool = False) -> dict[str, Any]:
    logger = setup_logging("INFO")
    logger.info("=== GradientQL: Autonomous GraphQL Vulnerability Scanner (agent mode) ===")

    settings = load_settings(settings_path)
    if target_url:
        settings.setdefault("target", {})["url"] = target_url
        logger.info("Target URL overridden via --url: %s", target_url)
    if trace is not None:
        settings.setdefault("scanner", {})["trace"] = trace
    if verbose:
        settings.setdefault("scanner", {})["verbose"] = True

    if not settings.get("llm", {}).get("api_key"):
        api_key_env = settings.get("llm", {}).get("api_key_env", "OPENROUTER_API_KEY")
        logger.error("No API key found. Set the %s environment variable, put it in "
                     "config/api_key.local, or set llm.api_key in the settings file.", api_key_env)
        sys.exit(1)

    url = settings.get("target", {}).get("url")
    if not url:
        logger.error("No target URL. Set target.url in settings or pass --url.")
        sys.exit(1)

    logger.info("Target: %s", url)
    logger.info("Budget: %d steps", int(settings.get("scanner", {}).get("budget", 60)))
    logger.info("LLM: %s via %s",
                settings["llm"].get("attacker_model", "?"), settings["llm"].get("provider", "?"))

    return run_scan(settings, url)


def cli() -> None:
    parser = argparse.ArgumentParser(
        prog="gradientql",
        description="Autonomous, agent-driven GraphQL vulnerability scanner")
    parser.add_argument("--settings", type=str, default=None,
                        help="Path to settings.yaml (default: config/settings.yaml)")
    parser.add_argument("--url", type=str, default=None,
                        help="Target GraphQL endpoint (overrides target.url in settings)")
    parser.add_argument("--trace", nargs="?", const="__default__", default=None, metavar="PATH",
                        help="Record every step's prompt, response, observations, and state to a "
                             ".jsonl/.md trace. Bare --trace writes output/agent_trace_<ts>.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Log each step's full thought and observations to the console.")
    parser.add_argument("--tui", action="store_true",
                        help="Force the interactive banner/menu/live-dashboard UI.")
    parser.add_argument("--no-tui", action="store_true",
                        help="Force the plain log output even in a terminal.")
    args = parser.parse_args()

    interactive = sys.stdout.isatty() and not args.no_tui
    if args.tui or (args.url is None and interactive):
        if not sys.stdout.isatty():
            main(settings_path=args.settings, target_url=args.url, trace=args.trace, verbose=args.verbose)
            return
        from ..tui import launch
        launch(settings_path=args.settings, target_url=args.url, trace=args.trace, verbose=args.verbose)
        return
    main(settings_path=args.settings, target_url=args.url, trace=args.trace, verbose=args.verbose)


if __name__ == "__main__":
    cli()
