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


def _stdin_steer(logger: Any) -> Any:
    """In an interactive terminal, return a steer() callback fed by lines typed on stdin.

    A background reader thread queues each line; the scanner drains the queue once per step and
    injects the messages as operator instructions. Returns None when stdin is not a TTY.
    """
    if not sys.stdin.isatty():
        return None
    import queue
    import threading

    q: queue.Queue = queue.Queue()

    def _reader() -> None:
        for line in sys.stdin:
            msg = line.strip()
            if msg:
                q.put(msg)

    threading.Thread(target=_reader, daemon=True).start()
    logger.info("Steering: type a message + Enter at any time to redirect the agent "
                "(e.g. 'search for DoS now', or 'you missed the upload field').")

    def _drain() -> list[str]:
        out: list[str] = []
        try:
            while True:
                out.append(q.get_nowait())
        except queue.Empty:
            pass
        return out

    return _drain


def main(settings_path: str | None = None, target_url: str | None = None,
         trace: Any = None, verbose: bool = False, resume: str | None = None,
         max_tokens: int | None = None) -> dict[str, Any]:
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
    if max_tokens is not None:
        if max_tokens <= 0:
            logger.error("--max-tokens must be a positive integer (got %d).", max_tokens)
            sys.exit(1)
        settings.setdefault("llm", {})["attacker_max_tokens"] = int(max_tokens)
        logger.info("Max output tokens overridden via --max-tokens: %d", int(max_tokens))

    if not settings.get("llm", {}).get("api_key"):
        api_key_env = settings.get("llm", {}).get("api_key_env", "OPENROUTER_API_KEY")
        logger.error("No API key found. Set the %s environment variable, put it in "
                     "config/api_key.local, or set llm.api_key in the settings file.", api_key_env)
        sys.exit(1)

    from ..core.llm import verify_key
    ok, key_msg = verify_key(settings)
    if not ok:
        logger.error("%s", key_msg)
        sys.exit(1)

    from . import checkpoint as _cp
    resume_data: dict[str, Any] | None = None
    if resume:
        cpf = _cp.resolve(settings, resume)
        if cpf is None:
            logger.error("No checkpoint found for --resume %r (looked in %s).",
                         resume, _cp.checkpoint_dir(settings))
            sys.exit(1)
        try:
            resume_data = _cp.load(cpf)
        except (ValueError, OSError) as e:  # JSONDecodeError is a ValueError
            logger.error("Checkpoint %s is unreadable (%s).", cpf, str(e)[:80])
            sys.exit(1)
        if not target_url and resume_data.get("target_url"):
            settings.setdefault("target", {})["url"] = resume_data["target_url"]
        logger.info("Resuming run %s from step %d (%s)",
                    resume_data.get("run_id"), int(resume_data.get("step", -1)) + 1, cpf)

    url = settings.get("target", {}).get("url")
    if not url:
        logger.error("No target URL. Set target.url in settings or pass --url.")
        sys.exit(1)
    from ..core.config import PLACEHOLDER_URL
    if url.strip() == PLACEHOLDER_URL:
        logger.error("Target is still the placeholder %s - set target.url in config/settings.yaml "
                     "or pass --url to an endpoint you are authorized to test.", PLACEHOLDER_URL)
        sys.exit(1)

    logger.info("Target: %s", url)
    logger.info("Budget: %d steps", int(settings.get("scanner", {}).get("budget", 60)))
    logger.info("LLM: %s via %s (max output %s tokens)",
                settings["llm"].get("attacker_model", "?"), settings["llm"].get("provider", "?"),
                settings["llm"].get("attacker_max_tokens", "?"))

    run_id = resume_data.get("run_id") if resume_data else _cp.new_run_id()
    if _cp.is_enabled(settings):
        logger.info("Run ID: %s  (checkpoint every %d steps -> %s)",
                    run_id, _cp.interval(settings), _cp.checkpoint_path(settings, run_id))
    try:
        return run_scan(settings, url, steer=_stdin_steer(logger), run_id=run_id, resume=resume_data)
    except KeyboardInterrupt:
        if _cp.is_enabled(settings) and _cp.checkpoint_path(settings, run_id).is_file():
            logger.warning("Interrupted. Resume this run with:  gradientql --resume %s", run_id)
        elif _cp.is_enabled(settings):
            logger.warning("Interrupted before the first checkpoint was written - nothing to resume.")
        sys.exit(130)


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
    parser.add_argument("--resume", type=str, default=None, metavar="RUN_ID",
                        help="Resume a previous run from its last checkpoint (a run id like "
                             "gql-... or a checkpoint file path). See output/checkpoints/.")
    parser.add_argument("--max-tokens", type=int, default=None, metavar="N",
                        help="Override the model's max output tokens per step "
                             "(llm.attacker_max_tokens in settings).")
    parser.add_argument("--tui", action="store_true",
                        help="Force the interactive banner/menu/live-dashboard UI.")
    parser.add_argument("--no-tui", action="store_true",
                        help="Force the plain log output even in a terminal.")
    args = parser.parse_args()

    interactive = sys.stdout.isatty() and not args.no_tui and args.resume is None
    if args.resume is None and (args.tui or (args.url is None and interactive)):
        if not sys.stdout.isatty():
            main(settings_path=args.settings, target_url=args.url, trace=args.trace,
                 verbose=args.verbose, max_tokens=args.max_tokens)
            return
        from ..tui import launch
        launch(settings_path=args.settings, target_url=args.url, trace=args.trace, verbose=args.verbose)
        return
    result = main(settings_path=args.settings, target_url=args.url, trace=args.trace,
                  verbose=args.verbose, resume=args.resume, max_tokens=args.max_tokens)
    if isinstance(result, dict) and result.get("error"):
        sys.exit(2)


if __name__ == "__main__":
    cli()
