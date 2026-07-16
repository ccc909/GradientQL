"""Configuration loading from YAML files."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

# config/ next to the installed package (editable install / repo checkout), and next to the
# working directory (a plain `pip install`, or the Docker image's WORKDIR).
_CONFIG_DIRS = (Path(__file__).resolve().parent.parent.parent / "config", Path.cwd() / "config")

_SHARED_KEY_FILE = "api_key.local"


def _read_shared_api_key() -> str:
    for d in _CONFIG_DIRS:
        try:
            for line in (d / _SHARED_KEY_FILE).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
        except OSError:
            continue
    return ""


def load_settings(path: str | Path | None = None) -> dict[str, Any]:
    """Load YAML settings and resolve the LLM API key.

    Without an explicit path, look for config/settings.yaml next to the package and next to the
    working directory; if neither exists, fall back to built-in defaults (every setting has one).
    The returned dict is mutated to set llm.api_key, resolved in priority order: explicit config
    value, then the shared api_key.local file, then the api_key_env environment variable.
    """
    settings: Any = None
    candidates = [Path(path)] if path is not None else [d / "settings.yaml" for d in _CONFIG_DIRS]
    for cand in candidates:
        try:
            with open(cand, encoding="utf-8") as f:
                settings = yaml.safe_load(f)
            break
        except FileNotFoundError:
            continue
    if settings is None:
        if path is not None:
            raise FileNotFoundError(f"settings file not found: {path}")
        settings = {}  # no config file anywhere; every key falls back to a built-in default
    settings = settings or {}

    llm_cfg = settings.setdefault("llm", {})
    api_key_env = llm_cfg.get("api_key_env", "OPENROUTER_API_KEY")
    key = (llm_cfg.get("api_key") or "").strip()
    if not key:
        key = _read_shared_api_key()
    if not key:
        key = os.environ.get(api_key_env, "")
    llm_cfg["api_key"] = key

    return settings
