"""Configuration loading from YAML files."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

_CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config"

_SHARED_KEY_FILE = "api_key.local"


def _read_shared_api_key() -> str:
    path = _CONFIG_DIR / _SHARED_KEY_FILE
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                return line
    except OSError:
        pass
    return ""


def load_settings(path: str | Path | None = None) -> dict[str, Any]:
    """Load YAML settings and resolve the LLM API key.

    The returned dict is mutated to set llm.api_key, resolved in priority
    order: explicit config value, then the shared api_key.local file, then the
    api_key_env environment variable (empty string if none is found).
    """
    if path is None:
        path = _CONFIG_DIR / "settings.yaml"
    with open(path, encoding="utf-8") as f:
        settings = yaml.safe_load(f)

    llm_cfg = settings.setdefault("llm", {})
    api_key_env = llm_cfg.get("api_key_env", "OPENROUTER_API_KEY")
    key = (llm_cfg.get("api_key") or "").strip()
    if not key:
        key = _read_shared_api_key()
    if not key:
        key = os.environ.get(api_key_env, "")
    llm_cfg["api_key"] = key

    return settings
