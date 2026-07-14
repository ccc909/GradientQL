"""API-key precedence in load_settings.

Order: per-config YAML `api_key` > shared config/api_key.local > env var.
"""

import textwrap

import gradientql.core.config as config
from gradientql.core.config import load_settings


def _write(tmp_path, body):
    p = tmp_path / "s.yaml"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return str(p)


def _shared_key_dir(tmp_path, monkeypatch, contents=None):
    """Point the shared-key lookup at a tmp config dir; optionally seed api_key.local."""
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)
    if contents is not None:
        (tmp_path / "api_key.local").write_text(contents, encoding="utf-8")


def test_hardcoded_key_wins_over_env(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "env-key")
    path = _write(tmp_path, """
        llm:
          api_key_env: "OPENROUTER_API_KEY"
          api_key: "hardcoded-key"
    """)
    assert load_settings(path)["llm"]["api_key"] == "hardcoded-key"


def test_empty_hardcoded_falls_back_to_env(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "env-key")
    _shared_key_dir(tmp_path, monkeypatch)  # isolate: no shared api_key.local
    path = _write(tmp_path, """
        llm:
          api_key_env: "OPENROUTER_API_KEY"
          api_key: ""
    """)
    assert load_settings(path)["llm"]["api_key"] == "env-key"


def test_missing_key_field_falls_back_to_env(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "env-key")
    _shared_key_dir(tmp_path, monkeypatch)
    path = _write(tmp_path, """
        llm:
          api_key_env: "OPENROUTER_API_KEY"
    """)
    assert load_settings(path)["llm"]["api_key"] == "env-key"


def test_whitespace_only_key_falls_back(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "env-key")
    _shared_key_dir(tmp_path, monkeypatch)
    path = _write(tmp_path, """
        llm:
          api_key_env: "OPENROUTER_API_KEY"
          api_key: "   "
    """)
    assert load_settings(path)["llm"]["api_key"] == "env-key"


def test_no_env_and_no_key_is_empty(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setattr(config, "_CONFIG_DIR", tmp_path)  # no shared file present
    path = _write(tmp_path, """
        llm:
          api_key_env: "OPENROUTER_API_KEY"
    """)
    assert load_settings(path)["llm"]["api_key"] == ""


# --- shared config/api_key.local (the "everywhere" hardcode) ---

def test_shared_file_used_when_yaml_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "env-key")
    _shared_key_dir(tmp_path, monkeypatch,
                    contents="# my key\nsk-or-shared-123\n")
    path = _write(tmp_path, "llm:\n  api_key_env: \"OPENROUTER_API_KEY\"\n")
    # Shared file beats env, but loses to a per-config api_key.
    assert load_settings(path)["llm"]["api_key"] == "sk-or-shared-123"


def test_per_config_key_beats_shared_file(tmp_path, monkeypatch):
    _shared_key_dir(tmp_path, monkeypatch, contents="sk-or-shared-123\n")
    path = _write(tmp_path, """
        llm:
          api_key: "sk-or-per-config"
    """)
    assert load_settings(path)["llm"]["api_key"] == "sk-or-per-config"


def test_shared_file_comment_only_falls_back_to_env(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "env-key")
    _shared_key_dir(tmp_path, monkeypatch, contents="# only a comment here\n")
    path = _write(tmp_path, "llm:\n  api_key_env: \"OPENROUTER_API_KEY\"\n")
    assert load_settings(path)["llm"]["api_key"] == "env-key"
