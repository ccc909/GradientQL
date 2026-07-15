"""Tests for the CLI, including the stdin steering channel."""

from __future__ import annotations

import io
import logging
import time

from gradientql.scanner import cli


def test_stdin_steer_none_when_not_tty(monkeypatch):
    fake = io.StringIO("")
    fake.isatty = lambda: False
    monkeypatch.setattr("sys.stdin", fake)
    assert cli._stdin_steer(logging.getLogger("t")) is None


def test_stdin_steer_drains_typed_lines(monkeypatch):
    fake = io.StringIO("search for DoS now\ncheck the upload field\n")
    fake.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", fake)
    drain = cli._stdin_steer(logging.getLogger("t"))
    assert drain is not None
    msgs: list[str] = []
    for _ in range(25):
        msgs += drain()
        if len(msgs) >= 2:
            break
        time.sleep(0.02)
    assert "search for DoS now" in msgs
    assert "check the upload field" in msgs
    assert drain() == []          # queue drained
