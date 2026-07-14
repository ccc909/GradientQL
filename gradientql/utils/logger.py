"""Logging configuration for GradientQL."""

from __future__ import annotations

import logging
import os
import sys

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
os.environ.setdefault("TF_ENABLE_ONEDNN_OPTS", "0")
os.environ.setdefault("GRPC_VERBOSITY", "ERROR")


def _make_streams_utf8_safe() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass


_make_streams_utf8_safe()


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configure and return the package logger, attaching its handler once.

    Idempotent: re-running only adjusts the level and never duplicates handlers.
    Also quiets noisy third-party loggers to ERROR.
    """
    logger = logging.getLogger("gradientql")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            "[%(asctime)s] %(name)s %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.propagate = False

    for noisy in (
        "tensorflow",
        "absl",
        "h5py",
        "google.protobuf",
        "grpc",
        "sentence_transformers",
    ):
        logging.getLogger(noisy).setLevel(logging.ERROR)

    return logger


logger = setup_logging()
