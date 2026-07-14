"""Out-of-band (OOB) interaction scaffolding for BLIND SSRF / XXE / injection."""

from __future__ import annotations

import hashlib
import logging
from typing import Any

logger = logging.getLogger("gradientql.oob")


def is_enabled(settings: dict[str, Any]) -> bool:
    """Report whether OOB is both toggled on and given a collaborator domain."""
    oob = settings.get("scanner", {}).get("oob", {})
    return bool(oob.get("enabled")) and bool(oob.get("collaborator_domain"))


def collaborator_domain(settings: dict[str, Any]) -> str | None:
    return settings.get("scanner", {}).get("oob", {}).get("collaborator_domain") or None


def make_token(*seed_parts: str) -> str:
    """Derive a stable 13-char correlation label (`p` + 12 hex) from seed parts."""
    h = hashlib.sha1("|".join(seed_parts).encode()).hexdigest()[:12]
    return f"p{h}"


def callback_url(domain: str, token: str, scheme: str = "http") -> str:
    return f"{scheme}://{token}.{domain}/"


def oob_payloads(domain: str, token: str) -> dict[str, str]:
    """Build injection payloads (ssrf/ssrf_https/xxe/dns) that call back to token."""
    http = callback_url(domain, token, "http")
    return {
        "ssrf": http,
        "ssrf_https": callback_url(domain, token, "https"),
        "xxe": (
            f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "{http}">]><r>&x;</r>'
        ),
        "dns": f"{token}.{domain}",
    }


def detect_reflection(response_text: str, token: str) -> bool:
    return bool(token) and token in (response_text or "")


def poll_interactions(settings: dict[str, Any], tokens: list[str]) -> list[str]:
    """No-op stub; live polling lives in OobSession.reconcile."""
    return []


class OobSession:
    """A registered out-of-band channel that mints and reconciles callback tokens."""

    def __init__(self, settings: dict[str, Any]):
        oob = settings.get("scanner", {}).get("oob", {})
        self.enabled = bool(oob.get("enabled")) and bool(oob.get("collaborator_domain"))
        self.provider = (oob.get("provider") or "interactsh").lower()
        self.domain = oob.get("collaborator_domain") or ""
        self.client = None
        self.issued: dict[str, dict[str, Any]] = {}
        if self.enabled and self.provider == "interactsh":
            try:
                from .interactsh import InteractshClient
                c = InteractshClient(server=self.domain, token=oob.get("token"))
                if c.register():
                    self.client = c
                    logger.info("interactsh registered on %s (corr-id %s)", c.server, c.correlation_id)
                else:
                    logger.warning("interactsh registration failed — OOB falls back to reflection only")
            except Exception as e:  # noqa: BLE001
                logger.warning("interactsh unavailable (%s) — OOB falls back to reflection only", e)

    def issue(self, context: dict[str, Any]) -> tuple[str, str]:
        """Mint a callback URL, recording context under its label for later matching.

        Returns:
            The (url, label) pair; label is the correlation key stored in issued.
        """
        if self.client is not None:
            url, label = self.client.new_url()
        else:
            label = make_token(str(context.get("approach", "")), str(context.get("node", "")))
            url = callback_url(self.domain, label)
        self.issued[label] = context
        return url, label

    def reconcile(self) -> list[dict[str, Any]]:
        """Poll the collaborator and match interactions back to issued labels.

        Returns:
            One {context, interaction} dict per issued token that fired.
        """
        if self.client is None:
            return []
        hits: list[dict[str, Any]] = []
        try:
            interactions = self.client.poll()
        except Exception:  # noqa: BLE001
            return []
        for ix in interactions:
            full = str(ix.get("full-id") or ix.get("unique-id") or "")
            for label, ctx in self.issued.items():
                if label and label in full:
                    hits.append({"context": ctx, "interaction": ix})
                    break
        return hits


_session: OobSession | None = None


def get_session(settings: dict[str, Any]) -> OobSession:
    """Return the process-wide OobSession, constructing it on first call."""
    global _session
    if _session is None:
        _session = OobSession(settings)
    return _session


def reset_session() -> None:
    global _session
    _session = None
