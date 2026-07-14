"""Disposable inbox via mail.tm (free, no API key) for email-gated signup flows."""

from __future__ import annotations

import logging
import re
import secrets

import requests

logger = logging.getLogger("gradientql.tempmail")

_BASE = "https://api.mail.tm"
_TIMEOUT = 12

_URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
_KEY_RE = re.compile(r"(?:[?&](?:key|token|confirmation_key|code|id)=)([A-Za-z0-9_\-./%]+)", re.I)


class TempMailClient:
    """A single disposable mail.tm inbox used to receive signup/confirmation mail."""

    def __init__(self) -> None:
        self.address: str | None = None
        self._password: str | None = None
        self._token: str | None = None
        self._seen: set[str] = set()

    def create(self) -> str | None:
        """Register a random inbox and return its address, or None if unavailable."""
        try:
            doms = requests.get(f"{_BASE}/domains", timeout=_TIMEOUT).json()
            domain = (doms.get("hydra:member") or doms.get("member") or [{}])[0].get("domain")
            if not domain:
                return None
            self.address = f"sec{secrets.token_hex(6)}@{domain}"
            self._password = secrets.token_hex(10)
            r = requests.post(f"{_BASE}/accounts",
                              json={"address": self.address, "password": self._password}, timeout=_TIMEOUT)
            if r.status_code not in (200, 201):
                logger.info("tempmail: account create failed (%s)", r.status_code)
                self.address = None
                return None
            self._ensure_token()
            logger.info("tempmail: inbox ready %s", self.address)
            return self.address
        except Exception as e:  # noqa: BLE001
            logger.info("tempmail: create unavailable (%s)", e)
            return None

    def _ensure_token(self) -> str | None:
        if self._token:
            return self._token
        if not (self.address and self._password):
            return None
        try:
            t = requests.post(f"{_BASE}/token",
                              json={"address": self.address, "password": self._password}, timeout=_TIMEOUT).json()
            self._token = t.get("token")
        except Exception as e:  # noqa: BLE001
            logger.info("tempmail: token failed (%s)", e)
        return self._token

    def poll(self, only_new: bool = True) -> list[dict]:
        """Fetch messages, extracting links and confirmation keys from each.

        Args:
            only_new: When True, skip message ids already returned in a prior poll.
        """
        tok = self._ensure_token()
        if not tok:
            return []
        hdr = {"Authorization": f"Bearer {tok}"}
        try:
            listing = requests.get(f"{_BASE}/messages", headers=hdr, timeout=_TIMEOUT).json()
            items = listing.get("hydra:member") or listing.get("member") or []
        except Exception as e:  # noqa: BLE001
            logger.info("tempmail: poll failed (%s)", e)
            return []
        out: list[dict] = []
        for m in items:
            mid = m.get("id")
            if not mid or (only_new and mid in self._seen):
                continue
            self._seen.add(mid)
            body = ""
            try:
                full = requests.get(f"{_BASE}/messages/{mid}", headers=hdr, timeout=_TIMEOUT).json()
                body = full.get("text") or " ".join(full.get("html") or []) or ""
            except Exception:  # noqa: BLE001
                pass
            blob = f"{m.get('subject', '')}\n{body}"
            out.append({
                "id": mid,
                "from": (m.get("from") or {}).get("address", ""),
                "subject": m.get("subject", ""),
                "links": _URL_RE.findall(blob)[:6],
                "keys": [k for k in _KEY_RE.findall(blob)][:6],
                "snippet": body[:600],
            })
        return out
