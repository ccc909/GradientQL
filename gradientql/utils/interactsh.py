"""Interactsh (ProjectDiscovery) OOB client — register + poll public servers, no self-host."""

from __future__ import annotations

import base64
import json
import logging
import secrets
import string
from typing import Any
from uuid import uuid4

import requests

logger = logging.getLogger("gradientql.interactsh")

DEFAULT_SERVERS = ("oast.fun", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.me")
_LABEL_CHARS = string.ascii_lowercase + string.digits


def _rand_label(n: int) -> str:
    return "".join(secrets.choice(_LABEL_CHARS) for _ in range(n))


class InteractshClient:
    """One OOB-interaction session against a public interactsh server."""

    def __init__(self, server: str = "oast.fun", token: str | None = None, timeout: int = 15):
        from Crypto.PublicKey import RSA

        s = server.strip()
        for _pre in ("https://", "http://"):
            if s.startswith(_pre):
                s = s[len(_pre):]
        self.server = s.strip("/")
        self.token = token or None
        self.timeout = timeout
        self._priv = RSA.generate(2048)
        self.public_key_pem = self._priv.publickey().export_key()
        self.correlation_id = _rand_label(20)
        self.secret = str(uuid4())
        self.registered = False

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.token:
            h["Authorization"] = self.token
        return h

    def register(self) -> bool:
        """Register this client's public key with the server; set and return registered."""
        data = {
            "public-key": base64.b64encode(self.public_key_pem).decode(),
            "secret-key": self.secret,
            "correlation-id": self.correlation_id,
        }
        try:
            r = requests.post(f"https://{self.server}/register", json=data,
                              headers=self._headers(), timeout=self.timeout)
            self.registered = r.status_code == 200
            if not self.registered:
                logger.warning("interactsh register failed (%s): %s", r.status_code, r.text[:200])
        except requests.RequestException as e:
            logger.warning("interactsh register error: %s", e)
            self.registered = False
        return self.registered

    def deregister(self) -> None:
        try:
            requests.post(f"https://{self.server}/deregister",
                          json={"secret-key": self.secret, "correlation-id": self.correlation_id},
                          headers=self._headers(), timeout=self.timeout)
        except requests.RequestException:
            pass

    def new_url(self, scheme: str = "http") -> tuple[str, str]:
        """Mint a unique callback URL and its subdomain label for this session.

        The label embeds this client's correlation id so interactions on the URL
        surface through poll(); returns the full URL and the bare label.
        """
        label = self.correlation_id + _rand_label(13)
        return f"{scheme}://{label}.{self.server}/", label

    def poll(self) -> list[dict[str, Any]]:
        """Fetch and decrypt captured interactions since the last poll.

        Returns an empty list if not registered or on any transport, key, or
        record error; individual undecryptable records are skipped.
        """
        if not self.registered:
            return []
        try:
            r = requests.get(
                f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret}",
                headers=self._headers(), timeout=self.timeout,
            )
            body = r.json()
        except (requests.RequestException, ValueError) as e:
            logger.debug("interactsh poll error: %s", e)
            return []

        aes_key_b64 = body.get("aes_key")
        items = body.get("data") or []
        if not aes_key_b64 or not items:
            return []
        try:
            aes_key = self._decrypt_aes_key(aes_key_b64)
        except Exception as e:  # noqa: BLE001
            logger.debug("interactsh aes-key decrypt failed: %s", e)
            return []

        out: list[dict[str, Any]] = []
        for item in items:
            try:
                out.append(json.loads(self._decrypt_item(aes_key, item)))
            except Exception:  # noqa: BLE001 - skip a single bad record
                continue
        return out

    def _decrypt_aes_key(self, aes_key_b64: str) -> bytes:
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.Hash import SHA256
        cipher = PKCS1_OAEP.new(self._priv, hashAlgo=SHA256)
        return cipher.decrypt(base64.b64decode(aes_key_b64))

    @staticmethod
    def _decrypt_item(aes_key: bytes, item_b64: str) -> bytes:
        from Crypto.Cipher import AES
        decoded = base64.b64decode(item_b64)
        iv, ciphertext = decoded[: AES.block_size], decoded[AES.block_size:]
        cryptor = AES.new(key=aes_key, mode=AES.MODE_CTR, nonce=b"", initial_value=iv)
        return cryptor.decrypt(ciphertext)
