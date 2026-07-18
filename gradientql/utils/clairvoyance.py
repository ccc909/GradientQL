"""Clairvoyance: rebuild a GraphQL schema from validation-error suggestions when introspection is off.

Many servers disable introspection but still return "Cannot query field X ... Did you mean a, b?"
suggestions and "Field X must have a selection..." / "argument Y is required" errors. Firing a
wordlist of candidate field names and mining those messages reconstructs the root fields without
introspection - the classic Clairvoyance technique (here driven directly, wordlist baked in).
"""

from __future__ import annotations

import re
from typing import Any

_SUGGEST_RE = re.compile(r"[Dd]id you mean (.+?)(?:\?|$)")
_QUOTED_RE = re.compile(r"[\"'`]([A-Za-z_][A-Za-z0-9_]*)[\"'`]")
# a valid field surfaced by a "needs selection / needs argument" error names itself first
_VALID_FIELD_RE = re.compile(r'[Ff]ield [\"\'`]?([A-Za-z_][A-Za-z0-9_]*)[\"\'`]?')
_CANNOT_RE = re.compile(r"[Cc]annot query field")

# Compact wordlist of common GraphQL root-field / entity names across CMS, e-commerce, SaaS, auth.
DEFAULT_WORDLIST: tuple[str, ...] = (
    "me", "viewer", "currentUser", "user", "users", "account", "accounts", "node", "nodes",
    "profile", "profiles", "member", "members", "customer", "customers", "admin", "admins",
    "employee", "staff", "person", "people", "contact", "contacts", "organization", "organizations",
    "org", "team", "teams", "group", "groups", "role", "roles", "permission", "permissions",
    "session", "sessions", "token", "tokens", "apiKey", "apiKeys", "credential", "credentials",
    "login", "logout", "register", "signup", "signIn", "signUp", "authenticate", "auth",
    "resetPassword", "forgotPassword", "changePassword", "verifyEmail", "confirmEmail",
    "createUser", "updateUser", "deleteUser", "createAccount", "updateAccount", "deleteAccount",
    "order", "orders", "cart", "carts", "checkout", "invoice", "invoices", "payment", "payments",
    "transaction", "transactions", "subscription", "subscriptions", "plan", "plans", "price",
    "product", "products", "item", "items", "sku", "inventory", "catalog", "category", "categories",
    "collection", "collections", "review", "reviews", "rating", "ratings", "wishlist", "coupon",
    "coupons", "giftCard", "discount", "refund", "shipment", "shipping", "address", "addresses",
    "post", "posts", "page", "pages", "article", "articles", "blog", "comment", "comments",
    "media", "mediaItem", "mediaItems", "image", "images", "file", "files", "document", "documents",
    "upload", "attachment", "attachments", "asset", "assets", "tag", "tags", "menu", "menus",
    "search", "query", "filter", "config", "configuration", "settings", "setting", "preference",
    "preferences", "feature", "features", "flag", "flags", "notification", "notifications",
    "message", "messages", "chat", "conversation", "email", "emails", "sms", "webhook", "webhooks",
    "event", "events", "log", "logs", "audit", "activity", "activities", "report", "reports",
    "dashboard", "metric", "metrics", "analytics", "stat", "stats", "project", "projects", "task",
    "tasks", "ticket", "tickets", "issue", "issues", "job", "jobs", "workflow", "comment",
    "company", "companies", "vendor", "supplier", "store", "shop", "warehouse", "location",
    "country", "countries", "currency", "language", "translation", "secret", "secrets", "vault",
    "key", "keys", "certificate", "policy", "policies", "backup", "restore", "export", "import",
    "_entities", "_service", "_sdl", "healthCheck", "health", "version", "ping", "status",
)


def _parse_message(msg: str, candidates: set[str], found: set[str]) -> None:
    """Mine one error message for valid field names (suggestions + self-named valid fields)."""
    for m in _SUGGEST_RE.finditer(msg):
        for name in _QUOTED_RE.findall(m.group(1)):
            found.add(name)
    if not _CANNOT_RE.search(msg):
        vm = _VALID_FIELD_RE.search(msg)
        if vm and vm.group(1) in candidates:
            found.add(vm.group(1))


def recover_root_fields(client: Any, op: str, wordlist: tuple[str, ...] | list[str],
                        extra_headers: dict | None = None, max_requests: int = 10,
                        batch: int = 25) -> set[str]:
    """Recover valid `op` (query|mutation) root field names via the suggestion oracle.

    Fires the wordlist in aliased batches; a candidate is valid if it resolves into data or the
    server's error names it (needs-selection/needs-argument) or suggests it. Bounded by max_requests.
    """
    wl = list(dict.fromkeys(wordlist))
    found: set[str] = set()
    i = reqs = 0
    while i < len(wl) and reqs < max_requests:
        chunk = wl[i:i + batch]
        i += batch
        reqs += 1
        cand = set(chunk)
        query = op + " { " + " ".join(f"c{j}: {n}" for j, n in enumerate(chunk)) + " }"
        try:
            resp = client.execute(query, extra_headers=extra_headers)
        except Exception:  # noqa: BLE001
            continue
        data = resp.get("data")
        if isinstance(data, dict):
            for j, n in enumerate(chunk):
                if f"c{j}" in data:
                    found.add(n)
        for e in resp.get("errors") or []:
            _parse_message(str(e.get("message", "")), cand, found)
    return {f for f in found if not f.startswith("c") or not f[1:].isdigit()}
