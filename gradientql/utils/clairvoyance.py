"""Clairvoyance: rebuild a schema map from validation errors when introspection is disabled.

Handles both GraphQL error dialects:
  graphql-js:   Cannot query field "x" on type "Query".
                Field "y" of type "T" must have a selection of subfields.
                Field "z" argument "a" of type "A!" is required.
  graphql-java: Validation error (FieldUndefined@[x]) : Field 'x' in type 'Query' is undefined
                Validation error (SubselectionRequired@[y]) : Subselection required for type 'T'
                Validation error (MissingFieldArgument@[z]) : Missing field argument 'a'

Key idea: GraphQL validation is exhaustive - one request reports EVERY invalid field in the
selection. So for a batch `{ a b c ... }`, the fields the server does NOT flag as undefined are
valid. From the same errors we also learn each field's return type (needs-subselection) and required
arguments (missing-argument), which lets us descend into object types and recover a multi-level map -
not just root field names.
"""

from __future__ import annotations

import re
from typing import Any

_PATH_RE = re.compile(r"@\[([A-Za-z_][\w./]*)\]")
_CANNOT_RE = re.compile(r"cannot query field ['\"`]([A-Za-z_]\w*)", re.I)
_JAVA_UNDEF_RE = re.compile(r"field ['\"`]([A-Za-z_]\w*)['\"`] in type ['\"`][A-Za-z_]\w*['\"`] is undefined", re.I)
_SUBSEL_JAVA_RE = re.compile(r"subselection required for type ['\"`]?([A-Za-z_]\w*)", re.I)
_MUSTSEL_JS_RE = re.compile(r"field ['\"`]([A-Za-z_]\w*)['\"`] of type ['\"`]([A-Za-z_]\w*)['\"`][^.]*must have a selection", re.I)
_MISSINGARG_JAVA_RE = re.compile(r"missing field argument ['\"`]?([A-Za-z_]\w*)", re.I)
_REQARG_JS_RE = re.compile(r"field ['\"`]([A-Za-z_]\w*)['\"`] argument ['\"`]([A-Za-z_]\w*)", re.I)
_SUGGEST_RE = re.compile(r"did you mean (.+?)(?:\?|$)", re.I)
_QUOTED_RE = re.compile(r"['\"`]([A-Za-z_]\w*)['\"`]")
# WrongType errors name the expected argument type, e.g.
#   graphql-java: argument 'videoIds[0]' with value '...' is not a valid 'Int' - Expected an AST type of 'Int'
#   graphql-js:   Field "x" argument "id" of type "ID!" is required
_WT_ARG_RE = re.compile(r"argument ['\"`]?([A-Za-z_]\w*)(\[\d*\])?['\"`]?", re.I)
_WT_TYPE_RE = re.compile(r"(?:not a valid|AST type of|of type) ['\"`]?(\[?[A-Za-z_][\w]*)", re.I)
_WT_FIELD_JS_RE = re.compile(r"field ['\"`]([A-Za-z_]\w*)['\"`] argument", re.I)

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
    "media", "mediaItem", "mediaItems", "image", "images", "video", "videos", "file", "files",
    "document", "documents", "upload", "attachment", "attachments", "asset", "assets", "tag", "tags",
    "title", "name", "description", "body", "text", "content", "value", "key", "id", "type",
    "status", "state", "url", "uri", "link", "href", "email", "phone", "username", "createdAt",
    "updatedAt", "timestamp", "date", "count", "total", "amount", "quantity", "message", "messages",
    "notification", "notifications", "search", "query", "filter", "config", "configuration",
    "settings", "setting", "preference", "preferences", "feature", "features", "flag", "flags",
    "chat", "conversation", "sms", "webhook", "webhooks", "event", "events", "log", "logs", "audit",
    "activity", "activities", "report", "reports", "dashboard", "metric", "metrics", "analytics",
    "stat", "stats", "project", "projects", "task", "tasks", "ticket", "tickets", "issue", "issues",
    "job", "jobs", "workflow", "company", "companies", "vendor", "supplier", "store", "shop",
    "warehouse", "location", "country", "countries", "currency", "language", "translation",
    "secret", "secrets", "vault", "certificate", "policy", "policies", "backup", "export", "import",
    "_entities", "_service", "healthCheck", "health", "version", "ping", "status", "artwork",
    "genre", "genres", "series", "episode", "episodes", "season", "seasons", "movie", "movies",
    "title", "titles", "watchlist", "recommendation", "recommendations", "playback", "device",
    "devices", "membership", "billing", "gift",
)


def _leaf(path: str) -> str:
    return path.split("/")[-1].split(".")[-1]


def _analyze(resp: dict, chunk: list[str]) -> dict[str, dict]:
    """Classify a batch response into {field: {return_type, args, scalar}} for the valid fields.

    Returns {} when the response shows no per-field signal at all (a wholesale failure we can't
    trust), so we never hallucinate a schema from an unrelated error.
    """
    errors = resp.get("errors") or []
    data = resp.get("data")
    undefined: set[str] = set()
    obj_type: dict[str, str] = {}
    needs_arg: dict[str, list[str]] = {}
    suggestions: set[str] = set()

    for e in errors:
        msg = str(e.get("message", ""))
        for sm in _SUGGEST_RE.finditer(msg):
            suggestions.update(_QUOTED_RE.findall(sm.group(1)))
        mp = _PATH_RE.search(msg)
        path_field = _leaf(mp.group(1)) if mp else None

        m = _CANNOT_RE.search(msg) or _JAVA_UNDEF_RE.search(msg)
        if m:
            undefined.add(m.group(1))
            continue
        m = _MUSTSEL_JS_RE.search(msg)
        if m:
            obj_type[m.group(1)] = m.group(2)
            continue
        m = _SUBSEL_JAVA_RE.search(msg)
        if m and path_field:
            obj_type[path_field] = m.group(1)
            continue
        m = _REQARG_JS_RE.search(msg)
        if m:
            needs_arg.setdefault(m.group(1), []).append(m.group(2))
            continue
        m = _MISSINGARG_JAVA_RE.search(msg)
        if m and path_field:
            needs_arg.setdefault(path_field, []).append(m.group(1))
            continue

    resolved = {k for k in (data or {}) if k in chunk} if isinstance(data, dict) else set()
    chunk_set = set(chunk)
    positive = set(obj_type) | set(needs_arg) | resolved | (suggestions & chunk_set)
    if not (undefined or positive):
        return {}

    valid = (chunk_set - undefined) | positive
    # Guard against NON-exhaustive error reporting (an error cap, a persisted-query gate, or a WAF
    # that returns one generic error). On a broad wordlist BATCH an exhaustive server flags MOST words
    # as undefined; if it flagged fewer than half, it capped its errors, so "chunk - undefined" would
    # invent hundreds of junk fields - trust only positively-signalled fields there. (Small chunks,
    # e.g. a tiny type's fields, are exempt: a few valid out of a few is normal.)
    if len(chunk_set) >= 10 and len(undefined) < 0.5 * len(chunk_set):
        valid = positive
    out: dict[str, dict] = {}
    for f in valid:
        if f in undefined:
            continue
        out[f] = {"return_type": obj_type.get(f, ""), "args": needs_arg.get(f, []),
                  "scalar": f not in obj_type}
    return out


def _placeholder(type_ref: str) -> str:
    """A syntactically-valid placeholder value for an argument of the given (possibly unknown) type."""
    t = str(type_ref or "")
    base = t.strip("[]!").lower()
    if base in ("int", "float", "long", "bigint", "number"):
        val = "1"
    elif base in ("boolean", "bool"):
        val = "true"
    else:
        val = '"1"'
    return f"[{val}]" if "[" in t else val


def _arg_segment(field: str, args: list[dict]) -> str:
    """Render a field with typed placeholder args (correct type lets validation reach the subselection)."""
    if not args:
        return field
    return field + "(" + ", ".join(f'{a["name"]}: {_placeholder(a.get("type", ""))}' for a in args) + ")"


def _parse_arg_type(msg: str) -> tuple[str, str, str] | None:
    """Extract (field, arg, gql_type) from a WrongType / required-argument error, or None."""
    mp = _PATH_RE.search(msg)
    field = _leaf(mp.group(1)) if mp else None
    mjs = _WT_FIELD_JS_RE.search(msg)
    if mjs:
        field = mjs.group(1)
    ma = _WT_ARG_RE.search(msg)
    mt = _WT_TYPE_RE.search(msg)
    if not (field and ma and mt):
        return None
    base = mt.group(1).lstrip("[")
    is_list = bool(ma.group(2)) or mt.group(1).startswith("[")
    return field, ma.group(1), f"[{base}]" if is_list else base


def recover_schema(client: Any, extra_headers: dict | None = None,
                   wordlist: tuple[str, ...] | list[str] | None = None,
                   max_requests: int = 60, batch: int = 40, max_depth: int = 3) -> dict[str, Any]:
    """Crawl the endpoint's validation errors into a schema_map (types, fields, return types, args).

    Recovers root Query/Mutation fields and descends `max_depth` levels into the object types they
    return, bounded by `max_requests` total probe requests.
    """
    wl = list(dict.fromkeys(wordlist or DEFAULT_WORDLIST))
    budget = [max_requests]
    schema: dict[str, Any] = {"_query_type": "Query", "_mutation_type": "Mutation",
                              "_subscription_type": "", "_input_types": {}, "_enum_types": {},
                              "_interfaces": set(), "_unions": set(), "_type_kinds": {}}
    seen: set[str] = set()

    def build(op: str, path: list[str], candidates: list[str]) -> str:
        body = " ".join(candidates)
        for seg in reversed(path):
            body = f"{seg} {{ {body} }}"
        return f"{op} {{ {body} }}"

    def probe(op: str, type_name: str, path: list[str], depth: int) -> None:
        if budget[0] <= 0 or type_name in seen:
            return
        seen.add(type_name)
        found: dict[str, dict] = {}
        i = 0
        while i < len(wl) and budget[0] > 0:
            chunk = wl[i:i + batch]
            i += batch
            budget[0] -= 1
            try:
                resp = client.execute(build(op, path, chunk), extra_headers=extra_headers)
            except Exception:  # noqa: BLE001
                continue
            for f, meta in _analyze(resp, chunk).items():
                found.setdefault(f, meta)
        if not found:
            return
        schema[type_name] = {
            f: {"args": [{"name": a, "type": "", "default": None} for a in meta["args"]],
                # a return type equal to a root type is almost always a mis-parse - drop it to "unknown"
                "return_type": "" if meta["return_type"] in ("Query", "Mutation", "Subscription")
                else meta["return_type"], "description": "(recovered via clairvoyance)"}
            for f, meta in found.items()}
        _learn_arg_types(client, op, path, schema[type_name], extra_headers, budget)
        if depth < max_depth:
            for f, meta in found.items():
                t = meta["return_type"]
                if t and not meta["scalar"] and t not in seen and budget[0] > 0:
                    probe(op, t, path + [_arg_segment(f, schema[type_name][f]["args"])], depth + 1)

    probe("query", "Query", [], 0)
    probe("mutation", "Mutation", [], 0)
    return schema


def _learn_arg_types(client: Any, op: str, path: list[str], fields: dict[str, dict],
                     extra_headers: dict | None, budget: list[int]) -> None:
    """One probe: call each arg-bearing field with placeholder args and read WrongType to type the args."""
    callable_ = {f: m for f, m in fields.items()
                 if any(not a.get("type") for a in m.get("args", []))}
    if not callable_ or budget[0] <= 0:
        return
    sels = []
    for f, m in callable_.items():
        argstr = ", ".join(f'{a["name"]}: {_placeholder(a.get("type", ""))}' for a in m["args"])
        # NO `{ __typename }` selection: some servers (e.g. Netflix) reject __typename as introspection,
        # which would fail the whole probe. The WrongType arg error fires regardless of selection.
        sels.append(f"{f}({argstr})")
    body = " ".join(sels)
    for seg in reversed(path):
        body = f"{seg} {{ {body} }}"
    budget[0] -= 1
    try:
        resp = client.execute(f"{op} {{ {body} }}", extra_headers=extra_headers)
    except Exception:  # noqa: BLE001
        return
    for e in resp.get("errors") or []:
        parsed = _parse_arg_type(str(e.get("message", "")))
        if not parsed:
            continue
        field, arg, gtype = parsed
        for a in fields.get(field, {}).get("args", []):
            if a["name"] == arg and not a.get("type"):
                a["type"] = gtype


def merge_into_schema(schema_map: dict[str, Any], recovered: dict[str, Any]) -> int:
    """Merge a recovered schema fragment into schema_map in place; return the number of new fields."""
    added = 0
    for tname, fields in recovered.items():
        if tname.startswith("_") or not isinstance(fields, dict):
            continue
        bucket = schema_map.setdefault(tname, {})
        if not isinstance(bucket, dict):
            continue
        for fname, meta in fields.items():
            if fname not in bucket:
                bucket[fname] = meta
                added += 1
            elif not bucket[fname].get("return_type") and meta.get("return_type"):
                bucket[fname] = meta
    for k in ("_query_type", "_mutation_type"):
        schema_map.setdefault(k, recovered.get(k, k.split("_")[1].capitalize()))
    return added
