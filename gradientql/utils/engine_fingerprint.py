"""GraphQL server-engine fingerprinting via error signatures - a port of graphw00f's detection DB
paired with per-engine attack notes distilled from the GraphQL Threat Matrix.

Why it matters here: the detection is ERROR-SIGNATURE based (send a benign malformed query, match the
error), so it identifies the engine even when introspection is DISABLED - exactly our recovered-schema
case. Knowing the engine also tells us the error dialect (graphql-java vs graphql-js) that clairvoyance
parses, and its default security posture.

Credit: detection signatures adapted from graphw00f (https://github.com/dolevf/graphw00f, dolevf) and
per-engine notes from the GraphQL Threat Matrix (https://github.com/nicholasaleks/graphql-threat-matrix).
"""

from __future__ import annotations

from typing import Any

import requests

# --- probe queries (benign, malformed; they only trigger validation errors) ------------------- #
_EMPTY = ""
_SKIP = "query @skip { __typename }"
_DEPRECATED = "query @deprecated { __typename }"
_AAA = "aaa"
_BAD_QUERYY = "queryy { __typename }"
_TYPENAME = "query { __typename }"

# Each engine matches if ANY of its probe rules hits. Order mirrors graphw00f (specific first) so a
# shared probe (e.g. "@skip") resolves to the right engine.
_ENGINES: list[tuple[str, list[dict[str, Any]]]] = [
    ("inigo", [{"q": _TYPENAME, "ext": "inigo"}]),
    ("lighthouse", [{"q": "query { __typename @include(if: falsee) }", "err": "Internal server error"},
                    {"q": "query { __typename @include(if: falsee) }", "err": "internal", "part": "category"}]),
    ("caliban", [{"q": "query { __typename } fragment woof on __Schema { directives { name } }",
                  "err": "Fragment 'woof' is not used in any spread"}]),
    ("lacinia", [{"q": "query { graphw00f }", "err": "Cannot query field `graphw00f' on type `QueryRoot'."}]),
    ("jaal", [{"q": "{}", "err": "must have a single query"}]),
    ("morpheus-graphql", [{"q": _BAD_QUERYY, "err": "expecting white space"}]),
    ("mercurius", [{"q": _EMPTY, "err": "Unknown query"}]),
    ("graphql-yoga", [{"q": "subscription { __typename }",
                       "err": ["asyncExecutionResult[Symbol.asyncIterator] is not a function", "Unexpected error."]}]),
    ("agoo", [{"q": "query { zzz }", "err": "eval error", "part": "code"}]),
    ("tailcall", [{"q": "aa { __typename }", "err": "expected executable_definition"}]),
    ("dgraph", [{"q": "query { __typename @cascade }", "type": "Query"},
                {"q": _TYPENAME, "err": "There's no GraphQL schema in Dgraph"}]),
    ("graphene", [{"q": _AAA, "err": "Syntax Error GraphQL (1:1)"}]),
    ("ariadne", [{"q": "query { __typename @abc }", "err": "Unknown directive '@abc'.", "no_data": True},
                 {"q": _EMPTY, "err": "The query must be a string."}]),
    ("apollo", [{"q": _SKIP, "err": 'Directive "@skip" argument "if" of type "Boolean!" is required, but it was not provided.'},
                {"q": _DEPRECATED, "err": 'Directive "@deprecated" may not be used on QUERY.'}]),
    ("aws-appsync", [{"q": _SKIP, "err": "MisplacedDirective"}]),
    ("hasura", [{"q": "query @cached { __typename }", "type": "query_root"},
                {"q": "query { aaa }", "err": "field \"aaa\" not found in type: 'query_root'"},
                {"q": _SKIP, "err": 'directive "skip" is not allowed on a query'},
                {"q": "query { __schema }", "err": 'missing selection set for "__Schema"'}]),
    ("wpgraphql", [{"q": _EMPTY, "err": 'GraphQL Request must include at least one of those two parameters: "query" or "queryId"'}]),
    ("graphql-api-for-wp", [{"q": "query { alias1$1:__typename }", "alias": ("alias1$1", "QueryRoot")},
                            {"q": "query aa#aa { __typename }", "err": 'Unexpected token "END"'},
                            {"q": _EMPTY, "err": "The query in the body is empty"}]),
    ("graphql-java", [{"q": _BAD_QUERYY, "err": "Invalid Syntax : offending token 'queryy'"},
                      {"q": "query @aaa@aaa { __typename }", "err": "DuplicateDirectiveName"},
                      {"q": _EMPTY, "err": "Invalid Syntax : offending token '<EOF>'"}]),
    ("hypergraphql", [{"q": "zzz { __typename }", "err": "Validation error of type InvalidSyntax: Invalid query syntax."},
                      {"q": "query { alias1:__typename @deprecated }",
                       "err": "Validation error of type UnknownDirective: Unknown directive deprecated"}]),
    ("graphql-ruby", [{"q": _SKIP, "err": ["'@skip' can't be applied to queries",
                                           "Directive 'skip' is missing required arguments: if"]},
                      {"q": _DEPRECATED, "err": "'@deprecated' can't be applied to queries"},
                      {"q": "query { __typename { }", "err": 'Parse error on "}" (RCURLY)'}]),
    ("graphql-php", [{"q": "query ! { __typename }", "err": 'Syntax Error: Cannot parse the unexpected character "?".'},
                     {"q": _DEPRECATED, "err": 'Directive "deprecated" may not be used on "QUERY".'}]),
    ("gqlgen", [{"q": "query { __typename { }", "err": "expected at least one definition"},
                {"q": "query { alias^_:__typename { }", "err": "Expected Name, found <Invalid>"}]),
    ("graphql-go", [{"q": "query { __typename { }", "err": "Unexpected empty IN"},
                    {"q": _EMPTY, "err": "Must provide an operation."},
                    {"q": _TYPENAME, "type": "RootQuery"}]),
    ("juniper", [{"q": _BAD_QUERYY, "err": 'Unexpected "queryy"'},
                 {"q": _EMPTY, "err": "Unexpected end of input"}]),
    ("sangria", [{"q": _BAD_QUERYY, "field": ("syntaxError", 'Invalid input "queryy", expected ExecutableDefinition')}]),
    ("dianajl", [{"q": _BAD_QUERYY, "err": 'Syntax Error GraphQL request (1:1) Unexpected Name "queryy"'}]),
    ("strawberry", [{"q": _DEPRECATED, "err": "Directive '@deprecated' may not be used on query.", "needs_data": True}]),
    ("tartiflette", [{"q": "query @a { __typename }", "err": "Unknow Directive < @a >."},
                     {"q": _SKIP, "err": "Missing mandatory argument < if > in directive < @skip >."},
                     {"q": "query { graphwoof }", "err": "Field graphwoof doesn't exist on Query"}]),
    ("directus", [{"q": _EMPTY, "extcode": "INVALID_PAYLOAD"}]),
    ("absinthe-graphql", [{"q": "query { graphw00f }", "err": 'Cannot query field "graphw00f" on type "RootQueryType".'}]),
    ("graphql-dotnet", [{"q": _SKIP, "err": "Directive 'skip' may not be used on Query."}]),
    ("pg_graphql", [{"q": "query { __typename @skip(aa:true) }", "err": "Unknown argument to @skip: aa"}]),
    ("hotchocolate", [{"q": _BAD_QUERYY, "err": "Unexpected token: Name."},
                      {"q": "query @aaa@aaa { __typename }", "err": "The specified directive `aaa` is not supported"}]),
    ("ballerina", [{"q": "query { __typename ...A } fragment A on Query { ...B } fragment B on Query { ...A }",
                    "err": 'Cannot spread fragment "A" within itself via "B"'}]),
    ("flutter", [{"q": "query { __typename @deprecated }", "err": 'Directive "deprecated" may not be used on FIELD.'}]),
]


def _err_contains(resp: dict, needle: str, part: str = "message") -> bool:
    for e in resp.get("errors", []) or []:
        if not isinstance(e, dict):
            if needle in str(e):
                return True
            continue
        if needle in str(e.get(part, "")):
            return True
        ext = e.get("extensions")
        if isinstance(ext, dict) and needle in str(ext.get(part, "")):
            return True
    return False


def _match(rule: dict, resp: dict) -> bool:
    data = resp.get("data") if isinstance(resp, dict) else None
    if rule.get("needs_data") and not data:
        return False
    if rule.get("no_data") and data:
        return False
    if "err" in rule:
        needles = rule["err"] if isinstance(rule["err"], list) else [rule["err"]]
        return any(_err_contains(resp, n, rule.get("part", "message")) for n in needles)
    if "type" in rule:
        return isinstance(data, dict) and data.get("__typename") == rule["type"]
    if "alias" in rule:
        alias, val = rule["alias"]
        return isinstance(data, dict) and data.get(alias) == val
    if "field" in rule:
        fname, sub = rule["field"]
        return sub in str(resp.get(fname, ""))
    if "ext" in rule:
        ext = resp.get("extensions")
        return isinstance(ext, dict) and rule["ext"] in ext
    if "extcode" in rule:
        errs = resp.get("errors") or []
        return bool(errs) and isinstance(errs[0], dict) and (errs[0].get("extensions") or {}).get("code") == rule["extcode"]
    return False


def fingerprint_engine(target_url: str, session: Any = None, headers: dict | None = None,
                       timeout: int = 12) -> str | None:
    """Identify the GraphQL engine from error signatures (works with introspection disabled).

    Sends each distinct probe once (POST, then GET fallback) and matches every engine against the
    cached responses in graphw00f order. Returns the engine name, or None if nothing matched.
    """
    http = session or requests
    cache: dict[str, dict] = {}

    def probe(query: str) -> dict:
        if query in cache:
            return cache[query]
        resp: dict = {}
        for send in (
            lambda: http.post(target_url, json={"query": query}, headers=headers, timeout=timeout),
            lambda: http.get(target_url, params={"query": query}, headers=headers, timeout=timeout),
        ):
            try:
                r = send()
                body = r.json()
                if isinstance(body, dict):
                    resp = body
                    break
            except (requests.RequestException, ValueError):
                continue
        cache[query] = resp
        return resp

    for engine, rules in _ENGINES:
        for rule in rules:
            if _match(rule, probe(rule["q"])):
                return engine
    return None


# --- error dialect (for clairvoyance) --------------------------------------------------------- #
_JAVA_DIALECT = ("graphql-java", "hypergraphql")  # "is undefined" / SubselectionRequired / MissingFieldArgument
_RUBY_DIALECT = ("graphql-ruby",)


def engine_dialect(engine: str | None) -> str:
    if engine in _JAVA_DIALECT:
        return "graphql-java"
    if engine in _RUBY_DIALECT:
        return "graphql-ruby"
    return "graphql-js"  # Apollo/Graphene/Strawberry/etc. use "Cannot query field ..."


# --- per-engine attack notes (GraphQL Threat Matrix) ------------------------------------------ #
_ENGINE_NOTES: dict[str, str] = {
    "apollo": "Apollo (Node/TypeScript). Introspection + field suggestions ON by default (older versions); "
              "no built-in depth/cost limiting or batch cap unless armor/plugins added. Attack: introspection, "
              "field-suggestion schema leak, query batching (alias & array), deep-nesting/complexity DoS, APQ "
              "cache poisoning, CSRF-over-GET.",
    "graphene": "Graphene (Python). No native depth/cost limiting or batch cap; introspection usually on. "
                "Attack: introspection, deep nesting / alias amplification DoS, and injection through resolvers "
                "(SQLi/NoSQLi/ORM) since arg handling is app-code.",
    "hasura": "Hasura (Haskell). Auto-generated CRUD over Postgres. Attack: x-hasura-role / x-hasura-* header "
              "abuse (unauthorized/elevated roles), *_aggregate as a boolean/row oracle past row permissions, "
              "the run_sql metadata endpoint (/v1/query,/v2/query) if network-exposed, and nested-relationship "
              "permission gaps. Introspection often left on.",
    "graphql-java": "graphql-java. Field suggestions ON, verbose validation errors ('is undefined', "
                    "SubselectionRequired, MissingFieldArgument) - clairvoyance recovers the schema from these. "
                    "No native depth/cost limit unless instrumentation added. Attack: schema recovery, deep "
                    "nesting DoS, injection via resolvers.",
    "graphql-ruby": "graphql-ruby. Has optional max_depth/max_complexity (often unset). Attack: depth/complexity "
                    "DoS if limits unset, batching, and resolver-level injection. Distinct '@skip can't be applied "
                    "to queries' error dialect.",
    "graphql-php": "graphql-php (often Laravel/WPGraphQL/api-platform). No native cost cap. Attack: introspection, "
                   "deep nesting DoS, batching, and injection via resolvers.",
    "wpgraphql": "WPGraphQL (WordPress). Attack: users/user(id:/slug:) account enumeration, draft/private content "
                 "leak via status filters, mutation CSRF, and REST-bridge exposure. Content is public by design.",
    "strawberry": "Strawberry (Python). Introspection on by default; no native cost limiting. Attack: introspection, "
                  "deep nesting DoS, and resolver injection.",
    "gqlgen": "gqlgen (Go). Has a configurable complexity limit (often unset) and a fixed introspection toggle. "
              "Attack: complexity/depth DoS if unlimited, introspection, resolver injection.",
    "hotchocolate": "Hot Chocolate (.NET). Has execution-timeout / complexity options (often default-permissive). "
                    "Attack: complexity/depth DoS, introspection, persisted-query handling, resolver injection.",
    "hypergraphql": "HyperGraphQL (Java, over RDF/SPARQL). Verbose graphql-java-style validation errors "
                    "(clairvoyance-friendly). Attack: schema recovery, SPARQL injection via arguments, DoS.",
    "aws-appsync": "AWS AppSync. Managed; auth via API key / IAM / Cognito / OIDC. Attack: weak API-key exposure, "
                   "resolver (VTL) injection, and authorization-mode misconfig; introspection often enabled.",
    "directus": "Directus (Node headless CMS). Attack: role/permission misconfig on collections (public read), "
                "the items() filter as an injection/oracle surface, and file/asset access.",
    "pg_graphql": "pg_graphql (Supabase, Postgres extension). Authz is Postgres RLS. Attack: RLS gaps, JWT-claim "
                  "/ role confusion (anon vs authenticated), and reading tables the role shouldn't.",
    "dgraph": "Dgraph. Attack: the /admin API (schema alteration) if exposed, @cascade/filter as an oracle, and "
              "auth-rule (@auth) bypass.",
    "graphql-go": "graphql-go / gqlgen-adjacent (Go). No native cost cap. Attack: introspection, deep-nesting DoS, "
                  "resolver injection.",
}
_GENERIC_NOTE = ("{engine} engine. Check introspection + field suggestions (schema leak), query "
                 "batching/aliasing and deep-nesting for DoS (few engines cap cost by default), and "
                 "resolver-level injection (SQLi/NoSQLi/SSRF) on string/filter args.")


def engine_note(engine: str | None) -> str | None:
    """Return an attack-guidance fact for the engine, or None if it wasn't identified."""
    if not engine:
        return None
    note = _ENGINE_NOTES.get(engine) or _GENERIC_NOTE.format(engine=engine)
    return f"ENGINE = {engine} (fingerprinted from error signatures). {note}"
