"""Detect the GraphQL server/framework from the schema shape and seed targeted attack guidance.

Each detector returns durable facts (rendered as KNOWN every turn) that point the agent at the
framework-specific techniques that fit - Apollo Federation entity injection, Hasura run_sql /
aggregation oracles, WPGraphQL user enumeration - so it does not have to rediscover them.
"""

from __future__ import annotations

from typing import Any


def _root_fields(schema_map: dict[str, Any], key: str, default: str) -> set[str]:
    fields = schema_map.get(schema_map.get(key, default))
    if not isinstance(fields, dict):
        return set()
    return {f for f in fields if not str(f).startswith("_")}


def detect_frameworks(schema_map: dict[str, Any]) -> list[str]:
    """Return framework-specific attack-guidance facts for the schema, or [] if none match."""
    if not schema_map:
        return []
    facts: list[str] = []
    qroot = schema_map.get("_query_type", "Query")
    mroot = schema_map.get("_mutation_type", "Mutation")
    q = schema_map.get(qroot) if isinstance(schema_map.get(qroot), dict) else {}
    m = schema_map.get(mroot) if isinstance(schema_map.get(mroot), dict) else {}
    qnames = {f for f in q if not str(f).startswith("_")}
    mnames = {f for f in m if not str(f).startswith("_")}
    all_types = {k for k in schema_map if not str(k).startswith("_")}

    # --- Apollo Federation ---
    if "_entities" in q or "_service" in q or "_Service" in all_types or "_Entity" in all_types:
        facts.append(
            "APOLLO FEDERATION detected (_entities/_service present). (1) Attack _entities(representations:"
            "[{__typename:'<Type>', <keyfield>:'<value>'}]): the gateway resolves entity references by key "
            "and subgraphs often TRUST gateway-supplied representations without re-checking ownership - forge "
            "another user's/tenant's key to read their object = cross-subgraph BOLA. (2) @requires/@fromContext: "
            "request ONLY a field that @requires a protected field (never naming the protected one) - the "
            "planner fetches it internally, bypassing its field-level auth. (3) Dump the full federated SDL "
            "with query {_service{sdl}}.")

    # --- Hasura ---
    hasura = (qroot == "query_root" or mroot == "mutation_root"
              or any(str(f).endswith("_aggregate") for f in qnames)
              or any(str(f).startswith(("insert_", "update_", "delete_")) for f in mnames)
              or any(str(t).endswith("_bool_exp") for t in all_types))
    if hasura:
        facts.append(
            "HASURA detected (query_root / _aggregate / insert_*/*_bool_exp). (1) x-hasura-role/x-hasura-* "
            "headers: set x-hasura-role: admin (or a guessed elevated role) via set_identity - a misconfigured "
            "unauthorized-role or leaked admin secret grants full access. (2) *_aggregate{aggregate{count}} is a "
            "BOOLEAN/STATISTICAL ORACLE over rows a row-permission should hide - count>0 on a filtered aggregate "
            "leaks existence. (3) The metadata API /v1/query & /v2/query run_sql may execute arbitrary SQL if "
            "network-exposed (auto-probed). (4) Nested-relationship and computed-field permission gaps leak data "
            "a top-level permission blocks.")

    # --- WPGraphQL (WordPress) ---
    if qroot == "RootQuery" or {"contentNodes", "mediaItems"} & qnames or (
            "users" in qnames and {"Post", "MediaItem"} & all_types):
        facts.append(
            "WPGRAPHQL (WordPress) detected (RootQuery/contentNodes/mediaItems). users & user(id:/slug:) "
            "ENUMERATE accounts (usernames, slugs, emails) even for non-authors; contentNodes/posts with "
            "status filters can leak DRAFT/PRIVATE/scheduled content unauthenticated; and state-changing "
            "mutations are often CSRF-able. Enumerate users first, then probe private content and BOLA.")

    # --- Strapi (users-permissions plugin + EntityResponse content-type envelope) ---
    strapi = (any("userspermissions" in str(t).lower() for t in all_types)
              or any(str(t).endswith(("EntityResponse", "EntityResponseCollection", "RelationResponseCollection"))
                     for t in all_types)
              or "usersPermissionsUser" in q or "UsersPermissionsRegisterInput" in (schema_map.get("_input_types") or {}))
    if strapi:
        facts.append(
            "STRAPI CMS detected (users-permissions plugin / EntityResponse envelope). WARNING: content "
            "types (pages, articles, catalogs, procedures) are PUBLIC by default - reading them "
            "anonymously is NOT BOLA, and anon:DATA while an authenticated token is Forbidden is a Public-"
            "vs-Authenticated ROLE quirk, not a vuln. The REAL bugs here are in the users-permissions plugin: "
            "register MASS ASSIGNMENT (send role/confirmed/blocked in the register input), changePassword / "
            "resetPassword flaws, and the login NoSQL-injection CVE (CVE-2023-22894) via the identifier field. "
            "Focus there; do not report public content reads.")

    # --- PostGraphile ---
    if any(str(f).startswith("all") and str(f).endswith("s") for f in qnames) and "nodeId" in str(
            [i.get("name") for fx in q.values() if isinstance(fx, dict) for i in (fx.get("args") or [])]):
        facts.append(
            "POSTGRAPHILE detected (allXs / nodeId Relay ids). Authz is Postgres Row-Level Security mapped "
            "from JWT claims (request.jwt.claims/role via pgSettings); probe for RLS gaps, SECURITY DEFINER "
            "functions exposed as mutations, and role/claim confusion by swapping identities.")

    return facts
