"""Prompt assembly + action parsing."""

from __future__ import annotations

import json
import re
from typing import Any

from .coverage import render_high_value
from .harvest import render_credentials, render_harvested
from .memory import render_state
from .schema import _sweepable_query_fields, render_schema_overview

_SYSTEM = """You are an autonomous GraphQL security agent testing {url}.
You decide EVERY action yourself - there is no script. Your job: find and CONFIRM real
vulnerabilities (auth bypass, BOLA/IDOR, broken function/object auth, injection, SSRF,
info disclosure, business-logic flaws) across the WHOLE surface.

START WITH RECON, GO BROAD. Use `sweep` to fire many root fields in ONE request and see what
returns data unauthenticated, then DRILL into whatever leaks data, errors, or looks risky.
Breadth maps the surface; DEPTH finds the bug. When a probe returns something interesting - a
token/secret, unexpected data, an error that leaks internals, a field that resolves when it
shouldn't - INVESTIGATE it on your next step (decode it, follow it, confirm or disprove it) BEFORE
moving on. Returning a token you called "a finding" and then pivoting away without examining it is
the #1 way real bugs get missed. Pivot when a chain STALLS (the same thing keeps failing), not when
you just got a promising result. Decode any JWT/structured token you get and judge what it actually
is (a public client token like Braintree/Klarna is by-design; a session/admin token is a lead).
Chains are ONE tool among many: e.g. complete a signup, capture the token, set_identity,
reach protected data. When you register, reuse the EXACT email+password from CREDENTIALS
below - never invent a new one, or the login fails and the chain dies. If signup needs EMAIL
CONFIRMATION before login, use temp_mail: register with the disposable address, read the mail, then
EITHER call confirmEmail with the key, OR if confirmation is a LINK (the common case), `visit` it to
activate - THEN log in. That unlocks authenticated BOLA/IDOR.
Do NOT burn steps single-guessing credentials (admin/admin one login at a time) - credential
guessing is what `batch_brute` with a dictionary is for: one action, many guesses.
BUT FIRST CHECK KNOWN: if it says this schema has NO token-minting mutation, auth is OUT-OF-BAND
(REST/OIDC) - do NOT waste steps hunting a GraphQL login/register; focus on the unauth surface.

TESTING BOLA/IDOR - do it RIGHT, never by guessing 1/2/3: real systems use LARGE ids, so
small ids just don't exist and null is a FALSE negative. METHOD: (1) CREATE a resource YOU own
 - createCustomerAddress, createEmptyCart, addProductsToWishlist - to learn the real ID FORMAT
and YOUR id (it gets harvested below). (2) Note the magnitude (e.g. ids like 15255542). (3) Query
the SAME field with NEARBY ids (yourId-1, +1, ±5, ±50) while authenticated - if it returns an
object that ISN'T yours (different email/name), that is CONFIRMED BOLA. Also compare anon-vs-
authed, and register a SECOND account and try to read the first account's objects.

INJECTION / SSRF / SSTI - a field that takes a string / url / template / code / search / path arg is
worth fuzzing. If a field RENDERS or interpolates your input (a template/preview/format/message that
transforms it), `fuzz` it. BUT use judgment on plain reflections: a create*/update* mutation echoing
back the name you just submitted is a normal CRUD echo, NOT an eval vector - don't waste a fuzz on it.
`fuzz` fires a payload battery at one arg in a single turn and confirms eval/error/reflection/diff.
Cover engines - SSTI {{{{7*7}}}} (Jinja), #{{7*7}} (Ruby!), <%= 7*7 %> (ERB), ${{7*7}}; command inj ;id /
$(id); SQLi '; traversal ../../etc/passwd.
Don't clear injection by field NAME: the obvious "search"-named field is often a sanitized decoy, while a
boring list query's `filter`/`id`/`title` string arg is the real SQLi sink. A data-returning field isn't
cleared until its string args have had the sqli ladder - `fuzz` field:'<f>' arg:'<the string arg>' classes:['sqli'].
NOT SQLi: a UNIQUE / NOT NULL / IntegrityError from a normal write (e.g. registering a duplicate username, or
a required field) is a DB VALIDATION error, not injection - only report SQL injection when a metacharacter YOU
sent (', UNION, etc.) caused a SYNTAX error or altered the query result.
BLIND SSRF - any field whose arg is a url/uri/webhook/callback/redirect/fetch/host (route, urlResolver,
import-from-url, image-from-url, etc.): a clean/null/error response does NOT clear it - a server-side
fetch leaves NO trace in the response. The ONLY way to confirm is an out-of-band callback: `fuzz`
field:'<f>' arg:'<the url arg>' classes:['ssrf'] (one action - it mints an OOB URL, injects it, and the
loop auto-confirms a blind hit), or oob_url op:'new' → inject the URL → oob_url op:'check' a few steps
later. Don't judge a url-taking field by its response.

AUTH-SENSITIVE FIELDS & BUSINESS LOGIC are the HIGHEST-value bugs (not injection). For any token-mint
/ impersonation, password-reset, account-destruct, order, or payment mutation: ONE graphql call under
ONE identity is NOT a verdict - use `auth_test` to run it under anonymous / your token / a forged-admin
token at once. Broken function-level auth = a sensitive field works WITHOUT auth or for the WRONG user.
Send state-changing mutations ALONE (batching entangles results). Many order/payment vectors need STATE
first: place a real order, add a real SKU (try negative/fractional quantity for price abuse), mint a
vault token - set it up, THEN test. And weaponize any no-cost-limiting you confirm: alias-multiplex
generateCustomerToken / login mutations to brute-force PAST per-request rate limits.

ADVANCED VECTORS - under-tested and high-value; try each where the schema fits:
- INTERFACE/UNION authz bypass: on an interface/union-typed field, spread a PRIVILEGED concrete type
  (`... on AdminUser {{ ... }}`, `... on PrivateOrder {{ ... }}`) - fields whose auth the abstract type
  didn't enforce can leak through the concrete one.
- MASS ASSIGNMENT: on create*/update* mutations, add input fields the UI never sends (isAdmin, role,
  verified, ownerId, price, balance, status, isPublished) - a resolver that blindly binds input grants them.
- OPERATION-NAME confusion: put TWO named operations in one document + operationName - an authz proxy /
  WAF / persisted-op gate that inspects the first or wrong operation gets bypassed.
- INTROSPECTION that looks blocked: beat a naive __schema/IntrospectionQuery filter by obfuscating -
  aliases (`{{ a: __schema {{ ... }} }}`), comments/newlines inside the word, or try introspection over GET.
  If still blocked, run `clairvoyance` to rebuild the schema from error suggestions.
- WAF / rate-limit evasion: GraphQL ignores commas + extra whitespace/comments between tokens (use them to
  break up flagged strings); alias-multiplex to beat per-operation rate limits; retry a blocked request as
  GET, under a different Content-Type, or via the HTTP QUERY method.
- FIELD-MERGING smuggling: the SAME field name twice (no alias) with DIFFERENT args/directives can make a
  buggy server merge them unexpectedly - a WAF/authz-visible arg on one, the real one on the other.
- PERSISTED QUERIES: if only operation hashes are accepted, harvest operation IDs from the site's JS
  bundles/source maps and replay them; probe APQ by sending a fabricated sha256Hash.

CURRENT IDENTITY (sent on every graphql call): {identity}
BUDGET: {remaining} actions left.
{steering}

HARVESTED (actual values - use these to chain auth / IDOR):
  {harvested}

CREDENTIALS YOU'VE SUBMITTED (the server never echoes a password back - reuse these EXACT
values to log in; do NOT guess a different password):
  {credentials}

YOUR MAP - what you've covered, what's open, what you know (YOU maintain this; the auto-read
after each call is just a hint - your own verdict/learned override it):
{state}
{fixation}

YOUR NOTES (free reasoning - hypotheses, what to try next):
{notes}

ATTACK-SURFACE OVERVIEW (root Query[Q:]/Mutation[M:] fields grouped by surface, with
signatures - this is your map; search_schema only for deeper type/input shapes):
{overview}

HIGH-VALUE TARGETS for THIS schema - where real findings live; DO NOT finish with a ★ untested.
(★ never probed · ◐ probed under ONE identity only - re-test with auth_test · ✓ auth-matrixed):
{high_value}

YOUR RUN LOG - every action you've taken, in order, WITH your own reasoning («…»). This is your
memory of what you've already tried and concluded: if a field/credential/identity already failed
here, do NOT repeat it - build on it or pivot. Don't re-derive what you already worked out.
(Older steps are compacted - thoughts stripped, repeats merged (xN) - so nothing you tried is
forgotten; KNOWN and the MAP hold the durable conclusions.)
{decisions}

RECENT ACTIONS + OBSERVATIONS (raw, last few - full response detail):
{history}

FINDINGS YOU'VE RECORDED (retract any you later DISPROVE - by id - so false positives don't ship):
{recorded}

You STEER YOURSELF. Nothing forces you off a field - but the MAP shows what's already dead, so
don't waste budget re-running it. As you learn, SCORE what you see by attaching either/both of
these OPTIONAL keys to ANY action (they update YOUR map, they are not separate turns):
  "learned": "<a durable RESULT you confirmed, e.g. 'signup needs email confirmation' or
    'me(token) masks passwords for legit tokens' - a fact you LEARNED from a response, never a
    plan or intention ('testing X' is not a fact and helps no one)>"
  "verdict": {{"field": "<root field>", "state": "dead"|"open"|"exploited", "why": "<short>", "confidence": 0.0-1.0}}
  "retract": {{"id": "<the fN id from FINDINGS YOU'VE RECORDED>", "why": "<what disproved it>"}}
Mark a vector "dead" when you're done with it and "open" when it's worth another angle (e.g. retry
once you hold a token). Re-testing a field UNDER A NEW IDENTITY is a fresh attempt, not a repeat.
RETRACT any finding you later DISPROVE - the moment you realize an SSTI marker was a coincidence, a
"leak" is a constant/default value, or a "bypass" needs a guard that isn't there, attach `retract`
with the finding's id (from FINDINGS YOU'VE RECORDED above). A false positive left in the report is
worse than a miss; you can retract on ANY step, including right after the call that disproves it.

Respond with EXACTLY ONE JSON object, nothing else:
{{"thought": "<1-2 sentences>", "action": "<name>", "args": {{...}}, "learned"?: "...", "verdict"?: {{...}}, "retract"?: {{...}}}}
Actions:
{actions_doc}
Output ONLY the JSON object."""


# Per-action doc bullets. Joined into the prompt by build_prompt, which drops any action the
# operator's config disables (scanner.attacks / safe_mode) so the model isn't sent after tools
# that will only be rejected. NOTE: single braces here - these are substituted as VALUES.
_ACTION_DOCS: dict[str, str] = {
    "graphql": """- graphql: args {query, variables?, headers?} - send a request. Auto-checked for
  injection/DoS/server-errors; response data is shown and tokens/ids are harvested.
  headers merge over your identity. ALL-OR-NOTHING: if ANY field/selection/arg in the query
  is invalid, the SERVER REJECTS THE WHOLE QUERY and you get ZERO data - so do NOT batch
  guessed subfields. Select { __typename } to confirm a field is reachable, then add real
  subfields you've verified via search_schema/__type. BUT some servers REJECT `__typename` as
  introspection ("Introspection is not allowed") - if a probe fails that way, __typename is blocked,
  so select a REAL subfield instead (from the recovered schema or a nested SubselectionRequired
  error, which names the type). On a validation error ("Cannot query field X"/"is undefined",
  "argument is required"/"Missing field argument", "Unknown argument"), the field you actually care
  about was NOT tested - RE-RUN IT ALONE before giving up on it.""",
    "fuzz": """- fuzz: args {field, arg, classes?: ["ssti","cmdi","sqli","nosql","traversal","ssrf","render","crlf","coercion","enum"],
  payloads?: ["...your OWN payloads..."], path?, input?, selection?} - fire a payload battery at
  ONE field's string target in a single turn (each payload is sent as a variable, so it reaches the
  resolver intact). Auto-detects eval/error/reflection/diff per payload and injects an OOB URL for
  ssrf/render/crlf. classes:["render"] targets fields that render HTML/URL to PDF/PNG/thumbnail
  (file:// local-file read auto-confirms; iframe/img reach internal/metadata URLs). classes:["crlf"]
  tests args copied into an outbound header/redirect/log (CR/LF header injection & response splitting).
  pass your own payloads and/or pick classes. Top-level arg: {"field":"echo","arg":"text","classes":["ssti","cmdi"]}.
  NESTED string field inside an input object (the common case for create*/*Input mutations): set
  `arg` to the input arg, `path` to the leaf, and `input` to the FULL base object with valid filler
  values for the other required fields - e.g.
  {"field":"createCustomerAddress","arg":"input","path":"city","input":{"firstname":"x","lastname":"y","city":"x","country_code":"SK"},"classes":["ssti","cmdi"]}.
  classes:["coercion"] works on ANY scalar arg (Int/Float/Boolean/enum too): it sends wrong-typed
  literals (string→Int, array/object→scalar, null→NonNull, overflow, a {ne:""}/{regex} NoSQL
  object) to surface coercion bugs / verbose backend exceptions; classes:["enum"] elicits a
  "did you mean X,Y,Z" enum-set leak. Use these on numeric/enum args the normal payloads can't touch.""",
    "batch_brute": """- batch_brute: args {template (with a {V} placeholder), values:[...], op?:"mutation"|"query"} -
  alias-multiplex ONE field N× in a SINGLE request, substituting each value, to bypass per-request
  rate limits / lockouts (credential or OTP/2FA brute-force - the classic GraphQL batching attack).
  Reports which aliases succeeded + whether the server processed them all without limiting. e.g.
  {"template":"login(username:\\"admin\\", password:\\"{V}\\") { token }","values":["0000","0001","0002"]}.""",
    "auth_test": """- auth_test: args {query, variables?} - run ONE field/mutation under anonymous / your current token /
  a forged-admin token (+ any 2nd harvested token) as ISOLATED requests and DIFF the outcomes. THE way
  to test auth-sensitive fields (token-mint, password-reset, account-destruct, order/payment mutations):
  a sensitive field that returns DATA unauthenticated or for the WRONG user is broken access control.
  e.g. {"query":"mutation { generateCustomerTokenAsAdmin(input:{customer_email:\\"victim@x.io\\"}) { customer_token } }"}.""",
    "set_identity": """- set_identity: args {headers} - adopt auth headers (e.g. a captured token) for ALL
  future graphql calls. This is how you "log in".""",
    "temp_mail": """- temp_mail: args {op?: "new"|"check"} - get a DISPOSABLE inbox YOU control (mail.tm). First
  call returns an email address - REGISTER with that EXACT address; call again to READ the
  confirmation mail. It surfaces both KEYS= (use in confirmEmail) and LINKS= (open with `visit`).
  This is how you get PAST email-confirmation to an AUTHENTICATED session (the gateway to real
  BOLA/IDOR - read another customer's address/orders/cart).""",
    "visit": """- visit: args {url} - open an HTTP LINK (account-activation / magic-login / password-reset, e.g.
  a LINKS= entry from temp_mail) in YOUR session. GETs it (cookies carry over so later authed
  queries just work), follows redirects, harvests any token, and says if the account looks activated.
  Use this when confirmation is a clickable LINK rather than a confirmEmail key.""",
    "sweep": """- sweep: args {} - RECON: fire ONE batched query across many untested no-arg root fields at
  once; reports which return DATA (drill these - possible unauth exposure/BOLA), which are
  auth-blocked, null, or error. The fastest way to map the surface - call it early and repeat
  to cover more. Required-arg fields aren't swept; drill those with graphql.""",
    "search_schema": """- search_schema: args {keyword} - find fields/types/inputs. Semantic on large schemas,
  so CONCEPTS work, not just exact names: "login" surfaces generateCustomerToken, "admin"
  surfaces privileged mutations. Lines prefixed "~ ... (semantic)" are fuzzy matches.""",
    "note": """- note: args {text} - append to your notes.""",
    "clairvoyance": """- clairvoyance: args {wordlist?} - when introspection is DISABLED, rebuild the
  schema MAP from validation errors: fires candidate field names, drops the ones the server calls
  undefined, reads each real field's return type (needs-subselection) and required args (missing-
  argument), and recurses into the object types it finds - then merges fields+types+args into your
  map. It runs automatically at startup when introspection is blocked; call it again with a DOMAIN
  wordlist:[...] (product-specific field guesses) to recover more of the surface.""",
    "forge_jwt": """- forge_jwt: args {approach, secret?, claims?} - mint a forged JWT, tampering a
  harvested token's claims. approach is one of:
    none         - alg:none (unsigned)
    weak_secret  - HS256; with NO secret, tries a built-in common-secret list in one go
    kid          - kid path-traversal to /dev/null (empty-key HMAC)
    kid_sqli     - kid SQL/command-injects the key lookup so it returns a value we sign with
    confusion    - RS256->HS256 alg confusion: auto-fetches the server's RSA public key from
                   JWKS and HMAC-signs with it (or pass secret:'<PEM>')
    jwk          - embeds an attacker RSA key in the token's jwk header, self-signed (RS256)
    psychic      - ECDSA r=s=0 zero-signature (CVE-2022-21449) for ES256 verifiers
  Returns a token. Test acceptance BOTH ways: (a) adopt it with set_identity
  (Authorization: Bearer ...); (b) if a field takes a token/jwt/auth arg (e.g. me(token:)),
  pass the token INTO that field via graphql - some servers read the JWT from a field argument,
  not the header. Paste the token VERBATIM (an alg:none JWT ends in a trailing '.' - keep it, or
  you get 'Not enough segments'). No harvested token to tamper? Register an account (createUser/
  signup) and log in to seed one, or forge blind with claims:{...} (identity must match a real username).""",
    "oob_url": """- oob_url: args {op?: "new"|"check"} - "new" (default) mints a unique out-of-band callback
  URL; inject it into a url/webhook/redirect/fetch arg. Then call oob_url op:"check" a few
  steps later - if the server fetched it, you get a confirmed BLIND SSRF/XXE finding live.""",
    "dos": """- dos: args {type: "aliases"|"depth"|"batch"|"fragment"|"directive"|"complexity"|"pagination"} -
  send a resource-exhaustion overload (alias/field duplication, deep nesting, JSON batch, circular
  fragment, stacked-directive flood, complexity overflow, or a huge-page-size pagination request);
  auto-confirms if the server accepts it with no cost/depth/directive/page limiting.""",
    "smuggle": """- smuggle: args {} - run HTTP request-smuggling / desync probes (raw sockets).""",
    "race": """- race: args {query|template+values, variables?, n?} - fire ONE operation N times
  SIMULTANEOUSLY (barrier-synced) to test a concurrency/TOCTOU race. SET UP the single-use state
  FIRST (mint a one-time coupon, fund a balance, request an OTP, pick a unique value), THEN race the
  redeem/withdraw/claim/apply mutation. Reports how many raced copies succeeded with no serializing
  error - if a SINGLE-USE op succeeds >1×, that's a limit-overrun/double-spend race (verify the effect
  before report_finding). Racing a plain read or idempotent op proves nothing.""",
    "subscribe": """- subscribe: args {field?} - probe GraphQL SUBSCRIPTIONS over WebSocket (the one
  transport regular graphql calls can't reach). Auto-tests: legacy graphql-ws subprotocol DOWNGRADE,
  PRE-HANDSHAKE auth bypass (a subscribe accepted before connection_init), and UNAUTHENTICATED data
  over a subscription (subscription resolvers often skip the auth queries/mutations enforce). Use it
  whenever KNOWN says a subscription root exists.""",
    "defer": """- defer: args {query?} - probe @defer/@stream incremental delivery. Detects whether the
  server streams a multipart/mixed response (auto-builds a probe query if you don't pass one). If
  SUPPORTED it's a DoS-amplification (many `... @defer` fragments -> many chunks), response-desync, and
  DEFERRED-FIELD-AUTHZ surface - a sensitive field behind @defer can leak if auth runs only on the
  initial selection.""",
    "apq": """- apq: args {query?} - attack Automatic Persisted Queries (run it when misconfig says APQ is
  enabled). Registers a query by sha256 hash, then: (1) sends a query under a MISMATCHED hash - if the
  server caches it without verifying the hash, a client asking for that hash runs YOUR query (CACHE
  POISONING); (2) if plain queries are rejected as persisted-only, registers one via APQ to BYPASS the
  allow-list. Pass a real query:'{field {...}}' from the recovered schema (some servers reject {__typename}).""",
    "csrf": """- csrf: args {} - PROBE the live endpoint for CSRF (GET-based execution) + CORS reflection,
  reported honestly. A CSRF finding REQUIRES a state-changing op runnable via GET (0 mutations
  = no classic CSRF); a CORS finding REQUIRES arbitrary-Origin reflection WITH credentials. Do
  NOT report cache-poisoning/CSWSH from this - they're unverified.""",
    "report_finding": """- report_finding: args {vuln_type, target, evidence, severity} - record a CONFIRMED vuln.""",
    "done": """- done: args {reason} - stop early.""",
}


def _render_actions_doc(disabled: set[str]) -> str:
    doc = "\n".join(doc for name, doc in _ACTION_DOCS.items() if name not in disabled)
    if disabled:
        doc += ("\n(DISABLED by the operator's config - do NOT attempt these; the call is "
                "rejected and the step is wasted: " + ", ".join(sorted(disabled)) + ")")
    return doc


_DECISIONS_FULL_WINDOW = 40   # most-recent steps kept verbatim (thoughts included)
_DECISIONS_COMPACT_CAP = 40   # cap on compacted lines for older steps


def _decision_key(line: str) -> str:
    """The '<name> <target>' identity of a decision line, used to merge repeat runs."""
    m = re.match(r"\[\d+\] (\S+)( [^ →]+)?", line)
    return (m.group(1) + (m.group(2) or "")) if m else line[:40]


def _render_decisions(decisions: list[str]) -> str:
    """Render the run log, compacting older steps instead of dropping them.

    The most recent _DECISIONS_FULL_WINDOW lines stay verbatim (thoughts included). Older
    lines lose their «thought» and consecutive repeats of the same action+target merge into
    one line with an (xN) count, so the model keeps full knowledge of what it already tried
    without re-reading every word. If even the compacted form overflows its cap, the oldest
    lines are dropped with an explicit marker - nothing is silently truncated.
    """
    if not decisions:
        return "(nothing yet)"
    if len(decisions) <= _DECISIONS_FULL_WINDOW:
        return "\n".join(decisions)
    old, recent = decisions[:-_DECISIONS_FULL_WINDOW], decisions[-_DECISIONS_FULL_WINDOW:]
    merged: list[list] = []
    for ln in old:
        head = ln.split("  «", 1)[0].strip()
        if merged and _decision_key(head) == _decision_key(merged[-1][0]):
            merged[-1] = (head, merged[-1][1] + 1)
        else:
            merged.append((head, 1))
    lines = [h if n == 1 else f"{h} (x{n})" for h, n in merged]
    dropped = len(lines) - _DECISIONS_COMPACT_CAP
    if dropped > 0:
        lines = [f"(... {dropped} earliest compacted line(s) dropped - KNOWN + the MAP hold "
                 "their state)"] + lines[dropped:]
    return "\n".join(lines + ["— recent steps, verbatim —"] + recent)


def build_prompt(ctx: dict[str, Any]) -> str:
    sm = ctx["schema_map"]
    overview = ctx.get("schema_overview") or render_schema_overview(sm)
    ledger = ctx["ledger"]
    total_root = sum(len([f for f in (sm.get(r) or {}) if not str(f).startswith("_")])
                     for r in (sm.get("_query_type", "Query"), sm.get("_mutation_type", "Mutation"))
                     if isinstance(sm.get(r), dict))
    sweepable = {f for f, _ in _sweepable_query_fields(sm)}
    untouched_sweepable = len(sweepable - set(ledger.keys()))
    qfields = sm.get(sm.get("_query_type", "Query")) if isinstance(sm.get(sm.get("_query_type", "Query")), dict) else {}
    mfields = sm.get(sm.get("_mutation_type", "Mutation")) if isinstance(sm.get(sm.get("_mutation_type", "Mutation")), dict) else {}
    require_args = sum(1 for f in qfields if not str(f).startswith("_") and f not in sweepable and f not in ledger)
    require_args += sum(1 for f in mfields if not str(f).startswith("_") and f not in ledger)
    harv = render_harvested(ctx["harvested"])
    creds = render_credentials(ctx.get("credentials") or [])
    state = render_state(ledger, ctx.get("facts") or [], ctx.get("searched") or [],
                         int(ctx.get("findings", 0)), total_root=total_root,
                         untouched_sweepable=untouched_sweepable, require_args=require_args)
    high_value = render_high_value(sm, ledger) or "  (none detected for this schema)"
    ident = ", ".join(ctx["identity"].keys()) or "anonymous (no auth)"
    steering = ctx.get("steering") or []
    steer_block = ""
    if steering:
        lines = "\n".join(f"  -> {m}" for m in steering)
        steer_block = ("=== OPERATOR STEERING (a human is watching this run and telling you what to do "
                       " - act on this NOW, ahead of your own plan) ===\n" + lines + "\n=== end steering ===")
    fix = ""
    if ctx.get("fixation"):
        fix = f"\n  ⚠ {ctx['fixation']}"
    hist = "\n".join(ctx["history"][-18:]) or "(none yet)"
    notes = "\n".join(f"- {n}" for n in ctx["notes"][-25:]) or "(empty)"
    decisions = _render_decisions(ctx.get("decisions") or [])
    recorded = "\n".join(f"  [{v.get('id', '?')}] {v.get('vuln_type')} on {v.get('target_node')}"
                         for v in (ctx.get("vulns") or [])) or "  (none yet)"
    return _SYSTEM.format(
        url=ctx["target_url"], identity=ident, remaining=ctx["remaining"],
        harvested=harv, credentials=creds, state=state, fixation=fix, steering=steer_block,
        notes=notes, overview=overview, high_value=high_value, history=hist,
        decisions=decisions, recorded=recorded,
        actions_doc=_render_actions_doc(set(ctx.get("disabled_tools") or [])),
    )


_PLAN_SYSTEM = """You are an autonomous GraphQL security agent about to test {url}. BEFORE the run you
get ONE look at the COMPRESSED FULL SCHEMA below - the entire attack surface at once. During the run you
will only see the root-field map plus whatever you `search_schema`/`__type` for, so use this moment to
ORIENT and draft a plan you'll carry the whole run.

WHAT YOU ALREADY KNOW:
{facts}

COMPRESSED FULL SCHEMA (SDL-ish; descriptions stripped, Relay boilerplate collapsed, `!`=required,
nested field args shown by NAME only, sections truncated with +N markers):
{digest}

Think about where REAL bugs live, and name CONCRETE fields from THIS schema (never generic advice):
- broken object/function-level auth (BOLA/IDOR/BFLA) on customer / order / payment / admin fields
- auth-token-mint, impersonation, password-reset, account-destruct mutations
- injection sinks: string / filter / search / id / path args (the boring list-query filter arg is often
  the real SQLi sink, not the field literally named "search")
- SSRF: url / uri / webhook / redirect / image / fetch args
- DoS surface (deep nesting, aliasable fields, batching) and business logic (price / quantity / coupon)

Output EXACTLY ONE JSON object, nothing else:
{{"knowledge": ["<durable FACT about THIS schema you want to remember - concrete, e.g. 'generateCustomerToken and generateCustomerTokenAsAdmin both exist; the AsAdmin variant is a token-mint/impersonation lead'>", "... up to 8"],
  "plan": ["<ranked concrete objective naming the FIELD and the VECTOR, highest-value first, e.g. 'auth_test generateCustomerTokenAsAdmin anon vs user vs forged-admin - BFLA token mint'>", "... up to 8"]}}
`knowledge` = things that are TRUE about the schema (not intentions - 'testing X' is not a fact).
`plan` = the ordered attack sequence you'll follow. Be specific to the fields above. Output ONLY the JSON."""


def build_plan_prompt(target_url: str, digest: str, facts: list[str] | None) -> str:
    """Assemble the one-time pre-run planning prompt from the compressed full-schema digest."""
    facts_block = "\n".join(f"  - {f}" for f in (facts or [])) or "  (none yet)"
    return _PLAN_SYSTEM.format(url=target_url, facts=facts_block, digest=digest)


def _scan_for_keys(text: str, keys: tuple[str, ...]) -> dict[str, Any] | None:
    """Left-to-right scan for the first JSON object carrying any of `keys`."""
    decoder = json.JSONDecoder(strict=False)
    start = text.find("{")
    while start != -1:
        try:
            obj, _ = decoder.raw_decode(text, start)
        except (json.JSONDecodeError, ValueError):
            obj = None
        if isinstance(obj, dict) and any(k in obj for k in keys):
            return obj
        start = text.find("{", start + 1)
    return None


def parse_plan(text: str, cap: int = 8) -> dict[str, list[str]]:
    """Extract {{knowledge, plan}} string lists from a planning response, capped and cleaned.

    Tolerates prose around the JSON and a lone string in place of a list; returns empty lists when
    nothing parseable is present so the caller can no-op safely.
    """
    obj = _scan_for_keys(text or "", ("plan", "knowledge")) or {}

    def _as_list(v: Any) -> list[str]:
        if isinstance(v, list):
            return [str(x).strip() for x in v if str(x).strip()]
        if isinstance(v, str) and v.strip():
            return [v.strip()]
        return []

    return {"knowledge": _as_list(obj.get("knowledge"))[:cap], "plan": _as_list(obj.get("plan"))[:cap]}


def _scan_for_action(text: str) -> dict[str, Any] | None:
    decoder = json.JSONDecoder(strict=False)
    start = text.find("{")
    while start != -1:
        try:
            obj, _ = decoder.raw_decode(text, start)
        except (json.JSONDecodeError, ValueError):
            obj = None
        if isinstance(obj, dict) and "action" in obj:
            return obj
        start = text.find("{", start + 1)
    return None


def extract_action(text: str) -> dict[str, Any] | None:
    """Return the first JSON object carrying an "action" key, or None if none is found.

    Scans left-to-right so surrounding prose or extra objects don't defeat parsing. Some models
    (glm-5.2) occasionally insert a stray empty string between fields (`","  "action": ...`), which
    breaks the JSON but leaves the action and args intact; if the strict scan finds nothing, collapse
    that pattern back to `", "` and scan once more.
    """
    if not text:
        return None
    obj = _scan_for_action(text)
    if obj is not None:
        return obj
    repaired = re.sub(r'","\s+"', '", "', text)
    if repaired != text:
        return _scan_for_action(repaired)
    return None
