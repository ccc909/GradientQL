# Configuration reference

The full settings reference behind the [Configuration](../README.md#configuration) section of the
README.

Settings are written in YAML. `config/settings.yaml` is a template you copy and edit, and you can
point the scanner at a different file with `--settings`. Any key you leave out falls back to a
built-in default, so a config file only needs the values you want to change; `config/settings.yaml`
itself documents every field with its default.

## The settings file

```yaml
target:
  url: "https://your-target.example/graphql"
  headers: {}          # auth headers for an already-authenticated run
  csrf: { enabled: false }

http:
  proxy: ""            # route traffic through Burp or mitmproxy, e.g. "http://127.0.0.1:8080"
  delay: 0.0           # seconds between requests, for rate limiting
  verify_tls: true     # set false for an intercepting proxy or self-signed certs

llm:
  provider: "openrouter"
  attacker_model: "z-ai/glm-5.2"

scanner:
  budget: 60           # the most steps a scan takes; one model call per step (battery actions
                       # like sweep/fuzz fire several requests within a step)
  safe_mode: false     # one switch to disable the destructive techniques
  attacks:             # turn individual techniques on or off
    injection: true
    ssrf: true
    dos: false         # resource exhaustion, off by default because it can knock a target over
    jwt: true
    bola: true         # systematic BOLA/BFLA testing across identities
  oob: { enabled: true, provider: "interactsh", collaborator_domain: "oast.fun" }
```

## API key

The scanner uses the first key it finds, in this order:

1. the `llm.api_key` field in your settings file,
2. a `config/api_key.local` file (gitignored), then
3. the environment variable named by `llm.api_key_env`, which defaults to `OPENROUTER_API_KEY`.

## Fields

- **`target`**: `url` is the endpoint to scan (overridden by `--url` on the command line). `headers`
  carries auth headers for an already-authenticated run, and `csrf` toggles CSRF handling (token
  `source`: `meta` | `cookie` | `header`, plus `header_name` / `meta_name` / `cookie_name`).
- **`http`**: `proxy` routes traffic through an intercepting proxy such as Burp or mitmproxy, `delay`
  sets seconds between requests for rate limiting, `timeout` caps each request (default 30s),
  `retries` sets connection-level retries, and `verify_tls` can be turned off for an intercepting
  proxy or self-signed certificates.
- **`llm`**: `provider` and `attacker_model` choose the model that drives the scan; `api_key` /
  `api_key_env` supply its key (see [API key](#api-key) above). `temperature` (default 0.7),
  `attacker_max_tokens` (output cap per step, default 16000), `timeout` and `max_retries` tune the
  API calls; `response_format` can force `json_object` (leave `null` - it makes some models loop);
  `circuit_breaker.threshold` / `circuit_breaker.cooldown` control how provider outages are ridden
  out; `cache.memoize_responses` replays identical prompts (off by default; prompts almost never
  repeat during a scan).
- **`scanner`**: `budget` caps how many steps a scan takes (one model call per step; most actions
  make at most one request, battery actions like `sweep`/`fuzz`/`auth_test` fire several - up to
  ~16 within a single step), `safe_mode` is a single switch that disables the destructive
  techniques, `attacks` turns individual techniques on or off, and `oob` configures out-of-band
  callbacks for blind SSRF (`enabled`, `provider`, `collaborator_domain`, and `token` for private
  interactsh servers). `checkpoint` (`enabled`, `every`, `dir`) auto-saves resumable snapshots -
  resume with `--resume <run-id>`. `fuzz.max_payloads` caps the per-action battery (default 14),
  `obs_max_chars` bounds how much response body the model sees (default 2000), and `tuning.*`
  (`field_retry_cap`, `dup_fail_cap`, `coverage_nudge_every`) adjusts the anti-stall backstops.
  `tuning.preflight_plan` (default `true`) makes the agent take one pre-run look at the **whole**
  schema - compressed to a budgeted SDL-style digest - and draft durable knowledge + a ranked attack
  plan that seed its memory for the rest of the run (per-turn prompts still show only the lean root
  map); `tuning.plan_schema_char_budget` (default 60000) caps that one-time digest so a schema whose
  raw introspection runs to millions of tokens is still sent compactly. `tuning.auto_clairvoyance`
  (default `true`) recovers the schema from the server's own validation errors before the run when
  introspection is disabled - reading each field's return type and required args and recursing into
  the types it finds - so the agent starts with a real map instead of guessing field names.
- **`embeddings`**: `model` (default `all-MiniLM-L6-v2`) and `min_fields` (default 80) control the
  semantic schema index, built only for large schemas and only when the `semantic` install extra
  (`pip install "gradientql[semantic]"`) is present; otherwise schema search is lexical.
- **`ws` extra**: the `subscribe` action probes GraphQL-over-WebSocket subscriptions and needs the
  `ws` install extra (`pip install "gradientql[ws]"`). Without it the action reports it is unavailable
  and the rest of the scan is unaffected.

## Sessions and authentication

To reach authenticated objects, which is where bugs like broken object-level authorization live, the
scanner needs a session. You can give it one by putting a valid token in `target.headers`, or you can
let it earn one itself through the signup, email confirmation, and login flow using the `temp_mail`
action.
