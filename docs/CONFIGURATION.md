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
  attacker_model: "qwen/qwen3.7-max"

scanner:
  budget: 60           # the most steps a scan takes; each step is one model call and at most one request
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
  carries auth headers for an already-authenticated run, and `csrf` toggles CSRF handling.
- **`http`**: `proxy` routes traffic through an intercepting proxy such as Burp or mitmproxy, `delay`
  sets seconds between requests for rate limiting, and `verify_tls` can be turned off for an
  intercepting proxy or self-signed certificates.
- **`llm`**: `provider` and `attacker_model` choose the model that drives the scan; `api_key` /
  `api_key_env` supply its key (see [API key](#api-key) above).
- **`scanner`**: `budget` caps how many steps a scan takes (each step is one model call and at most
  one request), `safe_mode` is a single switch that disables the destructive techniques, `attacks`
  turns individual techniques on or off, and `oob` configures out-of-band callbacks for blind SSRF.

## Sessions and authentication

To reach authenticated objects, which is where bugs like broken object-level authorization live, the
scanner needs a session. You can give it one by putting a valid token in `target.headers`, or you can
let it earn one itself through the signup, email confirmation, and login flow using the `temp_mail`
action.
