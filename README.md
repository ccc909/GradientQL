# GradientQL

![License: MIT](https://img.shields.io/badge/License-MIT-e8a317.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)

GradientQL is a vibe powered GraphQL vulnerability scanner driven by a single language model. You 
give it an endpoint and a model API key, and it runs the whole assessment on its own: it reads the schema,
registers and logs into an account when it needs one, and probes for access-control flaws,
injection, server-side request forgery, and denial of service.

I started this about a year ago. The original plan was to buy a stack of Radeon MI50 GPUs and
fine-tune a model locally for GraphQL query generation, but that fell through. When Claude Opus 4.6
came out I revived the idea with cloud models instead. I was short on time, so I built almost all of
it with an LLM, while still working on something I find interesting: automated vulnerability
hunting.

The first version was an implementation of the PrediQL paper (arXiv:2510.10407). Out of curiosity I
replaced its control loop with a fully agentic one, and the results were interesting enough to keep
going. Early on I pointed it at a production GraphQL API inside a vulnerability disclosure program.
On an innocuous-looking query the model noticed a database error in the response and flagged it,
which turned into a blind SQL injection with real impact. It was reported through the program and
fixed.

Please note: this tool sends real attack traffic and has no built-in consent check. It targets
whatever URL you give it. Only run it against systems you are allowed to test: your own deployment,
a local target like DVGA, or something inside a bug bounty or disclosure scope you hold. Running it
against someone else's system without permission is likely illegal, and staying in scope is your
responsibility.

## Requirements

- Python 3.10 or newer
- An API key for a model on OpenRouter
- Room for the machine-learning stack (FAISS, sentence-transformers, and PyTorch) that the scanner
  uses for schema search

## Installation

Clone the repository and install it in editable mode:

```
pip install -e ".[dev]"
```

## Setting the model key

The scanner looks for the model API key in three places and uses the first one it finds:

1. The environment variable named by `llm.api_key_env`, which defaults to `OPENROUTER_API_KEY`.
2. A file at `config/api_key.local`, which is ignored by git.
3. The `llm.api_key` field in your settings file.

```

## Running a scan

Point the scanner at an endpoint you are allowed to test:

```
python -m gradientql --url https://your-target.example/graphql
```

Add `--trace` to record everything the model did during the run. This is the main way to
understand a scan after it finishes:

```
python -m gradientql --url https://your-target.example/graphql --trace
```

`--url` overrides the target set in the config file, and after installing, the `gradientql` command
runs the same thing. The mode is chosen automatically: run `gradientql` with no `--url` in an
interactive terminal and it opens the [interface](#interactive-interface); pass `--url`, pipe or
redirect the output, or add `--no-tui`, and it prints plain logs. `--tui` forces the interface even
with `--url` set, as long as a terminal is attached.

## Command-line arguments

| Argument | Effect |
| --- | --- |
| `--url URL` | Target GraphQL endpoint. Overrides `target.url` from the settings file. |
| `--settings PATH` | Path to the settings file. Defaults to `config/settings.yaml`. |
| `--trace [PATH]` | Record every step's prompt, response, observations, and state to a `.jsonl` log and a matching `.md` digest. Bare `--trace` writes `output/agent_trace_<timestamp>.*`; pass a path or prefix to write elsewhere. |
| `-v`, `--verbose` | Print each step's full, untruncated thought and observations to the console (plain-log mode). |
| `--tui` | Force the interactive interface. Falls back to plain logs when no terminal is attached. |
| `--no-tui` | Force plain log output even in an interactive terminal. |
| `-h`, `--help` | Show usage and exit. |

## Interactive interface

Run `gradientql` with no arguments to open the TUI, it is composed of:

- A menu that shows the current target, budget, model, proxy, and whether an API key is set, with
  buttons to start a scan or open settings.
- A settings screen for the target URL, budget, model, proxy, request delay and timeout, and the
  fuzz payload cap, plus a submenu of per-technique attack toggles (injection, SSRF, denial of
  service, request smuggling, CSRF, JWT, brute force, and access-control testing).
- A live dashboard, shown once a scan starts. Before the scan runs it checks that the API key
  authenticates and stops with a clear message if the key is missing or rejected. During the run it
  updates in place: a stats line (step, elapsed time, request rate, findings, model), a coverage map
  of the schema, an activity feed of the model's decisions as they happen, a loot pane with any
  harvested credentials, the current session token, and recorded facts, and a table of findings.

The coverage map marks each root field as untested, shallow, open, data, dead, or a finding, so you
can watch the attack surface fill in as the agent works. Pass `--tui` to force this interface
together with `--url`, or `--no-tui` to force plain log output.

### Using it

The interface is keyboard- and mouse-driven; the active keys show in the footer.

- **Menu** — `s` starts a scan, `g` opens settings, `q` quits.
- **Settings and attacks** — edit the fields and switches; the Attacks button opens the
  per-technique toggles. `Esc` (or Back) saves and returns, and changes apply to the next scan.
- **Dashboard** — opens when a scan starts and updates in place. `Esc` stops the scan and returns to
  the menu.

A scan needs a target URL and a working key; the dashboard verifies the key before it starts and
stops with a clear message if the key is missing or rejected.

## How it works

A scan is a short pipeline. The scanner introspects the schema, runs a quick check for common
misconfigurations, hands control to the model, waits for any out-of-band callbacks to arrive,
removes duplicate findings, and prints a report.

The middle step is where the work happens. On each turn the model is given a compressed view of
the situation: the schema, a summary of what it has already tried, the facts it has recorded, and
any credentials or tokens it has harvested. It replies with one JSON action, for example:

```json
{"thought": "...", "action": "sweep", "args": {}, "learned": "optional note", "verdict": {}}
```

The `learned` and `verdict` fields are optional and can be attached to any action. They are how
the model writes to its own memory. `learned` records a fact worth keeping, and `verdict` marks a
field as dead, open, or exploited. The program also classifies each response on its own, but the
model's verdict takes priority, so the model stays in charge of judgment while a simple default
fills in when it stays silent.

The actions the model can take are `graphql`, `sweep`, `search_schema`, `fuzz`, `set_identity`,
`temp_mail`, `forge_jwt`, `oob_url`, `dos`, `smuggle`, `csrf`, `auth_test`, `batch_brute`, `visit`,
`note`, `report_finding`, and `done`. Between them they cover
reconnaissance, authentication (including registering an account, reading a confirmation email
from a disposable mailbox, and logging in), and the individual attack techniques.

## Configuration

Settings are written in YAML. `config/settings.yaml` is a template you copy and edit, and you can
point the scanner at a different file with `--settings`. Any key you leave out falls back to a
built-in default, so a config file only needs the values you want to change. The fields that
matter most:

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

The `http` block routes traffic through a proxy and sets timeouts and rate limiting, `safe_mode` and
the `attacks` map gate individual techniques, and `config/settings.yaml` documents every field with
its default.

To reach authenticated objects, which is where bugs like broken object-level authorization live,
the scanner needs a session. You can give it one by putting a valid token in `target.headers`, or
you can let it earn one itself through the signup, email confirmation, and login flow using the
`temp_mail` action.

## Output

Everything the scanner writes goes under `output/`, which is ignored by git:

- `agent_trace_<timestamp>.jsonl` and the matching `.md` file, written when `--trace` is on. Each
  step records the exact prompt sent to the model, the raw reply, the parsed action, the
  observation fed back in, and a snapshot of the state. The `.md` file is the readable version.
- `vuln_stream.jsonl`, which holds the findings. They are written as they are confirmed, so a
  crash partway through a run does not lose them.

## Testing

```
python -m pytest -q
```

The test suite is fast and runs entirely offline.

## Limitations

There is no consent gate, and that is deliberate. Scoping is your responsibility, so read the note
near the top before you run anything.

Runs are not deterministic. The model drives, so two scans of the same target will differ, and
whether a bug is found depends on the model reasoning its way to it.

The path from a disposable mailbox to an authenticated broken-object-level test is covered by unit
tests with mocks. It has not yet been checked end to end against a live signup that requires email
confirmation.

Some models refuse to attack a named live domain. When that happens the run stops after a few
refusals rather than spending the whole budget.

## Authorship

This project was written by Claude working under human direction. A person sets the goals, reviews
the output, and decides what ships, but most of the code, tests, and documentation are generated by
the model.

## License

MIT. See the LICENSE file.
