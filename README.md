# GradientQL

![License: MIT](https://img.shields.io/badge/License-MIT-e8a317.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
[![Open in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/ccc909/GradientQL/blob/main/notebooks/gradientql_dvga.ipynb)

GradientQL is an autonomous GraphQL vulnerability scanner driven by a single language model. You
give it an endpoint and a model API key, and it runs the whole assessment on its own, against a live
target: it reads the schema, registers and logs into an account when it needs one, and probes for
access-control flaws, injection, server-side request forgery, JWT forgery, request smuggling, CSRF,
credential brute-forcing, and denial of service.

It does not replay a payload list - it reasons. The model maps the attack surface, forms hypotheses,
and chains what it finds into what it tries next. In validation it used a command injection to read
the target's own source code, recovered a hardcoded JWT secret from it, and derived a second-order
auth bypass no payload list would have found. It also grades its own work: findings it later
disproves are retracted, so the report you read at the end is one you can act on.

<table>
  <tr>
    <td align="center" width="50%"><a href="https://raw.githubusercontent.com/ccc909/GradientQL/refs/heads/main/docs/menu.svg"><img src="docs/menu.svg" alt="GradientQL menu" width="440"></a><br><sub>Menu: set a target, then start a scan</sub></td>
    <td align="center" width="50%"><a href="https://raw.githubusercontent.com/ccc909/GradientQL/refs/heads/main/docs/settings.svg"><img src="docs/settings.svg" alt="GradientQL settings" width="440"></a><br><sub>Settings: budget, model, proxy, per-technique attacks</sub></td>
  </tr>
  <tr>
    <td align="center" colspan="2"><a href="https://raw.githubusercontent.com/ccc909/GradientQL/refs/heads/main/docs/dashboard.svg"><img src="docs/dashboard.svg" alt="GradientQL live dashboard" width="960"></a><br><sub>Live dashboard during a scan: coverage map, activity feed, loot, and findings (illustrative data)</sub></td>
  </tr>
  <tr>
    <td align="center" colspan="2"><a href="https://raw.githubusercontent.com/ccc909/GradientQL/refs/heads/main/docs/model_comparison.svg"><img src="docs/model_comparison.svg" alt="DVGA detection rate by category and model, five runs at a 30-step budget" width="760"></a><br><sub>Detection results: the runs (of five) in which each model found each DVGA vulnerability category</sub></td>
  </tr>
</table>

> [!WARNING]
> GradientQL attacks live endpoints autonomously, with no consent gate. Only run it against a target
> you own or are authorized to test. Scoping is your responsibility.

## How it works

A scan is a short pipeline. The scanner introspects the schema, runs a quick check for common
misconfigurations, hands control to the model, waits for any out-of-band callbacks to arrive,
removes duplicate findings, and prints a report.

The middle step is where the work happens. The model drives: on each turn it is given a compressed
view of the situation (the schema, a summary of what it has already tried, the facts it has
recorded, and any credentials or tokens it has harvested) and replies with one JSON action. A run is
measured in **steps**: each step is one model call plus the action it chooses. Most actions make at
most one request to the target; the battery actions fan out further - `sweep` and a full `fuzz`
ladder fire up to about 16 requests in a single step, `auth_test` one per identity. The `budget`
caps how many steps a scan takes.

```json
{"thought": "...", "action": "sweep", "args": {}, "learned": "optional note", "verdict": {}}
```

The `learned` and `verdict` fields are optional and can be attached to any action. They are how
the model writes to its own memory: `learned` records a fact worth keeping, and `verdict` marks a
field as dead, open, or exploited. The program also classifies each response on its own, but the
model's verdict takes priority, so the model stays in charge of judgment while a simple default
fills in when it stays silent.

The model works through a fixed set of actions (`graphql`, `sweep`, `search_schema`, `fuzz`,
`set_identity`, `temp_mail`, `forge_jwt`, `oob_url`, `dos`, `smuggle`, `csrf`, `auth_test`,
`batch_brute`, `visit`, `note`, `report_finding`, and `done`) that between them cover
reconnaissance, authentication (registering an account, reading a confirmation email from a
disposable mailbox, and logging in), and the individual attack techniques.

## Quickstart

**Run it in your browser.** Open the notebook in Google Colab and step through it to scan the bundled
DVGA target with no local install (you supply an OpenRouter key):

[![Open in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/ccc909/GradientQL/blob/main/notebooks/gradientql_dvga.ipynb)

**Try it in one command.** Scan the bundled
[DVGA](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) target with Docker, no local
install needed:

```
OPENROUTER_API_KEY=sk-... docker compose -f docker/docker-compose.yml up --build
```

**Install locally.** Clone the repository and install it in editable mode:

```
pip install -e ".[dev]"
```

You need Python 3.10 or newer and an API key for a model on [OpenRouter](https://openrouter.ai). For
semantic schema search on large schemas (80+ fields), also install the `semantic` extra
(`pip install -e ".[dev,semantic]"`), which pulls FAISS, sentence-transformers, and CPU PyTorch;
without it the scanner falls back to lexical schema search and loses nothing else. The Docker image
already includes the `semantic` extra.

**Set your key and run** against an endpoint you are authorized to test:

```
export OPENROUTER_API_KEY=sk-...
python -m gradientql --url https://your-target.example/graphql
```

The `gradientql` command runs the same thing as `python -m gradientql`. With no `--url` in an
interactive terminal it opens the [interactive interface](#the-interactive-interface) instead of
plain logs; see [Configuration](#configuration) for other ways to supply the key and set the target.

## Usage

### Running a scan

Add `--trace` to record everything the model did during the run. This is the main way to understand a
scan after it finishes (see [Output](#output) for what it writes):

```
python -m gradientql --url https://your-target.example/graphql --trace
```

The mode is chosen automatically: with no `--url` in an interactive terminal it opens the
[interface](#the-interactive-interface); pass `--url`, pipe or redirect the output, or add `--no-tui`,
and it prints plain logs. `--tui` forces the interface even with `--url` set, as long as a terminal is
attached.

### Command-line arguments

| Argument | Effect |
| --- | --- |
| `--url URL` | Target GraphQL endpoint. Overrides `target.url` from the settings file. |
| `--settings PATH` | Path to the settings file. Defaults to `config/settings.yaml`. |
| `--trace [PATH]` | Record every step to a `.jsonl` log and a matching `.md` digest (see [Output](#output)). Bare `--trace` writes `output/agent_trace_<timestamp>.*`; pass a path or prefix to write elsewhere. |
| `-v`, `--verbose` | Print each step's full, untruncated thought and observations to the console (plain-log mode). |
| `--resume RUN_ID` | Resume a previous run from its last checkpoint (a run id like `gql-...` or a checkpoint file path; see `output/checkpoints/`). |
| `--max-tokens N` | Override the model's max output tokens per step (`llm.attacker_max_tokens`). |
| `--tui` | Force the interactive interface. Falls back to plain logs when no terminal is attached. |
| `--no-tui` | Force plain log output even in an interactive terminal. |
| `-h`, `--help` | Show usage and exit. |

### The interactive interface

Run `gradientql` with no arguments to open the TUI, which is composed of:

- A menu that shows the current target, budget, model, proxy, and whether an API key is set, with
  buttons to start a scan or open settings.
- A settings screen for the target URL, budget, model, proxy, request delay and timeout, and the
  fuzz payload cap, plus a submenu of per-technique attack toggles.
- A live dashboard, shown once a scan starts. Before the scan runs it checks that the API key
  authenticates and stops with a clear message if the key is missing or rejected. During the run it
  updates in place: a stats line (step, elapsed time, request rate, findings, model), a coverage map
  of the schema, an activity feed of the model's decisions as they happen, a loot pane with any
  harvested credentials, the current session token, and recorded facts, and a table of findings. A
  steering box along the bottom lets you redirect the agent mid-scan (see
  [Steering the agent](#steering-the-agent)).

The screens are shown in the [gallery](#gradientql) near the top of this page. The coverage map marks
each root field as untested, probed, auth-gated, data, exhausted, or a finding, so you can watch the
attack surface fill in as the agent works.

The interface is keyboard- and mouse-driven; the active keys show in the footer.

- **Menu**: `s` starts a scan, `g` opens settings, `q` quits.
- **Settings and attacks**: edit the fields and switches; the Attacks button opens the per-technique
  toggles. `Esc` (or Back) saves and returns: changes apply to the next scan and are written back to
  the settings file (the API key is never persisted - it stays in the environment or
  `config/api_key.local`).
- **Dashboard**: opens when a scan starts and updates in place. `Esc` stops the scan and returns to
  the menu.

### Steering the agent

The agent runs on its own, but you can redirect it while a scan is in progress. Whatever you send is
injected into the model's next prompt as an operator instruction that takes priority over its own
plan, and it is recorded in the trace. Use it to focus the run ("test the upload field for path
traversal"), flag a miss ("you skipped importPaste"), or change tack ("stop recon, try DoS now").

- **Interactive interface**: type into the steering box at the bottom of the dashboard and press
  Enter. The message shows in the activity feed as `operator: ...`.
- **Plain-log mode**: in an interactive terminal, type a line and press Enter at any point during
  the scan and it is picked up on the next step. This is disabled when input is piped or redirected.

A steering message stays in view for a few steps so the agent does not lose it mid-action.

## Configuration

Settings are written in YAML. `config/settings.yaml` is a template you copy and edit, and you can
point the scanner at a different file with `--settings`. Any key you leave out falls back to a
built-in default, so a config file only needs the values you want to change. The knobs you reach for
most:

```yaml
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

http:
  proxy: ""            # route traffic through Burp or mitmproxy, e.g. "http://127.0.0.1:8080"

llm:
  attacker_model: "z-ai/glm-5.2"
```

`config/settings.yaml` documents every field, and [docs/CONFIGURATION.md](docs/CONFIGURATION.md) is
the full reference, including the API-key resolution order, proxy and TLS options, and out-of-band
callback settings.

To reach authenticated objects, which is where bugs like broken object-level authorization live,
the scanner needs a session. Give it one by putting a valid token in `target.headers`, or let it
earn one itself through the signup, email confirmation, and login flow using the `temp_mail` action.

## Evaluation

Against a fresh
[Damn Vulnerable GraphQL Application](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application)
(DVGA), the standard intentionally-vulnerable GraphQL target, three models were each run five times
at a 30-step budget with the default attack configuration; the per-category detection results are in
the chart at the top of this page. All three find the easy categories (introspection, batch-query
denial of service, stack-trace leakage) in nearly every run, and separate on the multi-step
authentication chains, where glm is strongest. Mean findings per run: glm 7.4, qwen 6.0, gpt-oss 4.8.

Given a larger budget, the strongest model goes deeper. In a single 200-step run, glm self-terminated
at step 119 with **20 findings** and no false positives: it used a confirmed command injection to read
the target's own source, recovered the hardcoded `JWT_SECRET_KEY`, and from that derived a JSON-body
auth bypass that unmasks every user's password.

Full methodology, the exact per-category counts, larger-budget runs, and token usage are in
[docs/results.md](docs/results.md).

## Reference

### Docker

Two images are provided: `gradientql` (the scanner) and `gradientql-dvga` (a patched DVGA target with
the gevent concurrency fix baked in). The Compose file brings up DVGA and scans it in one command
(shown in the [Quickstart](#quickstart)). Full instructions, including scanning your own target from a
container, are in [docs/docker.md](docs/docker.md).

### Output

Everything the scanner writes goes under `output/`, which is ignored by git:

- `agent_trace_<timestamp>.jsonl` and the matching `.md` file, written when `--trace` is on. Each
  step records the exact prompt sent to the model, the raw reply, the parsed action, the
  observation fed back in, and a snapshot of the state. The `.md` file is the readable version.
  Both contain the full prompts - including any credentials and tokens harvested during the run -
  and checkpoints under `output/checkpoints/` store the run's identity headers and credentials.
  Treat all of these as secrets: don't attach them to bug reports or commit them anywhere.
- `vuln_stream.jsonl`, which holds the findings. They are written as they are confirmed, so a
  crash partway through a run does not lose them.

### Testing

```
python -m pytest -q
```

The test suite is fast and runs entirely offline.

## License

MIT. See the LICENSE file.
