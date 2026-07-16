# Running GradientQL with Docker

Two images are provided:

- **`gradientql`** ([`Dockerfile`](../Dockerfile)) is the scanner.
- **`gradientql-dvga`** ([`docker/dvga.Dockerfile`](dvga.Dockerfile)) is a patched build of the
  [Damn Vulnerable GraphQL Application](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application),
  for use as a practice target.

You need an API key for a model on OpenRouter. Provide it through the `OPENROUTER_API_KEY`
environment variable or by mounting a `config/api_key.local` file. Never bake a key into an image.

## Scan the bundled DVGA target in one command

This builds both images, starts DVGA, waits for it to be healthy, runs a scan against it, prints the
report, and exits. Findings and traces are written to `./output` on the host.

```
OPENROUTER_API_KEY=sk-... docker compose -f docker/docker-compose.yml up --build
```

## Scan any target

Build the scanner image:

```
docker build -t gradientql .
```

Run it against an endpoint you are allowed to test. `--no-tui` prints plain logs, which is what you
want inside a container; the interactive interface needs a real terminal (see [Notes](#notes)).

```
docker run --rm \
  -e OPENROUTER_API_KEY=sk-... \
  -v "$PWD/output:/app/output" \
  gradientql --url https://your-target.example/graphql --no-tui
```

Any [command-line argument](../README.md#command-line-arguments) works after the image name, for
example `--trace` to record every step, or `--settings /app/config/settings.yaml` with a mounted
config. Output lands in the mounted `./output` directory.

## Run DVGA on its own

If you want the target running by itself (to scan it from the host, from an IDE, or from a native
install of the scanner):

```
docker build -f docker/dvga.Dockerfile -t gradientql-dvga .
docker run -d -p 5013:5013 --name dvga gradientql-dvga
# GraphQL endpoint:  http://localhost:5013/graphql
# GraphiQL IDE:      http://localhost:5013/graphiql
```

To scan it from the scanner *container* (rather than a host install), put both on one network so the
scanner can resolve the target by name:

```
docker network create gql
docker run -d --network gql -p 5013:5013 --name dvga gradientql-dvga
docker run --rm --network gql -e OPENROUTER_API_KEY=sk-... \
  gradientql --url http://dvga:5013/graphql --no-tui
```

## Why the DVGA image is patched

The stock `dolevf/dvga` serves through gevent's WSGI server but never calls `monkey.patch_all()`.
gevent is cooperative, so a single blocking resolver (the server-side fetch in `importPaste`, the
command-injection subprocess in `systemDebug` / `systemDiagnostics`, or a heavy batched query)
freezes the whole server until it returns, and every other request queues and times out. A scan then
appears to stall on every step. The image prepends `monkey.patch_all()` to `app.py` so those
blocking calls yield instead, which keeps the server responsive and lets it handle concurrent scans.
This changes only the server's concurrency behavior, not the application or its vulnerabilities.

## Notes

- **API key.** Pass `-e OPENROUTER_API_KEY=sk-...`, or mount a key file with
  `-v "$PWD/config/api_key.local:/app/config/api_key.local"`. The key is never stored in the image.
- **Output.** Mount `-v "$PWD/output:/app/output"` to keep findings (`vuln_stream.jsonl`) and, with
  `--trace`, the per-step trace files.
- **Custom settings.** Mount your own file over the bundled one:
  `-v "$PWD/config/settings.yaml:/app/config/settings.yaml"`.
- **Interactive interface.** Containers run in plain-log mode. The Textual TUI needs an interactive
  terminal; for it, install the tool natively (`pip install -e .`) and run `gradientql`.
- **Image size.** The scanner image installs the CPU build of PyTorch (for schema search on large
  schemas). It is still a large image; the schema index is only built for schemas with 80+ fields,
  so small targets like DVGA never load it.
