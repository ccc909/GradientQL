# GradientQL, the autonomous GraphQL vulnerability scanner.
#
# Build:  docker build -t gradientql .
# Scan:   docker run --rm -e OPENROUTER_API_KEY=sk-... -v "$PWD/output:/app/output" \
#             gradientql --url https://your-target.example/graphql --no-tui
#
# The API key is read from OPENROUTER_API_KEY (or a mounted /app/config/api_key.local). Never bake a
# key into the image. Findings and traces are written to /app/output; mount it to keep them.
FROM python:3.12-slim

WORKDIR /app

# Install CPU-only PyTorch first. The default torch wheel is a multi-GB CUDA build; the CPU wheel is
# far smaller. torch/sentence-transformers/faiss back the schema-search index, which is only built
# for large schemas (>= 80 fields); small targets like DVGA use lexical search and never load it.
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

COPY pyproject.toml README.md ./
COPY gradientql ./gradientql
COPY config ./config

RUN pip install --no-cache-dir . && gradientql --help >/dev/null

ENV PYTHONUNBUFFERED=1
VOLUME ["/app/output"]

ENTRYPOINT ["gradientql"]
CMD ["--help"]
