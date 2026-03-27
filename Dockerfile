FROM python:3.12-slim AS builder

WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir .

FROM python:3.12-slim

LABEL maintainer="0xgetz"
LABEL description="🛡️ AllowScanner — Advanced Web Vulnerability Scanner"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/allowscanner /usr/local/bin/allowscanner

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["allowscanner"]
