# syntax=docker/dockerfile:1.7
# CrossCtlFrameworks — Copyright © 2026 Colleen Townsend
FROM python:3.12-slim AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libpq-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY pyproject.toml ./
COPY src ./src
RUN python -m venv /venv \
 && /venv/bin/pip install --upgrade pip setuptools wheel \
 && /venv/bin/pip install .

FROM python:3.12-slim AS runtime
LABEL org.opencontainers.image.title="Concord" \
      org.opencontainers.image.authors="Colleen Townsend" \
      org.opencontainers.image.licenses="Proprietary" \
      org.opencontainers.image.source="https://example.invalid/ccf" \
      org.opencontainers.image.description="Compliance controls platform"
ENV PATH="/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpq5 curl tini \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -u 10001 -r -s /sbin/nologin ccf
WORKDIR /app
COPY --from=builder /venv /venv
COPY migrations /app/migrations
COPY alembic.ini /app/alembic.ini
COPY src /app/src
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "ccf"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
