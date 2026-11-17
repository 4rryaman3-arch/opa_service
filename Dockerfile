# syntax=docker/dockerfile:1.7
# Securden OPM API (FastAPI). CPU-only, non-root, read-only root filesystem.
FROM python:3.13.3-slim-bookworm@sha256:56a11364ffe0fee3bd60af6d6d5209eba8a99c2c16dc4c7c5861dc06261503cc

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --system --gid 10001 opm \
 && useradd --system --uid 10001 --gid opm --no-create-home --shell /usr/sbin/nologin opm \
 && mkdir -p /data \
 && chown 10001:10001 /data \
 && chmod 0700 /data

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
# Read-only regulatory catalog API. The worker/CLI side of regintel runs on the host.
COPY regintel ./regintel

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"]

# Single worker per container: rate limiter and metrics are in-process.
# Scale with batch_concurrency or additional replicas behind Caddy.
CMD ["uvicorn", "app.main:app_factory", "--factory", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*", \
     "--no-server-header", "--no-access-log", \
     "--timeout-keep-alive", "30", "--limit-concurrency", "256"]
