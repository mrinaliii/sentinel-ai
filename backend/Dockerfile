# ─────────────────────────────────────────────────────────
#  Sentinel-AI Backend — Multi-stage Docker Build
# ─────────────────────────────────────────────────────────

# ── Stage 1: dependency builder ───────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build deps for native extensions (faiss, weasyprint, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpango-1.0-0 \
    libharfbuzz0b \
    libpangoft2-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: production runtime ────────────────────────────
FROM python:3.11-slim AS runtime

LABEL maintainer="security-eng@example.com"
LABEL app="sentinel-ai-backend"
LABEL version="1.0.0"

# Runtime libraries for WeasyPrint (PDF generation)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libharfbuzz0b \
    libpangoft2-1.0-0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for security
RUN groupadd --gid 10001 sentinel && \
    useradd --uid 10001 --gid sentinel --shell /bin/bash --create-home sentinel

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY --chown=sentinel:sentinel app/ ./app/

# Switch to non-root user
USER sentinel

# Environment defaults (override via docker-compose or K8s configmap)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ENVIRONMENT=production \
    HOST=0.0.0.0 \
    PORT=8000 \
    WORKERS=2

EXPOSE 8000

# Health check using the /health/live endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health/live || exit 1

# Production: Uvicorn with Gunicorn worker manager
CMD ["python", "-m", "uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--loop", "uvloop", \
     "--http", "httptools", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*"]
