
# Build stage
FROM python:3.11-slim AS builder
ENV PYTHONUNBUFFERED=1 \
	PIP_NO_CACHE_DIR=1 \
	PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
RUN apt-get update && \
	apt-get install -y --no-install-recommends gcc build-essential libpq-dev curl && \
	rm -rf /var/lib/apt/lists/*
RUN pip install --upgrade pip
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# Runtime stage
FROM python:3.11-slim AS runtime
ENV PYTHONUNBUFFERED=1 \
	PIP_NO_CACHE_DIR=1 \
	PATH="/home/appuser/.local/bin:$PATH"
WORKDIR /app
RUN apt-get update && \
	apt-get install -y --no-install-recommends libpq5 curl && \
	rm -rf /var/lib/apt/lists/*
RUN adduser --disabled-password --gecos "" appuser
COPY --from=builder /wheels /wheels
RUN pip install --upgrade pip && \
	pip install --no-cache-dir --no-index --find-links /wheels /wheels/* && \
	rm -rf /wheels
COPY --chown=appuser:appuser . .
USER appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 CMD curl -fs http://localhost:8000/health || exit 1
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
