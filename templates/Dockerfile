# Reference multi-stage Dockerfile for a crucibix-<context> service. Copy into the service repo.
FROM python:3.12-slim AS base
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

FROM base AS builder
COPY pyproject.toml ./
COPY src ./src
RUN pip install --upgrade pip build && pip wheel --no-deps -w /wheels . && pip install . --target /app/vendor

FROM base AS runtime
# non-root
RUN useradd -m -u 10001 app
COPY --from=builder /app/vendor /app/vendor
COPY src ./src
COPY alembic.ini ./
COPY migrations ./migrations
ENV PYTHONPATH=/app/vendor:/app/src
EXPOSE 8000
USER app
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/healthz').status==200 else 1)"
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
