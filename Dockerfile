# Multi-stage ultra-light Dockerfile for AuditAgent
FROM python:3.12-slim AS builder

WORKDIR /app

# Install uv for blazingly fast dependency installation
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy project definition
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Install dependencies into virtualenv
RUN uv sync --frozen --no-dev || uv sync --no-dev

# Final runtime image
FROM python:3.12-slim AS runner

WORKDIR /app

# Set environment
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Copy virtualenv and source from builder
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/src /app/src
COPY --from=builder /app/pyproject.toml /app/pyproject.toml
COPY --from=builder /app/README.md /app/README.md
COPY --from=builder /app/LICENSE /app/LICENSE
COPY examples/ /app/examples/

# Health check
RUN audit-agent --help > /dev/null 2>&1

ENTRYPOINT ["audit-agent"]
CMD ["--help"]
