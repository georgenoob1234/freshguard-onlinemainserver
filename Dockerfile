# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm

WORKDIR /app

# Create non-root user
RUN groupadd --gid 1000 appgroup \
    && useradd --uid 1000 --gid appgroup --shell /bin/bash --create-home appuser

# Install dependencies (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app/ ./app/
COPY config/ ./config/

# Ensure data dir exists and is writable
RUN mkdir -p /app/data/blobs && chown -R appuser:appgroup /app

USER appuser

EXPOSE 8080

ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
