FROM python:3.12-slim

WORKDIR /app

# System deps for psycopg2 and rarfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ cmake libpq-dev unrar-free && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY src/ src/
COPY alembic/ alembic/
COPY alembic.ini .
COPY rules/ rules/

RUN pip install --no-cache-dir ".[tlsh,yara]"

# Dirs for kit downloads and extraction (volume-mounted in compose)
RUN mkdir -p /app/downloads /app/extracted
