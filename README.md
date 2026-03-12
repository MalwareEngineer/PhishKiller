# PhishKiller

Phishing kit tracking and analysis platform. Downloads, extracts, deobfuscates, and scans phishing kits for indicators of compromise.

## Prerequisites

- Python 3.12+
- Docker & Docker Compose (for PostgreSQL, Redis, RabbitMQ)

## Quick Start

```bash
# Start backing services
docker compose up -d

# Install
pip install -e .

# Optional extras
pip install -e ".[dev,tlsh,yara]"

# Configure
cp .env.example .env
# Edit .env as needed

# Run database migrations
alembic upgrade head

# Start the API server
uvicorn phishkiller.main:app --reload

# Start a Celery worker (separate terminal)
celery -A phishkiller.celery_app worker -l info
```

## Usage

```bash
# Submit a kit for analysis
phishkiller submit https://example.com/kit.zip

# Check status
phishkiller status <kit_id>

# List kits
phishkiller kits list --status analyzed

# Search IOCs
phishkiller iocs search "admin@"

# IOC stats
phishkiller iocs stats

# Ingest threat feeds (PhishTank, URLhaus, OpenPhish)
phishkiller feeds ingest

# Service health check
phishkiller health
```

## License

MIT
