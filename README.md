# PhishKiller

Phishing kit tracking and analysis platform. Downloads, extracts, deobfuscates, and scans phishing kits for indicators of compromise.

## Prerequisites

- Python 3.12+
- Docker & Docker Compose

## Quick Start

```bash
# Clone and configure
cp .env.example .env
# Edit .env with your API keys (PhishTank, URLhaus)

# Start everything (infra + worker)
docker compose up -d

# Install locally for CLI and API server
pip install -e ".[tlsh]"

# Run database migrations
alembic upgrade head

# Start the API server
uvicorn phishkiller.main:app --reload
```

The `docker compose up -d` command starts:
- **PostgreSQL 16** — primary database
- **Redis 7** — result backend and cache
- **RabbitMQ 3.13** — Celery message broker
- **Celery worker** — task processing with embedded Beat scheduler

The worker automatically recovers stuck kits on startup and runs periodic tasks:
- Feed ingestion (PhishTank every 3h, URLhaus hourly, OpenPhish every 6h)
- Feed entry processing (every 2 minutes, batches of 2000)
- Stuck kit recovery sweep (every 15 minutes)

### Local Development (without Docker worker)

For development/debugging, you can run the worker on your host instead:

```bash
# Stop the Docker worker
docker compose stop worker

# Run locally with Beat scheduler
celery -A phishkiller.celery_app worker -l info -P solo -B -Q celery,feeds,downloads,analysis,certstream
```

## Architecture

```
Feed Sources (PhishTank, URLhaus, OpenPhish)
    |
    v
[Feed Ingestion] --> feed_entries table
    |
    v
[process_feed_entries] --> kits table (status: PENDING)
    |
    v
[Analysis Chain per kit]
    download_kit ........... PENDING -> DOWNLOADING -> DOWNLOADED
    compute_hashes ......... SHA256, MD5, SHA1, TLSH
    extract_archive ........ ZIP/TAR/RAR extraction (skips non-archives)
    deobfuscate_files ...... JS/PHP deobfuscation
    extract_iocs ........... IOC extraction -> ANALYZED
```

## CLI

```bash
# Submit a kit for analysis
phishkiller submit https://example.com/kit.zip

# Check kit status
phishkiller status <kit_id>

# List and manage kits
phishkiller kits list --status analyzed
phishkiller kits get <kit_id>
phishkiller kits similar <kit_id>    # TLSH fuzzy matching
phishkiller kits delete <kit_id>

# Query indicators of compromise
phishkiller iocs list --type url
phishkiller iocs search "admin@"
phishkiller iocs stats

# Feed management
phishkiller feeds ingest              # Trigger feed ingestion
phishkiller feeds status              # Processing stats
phishkiller feeds entries             # List entries

# Worker management
phishkiller worker recover            # Recover stuck kits manually

# Service health
phishkiller health
```

## License

MIT
