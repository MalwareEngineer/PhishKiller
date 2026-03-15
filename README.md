# PhishKiller

Automated phishing kit collection, extraction, and analysis platform.

## Requirements

- Docker & Docker Compose
- 4+ CPU cores (2 for analysis workers, 1 for downloads, 1 for beat/OS)
- 4 GB RAM minimum (8 GB recommended — PostgreSQL, Redis, RabbitMQ, 3 workers)
- 20 GB disk (kit downloads + extracted archives)

## Setup

```bash
cp .env.example .env        # configure API keys
docker compose up -d         # postgres, redis, rabbitmq, 3 workers
alembic upgrade head         # run migrations
```

Optional for local API/CLI development:

```bash
pip install -e ".[tlsh]"
uvicorn phishkiller.main:app --reload
```

## Analysis Pipeline

Each kit runs through an 8-step Celery chain:

```
download → hash → extract → deobfuscate → yara_scan → extract_iocs → compute_similarity → correlate_actors
```

- **Hash**: SHA256, MD5, SHA1, TLSH (fuzzy)
- **Extract**: ZIP/TAR/RAR, skips non-archives
- **Deobfuscate**: PHP `eval(base64_decode(...))` unwrapping
- **YARA**: 892 rules — 890 t4d ZIP-level kit signatures + custom content rules
- **IOCs**: emails, URLs, domains, IPs, crypto wallets, Telegram tokens/handles, SMTP creds, PHP mailers
- **Similarity**: TLSH distance clustering (threshold ≤100)
- **Actors**: Auto-correlates kits sharing exfil infrastructure

## Feeds

| Source | Interval | Notes |
|--------|----------|-------|
| PhishTank | 3h | JSON API, optional API key |
| URLhaus | 1h | abuse.ch, optional auth key |
| OpenPhish | 6h | Plain text URL list |
| PhishStats | 6h | CSV, score ≥ 5 filter |
| Phishing.Database | 12h | GitHub, ~800K URLs |
| Feed entry processing | 2min | Batch 2000 → download queue |
| Stuck kit recovery | 15min | Re-queues hung kits |

Feeds use HTTP conditional requests (ETag/If-Modified-Since) cached in Redis — unchanged feeds return 304 and skip all DB work.

## Workers

| Container | Pool | Concurrency | Queues | Role |
|-----------|------|-------------|--------|------|
| worker-beat | solo | 1 | celery, feeds | Beat scheduler, feed ingestion, recovery |
| worker-downloads | prefork | 2 | downloads | I/O-bound kit downloads |
| worker-analysis | prefork | 10 | analysis | CPU-bound YARA, hashing, IOC extraction |

Total: ~16 OS processes (beat 2, downloads 3, analysis 11).

## CLI

```bash
# Submit & inspect
phishkiller submit https://example.com/kit.zip
phishkiller status <kit_id>
phishkiller kits list --status analyzed
phishkiller kits similar <kit_id>

# IOCs
phishkiller iocs list --type url
phishkiller iocs search "admin@"
phishkiller iocs stats

# Actors
phishkiller actors list
phishkiller actors get <actor_id>

# Feeds
phishkiller feeds ingest
phishkiller feeds status

# Operations
phishkiller worker recover          # unstick hung kits
phishkiller worker reset            # purge queues + re-run all kits
phishkiller health
```

## Local Dev (no Docker workers)

```bash
docker compose stop worker-beat worker-downloads worker-analysis
celery -A phishkiller.celery_app worker -l info -P solo -B -Q celery,feeds,downloads,analysis
```

## License

MIT
