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
pip install -e ".[tlsh,yara,qr]"
uvicorn phishkiller.main:app --reload
```

## Analysis Pipeline

Each kit runs through an 11-step Celery chain:

```
download → hash → extract → parse_eml → deobfuscate → yara_scan → extract_iocs → decode_qr → compute_similarity → correlate_actors → crawl_chain
```

- **Hash**: SHA256, MD5, SHA1, TLSH (fuzzy)
- **Extract**: ZIP/TAR/RAR, skips non-archives
- **EML Parse**: MIME walking, link extraction, attachment saving, inline image extraction
- **Deobfuscate**: PHP `eval(base64_decode(...))` unwrapping
- **YARA**: 892 rules — 890 t4d ZIP-level kit signatures + custom content rules
- **IOCs**: emails, URLs, domains, IPs, crypto wallets, Telegram tokens/handles, SMTP creds, PHP mailers
- **QR Decode**: Scans extracted images for QR codes containing phishing URLs (pyzbar + Pillow)
- **Similarity**: TLSH distance clustering (threshold ≤100)
- **Actors**: Auto-correlates kits sharing exfil infrastructure
- **Chain Crawl**: Scores discovered links and spawns child kits for multi-step phish tracking

### Multi-Step Chain Crawling

Phishing campaigns often use multiple redirects, QR codes, and intermediary pages. PhishKiller follows these chains automatically:

1. **Link discovery** — EML links, QR code URLs, redirect hops, and HTML form actions
2. **Smart scoring** — each link scored 0–1 based on source type, domain reputation, phish keywords, and URL shortener detection
3. **Child kit submission** — links above threshold (default 0.5) spawn new kits with full pipeline analysis
4. **Depth limiting** — configurable max depth (default 3) prevents runaway crawling

Chains are grouped into **Investigations** — submit a URL or `.eml` file to start one. Each investigation tracks the full parent→child tree, total depth reached, and per-kit discovery method.

### Pattern Versioning

IOC extraction rules (regex, filters, allowlists) are versioned via `PATTERN_VERSION`. When patterns change, kits with a stale version can be selectively re-analyzed without reprocessing the entire database.

## Feeds

| Source | Interval | Notes |
|--------|----------|-------|
| PhishTank | 3h | JSON API, optional API key |
| OpenPhish | 6h | Plain text URL list |
| PhishStats | 6h | CSV, score ≥ 5 filter |
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

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/kits` | GET | List kits with filtering |
| `/api/v1/kits/upload` | POST | Upload `.eml` or kit archive (auto-creates investigation for `.eml`) |
| `/api/v1/investigations` | GET | List investigations |
| `/api/v1/investigations` | POST | Start investigation from URL or file upload |
| `/api/v1/investigations/{id}` | GET | Investigation details |
| `/api/v1/investigations/{id}/tree` | GET | Parent→child kit tree |
| `/api/v1/investigations/{id}/kits` | GET | Flat kit list for investigation |

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
