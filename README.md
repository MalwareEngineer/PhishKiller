# PhishKiller

Automated phishing kit collection, extraction, and analysis platform.

## Setup

```bash
cp .env.example .env        # configure API keys (PhishTank, URLhaus)
docker compose up -d         # postgres, redis, rabbitmq, worker
pip install -e ".[tlsh]"     # local CLI + API
alembic upgrade head         # run migrations
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
phishkiller worker reset            # purge queues + re-run all kits on current chain
phishkiller health
```

## Feeds

| Source | Interval |
|--------|----------|
| PhishTank | 3h |
| URLhaus | 1h |
| OpenPhish | 6h |
| Feed entry processing | 2min (batch 2000) |
| Stuck kit recovery | 15min |

## Local Dev (no Docker worker)

```bash
docker compose stop worker
celery -A phishkiller.celery_app worker -l info -P solo -B -Q celery,feeds,downloads,analysis,certstream
```

## License

MIT
