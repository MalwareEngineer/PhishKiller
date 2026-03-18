# PhishKiller

Automated phishing kit analysis platform. Downloads, extracts, decrypts, and
scans phishing kits to extract IOCs, classify kit families, correlate threat
actors, and group campaigns — all through a Celery-driven analysis pipeline.

## Setup

```bash
cp .env.example .env
docker compose up -d
docker compose exec api alembic upgrade head
```

### Private Configuration

Generate operational data (user agents, CertStream brands/keywords) that is
kept out of version control:

```bash
python scripts/setup_private.py
```

### YARA Rules

Download the [t4d PhishingKit-Yara-Rules](https://github.com/t4d/PhishingKit-Yara-Rules)
into `rules/t4d/`:

```bash
./scripts/update_yara_rules.sh
```

Rules are mounted read-only into Docker containers. Re-run the script to pull
updates. YARA scanning is optional — the pipeline runs without rules.

## CLI

The `phishkiller` CLI wraps the REST API for day-to-day use.

```bash
# Submit a URL or local file
phishkiller submit https://suspicious-site.com/login
phishkiller submit phish.eml
phishkiller submit kit.zip
phishkiller submit --batch urls.txt

# Watch analysis progress
phishkiller watch <kit_id>

# Kit details (shows parent/child kits, investigation, campaigns, IOCs)
phishkiller status <kit_id>

# List / search
phishkiller kits list --status analyzed
phishkiller kits similar <kit_id>
phishkiller iocs list --type c2_url
phishkiller iocs search "example.com"

# Investigations (chain crawling)
phishkiller investigations create https://suspicious-site.com/login
phishkiller investigations list
phishkiller investigations tree <investigation_id>

# Campaigns
phishkiller campaigns list
phishkiller campaigns get <campaign_id>
phishkiller campaigns create --name "BEC Q1" --brand Microsoft

# Actors
phishkiller actors list
phishkiller actors get <actor_id>
phishkiller actors search "actor@example.com"

# Feeds & maintenance
phishkiller feeds ingest
phishkiller feeds status
phishkiller health
phishkiller worker recover
```

## API

Full REST API at `http://localhost:8000/api/v1/`. Submit samples via curl when
the CLI isn't available:

```bash
# URL submission (creates investigation with chain crawling)
curl -X POST http://localhost:8000/api/v1/investigations \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.com/login"}'

# File upload (EML, ZIP, RAR, HTML)
curl -X POST http://localhost:8000/api/v1/kits/upload -F "file=@phish.eml"
```

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/kits` | List kits |
| `GET /api/v1/kits/{id}` | Kit detail with children, campaigns, IOCs |
| `GET /api/v1/kits/{id}/similar` | Find similar kits by TLSH |
| `GET /api/v1/investigations` | List investigations |
| `GET /api/v1/investigations/{id}/tree` | Kit chain tree |
| `GET /api/v1/campaigns` | List campaigns |
| `GET /api/v1/campaigns/{id}` | Campaign detail with linked kits and actors |
| `GET /api/v1/actors` | List actors |
| `GET /api/v1/indicators` | List IOCs |
| `POST /api/v1/kits` | Submit URL |
| `POST /api/v1/kits/upload` | Upload file |
| `POST /api/v1/kits/upload/bulk` | Bulk file upload |
| `POST /api/v1/investigations` | Start investigation |

## Analysis Pipeline

Each sample runs through a 14-step Celery chain:

```
download → hash → extract → parse_eml → deobfuscate → decrypt_html →
yara_scan → extract_iocs → decode_qr → similarity → correlate_actors →
auto_assign_campaign → crawl_chain → finalize
```

**Key stages:**

- **extract** — ZIP, RAR, TAR, GZ archives with path traversal protection
- **parse_eml** — Extract URLs, attachments, and headers from email files
- **deobfuscate** — PHP `eval(base64_decode(...))` unwrapping
- **decrypt_html** — AES-GCM encrypted phishing pages (device code kits, etc.)
- **yara_scan** — t4d PhishingKit rules on raw downloads and extracted files
- **extract_iocs** — C2 URLs, emails, IPs, domains, crypto wallets, Telegram tokens, SMTP creds, phone numbers
- **decode_qr** — QR code extraction from images (quishing attacks)
- **similarity** — TLSH fuzzy hashing for kit family clustering
- **correlate_actors** — Auto-create threat actors from high-confidence IOCs
- **auto_assign_campaign** — Group kits by shared actor + TLSH similarity
- **crawl_chain** — Follow scored links as child kits (redirects, form actions, QR targets)

## Automated Feeds

PhishTank and OpenPhish entries are polled on a schedule and run through the
full pipeline automatically. Check feed health with `phishkiller feeds health`.

## Campaigns & Actors

Kits sharing both a correlated actor (via high-confidence IOCs) and tight TLSH
similarity (≤30) are automatically grouped into campaigns. Actors are
auto-created from email addresses, Telegram handles, and other identifying
IOCs. Investigations track URL chains via parent-child kit relationships.

## License

MIT
