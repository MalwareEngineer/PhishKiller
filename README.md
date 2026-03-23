# PhishKiller

Phishing kit analysis platform. Downloads, extracts, decrypts, and scans
phishing kits to extract IOCs, classify kit families, correlate threat actors,
and group campaigns — all through a Celery-driven analysis pipeline.

Designed for manual/API-only intake: every kit traces back to an analyst
submission (GUI/CLI) or API integration (email gateway, SOAR playbook).

## Features

- **14-step analysis pipeline** — download, extract, decrypt, scan, correlate, and discover linked kits automatically
- **React dashboard** — SOC analyst GUI for kit triage, investigation trees, indicator search, campaign/actor management
- **YARA scanning** — 890+ t4d PhishingKit rules plus custom rules for kit families, evasion techniques, and credential exfiltration patterns
- **IOC extraction** — C2 URLs, emails, IPs, domains, crypto wallets, Telegram bot tokens/chat IDs, SMTP credentials, phone numbers
- **AES-GCM decryption** — Decrypt encrypted phishing pages (device code kits, self-decrypting HTML)
- **QR code detection** — Extract and decode QR codes from phishing images (quishing)
- **TLSH similarity clustering** — Fuzzy-hash kits to find related variants and group kit families
- **Kit chain discovery** — Follow C2 URLs, redirects, and form actions to discover child/grandchild kits up to configurable depth
- **Actor correlation** — Auto-create threat actors from high-confidence IOCs (email, Telegram, crypto wallets)
- **Campaign grouping** — Automatically group kits sharing actors and TLSH similarity into campaigns
- **Stealth browser fallback** — Camoufox (anti-detect Firefox) for Cloudflare-protected pages with Turnstile, FingerprintJS, and anti-VM detection
- **CLI + REST API** — Full-featured command line and HTTP API for submissions, search, and management

## Architecture

Eight Docker Compose services:

| Service | Role |
|---------|------|
| `postgres` | Primary database (PostgreSQL 16) |
| `redis` | Caching and Celery result backend |
| `rabbitmq` | Celery message broker |
| `api` | FastAPI REST API (uvicorn) |
| `worker-beat` | Celery beat scheduler (stuck-kit recovery) |
| `worker-downloads` | Download worker (prefork, 4 processes) |
| `worker-analysis` | Analysis pipeline worker (prefork, 10 processes) |
| `worker-browser` | Stealth browser worker (Camoufox, solo pool) |

## Setup

```bash
cp .env.example .env
docker compose up -d
docker compose exec api alembic upgrade head
```

### Frontend

```bash
cd frontend
npm install
npm run dev       # dev server on :5173
npm run build     # production bundle
```

### YARA Rules

Download the [t4d PhishingKit-Yara-Rules](https://github.com/t4d/PhishingKit-Yara-Rules)
into `rules/t4d/`:

```bash
./scripts/update_yara_rules.sh
```

Custom rules in `rules/` detect kit families, evasion techniques, credential
exfiltration, and brand-targeted templates. Rules are mounted read-only into
Docker containers. YARA scanning is optional — the pipeline runs without rules.

## CLI

The `phishkiller` CLI wraps the REST API.

```bash
# Submit a URL or local file
phishkiller submit https://suspicious-site.com/login
phishkiller submit phish.eml
phishkiller submit kit.zip
phishkiller submit --batch urls.txt

# Watch analysis progress
phishkiller watch <kit_id>

# Kit details
phishkiller status <kit_id>

# List / search
phishkiller kits list --status analyzed
phishkiller kits similar <kit_id>
phishkiller iocs list --type c2_url
phishkiller iocs search "example.com"

# Investigations
phishkiller investigations create https://suspicious-site.com/login
phishkiller investigations tree <investigation_id>

# Campaigns & actors
phishkiller campaigns list
phishkiller actors list

# Maintenance
phishkiller health
phishkiller worker recover
```

## API

REST API at `http://localhost:8000/api/v1/`.

```bash
# URL submission (creates investigation with chain crawling)
curl -X POST http://localhost:8000/api/v1/investigations \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.com/login"}'

# File upload (EML, ZIP, RAR, HTML)
curl -X POST http://localhost:8000/api/v1/kits/upload -F "file=@phish.eml"

# Bulk file upload
curl -X POST http://localhost:8000/api/v1/kits/upload/bulk \
  -F "files=@kit1.zip" -F "files=@kit2.zip"
```

| Endpoint | Description |
|----------|-------------|
| `POST /api/v1/kits` | Submit URL |
| `POST /api/v1/kits/upload` | Upload file |
| `POST /api/v1/kits/upload/bulk` | Bulk file upload |
| `POST /api/v1/investigations` | Start investigation |
| `GET /api/v1/kits` | List kits |
| `GET /api/v1/kits/{id}` | Kit detail with children, campaigns, IOCs |
| `GET /api/v1/kits/{id}/similar` | Find similar kits by TLSH |
| `GET /api/v1/kits/{id}/delete-preview` | Preview cascade deletion impact |
| `DELETE /api/v1/kits/{id}` | Delete kit (cascades to children, indicators, results) |
| `GET /api/v1/investigations` | List investigations |
| `GET /api/v1/investigations/{id}/tree` | Kit chain tree |
| `GET /api/v1/indicators` | List IOCs |
| `GET /api/v1/indicators/search` | Search IOCs |
| `GET /api/v1/actors` | List actors |
| `GET /api/v1/campaigns` | List campaigns |
| `GET /api/v1/campaigns/{id}` | Campaign detail with linked kits and actors |

## Analysis Pipeline

Each sample runs through a 14-step Celery chain:

```
download → hash → extract → parse_eml → deobfuscate → decrypt_html →
yara_scan → extract_iocs → decode_qr → similarity → correlate_actors →
auto_assign_campaign → crawl_chain → finalize
```

- **extract** — ZIP, RAR, TAR, GZ archives with path traversal protection
- **parse_eml** — Extract URLs, attachments, and headers from email files
- **deobfuscate** — PHP `eval(base64_decode(...))` unwrapping
- **decrypt_html** — AES-GCM encrypted phishing pages (device code kits)
- **yara_scan** — t4d PhishingKit rules on raw downloads and extracted files
- **extract_iocs** — C2 URLs, emails, IPs, domains, crypto wallets, Telegram tokens, SMTP creds, phone numbers
- **decode_qr** — QR code extraction from images (quishing attacks)
- **similarity** — TLSH fuzzy hashing for kit family clustering
- **correlate_actors** — Auto-create threat actors from high-confidence IOCs
- **auto_assign_campaign** — Group kits by shared actor + TLSH similarity
- **crawl_chain** — Follow scored links as child kits (redirects, form actions, QR targets)

## License

MIT
