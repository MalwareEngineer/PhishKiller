# PhishKiller

Automated phishing kit analysis platform with multi-step chain crawling.

## Setup

```bash
cp .env.example .env
docker compose up -d
alembic upgrade head
```

## Submitting Phishing Samples

### Via API

**URL submission:**
```bash
curl -X POST http://localhost:8000/api/v1/investigations \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.com/login"}'
```

**EML file upload** (auto-creates an investigation, follows links and QR codes):
```bash
curl -X POST http://localhost:8000/api/v1/kits/upload \
  -F "file=@phish.eml"
```

**Kit archive upload:**
```bash
curl -X POST http://localhost:8000/api/v1/kits/upload \
  -F "file=@kit.zip"
```

### Via CLI

```bash
phishkiller submit https://suspicious-site.com/login
phishkiller status <kit_id>
phishkiller kits list --status analyzed
```

## What Happens After Submission

Each sample runs through an 11-step analysis chain:

```
download → hash → extract → parse_eml → deobfuscate → yara_scan → extract_iocs → decode_qr → similarity → correlate_actors → crawl_chain
```

- **EML Parse** — extracts links, attachments, and inline images from email files
- **QR Decode** — scans images for QR codes containing phishing URLs
- **YARA** — 892 phishing kit signature rules
- **IOCs** — emails, URLs, domains, IPs, crypto wallets, Telegram handles, SMTP creds
- **Chain Crawl** — scores discovered links and follows the phishing chain (redirects, QR targets, form actions) up to configurable depth

### Investigations

`.eml` uploads and URL submissions create **Investigations** that track the full chain:

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/investigations` | List all investigations |
| `GET /api/v1/investigations/{id}` | Investigation summary |
| `GET /api/v1/investigations/{id}/tree` | Parent-child kit tree |
| `GET /api/v1/investigations/{id}/kits` | All kits in the chain |

Links are scored 0-1 based on source type, domain reputation, phish keywords, and URL shortener usage. Only links above the threshold (default 0.5) spawn child kits. Max chain depth defaults to 3.

## Viewing Results

```bash
# IOCs extracted from analyzed kits
phishkiller iocs list --type url
phishkiller iocs search "admin@"
phishkiller iocs stats

# Threat actor correlation
phishkiller actors list
phishkiller actors get <actor_id>

# Similar kits (TLSH fuzzy matching)
phishkiller kits similar <kit_id>
```

## License

MIT
