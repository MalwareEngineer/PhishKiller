# PhishKiller

Automated phishing kit analysis platform.

## Setup

```bash
cp .env.example .env
docker compose up -d
docker compose exec api alembic upgrade head
```

## Submitting Samples

**URL submission:**
```bash
curl -X POST http://localhost:8000/api/v1/investigations \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.com/login"}'
```

**EML file upload:**
```bash
curl -X POST http://localhost:8000/api/v1/kits/upload -F "file=@phish.eml"
```

**Kit archive upload:**
```bash
curl -X POST http://localhost:8000/api/v1/kits/upload -F "file=@kit.zip"
```

## Analysis Pipeline

Each sample runs through a 13-step chain:

```
download → hash → extract → parse_eml → deobfuscate → yara_scan →
extract_iocs → decode_qr → similarity → correlate_actors →
auto_assign_campaign → crawl_chain → finalize
```

**IOC types extracted:** C2 URLs, IPs, domains, emails, crypto wallets, Telegram bot tokens/chat IDs, SMTP credentials, phone numbers.

## Automated Feeds

PhishTank and OpenPhish entries are polled on a schedule and run through the full pipeline automatically.

## Campaigns & Actors

Kits sharing both a correlated actor (via high-confidence IOCs) and tight TLSH similarity (≤30) are automatically grouped into campaigns. Investigations remain manual-only.

## API

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/kits` | List kits |
| `GET /api/v1/kits/{id}` | Kit detail |
| `GET /api/v1/investigations` | List investigations |
| `GET /api/v1/investigations/{id}/tree` | Kit chain tree |
| `GET /api/v1/campaigns` | List campaigns |
| `GET /api/v1/actors` | List actors |
| `GET /api/v1/indicators` | List IOCs |

## License

MIT
