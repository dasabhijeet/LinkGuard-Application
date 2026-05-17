# LinkGuard Application

Self-hosted URL threat intelligence API. Math-based scoring engine with AI-powered summaries via OpenRouter. Other LLMs can be used as well, but the choice I made is for simplicity.

Future goal is to host AI locally and use this application instead of sending data to third party servers.

## What it does

Scans URLs through six independent scorers, then sends the result to an LLM (via OpenRouter/free tier) for a plain English security summary.

| Scorer     | Method     | What it checks                                           |
|------------|------------|----------------------------------------------------------|
| Entropy    | numpy math | Shannon entropy detects random/obfuscated URLs           |
| Homoglyph  | string ops | Character substitution impersonating brands (paypa2.com) |
| TLD        | lookup     | High-abuse top-level domains (.tk, .xyz, .click)         |
| Subdomain  | math       | Deeply nested subdomains hiding the real domain          |
| Keywords   | string ops | Phishing keyword density in URL path and query           |
| Reputation | DB lookup  | Domain reputation from CSV-seeded SQLite list            |

**AI summary** — result is sent to `openrouter/free` via OpenRouter. One HTTP POST. Falls back gracefully if unavailable. Models can change over time, so use test_openrouter.py to test LLM API before running actual project. Ideally use free LLM's, they are not bad for security summaries as per my tests.

---

## Setup

```bash
# 1. Install dependencies
pip install fastapi uvicorn[standard] python-dotenv httpx numpy

# 2. Configure
cp .env.example .env
# Edit .env — add your OPENROUTER_API_KEY

# 3. Run
python app.py
```

---

## Endpoints

All endpoints except `/health` require header: `x-api-key: linkguard-secret-key` (customize this as per needs, further API security improvements for future releases.)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scan` | Scan a URL |
| GET | `/history?url=...` | Past scans for a URL |
| POST | `/history` | Past scans via request body |
| GET | `/stats` | Total scans, risk counts, top 10 domains |
| GET | `/metrics` | Prometheus-compatible plaintext (future release) |
| GET | `/health` | Health check, no key needed |

### POST /scan — example response
```json
{
  "url": "https://secure-login-verify-account.tk/paypal",
  "risk_level": "MALICIOUS",
  "total_score": 87,
  "ai_summary": "This URL shows multiple high-risk signals including a high-abuse TLD and phishing keywords. It appears to impersonate PayPal. Avoid clicking this link.",
  "breakdown": [
    { "scorer": "tld",        "score": 20, "reason": "TLD '.tk' has high phishing abuse rate" },
    { "scorer": "keywords",   "score": 25, "reason": "4 phishing keywords detected: verify, login, secure, account" },
    { "scorer": "reputation", "score": 40, "reason": "domain flagged as bad reputation" }
  ],
  "scanned_at": "2026-05-17T12:00:00+00:00"
}
```

---

## Configuration (`.env`)

| Variable               | Default                              | Description                        |
|------------------------|--------------------------------------|------------------------------------|
| `DB_PATH`              | `linkguard.db`                       | SQLite database path               |
| `REPUTATION_CSV`       | `domain_reputation.csv`              | Domain reputation list             |
| `OPENROUTER_API_KEY`   | —                                    | Your OpenRouter key                |
| `OPENROUTER_MODEL`     | `openrouter/free`                    | Model to use for summaries         |
| `API_KEY`              | `linkguard-secret-key`               | API key for all endpoints          |
| `SUSPICIOUS_THRESHOLD` | `30`                                 | Score threshold for SUSPICIOUS     |
| `MALICIOUS_THRESHOLD`  | `60`                                 | Score threshold for MALICIOUS      |
| `HOST`                 | `127.0.0.1`                          | Server bind address                |
| `PORT`                 | `8000`                               | Server port                        |

---

## Project structure

```
linkguard/
├── app.py                  # FastAPI + pipeline
├── utils/
│   ├── sqlite_utils.py     # All DB operations
│   └── ai_summary.py       # AI/LLM integration
├── scorers/
│   ├── entropy.py          # Shannon entropy via numpy
│   ├── homoglyph.py        # Brand impersonation detection
│   ├── subdomain.py        # Subdomain depth scoring
│   ├── tld.py              # TLD risk list
│   ├── keywords.py         # Phishing keyword density
│   └── reputation.py       # Domain reputation DB lookup
├── domain_reputation.csv   # Editable reputation list
├── .env                    # Your config (gitignored)
├── requirements.txt
└── README.md
```