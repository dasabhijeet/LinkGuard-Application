# LinkGuard Application

Self-hosted URL threat intelligence API. Math-based scoring engine with AI-powered summaries via OpenRouter. Other LLMs can be used as well, but the choice I made is for simplicity.

Future goal is to host AI locally and use this application instead of sending data to third party servers.

This project was inspired from my earlier cybersecurity backend demo project: https://github.com/dasabhijeet/Signal-Transfer-Pipeline

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

## Screenshots

### 1. Server start

<img width="930" height="360" alt="Screenshot 2026-05-17 202317" src="https://github.com/user-attachments/assets/172dd3f0-f918-421c-8a4a-c70b8aa9ca99" />

### 2. /scan endpoint

<img width="1450" height="443" alt="Screenshot 2026-05-17 201527" src="https://github.com/user-attachments/assets/492ed8fa-41f7-4e5e-9b54-3a581895bf3b" />

### 3. /health endpoint

<img width="1457" height="432" alt="Screenshot 2026-05-17 201654" src="https://github.com/user-attachments/assets/4972ff72-4bf2-47bc-be5d-11e2349c8d88" />

### 4. /history?url=.... endpoint

<img width="1458" height="412" alt="Screenshot 2026-05-17 201726" src="https://github.com/user-attachments/assets/3918d797-0e29-4614-b3c0-a2236e4fe80d" />

### 5. /stats endpoint

<img width="1457" height="422" alt="Screenshot 2026-05-17 201838" src="https://github.com/user-attachments/assets/21665d0e-4e91-4268-a187-87a9a138faba" />

### 6. /metrics endpoint

<img width="1433" height="455" alt="Screenshot 2026-05-17 201948" src="https://github.com/user-attachments/assets/5dfe718e-2fdc-46a7-8283-aa6c818a710a" />
