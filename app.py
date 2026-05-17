# import libraries
import sys
import os
import hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Header, Query
from fastapi.responses import PlainTextResponse
from dotenv import load_dotenv

load_dotenv()

# configs
API_KEY              = os.getenv("API_KEY", "linkguard-secret-key")
SUSPICIOUS_THRESHOLD = int(os.getenv("SUSPICIOUS_THRESHOLD", "30"))
MALICIOUS_THRESHOLD  = int(os.getenv("MALICIOUS_THRESHOLD", "60"))
HOST                 = os.getenv("HOST", "127.0.0.1")
PORT                 = int(os.getenv("PORT", "8000"))

sys.path.insert(0, os.path.dirname(__file__))

from utils.sqlite_utils import init_db, save_scan, get_scan_history, get_stats, get_domain_reputation, ping
from utils.ai_summary   import generate_summary
from scorers.entropy    import score_entropy
from scorers.homoglyph  import score_homoglyph
from scorers.tld        import score_tld
from scorers.subdomain  import score_subdomain
from scorers.keywords   import score_keywords
from scorers.reputation import score_reputation

# app startup
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    print("[LinkGuard] Ready.")
    yield

app = FastAPI(
    title="LinkGuard",
    description="URL threat intelligence API with AI-powered summaries via OpenRouter.",
    version="3.0.0",
    lifespan=lifespan,
)

# API auth
def require_api_key(x_api_key: str):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key.")

# Pipeline
# Each scorer runs independently. One failing never stops the rest.
# Scores are summed, clamped to 0 minimum, then risk tier is assigned.
# AI/LLM summary is generated last from the full result.

async def run_pipeline(url: str) -> dict:
    breakdown = []

    # Math and logic based scorers
    for fn in [score_entropy, score_homoglyph, score_tld, score_subdomain, score_keywords]:
        try:
            breakdown.append(fn(url))
        except Exception as e:
            breakdown.append({"scorer": fn.__name__, "score": 0, "reason": f"error: {e}"})

    # Reputation scorer
    try:
        breakdown.append(score_reputation(url, get_domain_reputation))
    except Exception as e:
        breakdown.append({"scorer": "reputation", "score": 0, "reason": f"error: {e}"})

    # Clamp to 0. Good reputation can reduce score but never below zero.
    total = max(0, sum(item["score"] for item in breakdown))

    risk = (
        "MALICIOUS"  if total >= MALICIOUS_THRESHOLD  else
        "SUSPICIOUS" if total >= SUSPICIOUS_THRESHOLD else
        "SAFE"
    )

    result = {
        "url":         url,
        "url_sha256_hash":    hashlib.sha256(url.encode()).hexdigest(),
        "risk_level":  risk,
        "total_score": total,
        "breakdown":   breakdown,
        "scanned_at":  datetime.now(timezone.utc).isoformat(),
    }

    # AI/LLM summary
    result["ai_summary"] = await generate_summary(result)

    return result

# API endpoints

@app.post("/scan")
async def scan_url(request: dict, x_api_key: str = Header(...)):
    require_api_key(x_api_key)
    url = request.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="Missing 'url' in request body.")
    if len(url) > 2048:
        raise HTTPException(status_code=400, detail="URL too long.")
    result = await run_pipeline(url)
    save_scan(result)
    return result

@app.get("/history")
async def history_query(url: str = Query(...), x_api_key: str = Header(...)):
    require_api_key(x_api_key)
    rows = get_scan_history(url)
    if not rows:
        raise HTTPException(status_code=404, detail="No history found for this URL.")
    return {"url": url, "scans": rows}

@app.post("/history")
async def history_body(request: dict, x_api_key: str = Header(...)):
    require_api_key(x_api_key)
    url = request.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="Missing 'url' in request body.")
    rows = get_scan_history(url)
    if not rows:
        raise HTTPException(status_code=404, detail="No history found for this URL.")
    return {"url": url, "scans": rows}

@app.get("/stats")
async def stats(x_api_key: str = Header(...)):
    require_api_key(x_api_key)
    return get_stats()

@app.get("/metrics", response_class=PlainTextResponse)
async def metrics(x_api_key: str = Header(...)):
    """Prometheus-compatible plaintext metrics. Future release plan."""
    require_api_key(x_api_key)
    data = get_stats()
    lines = [
        "# HELP linkguard_total_scans Total URLs scanned",
        "# TYPE linkguard_total_scans counter",
        f"linkguard_total_scans {data['total_scans']}",
        "# HELP linkguard_risk_safe Safe scan count",
        "# TYPE linkguard_risk_safe gauge",
        f"linkguard_risk_safe {data['risk_counts'].get('SAFE', 0)}",
        "# HELP linkguard_risk_suspicious Suspicious scan count",
        "# TYPE linkguard_risk_suspicious gauge",
        f"linkguard_risk_suspicious {data['risk_counts'].get('SUSPICIOUS', 0)}",
        "# HELP linkguard_risk_malicious Malicious scan count",
        "# TYPE linkguard_risk_malicious gauge",
        f"linkguard_risk_malicious {data['risk_counts'].get('MALICIOUS', 0)}",
    ]
    return "\n".join(lines)

@app.get("/health")
async def health():
    return {
        "status":  "ok" if ping() else "degraded",
        "db":      "connected" if ping() else "error",
        "version": "3.0.0",
    }

# App entry point

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host=HOST, port=PORT, reload=False)
