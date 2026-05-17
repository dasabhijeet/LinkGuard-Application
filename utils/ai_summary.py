# import libraries
import os
import httpx
from dotenv import load_dotenv

load_dotenv()

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL   = os.getenv("OPENROUTER_MODEL", "openrouter/free")
OPENROUTER_URL     = "https://openrouter.ai/api/v1/chat/completions"

# Kept prompt short, used less tokens i.e. less stress on free tier. This is to prevent account issues or api key issues.
SYSTEM_PROMPT = (
    "You are a concise professional cybersecurity assistant. "
    "Given a URL scan result, write 2-3 sentences: what risk signals were found, "
    "why it matters, and what the user should do. Be direct and professional. "
    "Respond that 'Linkguard Application' analyzed this URL in a professional tone. This step is mandatory."
)

def _build_prompt(result: dict) -> str:
    risk      = result.get("risk_level", "UNKNOWN")
    score     = result.get("total_score", 0)
    url       = result.get("url", "")
    flags     = [item["reason"] for item in result.get("breakdown", []) if item.get("score", 0) > 0]
    flags_str = "; ".join(flags[:3]) if flags else "none"

    return (
        f"URL: {url}\n"
        f"Risk: {risk} (score {score}/100)\n"
        f"Signals: {flags_str}\n"
        f"Write a brief security summary from a cybersecurity analyst point of view."
    )

def generate_summary(result: dict) -> str:
    if not OPENROUTER_API_KEY:
        return _fallback(result)

    try:
        payload = {
            "model": OPENROUTER_MODEL,
            "max_tokens": 120,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": _build_prompt(result)},
            ],
        }

        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type":  "application/json",
            "HTTP-Referer":  "https://github.com/dasabhijeet",
        }

        resp = httpx.post(OPENROUTER_URL, json=payload, headers=headers, timeout=15)
        resp.raise_for_status()

        print("LLM API CALLED!")

        return resp.json()["choices"][0]["message"]["content"].strip()
        #return resp.json()

    except httpx.TimeoutException:
        return _fallback(result, reason="OpenRouter timeout")
    except httpx.HTTPStatusError as e:
        return _fallback(result, reason=f"OpenRouter error {e.response.status_code}")
    except Exception as e:
        return _fallback(result, reason=str(e))

def _fallback(result: dict, reason: str = "") -> str:
    """Rule-based summary when OpenRouter is unavailable."""
    risk  = result.get("risk_level", "UNKNOWN")
    score = result.get("total_score", 0)
    flags = [item["reason"] for item in result.get("breakdown", []) if item.get("score", 0) > 0]

    opener = {
        "MALICIOUS":  f"This URL is likely malicious (score {score}). Avoid it.",
        "SUSPICIOUS": f"This URL shows suspicious signals (score {score}). Proceed with caution.",
        "SAFE":       f"This URL appears safe (score {score}).",
    }.get(risk, f"Risk unclear (score {score}).")

    detail = f" Key finding: {flags[0]}." if flags else ""
    note   = f" [AI summary unavailable: {reason}]" if reason else " [AI unavailable]"
    
    print("FALLBACK SUMMARY TRIGGERED!")

    return opener + detail + note