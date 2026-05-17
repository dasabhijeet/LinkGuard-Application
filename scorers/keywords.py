from urllib.parse import urlparse

# Common words found in phishing URLs
PHISHING_KEYWORDS = [
    "verify", "suspended", "urgent", "login", "secure", "account",
    "update", "confirm", "password", "reset", "alert", "invoice",
    "download", "claim", "prize", "bonus", "free", "winner", "lucky",
    "billing", "payment", "support", "service", "unusual", "activity",
]

# Legit domains don't usually have these in their path
SUSPICIOUS_PATH_WORDS = [
    "wp-admin", "admin", "cmd", "shell", "exec", "base64",
    "redirect", "goto", "redir", "out", "click", "track",
]

def score_keywords(url: str) -> dict:
    url_lower = url.lower()
    parsed    = urlparse(url_lower)
    full_text = parsed.netloc + parsed.path + parsed.query

    keyword_hits = [kw for kw in PHISHING_KEYWORDS if kw in full_text]
    path_hits    = [kw for kw in SUSPICIOUS_PATH_WORDS if kw in parsed.path]

    total_hits = len(keyword_hits) + len(path_hits)

    if total_hits >= 4:
        return {"scorer": "keywords", "score": 25, "reason": f"{total_hits} phishing keywords detected: {', '.join((keyword_hits + path_hits)[:4])}"}
    elif total_hits >= 2:
        return {"scorer": "keywords", "score": 12, "reason": f"{total_hits} phishing keywords detected: {', '.join((keyword_hits + path_hits)[:2])}"}
    elif total_hits == 1:
        return {"scorer": "keywords", "score": 5,  "reason": f"1 phishing keyword detected: {(keyword_hits + path_hits)[0]}"}

    return {"scorer": "keywords", "score": 0, "reason": "no phishing keywords detected"}