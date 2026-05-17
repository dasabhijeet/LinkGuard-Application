from urllib.parse import urlparse

HIGH_RISK_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".club", ".work", ".click",
    ".loan", ".win", ".download", ".stream",
    ".zip", ".mov",
}

MEDIUM_RISK_TLDS = {
    ".info", ".biz", ".online", ".site",
    ".website", ".space", ".fun", ".live",
}

def score_tld(url: str) -> dict:
    parsed = urlparse(url)
    parts = parsed.netloc.lower().split(".")

    if len(parts) < 2:
        return {"scorer": "tld", "score": 0, "reason": "could not extract TLD"}

    tld = "." + parts[-1]

    if tld in HIGH_RISK_TLDS:
        return {"scorer": "tld", "score": 20, "reason": f"TLD '{tld}' has high phishing abuse rate"}
    if tld in MEDIUM_RISK_TLDS:
        return {"scorer": "tld", "score": 10, "reason": f"TLD '{tld}' has moderate phishing abuse rate"}

    return {"scorer": "tld", "score": 0, "reason": f"TLD '{tld}' is not in any risk list"}