from urllib.parse import urlparse

HOMOGLYPH_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b",
    "vv": "w", "rn": "m",
}

TARGET_BRANDS = [
    "paypal", "google", "microsoft", "amazon", "apple",
    "netflix", "facebook", "instagram", "twitter", "linkedin",
    "gmail", "outlook", "dropbox", "github", "stripe",
    "binance", "coinbase", "wellsfargo", "bankofamerica",
]

def normalize(text: str) -> str:
    result = text.lower()
    for fake, real in HOMOGLYPH_MAP.items():
        result = result.replace(fake, real)
    return result

def score_homoglyph(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc.lower().replace("www.", "")
    domain_base = domain.split(".")[0]
    normalized = normalize(domain_base)

    for brand in TARGET_BRANDS:
        if normalized == brand and domain_base != brand:
            return {"scorer": "homoglyph", "score": 50, "reason": f"domain '{domain_base}' is a homoglyph of '{brand}'"}
        if brand in normalized and brand not in domain_base:
            return {"scorer": "homoglyph", "score": 25, "reason": f"domain contains homoglyph variant of '{brand}'"}

    return {"scorer": "homoglyph", "score": 0, "reason": "no homoglyph brand impersonation detected"}