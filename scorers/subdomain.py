from urllib.parse import urlparse

def score_subdomain(url: str) -> dict:
    parsed = urlparse(url)
    host = parsed.netloc.lower().replace("www.", "")

    if ":" in host:
        host = host.split(":")[0]

    parts = host.split(".")
    depth = max(0, len(parts) - 2)

    if depth >= 4:
        return {"scorer": "subdomain", "score": 30, "reason": f"very deep subdomain nesting ({depth} levels) — common in phishing"}
    elif depth >= 2:
        return {"scorer": "subdomain", "score": 10, "reason": f"multiple subdomain levels ({depth}) — slightly elevated"}

    return {"scorer": "subdomain", "score": 0, "reason": f"normal subdomain depth ({depth})"}