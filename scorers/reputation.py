from urllib.parse import urlparse


def _extract_domain(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc.lower().replace("www.", "")
    return host.split(":")[0]


def score_reputation(url: str, get_reputation_fn) -> dict:
    """
    Checks the URL's domain against the reputation list loaded from domain_reputation.csv.
    Reputation data is stored in SQLite and queried via get_reputation_fn (passed from app).
    This keeps the scorer free of direct DB imports.

    Score:
        bad     -> +40
        unknown -> +10  (unrecognised domains are mildly suspicious)
        medium  ->   0
        good    -> -10  (trusted domains reduce overall score slightly)
    """
    domain = _extract_domain(url)

    if not domain:
        return {"scorer": "reputation", "score": 0, "reason": "could not extract domain"}

    reputation = get_reputation_fn(domain)

    if reputation == "bad":
        return {"scorer": "reputation", "score": 40, "reason": f"domain '{domain}' is flagged as bad reputation"}
    elif reputation == "unknown":
        return {"scorer": "reputation", "score": 10, "reason": f"domain '{domain}' is not in the reputation list — treat with caution"}
    elif reputation == "medium":
        return {"scorer": "reputation", "score": 0,  "reason": f"domain '{domain}' has medium reputation — no extra risk added"}
    elif reputation == "good":
        return {"scorer": "reputation", "score": -10, "reason": f"domain '{domain}' is a known trusted domain"}

    return {"scorer": "reputation", "score": 0, "reason": f"reputation check inconclusive for '{domain}'"}
