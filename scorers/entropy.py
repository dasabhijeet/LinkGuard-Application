import numpy as np
from urllib.parse import urlparse

def score_entropy(url: str) -> dict:
    parsed = urlparse(url)
    target = parsed.netloc + parsed.path + parsed.query

    if not target:
        return {"scorer": "entropy", "score": 0, "reason": "no content to analyze"}

    # Count character frequencies, compute probability distribution
    chars, counts = np.unique(list(target), return_counts=True)
    probs         = counts / counts.sum()

    # Shannon entropy: -sum(p * log2(p))
    entropy = float(-np.sum(probs * np.log2(probs)))

    if entropy > 4.5:
        return {"scorer": "entropy", "score": 30, "reason": f"very high URL entropy ({entropy:.2f}) — likely random or obfuscated"}
    elif entropy > 3.8:
        return {"scorer": "entropy", "score": 15, "reason": f"elevated URL entropy ({entropy:.2f}) — somewhat suspicious"}

    return {"scorer": "entropy", "score": 0, "reason": f"normal URL entropy ({entropy:.2f})"}