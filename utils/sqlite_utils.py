#import libs
import sqlite3
import hashlib
import csv
import os
from dotenv import load_dotenv

load_dotenv()

DB_PATH  = os.getenv("DB_PATH", "linkguard.db")
CSV_PATH = os.getenv("REPUTATION_CSV", "domain_reputation.csv")

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()

    # Stores every scan result
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url_hash    TEXT NOT NULL,
            url         TEXT NOT NULL,
            risk_level  TEXT NOT NULL,
            total_score INTEGER NOT NULL,
            scanned_at  TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # Stores per-scorer breakdown for each scan
    c.execute("""
        CREATE TABLE IF NOT EXISTS score_breakdown (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER NOT NULL REFERENCES scans(id),
            scorer_name TEXT NOT NULL,
            score       INTEGER NOT NULL,
            reason      TEXT NOT NULL
        )
    """)

    # Domain reputation list loaded from CSV
    c.execute("""
        CREATE TABLE IF NOT EXISTS domain_reputation (
            domain      TEXT PRIMARY KEY,
            reputation  TEXT NOT NULL CHECK(reputation IN ('good', 'medium', 'bad'))
        )
    """)

    # Tracks how many times each domain has been scanned and its highest risk seen
    c.execute("""
        CREATE TABLE IF NOT EXISTS domain_hits (
            domain          TEXT PRIMARY KEY,
            hit_count       INTEGER DEFAULT 1,
            highest_risk    TEXT NOT NULL,
            last_seen       TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)

    conn.commit()
    conn.close()

    _load_reputation_csv()

def _load_reputation_csv():
    """Load domain_reputation.csv into DB on startup. Skips existing rows."""
    if not os.path.exists(CSV_PATH):
        print(f"[LinkGuard] Warning: reputation CSV not found at {CSV_PATH}")
        return

    conn = get_conn()
    c = conn.cursor()

    with open(CSV_PATH, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            c.execute("""
                INSERT OR IGNORE INTO domain_reputation (domain, reputation)
                VALUES (?, ?)
            """, (row["domain"].strip().lower(), row["reputation"].strip().lower()))

    conn.commit()
    conn.close()

def get_domain_reputation(domain: str) -> str:
    """Returns 'good', 'medium', 'bad', or 'unknown'."""
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT reputation FROM domain_reputation WHERE domain = ?", (domain.lower(),))
    row = c.fetchone()
    conn.close()
    return row["reputation"] if row else "unknown"

def _update_domain_hits(domain: str, risk_level: str):
    """Increment hit count for domain, track highest risk seen."""
    priority = {"SAFE": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
    conn = get_conn()
    c = conn.cursor()

    c.execute("SELECT hit_count, highest_risk FROM domain_hits WHERE domain = ?", (domain,))
    row = c.fetchone()

    if row:
        new_highest = risk_level if priority.get(risk_level, 0) > priority.get(row["highest_risk"], 0) else row["highest_risk"]
        c.execute("""
            UPDATE domain_hits
            SET hit_count    = hit_count + 1,
                highest_risk = ?,
                last_seen    = datetime('now')
            WHERE domain = ?
        """, (new_highest, domain))
    else:
        c.execute("""
            INSERT INTO domain_hits (domain, highest_risk)
            VALUES (?, ?)
        """, (domain, risk_level))

    conn.commit()
    conn.close()

def _extract_domain(url: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.netloc.lower().replace("www.", "")
    return host.split(":")[0]

def save_scan(result: dict):
    conn = get_conn()
    c = conn.cursor()

    url_hash = hashlib.sha256(result["url"].encode()).hexdigest()

    c.execute("""
        INSERT INTO scans (url_hash, url, risk_level, total_score)
        VALUES (?, ?, ?, ?)
    """, (url_hash, result["url"], result["risk_level"], result["total_score"]))

    scan_id = c.lastrowid

    for item in result.get("breakdown", []):
        c.execute("""
            INSERT INTO score_breakdown (scan_id, scorer_name, score, reason)
            VALUES (?, ?, ?, ?)
        """, (scan_id, item["scorer"], item["score"], item["reason"]))

    conn.commit()
    conn.close()

    domain = _extract_domain(result["url"])
    if domain:
        _update_domain_hits(domain, result["risk_level"])

def get_scan_history(url: str) -> list:
    url_hash = hashlib.sha256(url.encode()).hexdigest()
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        SELECT id, url, risk_level, total_score, scanned_at
        FROM scans
        WHERE url_hash = ?
        ORDER BY scanned_at DESC
        LIMIT 50
    """, (url_hash,))

    scans = []
    for row in c.fetchall():
        scan = dict(row)
        c.execute("""
            SELECT scorer_name, score, reason
            FROM score_breakdown
            WHERE scan_id = ?
        """, (row["id"],))
        scan["breakdown"] = [dict(r) for r in c.fetchall()]
        scans.append(scan)

    conn.close()
    return scans

def get_stats() -> dict:
    conn = get_conn()
    c = conn.cursor()

    c.execute("SELECT COUNT(*) as total FROM scans")
    total_scans = c.fetchone()["total"]

    c.execute("""
        SELECT risk_level, COUNT(*) as count
        FROM scans
        GROUP BY risk_level
    """)
    risk_counts = {row["risk_level"]: row["count"] for row in c.fetchall()}

    # Top 10 domains by scan frequency with hit data from domain_hits table
    c.execute("""
        SELECT domain, hit_count, highest_risk, last_seen
        FROM domain_hits
        ORDER BY hit_count DESC
        LIMIT 10
    """)
    top_domains = [dict(row) for row in c.fetchall()]

    conn.close()

    return {
        "total_scans": total_scans,
        "risk_counts": risk_counts,
        "top_domains": top_domains,
    }

def ping() -> bool:
    try:
        conn = get_conn()
        conn.execute("SELECT 1")
        conn.close()
        return True
    except Exception:
        return False