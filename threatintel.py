"""
threatintel.py — enrich an IP with open-source reputation data and assign a
severity used for the dashboard's colour coding.

Sources (all have free tiers; each is optional and degrades gracefully):
  * AbuseIPDB   — abuse confidence score 0-100   (env: ABUSEIPDB_KEY)
  * GreyNoise   — community classification         (env: GREYNOISE_KEY)
  * Tor exit list — downloaded once, cached         (no key)

If no keys are set, severity is inferred from a light local heuristic so the
build still runs and still colour-codes sensibly. NOTHING here claims
nation-state attribution — it flags KNOWN-malicious infrastructure and scanners.

Severity returned:
  "scan"       -> routine background scanning            (low / cyan)
  "suspicious" -> flagged by reputation, moderate score  (med / amber)
  "malicious"  -> high-confidence known-bad / exploit    (high / red)
"""

import os
import threading
import time
import requests

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")
GREYNOISE_KEY = os.environ.get("GREYNOISE_KEY", "")

# Ports that, when hit with a payload, suggest active exploitation attempts
HIGH_RISK_PORTS = {23, 3389, 445, 1433, 5900, 6379, 9200}

_cache: dict[str, dict] = {}
_lock = threading.Lock()
_tor_exits: set[str] = set()
_tor_loaded_at = 0.0
_TOR_TTL = 3600  # refresh hourly


def _load_tor_exits() -> set[str]:
    global _tor_exits, _tor_loaded_at
    if _tor_exits and (time.time() - _tor_loaded_at) < _TOR_TTL:
        return _tor_exits
    try:
        resp = requests.get(
            "https://check.torproject.org/torbulkexitlist", timeout=6)
        if resp.ok:
            _tor_exits = {line.strip() for line in resp.text.splitlines()
                          if line.strip() and not line.startswith("#")}
            _tor_loaded_at = time.time()
            print(f"[ti] loaded {len(_tor_exits)} Tor exit nodes", flush=True)
    except requests.RequestException:
        pass
    return _tor_exits


def _abuseipdb(ip: str) -> int | None:
    if not ABUSEIPDB_KEY:
        return None
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        if resp.ok:
            return resp.json()["data"]["abuseConfidenceScore"]
    except (requests.RequestException, KeyError, ValueError):
        pass
    return None


def _greynoise(ip: str) -> str | None:
    if not GREYNOISE_KEY:
        return None
    try:
        resp = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": GREYNOISE_KEY},
            timeout=5,
        )
        if resp.ok:
            return resp.json().get("classification")  # benign|malicious|unknown
    except (requests.RequestException, ValueError):
        pass
    return None


def assess(ip: str, dst_port: int = 0, has_payload: bool = False) -> dict:
    """
    Return {"severity", "score", "tags"} for an IP.
    Cached per-IP (reputation doesn't change minute to minute).
    """
    with _lock:
        if ip in _cache:
            return _cache[ip]

    tags: list[str] = []
    score = 0

    confidence = _abuseipdb(ip)
    if confidence is not None:
        score = max(score, confidence)
        if confidence >= 25:
            tags.append(f"abuseipdb:{confidence}")

    classification = _greynoise(ip)
    if classification == "malicious":
        score = max(score, 85)
        tags.append("greynoise:malicious")
    elif classification == "benign":
        tags.append("greynoise:benign")

    if ip in _load_tor_exits():
        tags.append("tor-exit")
        score = max(score, 50)

    # Local heuristic when no external signal raised the score
    if dst_port in HIGH_RISK_PORTS:
        score = max(score, 60 if has_payload else 40)
        tags.append("high-risk-port")

    if score >= 70:
        severity = "malicious"
    elif score >= 35:
        severity = "suspicious"
    else:
        severity = "scan"

    result = {"severity": severity, "score": score, "tags": tags}
    with _lock:
        _cache[ip] = result
    return result
