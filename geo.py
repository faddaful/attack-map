"""
geo.py — turn an IP address into latitude/longitude/country/city.

Primary source: a local MaxMind GeoLite2-City.mmdb (free, offline, fast — see
README for the one-time signup + download). Falls back to the free ip-api.com
HTTP endpoint if the database isn't present, so the project runs out of the box.
Results are cached in memory; private/reserved IPs are skipped.
"""

import ipaddress
import os
import threading
import time
import requests

GEOIP_DB = os.environ.get("GEOIP_DB", "GeoLite2-City.mmdb")

_cache: dict[str, dict | None] = {}
_lock = threading.Lock()
_reader = None
_reader_tried = False

# ip-api.com free endpoint allows 45 req/min per IP. We honour its X-Rl / X-Ttl
# headers and pause querying when exhausted, so we never trip the temporary ban.
_ipapi_block_until = 0.0


def _get_reader():
    """Lazily open the GeoLite2 database if it exists."""
    global _reader, _reader_tried
    if _reader_tried:
        return _reader
    _reader_tried = True
    try:
        import geoip2.database
        if os.path.exists(GEOIP_DB):
            _reader = geoip2.database.Reader(GEOIP_DB)
            print(f"[geo] using local database {GEOIP_DB}", flush=True)
        else:
            print("[geo] GeoLite2 db not found, falling back to ip-api.com",
                  flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"[geo] could not open db ({e}); using ip-api.com", flush=True)
    return _reader


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved
                    or addr.is_link_local or addr.is_multicast)
    except ValueError:
        return False


def _lookup_local(ip: str) -> dict | None:
    reader = _get_reader()
    if reader is None:
        return None
    try:
        r = reader.city(ip)
        if r.location.latitude is None:
            return None
        return {
            "lat": r.location.latitude,
            "lon": r.location.longitude,
            "country": r.country.name or "Unknown",
            "country_code": r.country.iso_code or "??",
            "city": r.city.name or "",
        }
    except Exception:  # noqa: BLE001  (AddressNotFound etc.)
        return None


def _lookup_ipapi(ip: str) -> dict | None:
    global _ipapi_block_until
    # If we previously exhausted the quota, stay quiet until the window resets.
    if time.time() < _ipapi_block_until:
        return None
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",          # free tier is HTTP-only
            params={"fields": "status,country,countryCode,city,lat,lon"},
            timeout=4,
        )
        # Honour the documented rate-limit headers to avoid a temporary ban.
        ttl = resp.headers.get("X-Ttl")
        backoff = int(ttl) if (ttl and ttl.isdigit()) else 60
        remaining = resp.headers.get("X-Rl")
        if resp.status_code == 429 or (remaining is not None
                                       and remaining.isdigit()
                                       and int(remaining) == 0):
            _ipapi_block_until = time.time() + backoff
            if resp.status_code == 429:
                return None
        data = resp.json()
        if data.get("status") != "success":
            return None
        return {
            "lat": data["lat"],
            "lon": data["lon"],
            "country": data.get("country", "Unknown"),
            "country_code": data.get("countryCode", "??"),
            "city": data.get("city", ""),
        }
    except (requests.RequestException, ValueError, KeyError):
        return None


def locate(ip: str) -> dict | None:
    """Return {lat, lon, country, country_code, city} or None."""
    if not _is_public(ip):
        return None
    with _lock:
        if ip in _cache:
            return _cache[ip]
    result = _lookup_local(ip) or _lookup_ipapi(ip)
    with _lock:
        _cache[ip] = result
    return result
