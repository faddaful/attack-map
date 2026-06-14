#!/usr/bin/env python3
"""
server.py — the live pipeline + dashboard host.

Tails the honeypot's EVENTS_FILE, enriches each new event with geolocation and
threat-intel severity, and pushes it to every connected browser over a
WebSocket. Serves the dashboard at  http://<host>:8000/

Env:
  EVENTS_FILE   path to JSONL written by sensor.py or Cowrie (default events.jsonl)
  GEOIP_DB      path to GeoLite2-City.mmdb (optional; see geo.py)
  ABUSEIPDB_KEY / GREYNOISE_KEY  optional threat-intel keys (see threatintel.py)
  SENSOR_LAT / SENSOR_LON        the map's "home" point (your honeypot).
                                 If unset, we geolocate the server's public IP.

Run:
    EVENTS_FILE=events.jsonl uvicorn server:app --host 0.0.0.0 --port 8000
"""

import asyncio
import json
import os
from collections import deque

import requests
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

import geo
import threatintel

EVENTS_FILE = os.environ.get("EVENTS_FILE", "events.jsonl")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

app = FastAPI(title="Live Cyber Attack Map")

clients: set[WebSocket] = set()
recent: deque[dict] = deque(maxlen=200)   # backfill buffer for new clients
sensor_point = {"lat": 0.0, "lon": 0.0, "label": "SENSOR"}


def resolve_sensor_point() -> dict:
    """Where on the globe the attacks are aimed (your honeypot VPS)."""
    lat = os.environ.get("SENSOR_LAT")
    lon = os.environ.get("SENSOR_LON")
    if lat and lon:
        return {"lat": float(lat), "lon": float(lon), "label": "SENSOR"}
    try:
        ip = requests.get("https://api.ipify.org", timeout=4).text.strip()
        loc = geo.locate(ip)
        if loc:
            return {"lat": loc["lat"], "lon": loc["lon"], "label": "SENSOR"}
    except (requests.RequestException, KeyError):
        pass
    return {"lat": 0.0, "lon": 0.0, "label": "SENSOR"}


def enrich(raw: dict) -> dict | None:
    """Add geo + threat data. Drop events we can't place on the map."""
    src_ip = raw.get("src_ip", "")
    loc = geo.locate(src_ip)
    if not loc:
        return None
    ti = threatintel.assess(
        src_ip,
        dst_port=raw.get("dst_port", 0),
        has_payload=bool(raw.get("payload")),
    )
    return {
        "ts": raw.get("ts"),
        "src_ip": src_ip,
        "dst_port": raw.get("dst_port"),
        "service": raw.get("service", "unknown"),
        "lat": loc["lat"],
        "lon": loc["lon"],
        "country": loc["country"],
        "country_code": loc["country_code"],
        "city": loc["city"],
        "severity": ti["severity"],
        "score": ti["score"],
        "tags": ti["tags"],
        "dst_lat": sensor_point["lat"],
        "dst_lon": sensor_point["lon"],
    }


async def broadcast(event: dict) -> None:
    recent.append(event)
    dead = []
    for ws in clients:
        try:
            await ws.send_json(event)
        except (WebSocketDisconnect, RuntimeError):
            dead.append(ws)
    for ws in dead:
        clients.discard(ws)


async def tail_events() -> None:
    """Follow EVENTS_FILE like `tail -f`, enriching + broadcasting new lines."""
    # Wait for the file to exist, then seek to the end so we only stream new hits.
    while not os.path.exists(EVENTS_FILE):
        await asyncio.sleep(1)
    loop = asyncio.get_event_loop()

    def open_at_end():
        f = open(EVENTS_FILE, "r", encoding="utf-8")
        f.seek(0, os.SEEK_END)
        return f

    fh = await loop.run_in_executor(None, open_at_end)
    print(f"[srv] tailing {EVENTS_FILE}", flush=True)
    while True:
        line = await loop.run_in_executor(None, fh.readline)
        if not line:
            await asyncio.sleep(0.4)
            continue
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Cowrie compatibility: map its field names onto ours.
        if "src_ip" not in raw and "peerIP" in raw:
            raw["src_ip"] = raw["peerIP"]
        if "dst_port" not in raw and "dst_port" in raw.get("data", {}):
            raw["dst_port"] = raw["data"]["dst_port"]
        event = await loop.run_in_executor(None, enrich, raw)
        if event:
            await broadcast(event)


@app.on_event("startup")
async def startup() -> None:
    global sensor_point
    sensor_point = await asyncio.get_event_loop().run_in_executor(
        None, resolve_sensor_point)
    print(f"[srv] sensor point: {sensor_point}", flush=True)
    asyncio.create_task(tail_events())


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/config")
async def config() -> dict:
    return {"sensor": sensor_point}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    clients.add(ws)
    # Backfill so a freshly-opened tab isn't empty.
    await ws.send_json({"type": "init", "sensor": sensor_point,
                        "recent": list(recent)})
    try:
        while True:
            await ws.receive_text()   # we don't expect messages; keeps it open
    except WebSocketDisconnect:
        clients.discard(ws)


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
