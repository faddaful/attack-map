# THREATSCOPE — Live Cyber Attack Map

A real-time global attack map: a honeypot sensor lures unsolicited internet
attacks, Python enriches each hit with geolocation + open-source threat intel,
and a glowing globe streams it live over WebSocket. Built for the YouTube build
video, but it's a genuinely useful home-lab SOC toy.

```
honeypot.py  →  events.jsonl  →  server.py (geo + threat intel + WebSocket)  →  static/index.html (globe.gl)
   sensor          raw log              the Python pipeline                          the dashboard
```

**This is a DEFENSIVE tool.** The honeypot only *records* what hits it — it
never emulates a real shell and never runs anything an attacker sends, so it
can't be turned against others. Don't run it on infrastructure you don't own.

---

## 0. What you need
- A cheap throwaway VPS (DigitalOcean / Hetzner / Vultr, ~$5/mo). **Do not run
  this on africonnect.app or any box you care about** — a honeypot is meant to
  be probed, so it stays isolated.
- Python 3.10+.
- (Free, optional) MaxMind GeoLite2 account for offline geolocation.
- (Free, optional) AbuseIPDB and/or GreyNoise API keys for richer threat scores.

## 1. Harden the VPS FIRST (do this before binding the honeypot)
The honeypot wants port 22, but that's where your real SSH lives. Move your real
SSH to a high port so you don't lock yourself out:

```bash
sudo sed -i 's/^#\?Port .*/Port 49222/' /etc/ssh/sshd_config
sudo systemctl restart ssh
# reconnect on the new port:  ssh -p 49222 user@your-vps
```
From now on you log in on `49222`; the honeypot can safely own `22`.

## 2. Install
```bash
git clone <your-repo> attack-map && cd attack-map
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## 3. Geolocation — ip-api.com (default, zero-setup)
Geolocation turns each attacker IP into a point on the globe. The project ships
with **ip-api.com as the default**, so it works the moment you clone it — no
account, no API key, nothing to download. `geo.py` uses it automatically
whenever a local GeoLite2 database isn't present.

How the ip-api fallback works in this build:
- **Endpoint:** `http://ip-api.com/json/<ip>` requesting only the fields we need
  (`status,country,countryCode,city,lat,lon`). The free tier is **HTTP-only** —
  HTTPS requires their paid plan, which is why the code uses `http://`.
- **Rate limit:** **45 requests/minute per IP.** Go over and you get throttled
  (HTTP 429); keep hammering and your IP can be banned for up to an hour.
- **We respect the limit automatically.** Each response carries `X-Rl`
  (requests remaining) and `X-Ttl` (seconds to reset). `geo.py` reads these and,
  when the quota hits 0 or a 429 comes back, stops querying until the window
  resets — so a busy honeypot can't get your VPS banned mid-recording.
- **Caching does the heavy lifting.** Every IP is looked up once and cached in
  memory, so repeat offenders (most botnet traffic) never re-spend your quota.
  In practice 45/min comfortably covers a normal honeypot once the cache warms.
- **Under-count, not crash.** If you're ever rate-limited, `geo.locate()`
  returns `None`, and `server.enrich()` simply skips that event (it can't be
  placed on the map). The dashboard keeps running; it just momentarily shows
  fewer arcs. Nothing breaks.
- **Licensing:** the free endpoint is for **non-commercial use only**. A
  personal/educational home-lab build is fine; if this ever becomes part of a
  commercial product, switch to GeoLite2 (below) or ip-api Pro.

No configuration is required for ip-api — skip to step 4.

### Optional upgrade — offline GeoLite2 (no limits)
If you expect heavy sustained traffic or want zero network dependency while
filming, drop in MaxMind's free offline database. `geo.py` prefers it
automatically when present:
1. Sign up at maxmind.com → generate a license key → download **GeoLite2-City.mmdb**.
2. Put it in the project folder, or set `GEOIP_DB=/path/to/GeoLite2-City.mmdb`.

On startup you'll see `[geo] using local database ...` (GeoLite2) or
`[geo] ... falling back to ip-api.com` — that line tells you which is live.

## 4. (Optional) Threat-intel keys
Color-coding works without keys (local heuristic + Tor list), but real
reputation data is the magic:
```bash
export ABUSEIPDB_KEY=...   # abuseipdb.com — free 1000 checks/day
export GREYNOISE_KEY=...    # greynoise.io — free community tier
```

## 5. Run it (two terminals)
```bash
# terminal 1 — the sensor (needs privilege for ports <1024)
sudo -E EVENTS_FILE=$PWD/events.jsonl python3 honeypot.py

# terminal 2 — the pipeline + dashboard
export EVENTS_FILE=$PWD/events.jsonl
export SENSOR_LAT=51.5 SENSOR_LON=-0.12   # your VPS location, or omit to auto-detect
uvicorn server:app --host 0.0.0.0 --port 8000
```
Open `http://<your-vps-ip>:8000`. On a public VPS, real scans usually start
lighting up the map within **minutes**. Hit **SIMULATE** (top-right) for
instant B-roll while you wait.

---

## Richer footage: Cowrie instead of honeypot.py
`honeypot.py` is the safe, zero-dependency default. For the cinematic
"watch them try `root / 123456` then run commands" footage, swap in **Cowrie**
(a medium-interaction, *sandboxed* honeypot — emulated shell, attacker never
touches a real OS):

1. Install Cowrie (its docs walk you through it; it runs as a non-root user and
   listens on 2222, with port 22 redirected to it via iptables).
2. Point the pipeline at Cowrie's JSON log:
   ```bash
   export EVENTS_FILE=/home/cowrie/cowrie/var/log/cowrie/cowrie.json
   ```
`server.py` already maps Cowrie's field names (`peerIP` → `src_ip`) onto the
internal format, so the dashboard just works.

> Avoid **high-interaction** honeypots (a real exposed OS). They can be
> compromised and used to attack others — real legal/liability risk, and
> unnecessary for this build.

---

## The shoot script (mapped to your segment plan)

**Cold open / hook —** record the finished globe under heavy SIMULATE load,
arcs raining in. Voiceover: the invisible war, thousands of probes a minute.

**Segment 1 · The visible threat —** show the empty globe + dashboard chrome.
Explain why SOCs need instant visual telemetry; preview the Python + OSINT stack.

**Segment 2 · The data pipeline —** stand up the VPS, harden SSH, launch
`honeypot.py`. `tail -f events.jsonl` on camera as the first real connections
land. Walk through how it pulls source IP, port, and service from each hit.

**Segment 3 · Geolocation & intelligence —** open `geo.py`; turn an IP into
lat/lon. Then `threatintel.py`: cross-reference AbuseIPDB / GreyNoise / Tor to
flag known-malicious bots and scanners. *(Be honest on camera: this identifies
known-bad infrastructure — it is not real-time nation-state attribution.)*
Show the normalized, enriched event object — the unified stream.

**Segment 4 · Mapping the attack surface —** open `server.py`: the WebSocket
push and the `enrich()` step. Then the front-end — arcs, impact rings, and the
color code: **cyan = routine scan, amber = suspicious, red = high-severity**,
driven by the threat score. Note the run-in-executor tailing keeps it lag-free.

**Segment 5 · Actionable insights —** let it run on real traffic, then read the
map: Top Origins, Targeted Ports, severity split. Discuss expanding it into a
home-lab SOC — pipe events to alerting, add more honeypot services, log to a
SIEM. Close on the thesis: visualizing the data turns abstract logs into
defensive strategy.

### Suggested title (strongest of your options)
**"I Built a Live Cyber Attack Map Using Python (And You Can Too)"**

---

## Architecture notes
- `honeypot.py` — async passive listener on common ports; one JSON line per hit.
- `geo.py` — ip-api.com by default (rate-limit aware via X-Rl/X-Ttl), optional
  offline GeoLite2, in-memory cache, private-IP gate.
- `threatintel.py` — AbuseIPDB + GreyNoise + Tor exit list → severity + score.
- `server.py` — tails the log, enriches, broadcasts over `/ws`; backfills new tabs.
- `static/index.html` — globe.gl render layer; reconnecting WebSocket; SIMULATE mode.

## Troubleshooting
- *Map empty?* On a fresh VPS give it a few minutes, or hit SIMULATE. Confirm
  `events.jsonl` is growing (`tail -f`) and that `server.py` points at the same file.
- *Everything cyan?* You haven't set threat-intel keys — only the local
  heuristic is scoring. Add `ABUSEIPDB_KEY` for real reputation data.
- *Permission denied binding ports?* Run the honeypot with `sudo`, or bind only
  high ports (e.g. 2222, 8080) by trimming the `PORTS` dict.
- *Arcs thin out under heavy traffic?* You're hitting ip-api's 45/min limit and
  `geo.py` is backing off (events without a location are skipped). The in-memory
  cache usually prevents this; if it persists, add a GeoLite2 database (step 3)
  for unlimited offline lookups.
- *`firewalld`/cloud firewall?* Open inbound 8000 (dashboard) and the honeypot
  ports in your provider's security group.
