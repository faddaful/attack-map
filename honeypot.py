#!/usr/bin/env python3
"""
honeypot.py — a SAFE low-interaction honeypot sensor.

It listens on a set of commonly-probed ports, records who connected, what
banner/credentials they sent, then closes. It NEVER emulates a real shell and
NEVER executes anything an attacker sends — so it cannot be weaponised against
others. Every connection is written as one JSON line to EVENTS_FILE, which the
dashboard server tails.

For richer "login + command" footage, run Cowrie instead (see README) and point
the server at Cowrie's cowrie.json — the event format below is compatible.

Run (binding to low ports <1024 needs privilege — see README):
    sudo EVENTS_FILE=events.jsonl python3 honeypot.py
"""

import asyncio
import json
import os
from datetime import datetime, timezone

EVENTS_FILE = os.environ.get("EVENTS_FILE", "events.jsonl")

# port -> (service label, banner sent on connect to make bots talk)
PORTS = {
    22:   ("ssh",    b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"),
    23:   ("telnet", b"\xff\xfd\x18\xff\xfd\x20login: "),
    80:   ("http",   b""),
    443:  ("https",  b""),
    2222: ("ssh-alt", b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"),
    3389: ("rdp",    b""),
    5900: ("vnc",    b"RFB 003.008\n"),
    8080: ("http-alt", b""),
}

READ_TIMEOUT = 3.0      # seconds to wait for the client to send something
MAX_PAYLOAD = 2048      # cap bytes we record


def write_event(event: dict) -> None:
    """Append one event as a JSON line. Atomic enough for a single writer."""
    with open(EVENTS_FILE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 port: int, service: str, banner: bytes) -> None:
    peer = writer.get_extra_info("peername")
    src_ip = peer[0] if peer else "0.0.0.0"
    src_port = peer[1] if peer and len(peer) > 1 else 0

    payload = b""
    try:
        if banner:
            writer.write(banner)
            await writer.drain()
        # Read whatever the bot throws at us, then hang up.
        payload = await asyncio.wait_for(reader.read(MAX_PAYLOAD), READ_TIMEOUT)
    except (asyncio.TimeoutError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass

    text = payload.decode("utf-8", errors="replace").strip()
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": port,
        "service": service,
        "event": "connection",
        "payload": text[:512],   # truncated for safety/readability
    }
    write_event(event)
    print(f"[+] {src_ip}:{src_port} -> :{port} ({service}) "
          f"{len(payload)}B", flush=True)


async def main() -> None:
    servers = []
    for port, (service, banner) in PORTS.items():
        try:
            srv = await asyncio.start_server(
                lambda r, w, p=port, s=service, b=banner: handle(r, w, p, s, b),
                host="0.0.0.0", port=port,
            )
            servers.append(srv)
            print(f"[*] listening on 0.0.0.0:{port} ({service})", flush=True)
        except PermissionError:
            print(f"[!] no permission to bind :{port} (run as root or use "
                  f"setcap / a high port). skipping.", flush=True)
        except OSError as e:
            print(f"[!] could not bind :{port} ({e}). skipping.", flush=True)

    if not servers:
        print("[!] no ports bound — nothing to do. exiting.", flush=True)
        return

    print(f"[*] writing events to {EVENTS_FILE}", flush=True)
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] shutting down sensor.", flush=True)
