#!/usr/bin/env python3
"""
proxy-forge — deep subnet scanner
After forge.py runs, scan subnets of active proxies for hidden gems.
"""
from __future__ import annotations

import json
import os
import queue
import random
import re
import sys
import threading
import time
from datetime import datetime, timezone

import requests

from settings import (
    CHECK_URL, COUNTRY_DIR, GEO_URL, HUNTER_PORTS, HUNTER_WORKERS,
    MAX_LATENCY_MS, OUTPUT_DIR, PROTO_DIR, SOCKET_TIMEOUT, USER_AGENTS,
)


# ── state ─────────────────────────────────────────────────────────────────────
lock = threading.Lock()
found: list[dict] = []
q: queue.Queue[str] = queue.Queue()
scanned_subnets: set[str] = set()
checked = 0
my_ip: str | None = None


def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{ts}] {msg}", flush=True)


def classify_anonymity(data: dict) -> str:
    origin = data.get("origin", "")
    if my_ip and my_ip in origin:
        return "transparent"
    return "elite" if not data.get("headers", {}).get("Via") else "anonymous"


def geo_lookup(session: requests.Session, ip: str) -> tuple[str, str]:
    try:
        r = session.get(GEO_URL.format(ip=ip), timeout=5)
        d = r.json()
        if d.get("status") == "success":
            return d.get("countryCode", "??"), d.get("isp", "")
        return "??", ""
    except Exception:
        return "??", ""


def worker() -> None:
    global checked
    session = requests.Session()
    headers = {"User-Agent": random.choice(USER_AGENTS)}

    while not q.empty():
        proxy = q.get()
        try:
            _try_proxy(proxy, session, headers)
        except Exception:
            pass
        finally:
            with lock:
                checked += 1
                if checked % 500 == 0:
                    log(f"  … {checked} scanned, queue={q.qsize()}, found={len(found)}")
            q.task_done()


def _try_proxy(proxy: str, session: requests.Session, headers: dict) -> None:
    global my_ip
    for proto in ("http", "socks5"):
        proxy_url = f"{proto}://{proxy}"
        proxies = {"http": proxy_url, "https": proxy_url}
        try:
            t0 = time.monotonic()
            r = session.get(
                CHECK_URL, proxies=proxies,
                timeout=SOCKET_TIMEOUT, headers=headers,
            )
            latency_ms = int((time.monotonic() - t0) * 1000)

            if r.status_code != 200 or latency_ms > MAX_LATENCY_MS:
                continue

            data = r.json()
            ip = proxy.split(":")[0]
            cc, isp = geo_lookup(session, ip)
            anon = classify_anonymity(data)

            entry = {
                "proxy": proxy,
                "proto": proto,
                "country": cc,
                "anonymity": anon,
                "latency_ms": latency_ms,
                "speed_kbs": None,
                "isp": isp.strip()[:40],
                "score": round(latency_ms / 100.0 - (5 if anon == "elite" else 0), 2),
                "source": "hunter",
            }

            with lock:
                found.append(entry)
                log(f"  ✓ HUNTED {proto.upper()} {proxy:25s} {cc} {anon} {latency_ms}ms @ {isp[:20]}")

            # deep scan: expand subnet if we found something non-transparent
            if anon != "transparent":
                subnet = ".".join(ip.split(".")[:3])
                if subnet not in scanned_subnets:
                    with lock:
                        if subnet in scanned_subnets:
                            return
                        scanned_subnets.add(subnet)
                    log(f"  → Deep scanning subnet {subnet}.x (found {anon} @ {isp[:20]})")
                    for d in range(1, 255):
                        for port in HUNTER_PORTS:
                            q.put(f"{subnet}.{d}:{port}")

            break
        except Exception:
            continue


def main() -> None:
    global my_ip

    log("═══ proxy-forge hunter start ═══")

    # load existing results
    all_file = os.path.join(OUTPUT_DIR, "all.txt")
    if not os.path.exists(all_file):
        log(f"ERROR: {all_file} not found. Run forge.py first.")
        sys.exit(1)

    # get our IP
    try:
        my_ip = requests.get("https://api.ipify.org", timeout=10).text.strip()
    except Exception:
        pass

    # extract subnets from existing proxies
    active_subnets: set[str] = set()
    with open(all_file) as f:
        for line in f:
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line.strip())
            if m:
                parts = m.group(1).split(".")
                active_subnets.add(f"{parts[0]}.{parts[1]}.{parts[2]}")

    log(f"Found {len(active_subnets)} active subnets to scan")

    # queue all IP:port combos
    for subnet in active_subnets:
        for d in range(1, 255):
            for port in HUNTER_PORTS:
                q.put(f"{subnet}.{d}:{port}")

    total = q.qsize()
    log(f"Total targets: {total} (IP × port), {HUNTER_WORKERS} workers")

    # launch workers
    workers = []
    for _ in range(HUNTER_WORKERS):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        workers.append(t)

    q.join()

    # merge with existing results
    existing: list[dict] = []
    details_file = os.path.join(OUTPUT_DIR, "details.json")
    if os.path.exists(details_file):
        try:
            with open(details_file) as f:
                existing = json.load(f).get("proxies", [])
        except Exception:
            pass

    # merge: new hunters + existing (dedupe by proxy:proto)
    seen: set[str] = set()
    merged: list[dict] = []
    for entry in found:
        key = f"{entry['proto']}://{entry['proxy']}"
        if key not in seen:
            seen.add(key)
            merged.append(entry)
    for entry in existing:
        key = f"{entry.get('proto', 'http')}://{entry['proxy']}"
        if key not in seen:
            seen.add(key)
            merged.append(entry)

    # re-sort by score
    merged.sort(key=lambda h: h.get("score", 999))

    # update all.txt
    with open(all_file, "w") as f:
        for h in merged:
            f.write(f"{h['proxy']}\n")

    # update details.json
    if os.path.exists(details_file):
        with open(details_file) as f:
            details = json.load(f)
        details["proxies"] = merged
        details["alive"] = len(merged)
        details["hunter_found"] = len(found)
        with open(details_file, "w") as f:
            json.dump(details, f, indent=2)

    log(f"═══ hunter done: {len(found)} new, {len(merged)} total ═══")


if __name__ == "__main__":
    main()
