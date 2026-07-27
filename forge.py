#!/usr/bin/env python3
"""
proxy-forge — collect, validate, score & export free proxies
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import re
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

import requests

from settings import (
    BLACKLIST_FILE, BLACKLIST_MAX_AGE_DAYS, CHECK_URL, CI_MAX_PROXIES,
    CI_SKIP_QUALITY, COUNTRY_DIR, GEO_URL, HISTORY_FILE, IS_CI,
    MAX_LATENCY_MS, OUTPUT_DIR, PROTO_DIR, QUALITY_URL, SOCKET_TIMEOUT,
    SOURCES, SPEED_TEST_ENABLED, SPEED_TEST_TIMEOUT, SPEED_TEST_URL,
    USER_AGENTS, WORKERS,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def log(msg: str) -> None:
    print(f"[{ts()}] {msg}", flush=True)

def ua() -> str:
    return random.choice(USER_AGENTS)


# ── blacklist ─────────────────────────────────────────────────────────────────

def load_blacklist() -> set[str]:
    """Load dead proxies from previous runs."""
    if not os.path.exists(BLACKLIST_FILE):
        return set()
    cutoff = time.time() - BLACKLIST_MAX_AGE_DAYS * 86400
    bl: set[str] = set()
    with open(BLACKLIST_FILE) as f:
        for line in f:
            parts = line.strip().split("|", 1)
            if len(parts) == 2:
                proxy, ts_str = parts
                try:
                    if float(ts_str) > cutoff:
                        bl.add(proxy)
                except ValueError:
                    bl.add(proxy)  # old format, keep it
            elif parts[0]:
                bl.add(parts[0])
    return bl

def save_blacklist(dead: set[str], existing: set[str]) -> None:
    """Save dead proxies with timestamps."""
    now = time.time()
    merged = {p: now for p in dead}
    # keep old entries if not in dead set
    if os.path.exists(BLACKLIST_FILE):
        cutoff = now - BLACKLIST_MAX_AGE_DAYS * 86400
        with open(BLACKLIST_FILE) as f:
            for line in f:
                parts = line.strip().split("|", 1)
                if len(parts) == 2 and parts[0] not in dead:
                    try:
                        if float(parts[1]) > cutoff:
                            merged[parts[0]] = float(parts[1])
                    except ValueError:
                        pass
    os.makedirs(os.path.dirname(BLACKLIST_FILE) or ".", exist_ok=True)
    with open(BLACKLIST_FILE, "w") as f:
        for proxy, t in sorted(merged.items()):
            f.write(f"{proxy}|{t}\n")
    log(f"Blacklist: {len(merged)} entries ({len(dead)} new dead)")


# ── history ───────────────────────────────────────────────────────────────────

def load_history() -> dict[str, dict]:
    """Load previous run's alive proxies for historical scoring."""
    if not os.path.exists(HISTORY_FILE):
        return {}
    try:
        with open(HISTORY_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_history(hits: list[dict]) -> None:
    """Save current run results for next run's scoring."""
    hist: dict[str, dict] = {}
    for h in hits:
        key = f"{h['proto']}://{h['proxy']}"
        hist[key] = {
            "latency_ms": h["latency_ms"],
            "country": h["country"],
            "anonymity": h["anonymity"],
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "times_alive": 1,
        }
    # merge with old history
    old = load_history()
    for k, v in old.items():
        if k in hist:
            hist[k]["times_alive"] = v.get("times_alive", 0) + 1
        else:
            # keep old entries for 7 days
            try:
                last = datetime.fromisoformat(v["last_seen"].replace("Z", "+00:00"))
                if (datetime.now(timezone.utc) - last).days < 7:
                    hist[k] = v
            except Exception:
                pass
    with open(HISTORY_FILE, "w") as f:
        json.dump(hist, f, indent=2)
    log(f"History: {len(hist)} entries saved")


# ── phase 1: collect ─────────────────────────────────────────────────────────

def expand_sources() -> list[str]:
    """Flatten paginated + static source list. Skip paginated on CI."""
    urls: list[str] = []
    for entry in SOURCES:
        if isinstance(entry, tuple):
            if IS_CI:
                continue
            base, max_page = entry
            urls.extend(base.format(p) for p in range(1, max_page + 1))
        else:
            urls.append(entry)
    return urls


def fetch_source(url: str, session: requests.Session) -> set[str]:
    """Fetch one source URL, extract IP:PORT pairs."""
    try:
        r = session.get(url, timeout=20, headers={"User-Agent": ua()})
        if r.status_code != 200:
            return set()
        return set(re.findall(r"\d+\.\d+\.\d+\.\d+:\d+", r.text))
    except Exception:
        return set()


def collect_sources(blacklist: set[str]) -> list[str]:
    """Scrape all sources, dedupe, remove blacklisted."""
    urls = expand_sources()
    found: set[str] = set()
    session = requests.Session()

    log(f"Collecting from {len(urls)} source URLs …")
    for i, url in enumerate(urls, 1):
        batch = fetch_source(url, session)
        if batch:
            before = len(found)
            found.update(batch)
            added = len(found) - before
            if added:
                log(f"  [{i}/{len(urls)}] +{added} from {url[:60]}…")
        time.sleep(random.uniform(0.3, 0.8))

    # remove blacklisted
    before_bl = len(found)
    found -= blacklist
    removed = before_bl - len(found)
    if removed:
        log(f"  Removed {removed} blacklisted proxies")

    if IS_CI and len(found) > CI_MAX_PROXIES:
        found_list = list(found)
        random.shuffle(found_list)
        found_list = found_list[:CI_MAX_PROXIES]
        log(f"  CI mode: capped to {CI_MAX_PROXIES} proxies")
        return sorted(found_list)

    log(f"Collected {len(found)} unique proxy:port pairs")
    return sorted(found)


# ── phase 2: validate ────────────────────────────────────────────────────────

def classify_anonymity(data: dict, my_ip: str | None) -> str:
    origin = data.get("origin", "")
    if my_ip and my_ip in origin:
        return "transparent"
    if data.get("headers", {}).get("Via"):
        return "anonymous"
    return "elite"


def geo_lookup(session: requests.Session, ip: str) -> tuple[str, str]:
    try:
        r = session.get(GEO_URL.format(ip=ip), timeout=5)
        d = r.json()
        if d.get("status") == "success":
            return d.get("countryCode", "??"), d.get("isp", "")
        return "??", ""
    except Exception:
        return "??", ""


def measure_speed(session: requests.Session, proxy_url: str) -> int | None:
    """Download test file through proxy, return KB/s (0 if too slow)."""
    try:
        t0 = time.monotonic()
        r = session.get(
            SPEED_TEST_URL,
            proxies={"http": proxy_url, "https": proxy_url},
            timeout=SPEED_TEST_TIMEOUT,
            headers={"User-Agent": ua()},
        )
        elapsed = time.monotonic() - t0
        if r.status_code == 200 and elapsed > 0:
            kb = len(r.content) / 1024
            return int(kb / elapsed)
    except Exception:
        pass
    return None


def check_one(proxy: str, my_ip: str | None) -> dict[str, Any] | None:
    """Validate a single proxy. Returns result dict or None."""
    headers = {"User-Agent": ua()}

    for proto in ("http", "socks4", "socks5"):
        proxy_url = f"{proto}://{proxy}"
        proxies = {"http": proxy_url, "https": proxy_url}

        try:
            # Pass 1: httpbin — connectivity + anonymity
            t0 = time.monotonic()
            r = requests.get(
                CHECK_URL, proxies=proxies,
                timeout=SOCKET_TIMEOUT, headers=headers,
            )
            latency_ms = int((time.monotonic() - t0) * 1000)

            if r.status_code != 200 or latency_ms > MAX_LATENCY_MS:
                continue

            data = r.json()

            # Pass 2: Google quality (skip on CI)
            if not (IS_CI and CI_SKIP_QUALITY):
                g = requests.get(
                    QUALITY_URL, proxies=proxies,
                    timeout=SOCKET_TIMEOUT + 2, headers=headers,
                )
                if g.status_code != 200:
                    continue

            # Geo
            ip = proxy.split(":")[0]
            sess = requests.Session()
            cc, isp = geo_lookup(sess, ip)
            anon = classify_anonymity(data, my_ip)

            # Speed test
            speed_kbs: int | None = None
            if SPEED_TEST_ENABLED and not IS_CI:
                speed_kbs = measure_speed(sess, proxy_url)

            # Quality score: lower = better
            # latency (0-3000ms → 0-30pts) + speed bonus (fast → -10pts) + anonymity bonus
            score = latency_ms / 100.0
            if speed_kbs and speed_kbs > 100:
                score -= 10
            elif speed_kbs and speed_kbs > 50:
                score -= 5
            if anon == "elite":
                score -= 5
            elif anon == "anonymous":
                score -= 2

            return {
                "proxy": proxy,
                "proto": proto,
                "country": cc,
                "anonymity": anon,
                "latency_ms": latency_ms,
                "speed_kbs": speed_kbs,
                "isp": isp.strip()[:40],
                "score": round(score, 2),
            }
        except Exception:
            continue

    return None


# ── phase 3: export ───────────────────────────────────────────────────────────

def export(hits: list[dict], total_checked: int, history: dict) -> None:
    """Write results in multiple formats."""
    os.makedirs(PROTO_DIR, exist_ok=True)
    os.makedirs(COUNTRY_DIR, exist_ok=True)

    # Boost score for proxies that survived previous runs
    for h in hits:
        key = f"{h['proto']}://{h['proxy']}"
        if key in history:
            h["score"] -= history[key].get("times_alive", 0) * 2

    # Sort by quality score (lower = better)
    hits.sort(key=lambda h: h["score"])

    # 1) master list — proxy:port only, scored order
    with open(f"{OUTPUT_DIR}/all.txt", "w") as f:
        for h in hits:
            f.write(f"{h['proxy']}\n")

    # 2) by protocol
    by_proto: dict[str, list[str]] = defaultdict(list)
    for h in hits:
        by_proto[h["proto"]].append(h["proxy"])

    for proto, proxies in by_proto.items():
        with open(f"{PROTO_DIR}/{proto}.txt", "w") as f:
            f.write("\n".join(proxies) + "\n")

    # 3) by country
    by_cc: dict[str, list[str]] = defaultdict(list)
    for h in hits:
        by_cc[h["country"]].append(f"{h['proto']}://{h['proxy']}")

    for cc, proxies in sorted(by_cc.items(), key=lambda x: -len(x[1])):
        with open(f"{COUNTRY_DIR}/{cc}.txt", "w") as f:
            f.write("\n".join(proxies) + "\n")

    # 4) JSON metadata
    with open(f"{OUTPUT_DIR}/details.json", "w") as f:
        json.dump({
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "checked": total_checked,
            "alive": len(hits),
            "protocols": {p: len(v) for p, v in by_proto.items()},
            "countries": len(by_cc),
            "avg_latency_ms": sum(h["latency_ms"] for h in hits) // len(hits) if hits else 0,
            "avg_speed_kbs": sum(h["speed_kbs"] for h in hits if h["speed_kbs"]) // max(1, sum(1 for h in hits if h["speed_kbs"])),
            "proxies": hits,
        }, f, indent=2)

    # 5) CSV
    with open(f"{OUTPUT_DIR}/proxies.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["proxy", "proto", "country", "anonymity", "latency_ms", "speed_kbs", "isp", "score"])
        writer.writeheader()
        writer.writerows(hits)

    # 6) rotation list (just ip:port, one per line, scored order)
    with open(f"{OUTPUT_DIR}/rotation.txt", "w") as f:
        for h in hits:
            f.write(f"{h['proxy']}\n")

    # 7) proxychains format
    with open(f"{OUTPUT_DIR}/proxychains.txt", "w") as f:
        f.write("# proxy-forge auto-generated\n[ProxyList]\n")
        for h in hits:
            f.write(f"{h['proto']} {h['proxy'].split(':')[0]} {h['proxy'].split(':')[1]}\n")

    # 8) stats
    top_cc = sorted(by_cc.items(), key=lambda x: -len(x[1]))[:10]
    avg_lat = sum(h["latency_ms"] for h in hits) // len(hits) if hits else 0
    avg_spd = sum(h["speed_kbs"] for h in hits if h["speed_kbs"]) // max(1, sum(1 for h in hits if h["speed_kbs"]))
    with open(f"{OUTPUT_DIR}/stats.txt", "w") as f:
        f.write(f"Updated     : {ts()}\n")
        f.write(f"Checked     : {total_checked}\n")
        f.write(f"Alive       : {len(hits)}\n")
        f.write(f"Protocols   : {', '.join(f'{p}={c}' for p, c in sorted(by_proto.items()))}\n")
        f.write(f"Countries   : {len(by_cc)}\n")
        f.write(f"Top countries: {', '.join(f'{cc}({n})' for cc, n in top_cc)}\n")
        f.write(f"Avg latency : {avg_lat}ms\n")
        f.write(f"Avg speed   : {avg_spd} KB/s\n")
        elite = sum(1 for h in hits if h["anonymity"] == "elite")
        anon = sum(1 for h in hits if h["anonymity"] == "anonymous")
        trans = sum(1 for h in hits if h["anonymity"] == "transparent")
        f.write(f"Anonymity   : elite={elite} anonymous={anon} transparent={trans}\n")

    log(f"Exported {len(hits)} proxies:")
    log(f"  → all.txt, rotation.txt, proxychains.txt, proxies.csv, details.json, stats.txt")
    log(f"  → {len(by_proto)} protocols, {len(by_cc)} countries")


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    log("═══ proxy-forge start ═══")

    # detect our IP
    my_ip = None
    try:
        my_ip = requests.get("https://api.ipify.org", timeout=10).text.strip()
        log(f"Our IP: {my_ip}")
    except Exception:
        log("Warning: could not detect own IP")

    # load blacklist + history
    blacklist = load_blacklist()
    history = load_history()
    log(f"Blacklist: {len(blacklist)} entries, History: {len(history)} entries")

    # phase 1: collect
    raw = collect_sources(blacklist)
    if not raw:
        log("No proxies found. Exiting.")
        sys.exit(1)

    # phase 2: validate
    log(f"Validating {len(raw)} proxies with {WORKERS} workers …")
    hits: list[dict] = []
    dead: set[str] = set()
    done = 0

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(check_one, p, my_ip): p for p in raw}
        for future in as_completed(futures):
            done += 1
            proxy = futures[future]
            result = future.result()
            if result:
                hits.append(result)
                spd = f" {result['speed_kbs']}KB/s" if result["speed_kbs"] else ""
                log(f"  ✓ {result['proto'].upper():6s} {result['proxy']:25s} "
                    f"{result['country']} {result['anonymity']:11s} "
                    f"{result['latency_ms']}ms{spd} score={result['score']}")
            else:
                dead.add(proxy)
            if done % 300 == 0:
                log(f"  … {done}/{len(raw)} checked, {len(hits)} alive, {len(dead)} dead")

    # phase 3: export
    log("Exporting results …")
    export(hits, len(raw), history)

    # save blacklist + history
    save_blacklist(dead, blacklist)
    save_history(hits)

    log(f"═══ done: {len(hits)}/{len(raw)} alive ({len(dead)} blacklisted) ═══")


if __name__ == "__main__":
    main()
