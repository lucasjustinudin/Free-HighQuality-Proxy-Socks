# proxy-forge

Automated proxy collection, validation & scoring system. Updates every 2 hours.

## What makes it different

| Feature | proxy-forge | typical scrapers |
|---------|-------------|-----------------|
| Latency measurement | ✅ actual ms | ❌ pass/fail only |
| Speed test | ✅ KB/s download | ❌ none |
| Quality scoring | ✅ composite score | ❌ random order |
| Deep subnet scan | ✅ hunter mode | ❌ none |
| Blacklist | ✅ skip dead proxies | ❌ re-check every time |
| Historical scoring | ✅ recurring proxies ranked higher | ❌ no memory |
| Multiple formats | ✅ txt, json, csv, proxychains | ❌ txt only |
| CI-aware | ✅ auto-tunes for GitHub Actions | ❌ timeout city |

## Output files

```
output/
├── all.txt           # ip:port, scored order (fastest + most reliable first)
├── rotation.txt      # same as all.txt, ready for proxy rotator
├── proxies.csv       # full metadata in CSV
├── details.json      # full metadata in JSON
├── proxychains.txt   # proxychains-ng format
├── stats.txt         # human-readable stats
├── by_protocol/
│   ├── http.txt
│   ├── socks4.txt
│   └── socks5.txt
└── by_country/
    ├── ID.txt
    ├── US.txt
    └── ...
```

## Raw links

```
https://raw.githubusercontent.com/USER/REPO/main/output/all.txt
https://raw.githubusercontent.com/USER/REPO/main/output/rotation.txt
https://raw.githubusercontent.com/USER/REPO/main/output/by_protocol/http.txt
https://raw.githubusercontent.com/USER/REPO/main/output/by_protocol/socks5.txt
https://raw.githubusercontent.com/USER/REPO/main/output/by_country/ID.txt
https://raw.githubusercontent.com/USER/REPO/main/output/proxies.csv
```

## Quality score

Each proxy gets a composite score (lower = better):

```
score = latency_ms / 100
      - 10  if speed > 100 KB/s
      - 5   if speed > 50 KB/s
      - 5   if elite anonymity
      - 2   if anonymous
      - 2×  times_alive (historical bonus)
```

## Proxy formats

**details.json** per proxy:
```json
{
  "proxy": "103.82.20.76:8080",
  "proto": "http",
  "country": "VN",
  "anonymity": "elite",
  "latency_ms": 847,
  "speed_kbs": 156,
  "isp": "VNPT Corp",
  "score": -3.53
}
```

**proxychains.txt**:
```
[ProxyList]
http 103.82.20.76 8080
socks5 138.124.59.186 1080
```

## Run locally

```bash
pip install -r requirements.txt
python forge.py           # collect + validate + export
python hunter.py          # deep subnet scan (after forge)
```

## Config

Edit `settings.py`:

| Key | Default | Description |
|-----|---------|-------------|
| `WORKERS` | 150 | Thread pool size |
| `SOCKET_TIMEOUT` | 4 | TCP + first byte timeout (s) |
| `MAX_LATENCY_MS` | 3000 | Drop proxies slower than this |
| `SPEED_TEST_ENABLED` | True | Measure download speed |
| `HUNTER_PORTS` | 80,8080,... | Ports for deep scan |
| `HUNTER_WORKERS` | 200 | Deep scan thread pool |
| `BLACKLIST_MAX_AGE_DAYS` | 3 | Auto-expire blacklist entries |

## How it works

```
1. COLLECT   → 30+ sources (APIs + GitHub lists + paginated sites)
               ↓ minus blacklist
2. VALIDATE  → 150 threads, per proxy:
               - httpbin.org (anonymity + connectivity)
               - google.com (quality gate, skipped on CI)
               - ip-api.com (country + ISP)
               - speed test (1MB download, skipped on CI)
               ↓
3. SCORE     → composite: latency + speed + anonymity + history
               ↓
4. EXPORT    → 8 output formats (txt, json, csv, proxychains, ...)
               ↓
5. REMEMBER  → blacklist dead, save history for next run
               ↓
6. HUNT      → deep scan subnets of alive proxies
               (separate job, runs after forge)
```

## GitHub Actions

Two jobs, cascade:

1. **forge** (30min timeout) — collect + validate + export
2. **hunt** (60min timeout, needs forge) — deep subnet scan

CI auto-tuning:
- Skips paginated sources (too slow on free runners)
- Caps to 2000 proxies max
- Skips Google quality check
- Skips speed test
