"""
proxy-forge — configuration
"""
from __future__ import annotations
import os

# ── Concurrency ──────────────────────────────────────────────────────────────
WORKERS = int(os.environ.get("FORGE_WORKERS", "150"))
SOCKET_TIMEOUT = 4            # TCP connect + first byte
HTTP_TIMEOUT = 8              # full round-trip
MAX_LATENCY_MS = 3000         # drop anything slower

# ── CI tuning ─────────────────────────────────────────────────────────────────
IS_CI = os.environ.get("CI", "").lower() in ("1", "true", "yes")
CI_MAX_PROXIES = 2000         # cap for GH Actions speed
CI_SKIP_QUALITY = True        # skip Google quality check on CI

# ── Deep scan (hunter) ────────────────────────────────────────────────────────
HUNTER_PORTS = [80, 8080, 3128, 1080, 8888, 7890, 9050, 5678]
HUNTER_WORKERS = int(os.environ.get("FORGE_HUNTER_WORKERS", "200"))

# ── Speed test ────────────────────────────────────────────────────────────────
SPEED_TEST_URL = "http://speedtest.tele2.net/1MB.zip"
SPEED_TEST_TIMEOUT = 15       # seconds
SPEED_TEST_ENABLED = True

# ── Blacklist ─────────────────────────────────────────────────────────────────
BLACKLIST_FILE = "output/.blacklist"
BLACKLIST_MAX_AGE_DAYS = 3    # remove entries older than this

# ── History ───────────────────────────────────────────────────────────────────
HISTORY_FILE = "output/.history.json"

# ── Validation endpoints ──────────────────────────────────────────────────────
CHECK_URL = "http://httpbin.org/get?show_env=1"
QUALITY_URL = "https://www.google.com"
GEO_URL = "http://ip-api.com/json/{ip}?fields=status,countryCode,isp"

# ── Output ────────────────────────────────────────────────────────────────────
OUTPUT_DIR = "output"
PROTO_DIR = f"{OUTPUT_DIR}/by_protocol"
COUNTRY_DIR = f"{OUTPUT_DIR}/by_country"

# ── User agents ───────────────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
]

# ── Proxy sources ─────────────────────────────────────────────────────────────
SOURCES = [
    # Paginated (local only — skipped on CI)
    ("https://www.freeproxy.world/?page={}", 10),
    ("https://free.geonix.com/en/?page={}", 10),

    # API endpoints
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5",
    "https://api.proxyscrape.com/v4/free-proxy-list/get?protocol=all&timeout=10000&country=all&ssl=all&anonymity=all&limit=200000&request=displayproxies",
    "https://proxylist.geonode.com/api/proxy-list?filterLastChecked=10&limit=500&page=2&sort_by=lastChecked&sort_type=desc",
    "https://api.lumiproxy.com/web_v1/free-proxy/list?page_size=60&page=1&language=en-us",

    # GitHub community lists
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/proxy.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/Bes-js/public-proxy-list/refs/heads/main/proxies.txt",
    "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/refs/heads/main/all_proxies.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/refs/heads/main/Socks4.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/refs/heads/main/Socks5.txt",
    "https://raw.githubusercontent.com/stormsia/proxy-list/refs/heads/main/working_proxies.txt",
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/All_proxies.txt",
    "https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/socks5.txt",
    "https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/http.txt",
    "https://raw.githubusercontent.com/MrMarble/proxy-list/refs/heads/main/all.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/refs/heads/main/proxies/http.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/refs/heads/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/refs/heads/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/all-proxies.txt",
    "https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/all_proxies.txt",
    "https://raw.githubusercontent.com/Mohammedcha/ProxRipper/refs/heads/main/full_proxies/http.txt",
    "https://raw.githubusercontent.com/Mohammedcha/ProxRipper/refs/heads/main/full_proxies/socks4.txt",
    "https://raw.githubusercontent.com/Mohammedcha/ProxRipper/refs/heads/main/full_proxies/socks5.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/all/data.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/refs/heads/master/proxies.txt",
]
