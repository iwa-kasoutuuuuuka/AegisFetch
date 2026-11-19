"""
AegisFetch Proxy Rotator & Free Proxy Harvester (v2.1)
======================================================
Provides:
1. Round-robin / Random proxy rotation across multiple HTTP/HTTPS/SOCKS5 proxies (1 request = 1 distinct IP).
2. Automatic health scoring, dead-proxy eviction, and Direct-IP fallback safety net.
3. Multi-source Free Public Proxy Harvester (monosans, proxifly, proxyscrape) verified against Cloudflare HTTPS trace.
"""

import re
import time
import random
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Dict, Tuple
from curl_cffi import requests

from security import BLOCKED_NETWORKS, BLOCKED_HOSTNAMES

# Verified high-uptime public proxy sources (updated every 5-15 mins on GitHub)
FREE_PROXY_SOURCES = [
    ("http", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"),
    ("socks5", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt"),
    ("http", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt"),
    ("socks5", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt"),
    ("http", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=3000&country=all&ssl=yes&anonymity=all"),
]

# Pre-tested fallback free proxy preset
DEFAULT_FREE_PROXIES = [
    "http://176.111.37.5:39811",
    "http://91.134.141.4:3128",
    "http://54.36.150.233:3128",
    "http://185.238.238.29:58080",
    "http://20.98.234.24:8080",
    "http://45.155.226.177:3128",
    "http://45.194.41.141:8080",
    "http://52.128.238.98:18080",
    "http://49.229.100.235:8080",
    "http://4.144.146.21:80",
]

ALLOWED_PROXY_SCHEMES = ("http://", "https://", "socks5://", "socks5h://", "socks4://")


def mask_proxy_credentials(proxy_url: Optional[str]) -> str:
    """
    Mask username/password inside a proxy URL before logging or returning to UI/MCP.
    Example: 'http://admin:secret@1.2.3.4:8080' -> 'http://***:***@1.2.3.4:8080'
    """
    if not proxy_url:
        return "DIRECT"
    return re.sub(r"://([^:@\s]+):([^:@\s]+)@", "://***:***@", proxy_url)


def normalize_proxy_url(
    raw: str,
    default_scheme: str = "http://",
    block_private_ip: bool = True
) -> Optional[str]:
    """
    Normalize a raw proxy entry like '203.0.113.10:8080' or 'socks5://1.2.3.4:1080'
    into a valid proxy URL string. Blocks private/internal IPs by default (Proxy-SSRF protection).
    """
    if not raw or not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s or s.startswith("#"):
        return None

    lower = s.lower()
    if not any(lower.startswith(scheme) for scheme in ALLOWED_PROXY_SCHEMES):
        if not default_scheme.endswith("://"):
            default_scheme += "://"
        s = default_scheme + s

    m = re.match(
        r"^(?:https?|socks[45]h?)://(?:[^:@\s]+:[^:@\s]+@)?([a-zA-Z0-9.\-_]+):(\d{2,5})/?$",
        s,
        re.I
    )
    if not m:
        return None

    host = m.group(1).lower()
    port = int(m.group(2))
    if not (1 <= port <= 65535):
        return None

    if block_private_ip:
        if host in BLOCKED_HOSTNAMES:
            return None
        try:
            ip = ipaddress.ip_address(host)
            for net in BLOCKED_NETWORKS:
                if ip in net:
                    return None
        except ValueError:
            pass

    return s.rstrip("/")


class ProxyRotator:
    """
    Thread-safe proxy rotator that switches proxy on every download request
    (1 file = 1 different IP) and tracks proxy failures to deprioritize dead proxies.
    """

    def __init__(
        self,
        proxies: Optional[List[str]] = None,
        mode: str = "round_robin",
        max_failures_before_ban: int = 2
    ):
        self._lock = threading.Lock()
        self.mode = mode  # "round_robin" or "random"
        self.max_failures_before_ban = max_failures_before_ban
        self._proxies: List[str] = []
        self._failures: Dict[str, int] = {}
        self._index: int = 0

        if proxies:
            self.set_proxies(proxies)

    def set_proxies(self, raw_list: List[str]) -> List[str]:
        """Parse, deduplicate, and load a list of proxy strings."""
        cleaned = []
        seen = set()
        for item in raw_list:
            norm = normalize_proxy_url(item)
            if norm and norm not in seen:
                seen.add(norm)
                cleaned.append(norm)

        with self._lock:
            self._proxies = cleaned
            self._failures = {p: 0 for p in cleaned}
            self._index = 0
        return cleaned

    @property
    def active_proxies(self) -> List[str]:
        """Return list of proxies that haven't exceeded failure threshold."""
        with self._lock:
            alive = [
                p for p in self._proxies
                if self._failures.get(p, 0) < self.max_failures_before_ban
            ]
            if not alive and self._proxies:
                for p in self._proxies:
                    self._failures[p] = 0
                return list(self._proxies)
            return alive

    @property
    def total_count(self) -> int:
        with self._lock:
            return len(self._proxies)

    def get_next_proxy(self) -> Optional[str]:
        """Get the next proxy in rotation (1 request = 1 distinct IP)."""
        with self._lock:
            if not self._proxies:
                return None

            alive = [
                p for p in self._proxies
                if self._failures.get(p, 0) < self.max_failures_before_ban
            ]
            if not alive:
                for p in self._proxies:
                    self._failures[p] = 0
                alive = list(self._proxies)

            if self.mode == "random":
                return random.choice(alive)

            chosen = alive[self._index % len(alive)]
            self._index = (self._index + 1) % len(alive)
            return chosen

    def report_success(self, proxy_url: Optional[str]):
        """Reset failure count for a working proxy."""
        if not proxy_url:
            return
        with self._lock:
            if proxy_url in self._failures:
                self._failures[proxy_url] = 0

    def report_failure(self, proxy_url: Optional[str]):
        """Increment failure count for a broken/blocked proxy."""
        if not proxy_url:
            return
        with self._lock:
            if proxy_url in self._failures:
                self._failures[proxy_url] += 1


def _probe_single_proxy(
    proxy_url: str,
    test_url: str = "https://www.cloudflare.com/cdn-cgi/trace",
    timeout: float = 3.5
) -> Tuple[str, bool, float, str]:
    """
    Test if a single proxy is alive and supports HTTPS tunneling to Cloudflare.
    Returns (proxy_url, is_alive, latency_ms, country_code).
    """
    t0 = time.time()
    try:
        with requests.Session(impersonate="chrome124") as s:
            s.proxies = {"http": proxy_url, "https": proxy_url}
            resp = s.get(test_url, timeout=timeout)
            if resp.status_code == 200 and "ip=" in resp.text:
                latency = round((time.time() - t0) * 1000, 1)
                m_loc = re.search(r"loc=([A-Z]{2})", resp.text)
                country = m_loc.group(1) if m_loc else "??"
                return (proxy_url, True, latency, country)
    except Exception:
        pass
    return (proxy_url, False, 9999.0, "")


def fetch_and_test_free_proxies(
    per_source_limit: int = 35,
    target_working_count: int = 15,
    timeout: float = 3.5,
    verify_live: bool = True
) -> Dict[str, object]:
    """
    Harvest free proxies from multiple public GitHub & API sources and run a multi-threaded
    HTTPS connectivity check against Cloudflare so only live, working proxies are returned.
    """
    candidates: List[str] = []
    seen = set()

    with requests.Session(impersonate="chrome124") as s:
        for proto, src_url in FREE_PROXY_SOURCES:
            try:
                resp = s.get(src_url, timeout=5)
                if resp.status_code == 200:
                    count = 0
                    for line in resp.text.splitlines():
                        norm = normalize_proxy_url(line, default_scheme=f"{proto}://")
                        if norm and norm not in seen:
                            seen.add(norm)
                            candidates.append(norm)
                            count += 1
                            if count >= per_source_limit:
                                break
            except Exception:
                continue

    if not candidates:
        return {
            "success": True,
            "fetched_total": len(DEFAULT_FREE_PROXIES),
            "tested_count": 0,
            "working_count": len(DEFAULT_FREE_PROXIES),
            "working_proxies": list(DEFAULT_FREE_PROXIES),
            "details": [{"proxy": p, "latency_ms": None, "country": "PRESET"} for p in DEFAULT_FREE_PROXIES],
            "message": "Used built-in preset proxies (offline fallback)."
        }

    if not verify_live:
        chosen = candidates[:target_working_count]
        return {
            "success": True,
            "fetched_total": len(candidates),
            "tested_count": 0,
            "working_count": len(chosen),
            "working_proxies": chosen,
            "details": [{"proxy": p, "latency_ms": None, "country": "UNVERIFIED"} for p in chosen]
        }

    working: List[Tuple[str, float, str]] = []

    with ThreadPoolExecutor(max_workers=35) as executor:
        futures = {
            executor.submit(_probe_single_proxy, p, "https://www.cloudflare.com/cdn-cgi/trace", timeout): p
            for p in candidates
        }
        for fut in as_completed(futures):
            p_url, ok, latency, country = fut.result()
            if ok:
                working.append((p_url, latency, country))
                if len(working) >= target_working_count:
                    break

    working.sort(key=lambda x: x[1])

    # If live check yielded 0 (e.g. corporate firewall blocking external proxy ports), provide preset list
    if not working:
        return {
            "success": True,
            "fetched_total": len(candidates),
            "tested_count": len(candidates),
            "working_count": len(DEFAULT_FREE_PROXIES),
            "working_proxies": list(DEFAULT_FREE_PROXIES),
            "details": [{"proxy": p, "latency_ms": None, "country": "PRESET"} for p in DEFAULT_FREE_PROXIES],
            "message": "Live probe blocked or timed out; loaded preset proxy list."
        }

    return {
        "success": True,
        "fetched_total": len(candidates),
        "tested_count": len(candidates),
        "working_count": len(working),
        "working_proxies": [w[0] for w in working],
        "details": [{"proxy": w[0], "latency_ms": w[1], "country": w[2]} for w in working],
    }
