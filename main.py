#!/usr/bin/env python3
"""
Ultra-Fast Asynchronous Proxy Checker & Scraper Telegram Bot
Python 3.11+ required.
"""
#uvloop>=0.19.0
#orjson>=3.9.0
#aiohttp[speedups]>=3.9.0
#aiohttp_socks>=0.8.0
#aiogram>=3.0.0
#aiosqlite>=0.19.0
#python-socks[asyncio]>=2.0.0
#aiodns>=3.0.0
#aiofiles>=23.2.0
#python-dotenv>=1.0.0

import asyncio
import logging
import os
import re
import socket
import time
from asyncio import Queue, Semaphore, wait_for
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

# Force uvloop if available
try:
    import uvloop

    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

import aiodns
import aiofiles
import aiohttp
import aiosqlite
import orjson
from aiogram import Bot, Dispatcher, F, Router, types
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandObject
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import FSInputFile, InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiohttp import ClientTimeout, TCPConnector
from aiohttp_socks import ProxyConnector
from dotenv import load_dotenv

load_dotenv()

# ============================================================================
# Configuration
# ============================================================================
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN environment variable not set")

ADMIN_IDS = list(map(int, os.getenv("ADMIN_IDS", "").split(","))) if os.getenv("ADMIN_IDS") else []

# Hardcoded proxy source URLs (40)
PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Https.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks4.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/main/Socks5.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks4.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://vakhov.github.io/fresh-proxy-list/http.txt",
    "https://vakhov.github.io/fresh-proxy-list/https.txt",
    "https://vakhov.github.io/fresh-proxy-list/socks4.txt",
    "https://vakhov.github.io/fresh-proxy-list/socks5.txt",
    "https://vakhov.github.io/fresh-proxy-list/proxylist.txt",
    "https://api.openproxylist.xyz/http.txt",
    "https://api.openproxylist.xyz/socks4.txt",
    "https://api.openproxylist.xyz/socks5.txt",
    "https://openproxylist.xyz/http.txt",
    "https://openproxylist.xyz/socks4.txt",
    "https://openproxylist.xyz/socks5.txt",
    "https://proxyspace.pro/http.txt",
    "https://proxyspace.pro/https.txt",
    "https://proxyspace.pro/socks4.txt",
    "https://proxyspace.pro/socks5.txt",
    "https://multiproxy.org/txt_all/proxy.txt",
    "http://worm.rip/http.txt",
    "http://worm.rip/socks5.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/https.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
]

# Judge URL for anonymity testing
DEFAULT_JUDGE_URL = "http://httpbin.org/headers"
TEST_URL = DEFAULT_JUDGE_URL  # can be changed via /seturl

# Concurrency settings
DEFAULT_CONCURRENCY = 1000
MAX_CONCURRENCY = 5000
current_concurrency = DEFAULT_CONCURRENCY

# Auto tasks intervals (in seconds)
AUTO_SCRAPE_INTERVAL = 6 * 3600  # 6 hours
AUTO_CHECK_INTERVAL = None  # disabled by default

# Database path
DB_PATH = "proxies.db"

# Batch write size
BATCH_SIZE = 500

# GeoIP resolution (decoupled from live checks to avoid rate-limit stalls)
IPAPI_KEY = os.getenv("IPAPI_KEY", "")
IPAPI_BATCH_URL = f"https://pro.ip-api.com/batch?key={IPAPI_KEY}" if IPAPI_KEY else "http://ip-api.com/batch"
GEOIP_BATCH_SIZE = 100
GEOIP_RESOLVE_INTERVAL = 30  # seconds between background resolver cycles

# Auto-check RAM cap: proxies pulled into memory per auto_check cycle
AUTO_CHECK_BATCH_SIZE = 5000

PRIVATE_IP_PREFIXES = (
    "127.", "192.168.", "10.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)

# ============================================================================
# Logging
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ============================================================================
# Database Layer (aiosqlite)
# ============================================================================
class Database:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._conn: Optional[aiosqlite.Connection] = None

    async def connect(self):
        self._conn = await aiosqlite.connect(self.db_path)
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self._conn.execute("""
            CREATE TABLE IF NOT EXISTS proxies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proxy TEXT UNIQUE NOT NULL,
                protocol TEXT,
                country TEXT,
                anonymity TEXT,
                speed INTEGER,
                last_checked TIMESTAMP,
                status TEXT DEFAULT 'dead',
                source_url TEXT
            )
        """)
        await self._conn.commit()
        # Create index for faster queries
        await self._conn.execute("CREATE INDEX IF NOT EXISTS idx_status ON proxies(status)")
        await self._conn.execute("CREATE INDEX IF NOT EXISTS idx_protocol ON proxies(protocol)")
        await self._conn.execute("CREATE INDEX IF NOT EXISTS idx_speed ON proxies(speed)")
        await self._conn.commit()

    async def close(self):
        if self._conn:
            await self._conn.close()

    async def execute(self, query: str, *args):
        async with self._conn.cursor() as cur:
            await cur.execute(query, args)
            await self._conn.commit()

    async def executemany(self, query: str, args_list: List[Tuple]):
        async with self._conn.cursor() as cur:
            await cur.executemany(query, args_list)
            await self._conn.commit()

    async def fetchone(self, query: str, *args):
        async with self._conn.cursor() as cur:
            await cur.execute(query, args)
            return await cur.fetchone()

    async def fetchall(self, query: str, *args):
        async with self._conn.cursor() as cur:
            await cur.execute(query, args)
            return await cur.fetchall()

    # ------------------------------------------------------------------------
    # Proxy management
    # ------------------------------------------------------------------------
    async def upsert_proxy(self, proxy: str, protocol: Optional[str] = None,
                           country: Optional[str] = None, anonymity: Optional[str] = None,
                           speed: Optional[int] = None, status: str = "unknown",
                           source_url: Optional[str] = None):
        """Insert or update proxy record."""
        await self.execute("""
            INSERT INTO proxies (proxy, protocol, country, anonymity, speed, last_checked, status, source_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(proxy) DO UPDATE SET
                protocol = COALESCE(excluded.protocol, protocol),
                country = COALESCE(excluded.country, country),
                anonymity = COALESCE(excluded.anonymity, anonymity),
                speed = COALESCE(excluded.speed, speed),
                last_checked = excluded.last_checked,
                status = excluded.status,
                source_url = COALESCE(excluded.source_url, source_url)
        """, proxy, protocol, country, anonymity, speed, datetime.utcnow(), status, source_url)

    async def batch_upsert(self, records: List[Tuple]):
        """Batch upsert using executemany. Mirrors upsert_proxy's COALESCE merge
        so a re-scrape (which passes protocol=None, country=None, etc.) no longer
        wipes out previously-verified data for a proxy that's already in the DB."""
        query = """
            INSERT INTO proxies (proxy, protocol, country, anonymity, speed, last_checked, status, source_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(proxy) DO UPDATE SET
                protocol = COALESCE(excluded.protocol, protocol),
                country = COALESCE(excluded.country, country),
                anonymity = COALESCE(excluded.anonymity, anonymity),
                speed = COALESCE(excluded.speed, speed),
                last_checked = excluded.last_checked,
                status = excluded.status,
                source_url = COALESCE(excluded.source_url, source_url)
        """
        await self.executemany(query, records)

    async def batch_update_country(self, records: List[Tuple[str, str]]):
        """Targeted country-only update (used by the async GeoIP resolver so it
        never clobbers a status that may have changed since the record was queued)."""
        query = "UPDATE proxies SET country = ? WHERE proxy = ?"
        await self.executemany(query, records)

    async def get_proxies(self, status: str = "alive", protocol: Optional[str] = None,
                          country: Optional[str] = None, anonymity: Optional[str] = None,
                          limit: Optional[int] = None) -> List[Tuple]:
        query = "SELECT proxy, protocol, country, anonymity, speed, last_checked FROM proxies WHERE status = ?"
        params = [status]
        if protocol:
            query += " AND protocol = ?"
            params.append(protocol)
        if country:
            query += " AND country = ?"
            params.append(country)
        if anonymity:
            query += " AND anonymity = ?"
            params.append(anonymity)
        query += " ORDER BY speed ASC"
        if limit:
            query += f" LIMIT {limit}"
        return await self.fetchall(query, *params)

    async def get_stats(self) -> Dict:
        total_row = await self.fetchone("SELECT COUNT(*) FROM proxies")
        alive_row = await self.fetchone("SELECT COUNT(*) FROM proxies WHERE status = 'alive'")
        total = total_row[0]
        alive = alive_row[0]
        # breakdown by protocol
        proto_counts = await self.fetchall(
            "SELECT protocol, COUNT(*) FROM proxies WHERE status = 'alive' GROUP BY protocol"
        )
        country_counts = await self.fetchall(
            "SELECT country, COUNT(*) FROM proxies WHERE status = 'alive' AND country IS NOT NULL GROUP BY country ORDER BY COUNT(*) DESC LIMIT 10"
        )
        anonymity_counts = await self.fetchall(
            "SELECT anonymity, COUNT(*) FROM proxies WHERE status = 'alive' AND anonymity IS NOT NULL GROUP BY anonymity"
        )
        return {
            "total": total,
            "alive": alive,
            "by_protocol": dict(proto_counts),
            "by_country": dict(country_counts),
            "by_anonymity": dict(anonymity_counts),
        }

    async def clear_dead(self):
        await self.execute("DELETE FROM proxies WHERE status = 'dead'")

    async def clear_old(self, days: int):
        cutoff = datetime.utcnow() - timedelta(days=days)
        await self.execute("DELETE FROM proxies WHERE last_checked < ?", cutoff)

    async def get_all_proxies_for_check(self, limit: Optional[int] = None) -> List[Tuple[str, Optional[str]]]:
        """Return list of (proxy, protocol_hint) tuples to be checked.
        limit caps how many rows get pulled into memory at once."""
        query = "SELECT proxy, protocol FROM proxies ORDER BY last_checked ASC"
        if limit:
            query += f" LIMIT {limit}"
        rows = await self.fetchall(query)
        return [(row[0], row[1]) for row in rows]

    async def get_proxies_missing_country(self, limit: int = 500) -> List[str]:
        """Alive proxies with no resolved country yet, for the background GeoIP resolver."""
        rows = await self.fetchall(
            "SELECT proxy FROM proxies WHERE status = 'alive' AND (country IS NULL OR country = '') LIMIT ?",
            limit,
        )
        return [row[0] for row in rows]

    async def vacuum(self):
        await self.execute("VACUUM")


# ============================================================================
# Global DB instance and queue for batch writes
# ============================================================================
db = Database()
write_queue: Queue = Queue()
batch_writer_task: Optional[asyncio.Task] = None

# ============================================================================
# Batch Writer Consumer
# ============================================================================
async def batch_writer():
    """Consumes proxy check results from queue and writes to DB in batches."""
    batch = []
    while True:
        try:
            # Wait for first item with timeout to allow flushing
            item = await asyncio.wait_for(write_queue.get(), timeout=2.0)
            batch.append(item)
            # Drain more items if available
            while len(batch) < BATCH_SIZE:
                try:
                    item = write_queue.get_nowait()
                    batch.append(item)
                except asyncio.QueueEmpty:
                    break
            if batch:
                await db.batch_upsert(batch)
                logger.debug(f"Batch written {len(batch)} proxies")
                batch.clear()
        except asyncio.TimeoutError:
            if batch:
                await db.batch_upsert(batch)
                logger.debug(f"Flushed {len(batch)} proxies on timeout")
                batch.clear()
        except Exception as e:
            logger.error(f"Batch writer error: {e}")
            await asyncio.sleep(1)


# ============================================================================
# Proxy Checker (Ultra-fast)
# ============================================================================
class ProxyChecker:
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
        self.resolver: Optional[aiodns.DNSResolver] = None
        self.geoip_cache: Dict[str, str] = {}
        self.geoip_semaphore = Semaphore(50)  # limit concurrent GeoIP lookups
        self._tcp_semaphore = Semaphore(2000)  # limit concurrent TCP pre-checks

    async def start(self):
        # Custom connector with aggressive settings
        connector = TCPConnector(
            limit=0,
            ttl_dns_cache=300,
            force_close=True,
            enable_cleanup_closed=True,
            use_dns_cache=True,
        )
        timeout = ClientTimeout(total=3, connect=1.5, sock_read=1.5)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            json_serialize=lambda obj: orjson.dumps(obj).decode(),
        )
        self.resolver = aiodns.DNSResolver()

    async def close(self):
        if self.session:
            await self.session.close()

    async def quick_tcp_test(self, ip: str, port: int) -> bool:
        """Fast pre-check if host:port is reachable."""
        try:
            async with self._tcp_semaphore:
                _, writer = await wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=1.0
                )
                writer.close()
                await writer.wait_closed()
                return True
        except Exception:
            return False

    async def check_http(self, proxy: str, proxy_type: str = "http", skip_tcp_check: bool = False) -> Optional[Dict]:
        """Test HTTP/HTTPS proxy."""
        ip, port = proxy.split(":")
        port = int(port)
        # Quick TCP pre-check (skipped if check_proxy already did it for this proxy)
        if not skip_tcp_check and not await self.quick_tcp_test(ip, port):
            return None

        start = time.monotonic()
        try:
            proxy_url = f"{proxy_type}://{proxy}"
            async with self.session.get(
                TEST_URL,
                proxy=proxy_url,
                timeout=ClientTimeout(total=3),
                headers={"User-Agent": "Mozilla/5.0"}
            ) as resp:
                if resp.status != 200:
                    return None
                content = await resp.text()
                speed = int((time.monotonic() - start) * 1000)

                # Detect anonymity
                anonymity = "transparent"
                headers_lower = content.lower()
                if "x-forwarded-for" not in headers_lower and "via" not in headers_lower:
                    anonymity = "anonymous"
                if "proxy-connection" not in headers_lower and anonymity == "anonymous":
                    anonymity = "elite"

                # Country is resolved later in bulk by the background GeoIP
                # resolver, not per-check — see resolve_geoip_batch().
                return {
                    "proxy": proxy,
                    "protocol": proxy_type,
                    "country": None,
                    "anonymity": anonymity,
                    "speed": speed,
                    "status": "alive",
                }
        except Exception:
            return None

    async def check_socks(self, proxy: str, socks_ver: int, skip_tcp_check: bool = False) -> Optional[Dict]:
        """Test SOCKS4/SOCKS5 proxy."""
        ip, port = proxy.split(":")
        port = int(port)
        if not skip_tcp_check and not await self.quick_tcp_test(ip, port):
            return None

        start = time.monotonic()
        try:
            connector = ProxyConnector.from_url(f"socks{socks_ver}://{proxy}")
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=ClientTimeout(total=3),
                cookie_jar=aiohttp.DummyCookieJar(),  # skip cookie-jar bookkeeping we never use
            ) as sess:
                async with sess.get(TEST_URL) as resp:
                    if resp.status != 200:
                        return None
                    speed = int((time.monotonic() - start) * 1000)
                    # SOCKS proxies are generally anonymous, but we can still classify
                    anonymity = "elite" if socks_ver == 5 else "anonymous"
                    return {
                        "proxy": proxy,
                        "protocol": f"socks{socks_ver}",
                        "country": None,
                        "anonymity": anonymity,
                        "speed": speed,
                        "status": "alive",
                    }
        except Exception:
            return None

    async def get_country(self, ip: str) -> str:
        """Get country code using ip-api.com (rate limited) or cache."""
        if ip in self.geoip_cache:
            return self.geoip_cache[ip]

        # Skip private/local IPs
        if ip.startswith(PRIVATE_IP_PREFIXES):
            return "local"

        async with self.geoip_semaphore:
            try:
                async with self.session.get(
                    f"http://ip-api.com/json/{ip}?fields=countryCode",
                    timeout=ClientTimeout(total=2)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(loads=orjson.loads)
                        country = data.get("countryCode", "unknown")
                        self.geoip_cache[ip] = country
                        return country
            except Exception:
                pass
        return "unknown"

    async def resolve_geoip_batch(self, ips: List[str]) -> Dict[str, str]:
        """Resolve country codes for many IPs at once via ip-api's /batch endpoint
        (up to 100 IPs per call), instead of one HTTP request per proxy. Paced to
        stay under the free-tier rate limit; set IPAPI_KEY for a paid tier if
        checking at very high volume."""
        results: Dict[str, str] = {}
        to_query: List[str] = []
        for ip in ips:
            if ip in self.geoip_cache:
                results[ip] = self.geoip_cache[ip]
            elif ip.startswith(PRIVATE_IP_PREFIXES):
                results[ip] = "local"
                self.geoip_cache[ip] = "local"
            else:
                to_query.append(ip)

        for i in range(0, len(to_query), GEOIP_BATCH_SIZE):
            chunk = to_query[i:i + GEOIP_BATCH_SIZE]
            async with self.geoip_semaphore:
                try:
                    async with self.session.post(
                        IPAPI_BATCH_URL,
                        json=[{"query": ip, "fields": "query,countryCode"} for ip in chunk],
                        timeout=ClientTimeout(total=8),
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json(loads=orjson.loads)
                            for entry in data:
                                ip_r = entry.get("query")
                                cc = entry.get("countryCode") or "unknown"
                                if ip_r:
                                    results[ip_r] = cc
                                    self.geoip_cache[ip_r] = cc
                        elif resp.status == 429:
                            logger.warning("GeoIP batch endpoint rate-limited, backing off")
                            await asyncio.sleep(5)
                except Exception as e:
                    logger.debug(f"GeoIP batch error: {e}")
            if i + GEOIP_BATCH_SIZE < len(to_query):
                await asyncio.sleep(1.5)  # pace successive batch calls
        return results

    async def check_proxy(self, proxy: str, semaphore: Semaphore,
                           protocol_hint: Optional[str] = None,
                           resolve_geo: bool = False) -> Optional[Dict]:
        """Check a single proxy.

        protocol_hint (from the source URL, e.g. a socks5.txt list) lets us
        probe only the relevant protocol(s) instead of blindly firing off
        http+https+socks4+socks5 for every proxy. Falls back to probing
        everything when the hint is unknown, so behavior is unchanged for
        proxies with no metadata.

        resolve_geo does an inline single-IP GeoIP lookup for callers that
        need an immediate answer (the /test command on a single proxy).
        Bulk checks leave country unset and let the background
        geoip_resolver_loop batch-resolve it instead.
        """
        async with semaphore:
            try:
                ip, port_str = proxy.split(":")
                port = int(port_str)
            except ValueError:
                return None

            # Single shared TCP reachability pre-check, done once instead of
            # once per protocol probe (was up to 4x per proxy).
            if not await self.quick_tcp_test(ip, port):
                record = (proxy, None, None, None, None, datetime.utcnow(), "dead", None)
                await write_queue.put(record)
                return None

            if protocol_hint == "socks5":
                probes = [self.check_socks(proxy, 5, skip_tcp_check=True)]
            elif protocol_hint == "socks4":
                probes = [self.check_socks(proxy, 4, skip_tcp_check=True)]
            elif protocol_hint == "http":
                probes = [
                    self.check_http(proxy, "http", skip_tcp_check=True),
                    self.check_http(proxy, "https", skip_tcp_check=True),
                ]
            else:
                probes = [
                    self.check_http(proxy, "http", skip_tcp_check=True),
                    self.check_http(proxy, "https", skip_tcp_check=True),
                    self.check_socks(proxy, 4, skip_tcp_check=True),
                    self.check_socks(proxy, 5, skip_tcp_check=True),
                ]
            results = await asyncio.gather(*probes, return_exceptions=True)

            best_result = None
            for res in results:
                if isinstance(res, dict) and res and res.get("status") == "alive":
                    if best_result is None or res["speed"] < best_result["speed"]:
                        best_result = res

            if best_result:
                if resolve_geo:
                    best_result["country"] = await self.get_country(ip)
                record = (
                    best_result["proxy"],
                    best_result["protocol"],
                    best_result["country"],
                    best_result["anonymity"],
                    best_result["speed"],
                    datetime.utcnow(),
                    "alive",
                    None,  # source_url not updated during check
                )
                await write_queue.put(record)
                return best_result
            else:
                record = (proxy, None, None, None, None, datetime.utcnow(), "dead", None)
                await write_queue.put(record)
                return None


# ============================================================================
# Proxy Scraper
# ============================================================================
def infer_protocol_hint(url: str) -> Optional[str]:
    """Guess a proxy's protocol from its source list URL (e.g. .../socks5.txt).
    Used to skip redundant protocol probing during checks. Returns None if
    the source doesn't indicate a protocol, in which case the checker falls
    back to probing all protocols for that proxy."""
    u = url.lower()
    if "socks5" in u:
        return "socks5"
    if "socks4" in u:
        return "socks4"
    if "http" in u:  # covers http.txt and https.txt lists
        return "http"
    return None


class ProxyScraper:
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.sources = PROXY_SOURCES.copy()

    async def fetch_url(self, url: str) -> Optional[str]:
        try:
            async with self.session.get(url, timeout=ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    return await resp.text()
        except Exception as e:
            logger.warning(f"Failed to fetch {url}: {e}")
        return None

    def parse_proxies(self, text: str) -> Set[str]:
        """Extract IP:PORT from text."""
        pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b")
        return set(pattern.findall(text))

    async def scrape_all(self) -> int:
        """Scrape all sources and return number of new proxies added."""
        tasks = [self.fetch_url(url) for url in self.sources]
        results = await asyncio.gather(*tasks)

        # Track a protocol hint per proxy based on which source list(s) it
        # came from (e.g. a proxy from socks5.txt gets hint "socks5"). This
        # lets check_proxy skip redundant protocol probes later.
        proxy_hints: Dict[str, Optional[str]] = {}
        for url, text in zip(self.sources, results):
            if not text:
                continue
            hint = infer_protocol_hint(url)
            for proxy in self.parse_proxies(text):
                if proxy not in proxy_hints or proxy_hints[proxy] is None:
                    proxy_hints[proxy] = hint

        records = [
            (proxy, hint, None, None, None, datetime.utcnow(), "unknown", "scraper")
            for proxy, hint in proxy_hints.items()
        ]
        await db.batch_upsert(records)
        logger.info(f"Scraped {len(proxy_hints)} unique proxies.")
        return len(proxy_hints)


# ============================================================================
# Telegram Bot Handlers
# ============================================================================
router = Router()
checker: Optional[ProxyChecker] = None
scraper: Optional[ProxyScraper] = None
auto_tasks: Dict[str, asyncio.Task] = {}  # "scrape", "check"
geoip_task: Optional[asyncio.Task] = None

# FSM for /addsource
class SourceStates(StatesGroup):
    waiting_for_url = State()


@router.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer(
        "🚀 **Ultra-Fast Proxy Checker & Scraper Bot**\n\n"
        "Use /help for available commands.\n"
        f"Current concurrency: {current_concurrency}\n"
        f"Test URL: {TEST_URL}"
    )

@router.message(Command("help"))
async def cmd_help(message: types.Message):
    help_text = """
**Commands:**

**Scraping:**
/scrape - Start manual scrape
/scrape_status - Show last scrape info
/addsource <url> - Add custom source
/removesource <url> - Remove source
/listsources - List all sources

**Checking:**
/check [amount] [protocol] [country] [anonymity] - Check proxies
/checkall - Check all proxies in DB
/test <proxy> - Test single proxy
/seturl <url> - Change test URL
/setthreads <number> - Set concurrency (max 5000)

**Stats & Filtering:**
/stats - Show statistics
/filter <protocol> <country> <anonymity> - List alive proxies
/top [amount] [protocol] [country] - Show fastest proxies
/countries - List countries with counts

**Export:**
/export [txt|json|csv] [protocol] [country] [anonymity]

**Maintenance:**
/clear_dead - Delete dead proxies
/clear_old [days] - Delete old records
/backup - Create DB backup
/reset - Reset database

**Automation:**
/auto_check [minutes] - Enable auto check
/auto_scrape [hours] - Enable auto scrape
/stop_auto - Stop all auto tasks
/status - Show system status

**Advanced:**
/scan <url> [protocol] [amount] - Test proxies against specific site
/judge - Show current judge URL
"""
    await message.answer(help_text, parse_mode=ParseMode.MARKDOWN)

# ----------------------------------------------------------------------------
# Scraping Commands
# ----------------------------------------------------------------------------
@router.message(Command("scrape"))
async def cmd_scrape(message: types.Message):
    if not scaper:
        await message.answer("Scraper not initialized.")
        return
    msg = await message.answer("🔄 Scraping started...")
    count = await scaper.scrape_all()
    await msg.edit_text(f"✅ Scraping completed. Added/updated {count} unique proxies.")

@router.message(Command("listsources"))
async def cmd_listsources(message: types.Message):
    sources = "\n".join(PROXY_SOURCES[:10]) + f"\n... and {len(PROXY_SOURCES)-10} more"
    await message.answer(f"**Proxy Sources ({len(PROXY_SOURCES)}):**\n{sources}")

@router.message(Command("addsource"))
async def cmd_addsource(message: types.Message, state: FSMContext):
    await message.answer("Send me the URL to add as a proxy source:")
    await state.set_state(SourceStates.waiting_for_url)

@router.message(SourceStates.waiting_for_url)
async def process_addsource(message: types.Message, state: FSMContext):
    url = message.text.strip()
    if not url.startswith(("http://", "https://")):
        await message.answer("Invalid URL. Must start with http:// or https://")
        return
    PROXY_SOURCES.append(url)
    await message.answer(f"✅ Added source: {url}")
    await state.clear()

@router.message(Command("removesource"))
async def cmd_removesource(message: types.Message, command: CommandObject):
    if not command.args:
        await message.answer("Usage: /removesource <url>")
        return
    url = command.args.strip()
    if url in PROXY_SOURCES:
        PROXY_SOURCES.remove(url)
        await message.answer(f"✅ Removed source: {url}")
    else:
        await message.answer("Source not found.")

# ----------------------------------------------------------------------------
# Checking Commands
# ----------------------------------------------------------------------------
async def perform_check(proxies: List[Tuple[str, Optional[str]]], message: types.Message):
    """Run checker on list of (proxy, protocol_hint) tuples with progress updates."""
    if not checker:
        await message.answer("Checker not initialized.")
        return

    total = len(proxies)
    if total == 0:
        await message.answer("No proxies to check.")
        return

    msg = await message.answer(f"⚡ Checking {total} proxies with concurrency {current_concurrency}...")
    semaphore = Semaphore(current_concurrency)
    alive_count = 0
    start_time = time.monotonic()

    # Create tasks and gather
    tasks = [checker.check_proxy(p, semaphore, hint) for p, hint in proxies]
    # Process in chunks to update progress
    chunk_size = 100
    for i in range(0, len(tasks), chunk_size):
        chunk = tasks[i:i+chunk_size]
        results = await asyncio.gather(*chunk, return_exceptions=True)
        alive_count += sum(1 for r in results if isinstance(r, dict) and r)
        # Update progress
        progress = min(i+chunk_size, total)
        elapsed = time.monotonic() - start_time
        rate = progress / elapsed if elapsed > 0 else 0
        await msg.edit_text(
            f"⚡ Checked {progress}/{total} | Alive: {alive_count} | {rate:.1f} p/s"
        )

    elapsed = time.monotonic() - start_time
    await msg.edit_text(
        f"✅ Check completed. {alive_count}/{total} alive.\n"
        f"Time: {elapsed:.1f}s | Rate: {total/elapsed:.1f} p/s"
    )

@router.message(Command("check"))
async def cmd_check(message: types.Message, command: CommandObject):
    args = command.args.split() if command.args else []
    limit = None
    protocol = None
    country = None
    anonymity = None
    try:
        if args:
            limit = int(args[0])
        if len(args) > 1:
            protocol = args[1]
        if len(args) > 2:
            country = args[2]
        if len(args) > 3:
            anonymity = args[3]
    except ValueError:
        await message.answer("Invalid arguments. Usage: /check [amount] [protocol] [country] [anonymity]")
        return

    proxies_data = await db.get_proxies(status="unknown", protocol=protocol, country=country, anonymity=anonymity, limit=limit)
    if not proxies_data:
        # If no unknown, check all alive as fallback?
        await message.answer("No proxies found matching criteria.")
        return
    proxies = [(p[0], p[1]) for p in proxies_data]
    await perform_check(proxies, message)

@router.message(Command("checkall"))
async def cmd_checkall(message: types.Message, command: CommandObject):
    limit = None
    if command.args:
        try:
            limit = int(command.args)
        except ValueError:
            await message.answer("Invalid number. Usage: /checkall [limit]")
            return
    proxies_data = await db.get_all_proxies_for_check(limit=limit)
    await perform_check(proxies_data, message)

@router.message(Command("test"))
async def cmd_test(message: types.Message, command: CommandObject):
    if not command.args:
        await message.answer("Usage: /test <proxy>")
        return
    proxy = command.args.strip()
    if not checker:
        await message.answer("Checker not initialized.")
        return
    msg = await message.answer(f"Testing {proxy}...")
    sem = Semaphore(1)
    result = await checker.check_proxy(proxy, sem, resolve_geo=True)
    if result:
        await msg.edit_text(
            f"✅ Proxy alive: {result['proxy']}\n"
            f"Protocol: {result['protocol']}\n"
            f"Country: {result['country']}\n"
            f"Anonymity: {result['anonymity']}\n"
            f"Speed: {result['speed']} ms"
        )
    else:
        await msg.edit_text(f"❌ Proxy dead: {proxy}")

@router.message(Command("seturl"))
async def cmd_seturl(message: types.Message, command: CommandObject):
    global TEST_URL
    if not command.args:
        await message.answer(f"Current test URL: {TEST_URL}")
        return
    TEST_URL = command.args.strip()
    await message.answer(f"✅ Test URL set to: {TEST_URL}")

@router.message(Command("setthreads"))
async def cmd_setthreads(message: types.Message, command: CommandObject):
    global current_concurrency
    if not command.args:
        await message.answer(f"Current concurrency: {current_concurrency}")
        return
    try:
        val = int(command.args)
        if val < 1 or val > MAX_CONCURRENCY:
            await message.answer(f"Value must be between 1 and {MAX_CONCURRENCY}")
            return
        current_concurrency = val
        await message.answer(f"✅ Concurrency set to {current_concurrency}")
    except ValueError:
        await message.answer("Invalid number.")

# ----------------------------------------------------------------------------
# Stats & Filtering
# ----------------------------------------------------------------------------
@router.message(Command("stats"))
async def cmd_stats(message: types.Message):
    stats = await db.get_stats()
    text = (
        f"📊 **Proxy Statistics**\n"
        f"Total in DB: {stats['total']}\n"
        f"Alive: {stats['alive']}\n\n"
        f"**By Protocol:**\n"
    )
    for proto, cnt in stats['by_protocol'].items():
        text += f"{proto}: {cnt}\n"
    text += "\n**Top Countries:**\n"
    for country, cnt in list(stats['by_country'].items())[:10]:
        text += f"{country}: {cnt}\n"
    text += "\n**By Anonymity:**\n"
    for anon, cnt in stats['by_anonymity'].items():
        text += f"{anon}: {cnt}\n"
    await message.answer(text)

@router.message(Command("filter"))
async def cmd_filter(message: types.Message, command: CommandObject):
    args = command.args.split() if command.args else []
    protocol = args[0] if len(args) > 0 else None
    country = args[1] if len(args) > 1 else None
    anonymity = args[2] if len(args) > 2 else None
    proxies = await db.get_proxies(status="alive", protocol=protocol, country=country, anonymity=anonymity, limit=50)
    if not proxies:
        await message.answer("No alive proxies found.")
        return
    text = "**Alive Proxies:**\n"
    for p in proxies:
        text += f"{p[0]} | {p[1]} | {p[2]} | {p[3]} | {p[4]}ms\n"
    await message.answer(text[:4000])  # Telegram limit

@router.message(Command("top"))
async def cmd_top(message: types.Message, command: CommandObject):
    args = command.args.split() if command.args else []
    limit = 10
    protocol = None
    country = None
    try:
        if args:
            limit = int(args[0])
        if len(args) > 1:
            protocol = args[1]
        if len(args) > 2:
            country = args[2]
    except ValueError:
        pass
    proxies = await db.get_proxies(status="alive", protocol=protocol, country=country, limit=limit)
    if not proxies:
        await message.answer("No proxies found.")
        return
    text = f"**Top {len(proxies)} Fastest Proxies:**\n"
    for p in proxies:
        text += f"{p[0]} | {p[1]} | {p[2]} | {p[3]} | {p[4]}ms\n"
    await message.answer(text)

@router.message(Command("countries"))
async def cmd_countries(message: types.Message):
    rows = await db.fetchall(
        "SELECT country, COUNT(*) FROM proxies WHERE status='alive' AND country IS NOT NULL GROUP BY country ORDER BY COUNT(*) DESC"
    )
    text = "**Country Counts (alive):**\n"
    for country, cnt in rows:
        text += f"{country}: {cnt}\n"
    await message.answer(text)

# ----------------------------------------------------------------------------
# Export
# ----------------------------------------------------------------------------
@router.message(Command("export"))
async def cmd_export(message: types.Message, command: CommandObject):
    args = command.args.split() if command.args else []
    fmt = args[0] if args else "txt"
    protocol = args[1] if len(args) > 1 else None
    country = args[2] if len(args) > 2 else None
    anonymity = args[3] if len(args) > 3 else None

    proxies = await db.get_proxies(status="alive", protocol=protocol, country=country, anonymity=anonymity)
    if not proxies:
        await message.answer("No alive proxies to export.")
        return

    filename = f"export_{int(time.time())}.{fmt}"
    if fmt == "txt":
        content = "\n".join([p[0] for p in proxies])
        async with aiofiles.open(filename, "w") as f:
            await f.write(content)
    elif fmt == "json":
        data = [{"proxy": p[0], "protocol": p[1], "country": p[2], "anonymity": p[3], "speed": p[4]} for p in proxies]
        async with aiofiles.open(filename, "wb") as f:
            await f.write(orjson.dumps(data, option=orjson.OPT_INDENT_2))
    elif fmt == "csv":
        content = "proxy,protocol,country,anonymity,speed\n"
        content += "\n".join([f"{p[0]},{p[1]},{p[2]},{p[3]},{p[4]}" for p in proxies])
        async with aiofiles.open(filename, "w") as f:
            await f.write(content)
    else:
        await message.answer("Unsupported format. Use txt, json, or csv.")
        return

    await message.answer_document(FSInputFile(filename))
    os.remove(filename)

# ----------------------------------------------------------------------------
# Maintenance
# ----------------------------------------------------------------------------
@router.message(Command("clear_dead"))
async def cmd_clear_dead(message: types.Message):
    await db.clear_dead()
    await message.answer("✅ Dead proxies cleared.")

@router.message(Command("clear_old"))
async def cmd_clear_old(message: types.Message, command: CommandObject):
    if not command.args:
        await message.answer("Usage: /clear_old <days>")
        return
    try:
        days = int(command.args)
        await db.clear_old(days)
        await message.answer(f"✅ Cleared proxies older than {days} days.")
    except ValueError:
        await message.answer("Invalid number.")

@router.message(Command("backup"))
async def cmd_backup(message: types.Message):
    backup_path = f"backup_{int(time.time())}.db"
    import shutil
    shutil.copy(DB_PATH, backup_path)
    await message.answer_document(FSInputFile(backup_path))
    os.remove(backup_path)

@router.message(Command("reset"))
async def cmd_reset(message: types.Message):
    await db.execute("DELETE FROM proxies")
    await db.vacuum()
    await message.answer("✅ Database reset.")

# ----------------------------------------------------------------------------
# Automation
# ----------------------------------------------------------------------------
async def auto_scrape_loop():
    while True:
        try:
            if scaper:
                await scaper.scrape_all()
        except Exception as e:
            logger.error(f"Auto scrape error: {e}")
        await asyncio.sleep(AUTO_SCRAPE_INTERVAL)

async def auto_check_loop():
    while True:
        try:
            # Capped batch instead of loading the whole table into RAM every cycle
            proxies = await db.get_all_proxies_for_check(limit=AUTO_CHECK_BATCH_SIZE)
            if proxies:
                semaphore = Semaphore(current_concurrency)
                tasks = [checker.check_proxy(p, semaphore, hint) for p, hint in proxies]
                await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            logger.error(f"Auto check error: {e}")
        await asyncio.sleep(AUTO_CHECK_INTERVAL)

async def geoip_resolver_loop():
    """Background task: periodically batch-resolves country codes for alive
    proxies that don't have one yet, via ip-api's /batch endpoint. Keeps
    GeoIP lookups off the hot path of check_proxy entirely, so bulk checks
    never stall or 429 waiting on the free-tier rate limit."""
    while True:
        try:
            proxies = await db.get_proxies_missing_country(limit=GEOIP_BATCH_SIZE * 5)
            if proxies:
                ip_to_proxies: Dict[str, List[str]] = defaultdict(list)
                for proxy in proxies:
                    ip_to_proxies[proxy.split(":")[0]].append(proxy)
                resolved = await checker.resolve_geoip_batch(list(ip_to_proxies.keys()))
                records = [
                    (cc, proxy)
                    for ip, cc in resolved.items()
                    for proxy in ip_to_proxies.get(ip, [])
                ]
                if records:
                    await db.batch_update_country(records)
                    logger.debug(f"GeoIP resolved {len(records)} proxies")
        except Exception as e:
            logger.error(f"GeoIP resolver error: {e}")
        await asyncio.sleep(GEOIP_RESOLVE_INTERVAL)

@router.message(Command("auto_scrape"))
async def cmd_auto_scrape(message: types.Message, command: CommandObject):
    global AUTO_SCRAPE_INTERVAL
    if command.args:
        try:
            hours = float(command.args)
            AUTO_SCRAPE_INTERVAL = int(hours * 3600)
        except ValueError:
            await message.answer("Invalid hours.")
            return
    if "scrape" in auto_tasks:
        auto_tasks["scrape"].cancel()
    task = asyncio.create_task(auto_scrape_loop())
    auto_tasks["scrape"] = task
    await message.answer(f"✅ Auto scrape enabled every {AUTO_SCRAPE_INTERVAL//3600} hours.")

@router.message(Command("auto_check"))
async def cmd_auto_check(message: types.Message, command: CommandObject):
    global AUTO_CHECK_INTERVAL
    if command.args:
        try:
            minutes = float(command.args)
            AUTO_CHECK_INTERVAL = int(minutes * 60)
        except ValueError:
            await message.answer("Invalid minutes.")
            return
    else:
        AUTO_CHECK_INTERVAL = 60  # default 1 min
    if "check" in auto_tasks:
        auto_tasks["check"].cancel()
    task = asyncio.create_task(auto_check_loop())
    auto_tasks["check"] = task
    await message.answer(f"✅ Auto check enabled every {AUTO_CHECK_INTERVAL//60} minutes.")

@router.message(Command("stop_auto"))
async def cmd_stop_auto(message: types.Message):
    for name, task in auto_tasks.items():
        task.cancel()
    auto_tasks.clear()
    await message.answer("✅ All auto tasks stopped.")

@router.message(Command("status"))
async def cmd_status(message: types.Message):
    status_text = f"**System Status**\n"
    status_text += f"Concurrency: {current_concurrency}\n"
    status_text += f"Test URL: {TEST_URL}\n"
    status_text += f"Auto scrape: {'enabled' if 'scrape' in auto_tasks else 'disabled'}\n"
    status_text += f"Auto check: {'enabled' if 'check' in auto_tasks else 'disabled'}\n"
    stats = await db.get_stats()
    status_text += f"Total proxies: {stats['total']}, Alive: {stats['alive']}\n"
    await message.answer(status_text)

# ----------------------------------------------------------------------------
# Advanced
# ----------------------------------------------------------------------------
@router.message(Command("scan"))
async def cmd_scan(message: types.Message, command: CommandObject):
    args = command.args.split() if command.args else []
    if len(args) < 1:
        await message.answer("Usage: /scan <url> [protocol] [amount]")
        return
    url = args[0]
    protocol = args[1] if len(args) > 1 else None
    limit = int(args[2]) if len(args) > 2 else 10

    proxies_data = await db.get_proxies(status="alive", protocol=protocol, limit=limit)
    if not proxies_data:
        await message.answer("No proxies found.")
        return

    msg = await message.answer(f"Scanning {url} with {len(proxies_data)} proxies...")
    sem = Semaphore(current_concurrency)

    async def test_one(proxy_str):
        try:
            proxy_url = f"http://{proxy_str}"
            async with checker.session.get(url, proxy=proxy_url, timeout=ClientTimeout(total=5)) as resp:
                return proxy_str, resp.status
        except Exception:
            return proxy_str, None

    tasks = [test_one(p[0]) for p in proxies_data]
    results = await asyncio.gather(*tasks)

    working = [r for r in results if r[1] == 200]
    text = f"**Scan Results for {url}**\n"
    for proxy, status in working:
        text += f"{proxy} -> {status}\n"
    text += f"\nWorking: {len(working)}/{len(proxies_data)}"
    await msg.edit_text(text)

@router.message(Command("judge"))
async def cmd_judge(message: types.Message):
    await message.answer(f"Current judge URL: {TEST_URL}")


# ============================================================================
# Main
# ============================================================================
async def on_startup():
    global checker, scaper, batch_writer_task, geoip_task
    await db.connect()
    checker = ProxyChecker()
    await checker.start()
    scaper = ProxyScraper(checker.session)
    batch_writer_task = asyncio.create_task(batch_writer())
    geoip_task = asyncio.create_task(geoip_resolver_loop())
    logger.info("Bot started, components initialized.")

async def on_shutdown():
    if batch_writer_task:
        batch_writer_task.cancel()
    if geoip_task:
        geoip_task.cancel()
    for task in auto_tasks.values():
        task.cancel()
    auto_tasks.clear()
    if checker:
        await checker.close()
    await db.close()
    logger.info("Bot shutdown.")

async def main():
    bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher(storage=MemoryStorage())
    dp.include_router(router)

    await on_startup()
    try:
        await dp.start_polling(bot)
    finally:
        await on_shutdown()

if __name__ == "__main__":
    asyncio.run(main())xies are generally anon
