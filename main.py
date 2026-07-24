import os
import re
import time
import json
import random
import base64
import asyncio
import logging
import hashlib
import aiofiles
import aiosqlite
from enum import Enum
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote, quote_plus

from selectolax.parser import HTMLParser
from curl_cffi.requests import AsyncSession

from aiogram import Bot, Dispatcher, Router, F
from aiogram.types import Message, BufferedInputFile
from aiogram.filters import Command
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties

# ==========================================
# 1. CONFIG & CONSTANTS
# ==========================================
BOT_TOKEN = "8710434434:AAHR3EcMzwmGh9dBuj8cO0NXDlPvG_05I8Y"
ADMIN_IDS = [6535041385]  # Replace with your Telegram User ID

DEFAULT_PAGES = 10
DEFAULT_RPS = 1.5
MAX_INFLIGHT_PER_PROXY = 5
MAX_QUEUE_SIZE = 100_000
WRITER_BATCH_SIZE = 500
WRITER_FLUSH_INTERVAL = 0.5

YAHOO_REGIONS = [
    "https://search.yahoo.com",
    "https://uk.search.yahoo.com",
    "https://sg.search.yahoo.com",
    "https://de.search.yahoo.com",
    "https://fr.search.yahoo.com"
]
YAHOO_FR_PARAMS = ["yfp-t", "sfp", "2", "ush-news"]

# Domain Blacklist to filter out search engines and professional sites
BLACKLISTED_DOMAINS = {
    "yahoo.com", "r.search.yahoo.com", "search.yahoo.com", "login.yahoo.com",
    "bing.com", "google.com", "duckduckgo.com", "baidu.com", "ask.com",
    "aol.com", "yandex.com", "msn.com", "wikipedia.org", "youtube.com",
    "facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com",
    "tiktok.com", "pinterest.com", "reddit.com", "amazon.com"
}

IDENTITY_BUNDLES = [
    {
        "tls": "chrome120",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "lang": "en-US,en;q=0.9",
        "sec_ch_ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
    },
    {
        "tls": "safari17_0",
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "lang": "en-US,en;q=0.9",
        "sec_ch_ua": None
    },
    {
        "tls": "edge99",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36 Edg/99.0.4844.74",
        "lang": "en-US,en;q=0.9",
        "sec_ch_ua": '"Not A;Brand";v="99", "Chromium";v="99", "Microsoft Edge";v="99"'
    },
    {
        "tls": "firefox120",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "lang": "en-US,en;q=0.9",
        "sec_ch_ua": None
    }
]

@dataclass
class Stats:
    total_requests: int = 0
    total_urls: int = 0
    failed_requests: int = 0
    start_time: float = 0.0

# ==========================================
# 2. PARSER & URL FILTERING
# ==========================================
def is_blacklisted(url: str) -> bool:
    try:
        netloc = urlparse(url).netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        for domain in BLACKLISTED_DOMAINS:
            if netloc == domain or netloc.endswith("." + domain):
                return True
        return False
    except Exception:
        return True

def decode_yahoo_url(raw_url: str) -> str:
    if not raw_url:
        return ""
    
    match = re.search(r'/RU=([^/]+)/R=', raw_url)
    if match:
        b64_str = match.group(1)
        missing_padding = len(b64_str) % 4
        if missing_padding:
            b64_str += '=' * (4 - missing_padding)
        try:
            decoded = base64.urlsafe_b64decode(b64_str).decode('utf-8')
            if decoded.startswith('http'):
                return decoded
        except Exception:
            pass

    match = re.search(r'RU=([^&]+)', raw_url)
    if match:
        decoded = unquote(match.group(1))
        if decoded.startswith('http'):
            return decoded

    if raw_url.startswith('http') and 'yahoo.com' not in raw_url:
        return raw_url

    return ""

def parse_yahoo_html(html_text: str):
    tree = HTMLParser(html_text)
    selectors = ['div#web ol li a.ac-1th', 'a.title', 'div.compTitle h3 a', 'a[data-boost]']
    
    found_urls = set()
    for selector in selectors:
        nodes = tree.css(selector)
        for node in nodes:
            href = node.attributes.get('href', '')
            if not href:
                continue
            
            url = decode_yahoo_url(href)
            if url and url not in found_urls:
                if is_blacklisted(url):
                    continue
                if url.startswith('javascript:') or url.startswith('mailto:'):
                    continue
                found_urls.add(url)
                yield url

# ==========================================
# 3. STORAGE & DEDUP
# ==========================================
class DedupManager:
    def __init__(self):
        self.seen = set()

    def normalize_url(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            path = parsed.path.rstrip('/')
            query = parse_qs(parsed.query)
            clean_query = {k: v for k, v in query.items() if not k.startswith(('utm_', 'ref', 'fr'))}
            query_str = urlencode(clean_query, doseq=True)
            return urlunparse((scheme, netloc, path, '', query_str, ''))
        except Exception:
            return url

    def is_duplicate(self, url: str) -> bool:
        norm = self.normalize_url(url)
        url_hash = hashlib.sha256(norm.encode()).hexdigest()
        if url_hash in self.seen:
            return True
        self.seen.add(url_hash)
        return False

class Database:
    def __init__(self, db_path: str = "yahoo_dorker.db"):
        self.db_path = db_path
        self.queue = asyncio.Queue(maxsize=100_000)
        self.dedup = DedupManager()
        self.writer_task = None
        self.db = None

    async def init(self):
        self.db = await aiosqlite.connect(self.db_path)
        self.db.row_factory = aiosqlite.Row
        await self.db.execute("PRAGMA journal_mode=WAL;")
        await self.db.execute("PRAGMA synchronous=NORMAL;")
        await self.db.execute("PRAGMA temp_store=MEMORY;")
        await self.db.execute("""
            CREATE TABLE IF NOT EXISTS urls (
                hash TEXT PRIMARY KEY,
                url TEXT,
                dork TEXT,
                ts INTEGER
            )
        """)
        await self.db.commit()
        self.writer_task = asyncio.create_task(self._writer_loop())

    async def _writer_loop(self):
        batch = []
        while True:
            try:
                item = await asyncio.wait_for(self.queue.get(), timeout=WRITER_FLUSH_INTERVAL)
                batch.append(item)
                while len(batch) < WRITER_BATCH_SIZE:
                    try:
                        item = self.queue.get_nowait()
                        batch.append(item)
                    except asyncio.QueueEmpty:
                        break
            except asyncio.TimeoutError:
                pass

            if batch:
                await self._insert_batch(batch)
                batch.clear()

    async def _insert_batch(self, batch):
        sql = "INSERT OR IGNORE INTO urls (hash, url, dork, ts) VALUES (?, ?, ?, ?)"
        await self.db.executemany(sql, batch)
        await self.db.commit()

    async def add_url(self, url: str, dork: str):
        if self.dedup.is_duplicate(url):
            return False
        norm = self.dedup.normalize_url(url)
        url_hash = hashlib.sha256(norm.encode()).hexdigest()
        await self.queue.put((url_hash, url, dork, int(time.time())))
        return True

# ==========================================
# 4. PROXY POOL
# ==========================================
class ProxyState(Enum):
    CLOSED = 1
    OPEN = 2
    HALF_OPEN = 3

@dataclass
class Proxy:
    proxy_str: str
    identity: dict
    state: ProxyState = ProxyState.CLOSED
    failure_count: int = 0
    last_failure_time: float = 0.0
    cooldown: int = 60
    inflight: int = 0
    tokens: float = field(default_factory=lambda: DEFAULT_RPS)
    last_token_update: float = field(default_factory=time.time)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    
    async def acquire(self, current_rps: float):
        async with self.lock:
            now = time.time()
            elapsed = now - self.last_token_update
            self.tokens = min(current_rps, self.tokens + (elapsed * current_rps))
            self.last_token_update = now
            
            if self.tokens < 1.0:
                return False
            
            if self.state == ProxyState.OPEN:
                if now - self.last_failure_time > self.cooldown:
                    self.state = ProxyState.HALF_OPEN
                else:
                    return False
            
            if self.inflight >= MAX_INFLIGHT_PER_PROXY:
                return False
                
            self.tokens -= 1.0
            self.inflight += 1
            return True

    async def release(self, success: bool):
        async with self.lock:
            self.inflight -= 1
            if success:
                self.failure_count = 0
                self.state = ProxyState.CLOSED
                self.cooldown = 60
            else:
                self.failure_count += 1
                self.last_failure_time = time.time()
                if self.failure_count >= 3:
                    self.state = ProxyState.OPEN
                    self.cooldown = min(self.cooldown * 2, 600)

class ProxyPool:
    def __init__(self):
        self.proxies: list[Proxy] = []
        
    def load_proxies(self, proxy_lines: list[str]):
        self.proxies.clear()
        for line in proxy_lines:
            line = line.strip()
            if not line or ':' not in line:
                continue
            identity = random.choice(IDENTITY_BUNDLES)
            self.proxies.append(Proxy(proxy_str=line, identity=identity))
            
    async def get_proxy(self, current_rps: float) -> Proxy | None:
        available = []
        for p in self.proxies:
            if await p.acquire(current_rps):
                available.append(p)
        if not available:
            return None
        return min(available, key=lambda p: p.inflight)

    async def check_proxies(self):
        alive = sum(1 for p in self.proxies if p.state == ProxyState.CLOSED)
        return {"alive": alive, "dead": len(self.proxies) - alive, "total": len(self.proxies)}

# ==========================================
# 5. DORK ENGINE
# ==========================================
class DorkEngine:
    def __init__(self, db: Database):
        self.db = db
        self.pool = ProxyPool()
        self.queue = asyncio.Queue(maxsize=100_000)
        self.stop_event = asyncio.Event()
        self.pause_event = asyncio.Event()
        self.pause_event.set()
        self.workers = []
        self.stats = Stats()
        self.current_speed = DEFAULT_RPS
        
    async def load_dorks(self, dorks: list[str], pages: int):
        for dork in dorks:
            dork = dork.strip()
            if not dork:
                continue
            for page in range(1, pages + 1):
                await self.queue.put((dork, page))
                
    async def start(self, num_workers: int = 50):
        self.stop_event.clear()
        self.pause_event.set()
        self.stats.start_time = time.time()
        
        if not self.workers:
            for i in range(num_workers):
                self.workers.append(asyncio.create_task(self._worker(i)))
                
    async def stop(self):
        self.stop_event.set()
        for w in self.workers:
            w.cancel()
        self.workers.clear()
        
    def pause(self):
        self.pause_event.clear()
        
    def resume(self):
        self.pause_event.set()
        
    def set_speed(self, rps: float):
        self.current_speed = rps
            
    async def _worker(self, worker_id: int):
        async with AsyncSession() as session:
            while not self.stop_event.is_set():
                await self.pause_event.wait()
                
                try:
                    dork, page = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                    
                proxy = await self.pool.get_proxy(self.current_speed)
                if not proxy:
                    await self.queue.put((dork, page))
                    await asyncio.sleep(1.0)
                    continue
                    
                success = False
                try:
                    url = self._build_yahoo_url(dork, page)
                    headers = {
                        "User-Agent": proxy.identity["ua"],
                        "Accept-Language": proxy.identity["lang"],
                        "Referer": random.choice(["https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/"])
                    }
                    if proxy.identity["sec_ch_ua"]:
                        headers["Sec-CH-UA"] = proxy.identity["sec_ch_ua"]
                        
                    proxies = {"http": proxy.proxy_str, "https": proxy.proxy_str}
                    
                    r = await session.get(
                        url, 
                        headers=headers, 
                        proxies=proxies, 
                        impersonate=proxy.identity["tls"], 
                        timeout=10
                    )
                    
                    self.stats.total_requests += 1
                    
                    if r.status_code == 200:
                        for extracted_url in parse_yahoo_html(r.text):
                            if await self.db.add_url(extracted_url, dork):
                                self.stats.total_urls += 1
                        success = True
                    elif r.status_code in (403, 429, 999):
                        success = False
                    else:
                        success = True 
                        
                except Exception as e:
                    success = False
                finally:
                    await proxy.release(success)
                    self.queue.task_done()
                    if not success:
                        self.stats.failed_requests += 1

    def _build_yahoo_url(self, dork: str, page: int) -> str:
        region = random.choice(YAHOO_REGIONS)
        fr = random.choice(YAHOO_FR_PARAMS)
        offset = (page - 1) * 10 + 1
        return f"{region}/search?p={quote_plus(dork)}&pz=10&b={offset}&fr={fr}"

# ==========================================
# 6. TELEGRAM BOT
# ==========================================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher()
router = Router()
dp.include_router(router)

db = Database()
engine = DorkEngine(db)
user_sessions = {}

def admin_only(func):
    async def wrapper(message: Message):
        if message.from_user.id not in ADMIN_IDS:
            return await message.reply("⛔ Unauthorized.")
        return await func(message)
    return wrapper

@router.message(Command("help"))
@admin_only
async def cmd_help(message: Message):
    await message.reply(
        "📖 <b>Yahoo Dorker Commands</b>\n"
        "/pages <n> - Set pages per dork (1-50)\n"
        "/setproxys - Upload .txt of proxies to load\n"
        "/checkproxys - Check alive/dead proxies\n"
        "/setspeed <rps> - Set per-proxy req/sec (default 1.5)\n"
        "/status - Live stats (updates every 2s)\n"
        "/pause - Pause engine\n"
        "/resume - Resume engine\n"
        "/stop - Stop engine and export results\n"
        "/export - Export current results to file\n"
        "/reset - Full reset queue & DB"
    )

@router.message(Command("pages"))
@admin_only
async def cmd_pages(message: Message):
    try:
        n = int(message.text.split()[1])
        if 1 <= n <= 50:
            user_sessions[message.from_user.id] = {"pages": n}
            await message.reply(f"✅ Pages set to {n}. Send .txt file with dorks to begin.")
        else:
            await message.reply("❌ Pages must be 1-50.")
    except:
        await message.reply("Usage: /pages <n>")

@router.message(Command("setproxys"))
@admin_only
async def cmd_setproxys(message: Message):
    await message.reply("📤 Please send a .txt file with proxies (ip:port or user:pass@ip:port).")

@router.message(F.document)
@admin_only
async def handle_document(message: Message):
    file_id = message.document.file_id
    file = await bot.get_file(file_id)
    
    if not file.file_name.endswith('.txt'):
        return await message.reply("❌ Only .txt files supported.")
        
    file_path = await bot.download_file(file.file_path)
    content = file_path.read().decode('utf-8', errors='ignore').splitlines()
    
    if "proxy" in message.caption.lower() if message.caption else False:
        engine.pool.load_proxies(content)
        await message.reply(f"✅ Loaded {len(engine.pool.proxies)} proxies.")
    else:
        pages = user_sessions.get(message.from_user.id, {}).get("pages", DEFAULT_PAGES)
        await engine.load_dorks(content, pages)
        if not engine.workers:
            await engine.start(num_workers=50)
        await message.reply(f"✅ Loaded {len(content)} dorks. Engine started with {pages} pages each.")

@router.message(Command("checkproxys"))
@admin_only
async def cmd_check(message: Message):
    stats = await engine.pool.check_proxies()
    await message.reply(f"🌐 Proxies: {stats['alive']} Alive / {stats['dead']} Dead (Total: {stats['total']})")

@router.message(Command("setspeed"))
@admin_only
async def cmd_speed(message: Message):
    try:
        rps = float(message.text.split()[1])
        engine.set_speed(rps)
        await message.reply(f"✅ Speed set to {rps} req/sec per proxy.")
    except:
        await message.reply("Usage: /setspeed <rps>")

@router.message(Command("pause"))
@admin_only
async def cmd_pause(message: Message):
    engine.pause()
    await message.reply("⏸ Engine paused.")

@router.message(Command("resume"))
@admin_only
async def cmd_resume(message: Message):
    engine.resume()
    await message.reply("▶️ Engine resumed.")

@router.message(Command("status"))
@admin_only
async def cmd_status(message: Message):
    msg = await message.reply("⏳ Gathering stats...")
    for _ in range(15):  # Update for 30 seconds
        elapsed = time.time() - engine.stats.start_time
        rps = engine.stats.total_requests / elapsed if elapsed > 0 else 0
        ups = engine.stats.total_urls / elapsed if elapsed > 0 else 0
        qsize = engine.queue.qsize()
        
        text = (
            f"📊 <b>Live Status</b>\n"
            f"RPS: <b>{rps:.1f}</b> | UPS: <b>{ups:.1f}</b>\n"
            f"Queue: <b>{qsize}</b>\n"
            f"Total Reqs: {engine.stats.total_requests}\n"
            f"Total URLs: {engine.stats.total_urls}\n"
            f"Failed Reqs: {engine.stats.failed_requests}"
        )
        
        try:
            await msg.edit_text(text)
        except Exception:
            pass 
        await asyncio.sleep(2.0)
        
@router.message(Command("export"))
@admin_only
async def cmd_export(message: Message):
    await message.reply("📦 Exporting URLs...")
    
    async with aiofiles.open("urls_export.txt", "w") as f:
        async with db.db.execute("SELECT url FROM urls") as cursor:
            while True:
                rows = await cursor.fetchmany(10000)
                if not rows:
                    break
                for row in rows:
                    await f.write(row[0] + "\n")
                    
    with open("urls_export.txt", "rb") as f:
        await message.reply_document(BufferedInputFile(f.read(), filename="urls_export.txt"))
    os.remove("urls_export.txt")

@router.message(Command("stop"))
@admin_only
async def cmd_stop(message: Message):
    await message.reply("🛑 Stopping engine...")
    await engine.stop()
    await cmd_export(message)

@router.message(Command("reset"))
@admin_only
async def cmd_reset(message: Message):
    global engine
    await engine.stop()
    engine = DorkEngine(db)
    await db.db.execute("DELETE FROM urls")
    await db.db.commit()
    await message.reply("🔄 System reset. DB cleared.")

async def main():
    logger.info("Initializing Database...")
    await db.init()
    logger.info("Starting Bot...")
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
