"""
Telegram Bot + Website Platform — bot.py
==========================================
BU FAYL: shu sessiyada Claude bilan birga yozilgan barcha kod bo'laklarining
yig'indisi. To'liq ishlaydigan holatda EMAS — ba'zi joylar orasidagi
bog'lanish (masalan bir nechta db_init() chaqiruvi bitta funksiyaga
birlashtirilishi kerak) qo'lda tekshirilishi kerak. Buni "davom ettirish
uchun konspekt kod" sifatida ishlating — yangi Claude sessiyasida
PROJECT_BRIEF.md bilan birga yuklang.

Bo'limlar tartibi: CONFIG -> DATABASE (barcha jadvallar) -> SECURITY/CRYPTO
-> PROVIDER MANAGER -> SERVER MANAGER -> WEB (login/dashboard/click) ->
BOT: keyboards/start/nav -> BOT YARATISH FSM -> BOTLARIM -> AI SOZLAMALARI
-> USER AI (api kalitlar + monitoring) -> ADMIN AI -> BALANS/CLICK ->
ADMIN PANEL (users/servers/bots) -> MAIN
"""

# ===================== IMPORTS =====================
import asyncio
import logging
import os
import json
import time
import hashlib
import hmac
import base64
import secrets
import signal
import gzip
import zipfile
import shutil
from decimal import Decimal, ROUND_HALF_UP
import io
import re
import urllib.parse
from pathlib import Path
from datetime import datetime, timedelta, timezone
from abc import ABC, abstractmethod

import aiosqlite
import aiohttp as aiohttp_client
from aiohttp import web
from aiogram import Bot, Dispatcher, Router, F
from aiogram.filters import Command
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.context import FSMContext
from aiogram.types import (
    InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery, Message, WebAppInfo,
    ReplyKeyboardMarkup, KeyboardButton
)
from cryptography.fernet import Fernet

# .env faylini os.environ'ga yuklaydi — bu chaqiruv os.getenv(...) bilan
# CONFIG bo'limi boshlanishidan OLDIN turishi shart, aks holda BOT_TOKEN va
# boshqa barcha sozlamalar doim None bo'lib qoladi (TokenValidationError
# aynan shu sababdan chiqadi). `pip install python-dotenv` kerak.
from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ===================== CONFIG =====================
BOT_TOKEN = os.getenv("BOT_TOKEN")
BOT_USERNAME = os.getenv("BOT_USERNAME")
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("WEB_PORT", "6000"))
WEB_DOMAIN = os.getenv("WEB_DOMAIN", "example.uz")
SESSION_SECRET = os.getenv("SESSION_SECRET")
SUPER_ADMIN_TELEGRAM_ID = int(os.getenv("SUPER_ADMIN_TELEGRAM_ID", "0"))
TOKEN_ENCRYPTION_KEY = os.getenv("TOKEN_ENCRYPTION_KEY")  # Fernet.generate_key()
# SMS/bildirishnoma monitoring qurilmasi (MacroDroid va h.k.) shu maxfiy tokenni
# har bir so'rovda X-Payment-Secret headerida yuborishi shart — token mos
# kelmasa so'rov 401 bilan rad etiladi. /payment/notify hech qachon ochiq,
# tekshiruvsiz endpoint bo'lmasligi kerak (secrets.compare_digest orqali
# doimiy-vaqtli solishtiriladi, timing-attackdan himoya uchun).
PAYMENT_WEBHOOK_SECRET = os.getenv("PAYMENT_WEBHOOK_SECRET", "")

DB_PATH = "data.db"
LOGS_DIR = Path("bot_logs")
LOGS_DIR.mkdir(exist_ok=True)

_fernet = Fernet(TOKEN_ENCRYPTION_KEY) if TOKEN_ENCRYPTION_KEY else None


def utcnow() -> datetime:
    """utcnow() o'rniga: xuddi shu (timezone-naive, UTC) qiymatni
    qaytaradi, lekin Python 3.12+ dagi DeprecationWarning'siz. Butun faylda
    saqlanadigan/solishtiriladigan barcha vaqtlar naive bo'lgani uchun bu yerda
    ataylab .replace(tzinfo=None) qilinadi — aks holda DB'dan o'qilgan naive
    datetime'lar bilan solishtirishda 'can't compare offset-naive and
    offset-aware datetimes' xatosi chiqadi."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


from contextlib import asynccontextmanager

@asynccontextmanager
async def db_connect():
    """aiosqlite.connect(DB_PATH) o'rniga: xuddi shunday async context manager,
    lekin har bir connection ochilganda darhol PRAGMA busy_timeout=10000 ni
    ham qo'llaydi. MUHIM: journal_mode=WAL fayl darajasida saqlanib qoladi
    (bir marta db_init() da o'rnatilgani yetarli), lekin busy_timeout HAR BIR
    yangi connection uchun alohida-alohida o'rnatilishi shart — aks holda
    o'sha connection uchun u 0 (ya'ni band bo'lsa DARHOL "database is locked"
    xatosi) bo'lib qoladi. Aynan shu sabab fon vazifalar (billing_monitor_loop,
    supervisor_loop va h.k.) bazani band qilib turgan paytda foydalanuvchi
    buyruqlariga (masalan /start) hech qanday javob kelmasligi mumkin edi."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA busy_timeout=10000")
        yield db


class DBWriteQueue:
    """Barcha INSERT/UPDATE/DELETE shu yagona worker orqali ketma-ket
    bajariladi -> "database is locked" butunlay yo'qoladi, chunki bir
    vaqtning o'zida faqat bitta connection yozadi. Har bir so'rov o'z
    mustaqil tranzaksiyasida ishlaydi (yoki execute_transaction orqali
    berilgan ro'yxat — bitta atomik tranzaksiyada) — bitta so'rovning
    xatosi navbatdagi boshqa mustaqil so'rovlarga ta'sir qilmaydi.
    SELECT'lar bunga bog'liq emas, alohida db_connect() orqali parallel
    davom etadi (WAL rejimi buni qo'llab-quvvatlaydi)."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._queue: asyncio.Queue = asyncio.Queue()
        self._conn: aiosqlite.Connection | None = None
        self._worker_task: asyncio.Task | None = None

    async def start(self):
        self._conn = await aiosqlite.connect(self.db_path)
        await self._conn.execute("PRAGMA busy_timeout=10000")
        self._worker_task = asyncio.create_task(self._worker(), name="db_write_worker")
        logger.info("DBWriteQueue ishga tushdi")

    async def stop(self):
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        if self._conn:
            await self._conn.close()

    async def _worker(self):
        while True:
            statements, fut = await self._queue.get()
            try:
                if len(statements) == 1:
                    sql, params = statements[0]
                    cur = await self._conn.execute(sql, params)
                    await self._conn.commit()
                    result = (cur.lastrowid, cur.rowcount)
                else:
                    await self._conn.execute("BEGIN IMMEDIATE")
                    result = (None, None)
                    for sql, params in statements:
                        cur = await self._conn.execute(sql, params)
                        result = (cur.lastrowid, cur.rowcount)
                    await self._conn.commit()
            except Exception as e:
                await self._conn.rollback()
                if not fut.done():
                    fut.set_exception(e)
            else:
                if not fut.done():
                    fut.set_result(result)
            finally:
                self._queue.task_done()

    async def execute(self, sql: str, params: tuple = ()) -> tuple:
        """Bitta INSERT/UPDATE/DELETE. (lastrowid, rowcount) qaytaradi."""
        fut = asyncio.get_running_loop().create_future()
        await self._queue.put(([(sql, params)], fut))
        return await fut

    async def execute_transaction(self, statements: list[tuple[str, tuple]]) -> tuple:
        """Bir nechta yozuvni BITTA tranzaksiyada bajaradi (hammasi yoki hech biri)."""
        fut = asyncio.get_running_loop().create_future()
        await self._queue.put((statements, fut))
        return await fut


bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
user_router = Router()
write_queue = DBWriteQueue(DB_PATH)


# ===================== SECURITY: TOKEN / SSH KEY ENCRYPTION =====================
def encrypt_token(value: str) -> bytes:
    if _fernet is None:
        raise RuntimeError(
            "TOKEN_ENCRYPTION_KEY .env faylida sozlanmagan — bot token/SSH kalit/"
            "karta raqami kabi maxfiy ma'lumotlarni shifrlab bo'lmaydi. "
            "`python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"` "
            "bilan kalit generatsiya qilib, .env'ga TOKEN_ENCRYPTION_KEY=... qilib yozing."
        )
    return _fernet.encrypt(value.encode())

def decrypt_token(value_encrypted: bytes) -> str:
    if _fernet is None:
        raise RuntimeError("TOKEN_ENCRYPTION_KEY .env faylida sozlanmagan — shifrni ochib bo'lmaydi.")
    return _fernet.decrypt(value_encrypted).decode()

def mask_token(token: str) -> str:
    return f"••••••••{token[-4:]}" if len(token) > 4 else "••••••••"


# ===================== RATE LIMITING =====================
# Sodda xotira-ichi (in-memory) sliding-window rate limiter. Bitta jarayon
# (single process) uchun yetarli — agar kelajakda botni bir nechta worker
# processda ishga tushirish kerak bo'lsa, buni Redis kabi umumiy xotiraga
# ko'chirish kerak bo'ladi (hozircha loyihada bitta process bor).
from collections import defaultdict

class RateLimiter:
    def __init__(self):
        self._hits: dict[str, list[float]] = defaultdict(list)
        # (limit, window_seconds) — kategoriya bo'yicha
        self.limits: dict[str, tuple[int, int]] = {
            "bot_user": (20, 10),      # oddiy foydalanuvchi: 20 ta update / 10s
            "bot_admin": (60, 10),     # adminlarga kengroq limit
            "web_api": (60, 60),       # /api/ va sahifalar: 60 so'rov / 60s (IP bo'yicha)
            "payment_webhook": (30, 60),  # /payment/notify: 30 so'rov / 60s (IP bo'yicha)
        }

    def check(self, key: str, category: str) -> bool:
        """True — ruxsat berilgan, False — limit oshgan (so'rov rad etilishi kerak)."""
        limit, window = self.limits.get(category, (30, 60))
        now = time.monotonic()
        bucket = self._hits[key]
        # Eskirgan urinishlarni tashlab yuborish (sliding window)
        cutoff = now - window
        i = 0
        while i < len(bucket) and bucket[i] < cutoff:
            i += 1
        if i:
            del bucket[:i]
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True

rate_limiter = RateLimiter()

async def rate_limit_bot_middleware(handler, event, data):
    """dp.message va dp.callback_query uchun umumiy outer middleware — har bir
    handlerga alohida qo'shish shart emas, barcha update'lar shu orqali o'tadi.
    Admin bo'lsa kengroq limit (bot_admin), oddiy foydalanuvchi uchun torroq
    (bot_user). is_admin() kutilmoqda — bu funksiya pastda ADMIN PANEL
    bo'limida aniqlangan (runtime'da chaqirilganda allaqachon mavjud)."""
    user = getattr(event, "from_user", None)
    logger.info(f"🔎 UPDATE KELDI: type={type(event).__name__} user_id={getattr(user, 'id', None)} text={getattr(event, 'text', None)!r}")
    if user is not None:
        try:
            is_admin_user = await is_admin(user.id)
        except Exception:
            is_admin_user = False
        category = "bot_admin" if is_admin_user else "bot_user"
        if not rate_limiter.check(f"bot:{user.id}", category):
            try:
                await event.answer("⏳ Juda ko'p so'rov yubordingiz. Bir necha soniya kutib, qaytadan urinib ko'ring.")
            except Exception:
                pass
            return
    try:
        return await handler(event, data)
    except Exception:
        logger.exception(f"❌ HANDLER XATOSI: user_id={getattr(user, 'id', None)}")
        try:
            await event.answer("⚠️ Kutilmagan xatolik yuz berdi. Birozdan so'ng qayta urinib ko'ring.")
        except Exception:
            pass


# ===================== DATABASE: BARCHA JADVALLAR =====================
async def db_init():
    async with db_connect() as db:
        # 🛡️ WAL rejimi: bir nechta fon vazifasi (supervisor_loop, billing_monitor_loop,
        # resource_monitor_loop va h.k.) HAMMASI shu bitta sqlite faylga bir vaqtda
        # ulanadi (har biri o'z aiosqlite.connect() chaqiruvi bilan). Standart
        # "rollback journal" rejimida bitta yozuvchi boshqa hamma o'qish/yozishni
        # bloklab qo'yishi mumkin — bu ayni "database is locked" xatosi va shuning
        # oqibatida foydalanuvchi buyruqlariga (masalan /start) javob kelmay qolishi
        # mumkin. WAL bir nechta o'qiydigan + bitta yozadigan ulanishga bir vaqtda
        # ishlashga ruxsat beradi. Bu sozlama DB fayl darajasida saqlanadi — bir
        # marta shu yerda o'rnatish yetarli, har bir keyingi connect() uni meros
        # qilib oladi.
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA busy_timeout=10000")  # 10 soniya (ms) — vaqtincha lock bo'lsa kutadi, darhol xato bermaydi
        await db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER UNIQUE NOT NULL,
                username TEXT,
                first_name TEXT,
                email TEXT,
                balance INTEGER DEFAULT 0,
                is_admin INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                balance_zero_at TEXT,
                warning_1_sent INTEGER DEFAULT 0,
                warning_2_sent INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                ip TEXT NOT NULL,
                ssh_port INTEGER DEFAULT 22,
                ssh_user TEXT DEFAULT 'root',
                ssh_key_encrypted BLOB,
                os TEXT,
                cpu_cores INTEGER,
                ram_gb INTEGER,
                disk_gb INTEGER,
                bandwidth TEXT,
                monthly_price INTEGER DEFAULT 0,
                bot_limit INTEGER DEFAULT 10,
                storage_limit_gb INTEGER DEFAULT 50,
                status TEXT DEFAULT 'available',
                provider TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS bots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                username TEXT NOT NULL,
                token_encrypted BLOB NOT NULL,
                server_id INTEGER,
                status TEXT DEFAULT 'stopped',
                health TEXT DEFAULT 'ok',
                health_reason TEXT,
                pid INTEGER,
                stopped_reason TEXT,
                allocated_ram_mb INTEGER DEFAULT 2048,
                overage_rate_per_gb INTEGER DEFAULT 5000,
                log_path TEXT,
                started_at TEXT,
                stopped_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_id) REFERENCES users(id),
                FOREIGN KEY (server_id) REFERENCES servers(id)
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                bot_id INTEGER,
                type TEXT NOT NULL,
                provider TEXT,
                provider_trans_id TEXT UNIQUE,
                merchant_trans_id TEXT,
                amount INTEGER NOT NULL,
                status TEXT DEFAULT 'pending',
                description TEXT,
                receipt_photo_id TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS click_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                merchant_id TEXT,
                service_id TEXT,
                secret_key_encrypted BLOB,
                callback_url TEXT,
                is_production INTEGER DEFAULT 0,
                min_amount INTEGER DEFAULT 5000,
                max_amount INTEGER DEFAULT 5000000,
                updated_at TEXT
            )
        """)
        await db.execute("INSERT OR IGNORE INTO click_settings (id) VALUES (1)")

        # ---- Payment Manager (karta-karta + SMS monitoring, Click'dan mustaqil) ----
        # Barcha summalar TIYINDA (INTEGER, 1 so'm = 100 tiyin) saqlanadi — FLOAT
        # emas (moliyada yaxlitlash xatosi xavfi). Kasrli so'm (masalan "14.03")
        # endi qabul qilinadi va tiyingacha aniq solishtiriladi; 2 xonadan ortiq
        # kasr yoki noto'g'ri format rad etiladi. payment_settings.allow_fractional
        # endi standart YOQILGAN (1) — pastga qarang.
        await db.execute("""
            CREATE TABLE IF NOT EXISTS payment_cards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                card_number_encrypted BLOB NOT NULL,
                card_last4 TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                monitor_device_name TEXT,
                last_notification_at TEXT,
                last_detected_transaction_id TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS payment_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                min_amount INTEGER DEFAULT 50000,
                max_amount INTEGER DEFAULT 5000000,
                payment_ttl_minutes INTEGER DEFAULT 5,
                max_concurrent_orders INTEGER DEFAULT 1,
                allow_fractional INTEGER DEFAULT 1,
                sms_monitoring_enabled INTEGER DEFAULT 0,
                ai_supervisor_enabled INTEGER DEFAULT 1,
                updated_at TEXT
            )
        """)
        await db.execute("INSERT OR IGNORE INTO payment_settings (id) VALUES (1)")

        await db.execute("""
            CREATE TABLE IF NOT EXISTS payment_orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_ref TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                bot_id INTEGER,
                amount INTEGER NOT NULL,
                provider TEXT,
                status TEXT DEFAULT 'draft',
                lock_card_id INTEGER,
                lock_expires_at TEXT,
                description TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (lock_card_id) REFERENCES payment_cards(id)
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS payment_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id INTEGER NOT NULL,
                provider TEXT NOT NULL,
                provider_trans_id TEXT,
                event_type TEXT NOT NULL,
                amount INTEGER NOT NULL,
                result TEXT NOT NULL,
                reason TEXT,
                raw_payload TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (order_id) REFERENCES payment_orders(id),
                UNIQUE (provider, provider_trans_id)
            )
        """)

        # fraud_events — 🛡️ Firibgarlik himoyasi qoidalari ishga tushgan har bir
        # hodisani yozadi (velocity, katta summa va h.k.). Bu jurnal ham admin
        # UI'da ko'rsatiladi, ham 🤖 AI Payment Supervisor'ning heuristik
        # hisobotiga xomashyo bo'lib xizmat qiladi.
        await db.execute("""
            CREATE TABLE IF NOT EXISTS fraud_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                order_id INTEGER,
                rule_key TEXT NOT NULL,
                severity TEXT NOT NULL,
                details TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS billing_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                grace_period_hours INTEGER DEFAULT 24,
                warning_1_enabled INTEGER DEFAULT 1,
                warning_2_enabled INTEGER DEFAULT 1,
                warning_2_hours_before INTEGER DEFAULT 12,
                auto_stop_enabled INTEGER DEFAULT 1,
                auto_restart_enabled INTEGER DEFAULT 1
            )
        """)
        await db.execute("INSERT OR IGNORE INTO billing_settings (id) VALUES (1)")

        await db.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                model_name TEXT NOT NULL,
                display_name TEXT NOT NULL,
                api_key_encrypted BLOB NOT NULL,
                priority INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                is_user_selectable INTEGER DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS user_api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                provider TEXT NOT NULL,
                model_name TEXT,
                label TEXT NOT NULL,
                api_key_encrypted BLOB NOT NULL,
                status TEXT DEFAULT 'unchecked',
                last_checked_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS bot_settings (
                bot_id INTEGER PRIMARY KEY,
                model_key_id INTEGER,
                character TEXT DEFAULT 'neytral',
                response_style TEXT DEFAULT 'oddiy',
                system_prompt TEXT DEFAULT '',
                language TEXT DEFAULT 'uz',
                response_length TEXT DEFAULT 'ortacha',
                memory_enabled INTEGER DEFAULT 1,
                api_fallback_enabled INTEGER DEFAULT 1,
                user_api_key_id INTEGER,
                watching_enabled INTEGER DEFAULT 0,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (bot_id) REFERENCES bots(id),
                FOREIGN KEY (model_key_id) REFERENCES api_keys(id),
                FOREIGN KEY (user_api_key_id) REFERENCES user_api_keys(id)
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS bot_ai_monitor_state (
                bot_id INTEGER PRIMARY KEY,
                last_error_hash TEXT,
                last_notified_at TEXT,
                last_ai_call_at TEXT,
                consecutive_same_error INTEGER DEFAULT 0,
                FOREIGN KEY (bot_id) REFERENCES bots(id)
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT,
                action TEXT,
                result TEXT,
                reason TEXT,
                target TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # backups jadvali (.db backup/restore bosqichi uchun) — quyida yaratiladi
        await db.execute("""
            CREATE TABLE IF NOT EXISTS backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_type TEXT NOT NULL,      -- 'system' / 'user' / 'bot'
                owner_id INTEGER NOT NULL,     -- system=0, user=users.id, bot=bots.id
                backup_type TEXT NOT NULL,     -- 'full' / 'bot_data' / 'user_data'
                file_path TEXT NOT NULL,
                file_size INTEGER,
                checksum TEXT,
                status TEXT DEFAULT 'creating',  -- creating / ready / failed / restoring
                created_by INTEGER,              -- amalni boshlagan telegram_id
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                restored_at TEXT,
                encrypted INTEGER DEFAULT 0
            )
        """)

        await db.execute("""
            CREATE TABLE IF NOT EXISTS backup_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                auto_backup_enabled INTEGER DEFAULT 0,
                interval_days INTEGER DEFAULT 7,
                retention_count INTEGER DEFAULT 7,
                last_auto_backup_at TEXT
            )
        """)
        await db.execute("INSERT OR IGNORE INTO backup_settings (id) VALUES (1)")

        # --- MIGRATION: backup_settings'ga shifrlash sozlamasi ---
        try:
            await db.execute("ALTER TABLE backup_settings ADD COLUMN encryption_enabled INTEGER DEFAULT 1")
        except aiosqlite.OperationalError as e:
            if "duplicate column" not in str(e).lower():
                raise
        try:
            await db.execute("ALTER TABLE backups ADD COLUMN encrypted INTEGER DEFAULT 0")
        except aiosqlite.OperationalError as e:
            if "duplicate column" not in str(e).lower():
                raise

        # --- MIGRATION: bots'ga Supervisor uchun crash-kuzatuv ustunlari.
        # consecutive_crash_count — ketma-ket (tuzalmagan) crash soni, bot
        # muvaffaqiyatli sog'lom bo'lganda 0'ga qaytariladi. Backoff jadvali
        # va SUPERVISOR_CRASH_ALERT_EVERY shu ustunga tayanadi.
        # desired_state — foydalanuvchi/tizim NIYATI ('running'/'stopped'):
        # Supervisor faqat desired_state='running' bo'lgan botlarni crashdan
        # keyin avtomatik tiklaydi; foydalanuvchi ⏹ Stop bossa desired_state
        # 'stopped'ga o'tadi va Supervisor uni boshqa tegmaydi.
        # total_restarts — bot yaratilgandan buyon jami muvaffaqiyatli start
        # soni (qo'lda + avtomatik), 📊 Statistika uchun.
        for ddl in (
            "ALTER TABLE bots ADD COLUMN consecutive_crash_count INTEGER DEFAULT 0",
            "ALTER TABLE bots ADD COLUMN last_crash_at TEXT",
            "ALTER TABLE bots ADD COLUMN desired_state TEXT DEFAULT 'stopped'",
            "ALTER TABLE bots ADD COLUMN total_restarts INTEGER DEFAULT 0",
        ):
            try:
                await db.execute(ddl)
            except aiosqlite.OperationalError as e:
                if "duplicate column" not in str(e).lower():
                    raise

        # --- MIGRATION: users'ga billing auto-stop uchun bir martalik xabar
        # flag'i. stop_notified — "⛔ botlaringiz to'xtatildi" xabari shu
        # grace-period davri uchun allaqachon yuborilganini bildiradi, shunday
        # qilib billing_monitor_loop uni har sikl (900s) sayin qayta-qayta
        # yubormaydi. Balans qayta to'lganda (balance_zero_at tozalanganda)
        # 0'ga qaytariladi.
        try:
            await db.execute("ALTER TABLE users ADD COLUMN stop_notified INTEGER DEFAULT 0")
        except aiosqlite.OperationalError as e:
            if "duplicate column" not in str(e).lower():
                raise

        # --- MIGRATION: 🛡️ Firibgarlik himoyasi sozlamalari (payment_settings'ga
        # qo'shimcha ustunlar). fraud_protection_enabled — butun qoidalar
        # dvigatelining bosh o'chirgichi (duplicate/aniq-summa/muddat kabi
        # DB darajasidagi qat'iy himoyalar bundan mustasno — ular hech qachon
        # o'chirilmaydi). fraud_velocity_* — bir foydalanuvchi qisqa vaqtda
        # nechta buyurtma ochishi mumkinligi. fraud_large_amount_threshold —
        # shundan katta summa kelsa avtomatik kredit berilmaydi, admin
        # tasdiqlashi kerak bo'ladi (0 = o'chirilgan).
        for ddl in (
            "ALTER TABLE payment_settings ADD COLUMN fraud_protection_enabled INTEGER DEFAULT 1",
            "ALTER TABLE payment_settings ADD COLUMN fraud_velocity_window_minutes INTEGER DEFAULT 10",
            "ALTER TABLE payment_settings ADD COLUMN fraud_velocity_max_orders INTEGER DEFAULT 3",
            "ALTER TABLE payment_settings ADD COLUMN fraud_large_amount_threshold INTEGER DEFAULT 0",
        ):
            try:
                await db.execute(ddl)
            except aiosqlite.OperationalError as e:
                if "duplicate column" not in str(e).lower():
                    raise

        # flagged_for_review/flag_reason — 🛡️ qoida (masalan katta summa)
        # buyurtmani "avtomatik kredit berilmasin, admin ko'rib chiqsin"
        # deb belgilaganda ishlatiladi. status='flagged_review' — bu holatda
        # SMS moslik topilgan, lekin balans hali OSHIRILMAGAN, admin
        # ✅/❌ bilan hal qilishi kerak.
        for ddl in (
            "ALTER TABLE payment_orders ADD COLUMN flagged_for_review INTEGER DEFAULT 0",
            "ALTER TABLE payment_orders ADD COLUMN flag_reason TEXT",
        ):
            try:
                await db.execute(ddl)
            except aiosqlite.OperationalError as e:
                if "duplicate column" not in str(e).lower():
                    raise

        # --- MIGRATION: universal AI provider tizimi (28-bosqich).
        # base_url — faqat kind='openai_compat' va PROVIDER_CATALOG'da standart
        # base_url yo'q providerlar uchun MAJBURIY ('other'); qolganlar uchun
        # NULL qoldirilsa, chaqiruv vaqtida katalogdagi standart qiymat ishlatiladi.
        # is_active — foydalanuvchining o'zi kalitni vaqtincha o'chirib qo'yishi
        # (fallback zanjiridan chiqarib qo'yish), status (ulanish holati) bilan
        # ARALASHTIRILMAYDI — ikkalasi mustaqil.
        for ddl in (
            "ALTER TABLE api_keys ADD COLUMN base_url TEXT",
            "ALTER TABLE user_api_keys ADD COLUMN base_url TEXT",
            "ALTER TABLE user_api_keys ADD COLUMN is_active INTEGER DEFAULT 1",
            "ALTER TABLE user_api_keys ADD COLUMN priority INTEGER DEFAULT 0",
            "ALTER TABLE user_api_keys ADD COLUMN last_error TEXT",
        ):
            try:
                await db.execute(ddl)
            except aiosqlite.OperationalError as e:
                if "duplicate column" not in str(e).lower():
                    raise

        # --- MIGRATION: bot_settings — 🧠 AI sozlamalari (28-bosqich).
        # ai_enabled — botning AI subtizimi uchun UMUMIY kalit (o'chiq bo'lsa
        # user_ai_monitor_loop bu botni butunlay o'tkazib yuboradi).
        # model_override — tanlangan API kalitning standart modelini FAQAT shu
        # bot uchun (kalitning o'zini o'zgartirmasdan) almashtirish imkonini beradi.
        # task_analyze_errors/task_recommend — kuzatuv yoqilganda AI aynan nima
        # qilishini nozik boshqarish (watching_enabled — umumiy "Monitoring"
        # kalitchasi, bular esa uning ICHIDAGI granular sozlamalari).
        for ddl in (
            "ALTER TABLE bot_settings ADD COLUMN ai_enabled INTEGER DEFAULT 1",
            "ALTER TABLE bot_settings ADD COLUMN model_override TEXT",
            "ALTER TABLE bot_settings ADD COLUMN task_analyze_errors INTEGER DEFAULT 1",
            "ALTER TABLE bot_settings ADD COLUMN task_recommend INTEGER DEFAULT 1",
        ):
            try:
                await db.execute(ddl)
            except aiosqlite.OperationalError as e:
                if "duplicate column" not in str(e).lower():
                    raise

        # --- MIGRATION: summalar TIYINGA o'tkazildi (butun so'm -> tiyin, x100).
        # Sabab: SMS/Click bildirishnomalarida tiyingacha aniq summa keladi
        # (masalan "14 030.03 so'm"), oldingi butun-so'm INTEGER buni ifoda
        # eta olmasdi. FLOAT/REAL ATAYLAB ishlatilmaydi (moliyada yaxlitlash
        # xatolari xavfi) — barcha summalar hamon INTEGER, lekin endi tiyin
        # birligida (1 so'm = 100 tiyin). Bu bloк FAQAT bitta marta ishlaydi:
        # system_settings'da "amounts_in_tiyin" flag bo'lmasa — eski
        # ma'lumotlar bazasi demak, barcha summa ustunlarini *100 qilamiz va
        # flagni o'rnatamiz. Yangi (bo'sh) bazada bu flag boshidanoq mavjud
        # bo'ladi (pastda INSERT OR IGNORE bilan), shu sabab yangi o'rnatishda
        # konversiya ishlamaydi (kerak ham emas — jadvallar bo'sh).
        await db.execute("""
            CREATE TABLE IF NOT EXISTS system_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT,
                value_type TEXT NOT NULL DEFAULT 'str',
                updated_by INTEGER,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        async with db.execute("SELECT value FROM system_settings WHERE key = 'amounts_in_tiyin'") as cur:
            _tiyin_flag = await cur.fetchone()
        if _tiyin_flag is None:
            for _ddl in (
                "UPDATE users SET balance = balance * 100",
                "UPDATE transactions SET amount = amount * 100",
                "UPDATE payment_settings SET min_amount = min_amount * 100, max_amount = max_amount * 100",
                "UPDATE payment_orders SET amount = amount * 100",
                "UPDATE payment_transactions SET amount = amount * 100",
                "UPDATE click_settings SET min_amount = min_amount * 100, max_amount = max_amount * 100",
            ):
                try:
                    await db.execute(_ddl)
                except aiosqlite.OperationalError as e:
                    if "no such table" not in str(e).lower():
                        raise
            await db.execute(
                "INSERT OR IGNORE INTO system_settings (key, value, value_type) VALUES ('amounts_in_tiyin', 'true', 'bool')"
            )

        # --- system_settings: FAQAT butun platformaga ta'sir qiladigan global
        # sozlamalar. Bot/AI/foydalanuvchi darajasidagi narsalar bot_settings'da,
        # billing/grace period billing_settings'da, Click sozlamalari
        # click_settings'da qoladi — bu yerga aralashmaydi.
        # ESLATMA: jadval yuqorida (tiyin migratsiyasi bloki) allaqachon
        # CREATE TABLE IF NOT EXISTS bilan yaratilgan — bu yerda qayta
        # yaratish shart emas edi (ikkalasi bir xil sxema bo'lgani uchun
        # funksional xato yo'q edi, lekin ortiqcha/chalkash kod edi).
        _default_settings = [
            # (key, value, value_type)
            ("registration_enabled", "true", "bool"),
            ("telegram_login_enabled", "true", "bool"),
            ("email_verification_enabled", "false", "bool"),
            ("maintenance_mode", "false", "bool"),
            ("maintenance_message", "Texnik xizmat ko'rsatilmoqda. Iltimos, keyinroq urinib ko'ring.", "str"),
            ("maintenance_admin_bypass", "true", "bool"),
            ("default_ram_price", "0", "int"),
            ("default_disk_price", "0", "int"),
            ("default_db_overage_price", "0", "int"),
            ("default_storage_overage_price", "0", "int"),
            ("default_bot_price", "0", "int"),
            ("notify_balance_warning", "true", "bool"),
            ("notify_maintenance", "true", "bool"),
            ("notify_payment", "true", "bool"),
            ("notify_server_issue", "true", "bool"),
            ("notify_bot_error", "true", "bool"),
            ("admin_audit_log_enabled", "true", "bool"),
            ("critical_action_confirmation_enabled", "true", "bool"),
            ("api_key_masking_enabled", "true", "bool"),
            ("session_timeout_minutes", "60", "int"),
            ("admin_ai_enabled", "true", "bool"),
            ("admin_ai_monitoring_enabled", "true", "bool"),
            ("admin_ai_auto_restart_enabled", "true", "bool"),
            ("admin_ai_auto_diagnosis_enabled", "true", "bool"),
            ("admin_ai_alerts_enabled", "true", "bool"),
            ("website_enabled", "true", "bool"),
            ("website_maintenance_banner", "", "str"),
            ("global_notifications_enabled", "true", "bool"),
        ]
        for key, value, vtype in _default_settings:
            await db.execute(
                "INSERT OR IGNORE INTO system_settings (key, value, value_type) VALUES (?, ?, ?)",
                (key, value, vtype),
            )

        # --- MIGRATION: api_keys jadvali = Admin AI API Pool. Yangi ustunlar
        # (last_checked_at, last_error, updated_at) — mavjud jadvalga qo'shiladi,
        # alohida admin_ai_api_keys jadvali OCHILMAYDI, chunki bot_settings.model_key_id
        # va db_get_admin_ai_pool()/call_admin_ai_pool() allaqachon api_keys'ga bog'langan.
        for ddl in (
            "ALTER TABLE api_keys ADD COLUMN last_checked_at TEXT",
            "ALTER TABLE api_keys ADD COLUMN last_error TEXT",
            "ALTER TABLE api_keys ADD COLUMN updated_at TEXT DEFAULT CURRENT_TIMESTAMP",
        ):
            try:
                await db.execute(ddl)
            except aiosqlite.OperationalError as e:
                if "duplicate column" not in str(e).lower():
                    raise

        await db.commit()

# ===================== DATABASE: USERS =====================
async def db_get_user_by_telegram_id(telegram_id: int) -> dict | None:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE telegram_id = ?", (telegram_id,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

async def db_get_user_by_id(user_id: int) -> dict | None:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE id = ?", (user_id,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

async def db_create_user(telegram_id: int, first_name: str, username: str, photo_url: str = "") -> dict:
    is_admin = 1 if telegram_id == SUPER_ADMIN_TELEGRAM_ID else 0
    async with db_connect() as db:
        await db.execute(
            """INSERT INTO users (telegram_id, first_name, username, is_admin)
               VALUES (?, ?, ?, ?)""",
            (telegram_id, first_name, username, is_admin),
        )
        await db.commit()
    return await db_get_user_by_telegram_id(telegram_id)

async def is_admin(telegram_id: int) -> bool:
    user = await db_get_user_by_telegram_id(telegram_id)
    return bool(user and user["is_admin"] == 1)

async def db_ensure_super_admin() -> None:
    """.env'dagi SUPER_ADMIN_TELEGRAM_ID'ga mos foydalanuvchi allaqachon
    ro'yxatdan o'tgan bo'lsa-yu, lekin is_admin=0 bo'lib qolgan bo'lsa (masalan
    SUPER_ADMIN_TELEGRAM_ID keyinroq to'g'irlangan yoki ro'yxatdan o'tishda
    hali sozlanmagan edi), uni admin qilib qo'yadi. Har bot ishga tushishida
    chaqiriladi — idempotent, hech narsa o'zgarmasa ham xavfsiz."""
    if not SUPER_ADMIN_TELEGRAM_ID:
        return
    user = await db_get_user_by_telegram_id(SUPER_ADMIN_TELEGRAM_ID)
    if user and not user["is_admin"]:
        await write_queue.execute("UPDATE users SET is_admin = 1 WHERE telegram_id = ?", (SUPER_ADMIN_TELEGRAM_ID,))
        logger.info(f"SUPER_ADMIN_TELEGRAM_ID={SUPER_ADMIN_TELEGRAM_ID} uchun admin huquqi tiklandi")

async def db_get_all_admins() -> list[dict]:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM users WHERE is_admin = 1") as cur:
            return [dict(r) for r in await cur.fetchall()]

async def db_search_users(query: str = None, filter_type: str = "all", page: int = 0, page_size: int = 5) -> tuple[list[dict], int]:
    conditions, params = [], []
    if filter_type == "active":
        conditions.append("is_active = 1")
    elif filter_type == "blocked":
        conditions.append("is_active = 0")
    elif filter_type == "admins":
        conditions.append("is_admin = 1")
    if query:
        conditions.append("(username LIKE ? OR CAST(telegram_id AS TEXT) LIKE ? OR first_name LIKE ?)")
        like = f"%{query}%"
        params += [like, like, like]
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(f"SELECT COUNT(*) FROM users {where}", params) as cur:
            (total,) = await cur.fetchone()
        async with db.execute(
            f"SELECT * FROM users {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [page_size, page * page_size],
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
    return rows, total

async def db_get_users_needing_billing_check() -> list[dict]:
    """Balansi <= 0 bo'lgan YOKI grace-period jarayonida (balance_zero_at bor)
    foydalanuvchilar — ikkalasi ham tekshirilishi kerak (birinchisi yangi
    ogohlantirish/auto-stop uchun, ikkinchisi balans to'lganda tiklash uchun).
    FAQAT kamida bitta boti bor userlar — aks holda "botlaringiz to'xtatiladi"
    degan ogohlantirish botsiz (masalan yangi ro'yxatdan o'tgan) userga ham
    yuborilib, chalkashlik keltirib chiqarardi (bot yo'q — nima to'xtaydi?)."""
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """SELECT * FROM users WHERE (balance <= 0 OR balance_zero_at IS NOT NULL)
               AND id IN (SELECT DISTINCT owner_id FROM bots)"""
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

async def db_set_billing_state(user_id: int, *, balance_zero_at, warning_1_sent: int, warning_2_sent: int,
                                stop_notified: int | None = None):
    if stop_notified is not None:
        await write_queue.execute(
            """UPDATE users SET balance_zero_at = ?, warning_1_sent = ?, warning_2_sent = ?,
               stop_notified = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
            (balance_zero_at, warning_1_sent, warning_2_sent, stop_notified, user_id),
        )
        return
    await write_queue.execute(
        """UPDATE users SET balance_zero_at = ?, warning_1_sent = ?, warning_2_sent = ?,
           updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
        (balance_zero_at, warning_1_sent, warning_2_sent, user_id),
    )

async def db_get_bots_by_owner_id(user_id: int) -> list[dict]:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM bots WHERE owner_id = ?", (user_id,)) as cur:
            return [dict(r) for r in await cur.fetchall()]

async def db_set_user_active(user_id: int, is_active: bool):
    await write_queue.execute("UPDATE users SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                               (int(is_active), user_id))

async def db_adjust_user_balance(user_id: int, amount: int, reason: str, admin_telegram_id: int):
    await write_queue.execute_transaction([
        ("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id)),
        ("""INSERT INTO transactions (user_id, type, amount, status, description)
            VALUES (?, 'admin_adjustment', ?, 'paid', ?)""", (user_id, amount, reason)),
    ])
    await log_admin_action(actor=f"admin:{admin_telegram_id}", action="adjust_balance",
                            result="OK", reason=reason, target=f"user_{user_id}")


# ===================== ADMIN LOGS (audit) =====================
async def log_admin_action(actor: str, action: str, result: str, reason: str = "", target: str = ""):
    # 🔐 Xavfsizlik sozlamasi: admin_audit_log_enabled o'chirilgan bo'lsa
    # yozilmaydi. Sozlamalarni o'qib bo'lmasa (masalan boshlang'ich ishga
    # tushish bosqichida) FAIL-SAFE — baribir yoziladi, jim o'tkazib
    # yuborilmaydi (audit yo'qolishi xavfsizlik nuqtai nazaridan yomonroq).
    try:
        settings = await db_get_all_settings()
        if not settings.get("admin_audit_log_enabled", True):
            return
    except Exception:
        pass
    await write_queue.execute(
        """INSERT INTO admin_logs (actor, action, result, reason, target, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (actor, action, result, reason, target, utcnow().isoformat()),
    )

# ===================== SYSTEM SETTINGS (global, platforma darajasida) =====================
_SETTINGS_CACHE: dict | None = None  # oddiy in-memory keshi; set/init da tozalanadi

def _parse_setting_value(value: str, value_type: str):
    if value_type == "bool":
        return str(value).lower() == "true"
    if value_type == "int":
        return int(value)
    if value_type == "float":
        return float(value)
    return value

async def db_get_all_settings(force_reload: bool = False) -> dict:
    global _SETTINGS_CACHE
    if _SETTINGS_CACHE is not None and not force_reload:
        return _SETTINGS_CACHE
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM system_settings") as cur:
            rows = await cur.fetchall()
    _SETTINGS_CACHE = {r["key"]: _parse_setting_value(r["value"], r["value_type"]) for r in rows}
    return _SETTINGS_CACHE

async def db_get_setting(key: str, default=None):
    settings = await db_get_all_settings()
    return settings.get(key, default)

async def db_set_setting(key: str, value, updated_by: int):
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT value_type FROM system_settings WHERE key = ?", (key,)) as cur:
            row = await cur.fetchone()
        if not row:
            return False
        vtype = row["value_type"]
        str_value = "true" if value is True else "false" if value is False else str(value)
        await db.execute(
            "UPDATE system_settings SET value = ?, updated_by = ?, updated_at = ? WHERE key = ?",
            (str_value, updated_by, utcnow().isoformat(), key),
        )
        await db.commit()
    global _SETTINGS_CACHE
    _SETTINGS_CACHE = None  # keyingi o'qishda qayta yuklanadi
    return True

async def db_toggle_setting(key: str, updated_by: int) -> bool:
    current = await db_get_setting(key)
    new_value = not bool(current)
    await db_set_setting(key, new_value, updated_by)
    return new_value

async def db_get_setting_type(key: str) -> str:
    async with db_connect() as db:
        async with db.execute("SELECT value_type FROM system_settings WHERE key = ?", (key,)) as cur:
            row = await cur.fetchone()
            return row[0] if row else "str"

# billing_settings o'zining bo'limi (bu yerga aralashmaydi) — faqat ko'rish uchun
async def db_get_billing_settings() -> dict:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM billing_settings WHERE id = 1") as cur:
            return dict(await cur.fetchone())


# ===================== DB BACKUP / RESTORE =====================
# backups jadvali: id, owner_type(system/user/bot), owner_id, backup_type,
# file_path, file_size, checksum, status, created_by, created_at, restored_at.
# Fayllar diskda saqlanadi (backups/system|users|bots/...), jadval faqat metadata.
BACKUPS_DIR = Path("backups")
for _sub in ("system", "users", "bots"):
    (BACKUPS_DIR / _sub).mkdir(parents=True, exist_ok=True)

# Faqat shu whitelist'dagi jadvallar system backup/restore'ga kiradi — jadval
# nomi hech qachon foydalanuvchi kiritmasidan olinmaydi (SQL injection'dan himoya).
SYSTEM_BACKUP_TABLES = [
    "users", "servers", "bots", "transactions", "click_settings",
    "billing_settings", "api_keys", "user_api_keys", "bot_settings",
    "bot_ai_monitor_state", "admin_logs",
]

def _row_to_jsonable(row: dict) -> dict:
    """BLOB (encrypted token/key) ustunlarini base64'ga o'tkazadi — shifrlangan
    holatida qoladi, backup faylida hech qachon ochiq matn bo'lmaydi."""
    out = {}
    for k, v in row.items():
        out[k] = {"__b64__": base64.b64encode(v).decode()} if isinstance(v, (bytes, bytearray)) else v
    return out

def _row_from_jsonable(row: dict) -> dict:
    out = {}
    for k, v in row.items():
        out[k] = base64.b64decode(v["__b64__"]) if isinstance(v, dict) and "__b64__" in v else v
    return out

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

async def _dump_table(db: aiosqlite.Connection, table: str) -> list[dict]:
    db.row_factory = aiosqlite.Row
    async with db.execute(f"SELECT * FROM {table}") as cur:  # table faqat whitelistdan keladi
        return [_row_to_jsonable(dict(r)) for r in await cur.fetchall()]

# --- backups jadvali CRUD ---
async def db_create_backup_record(owner_type: str, owner_id: int, backup_type: str, file_path: str,
                                   file_size: int, checksum: str, status: str, created_by: int,
                                   encrypted: bool = False) -> int:
    async with db_connect() as db:
        cur = await db.execute(
            """INSERT INTO backups (owner_type, owner_id, backup_type, file_path, file_size,
                                     checksum, status, created_by, created_at, encrypted)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (owner_type, owner_id, backup_type, file_path, file_size, checksum, status,
             created_by, utcnow().isoformat(), int(encrypted)),
        )
        await db.commit()
        return cur.lastrowid

# --- Backup fayllarini shifrlash (backup_settings.encryption_enabled ga bog'liq) ---
async def _finalize_backup_file(path: Path) -> tuple[Path, bool]:
    """Sozlamada yoqilgan bo'lsa, tayyor backup faylini Fernet bilan shifrlaydi
    (fayl kengaytmasiga .enc qo'shiladi) va asl (shifrlanmagan) faylni o'chiradi."""
    settings = await db_get_backup_settings()
    if settings.get("encryption_enabled") and _fernet:
        raw = path.read_bytes()
        enc_path = path.with_name(path.name + ".enc")
        enc_path.write_bytes(_fernet.encrypt(raw))
        path.unlink()
        return enc_path, True
    return path, False

def _read_backup_bytes(path: Path, encrypted: bool) -> bytes:
    raw = path.read_bytes()
    return _fernet.decrypt(raw) if encrypted and _fernet else raw

async def db_update_backup_status(backup_id: int, status: str, restored_at: str | None = None):
    async with db_connect() as db:
        if restored_at:
            await db.execute("UPDATE backups SET status = ?, restored_at = ? WHERE id = ?",
                              (status, restored_at, backup_id))
        else:
            await db.execute("UPDATE backups SET status = ? WHERE id = ?", (status, backup_id))
        await db.commit()

async def db_get_backup(backup_id: int) -> dict | None:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM backups WHERE id = ?", (backup_id,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

async def db_list_backups(owner_type: str, owner_id: int | None = None,
                           page: int = 0, page_size: int = 5) -> tuple[list[dict], int]:
    conditions, params = ["owner_type = ?"], [owner_type]
    if owner_id is not None:
        conditions.append("owner_id = ?")
        params.append(owner_id)
    where = " AND ".join(conditions)
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(f"SELECT COUNT(*) FROM backups WHERE {where}", params) as cur:
            (total,) = await cur.fetchone()
        async with db.execute(
            f"SELECT * FROM backups WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [page_size, page * page_size],
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
    return rows, total

async def db_delete_backup_record(backup_id: int):
    backup = await db_get_backup(backup_id)
    if backup:
        try:
            Path(backup["file_path"]).unlink(missing_ok=True)
        except Exception:
            logger.exception(f"Backup faylini o'chirishda xato: {backup['file_path']}")
    async with db_connect() as db:
        await db.execute("DELETE FROM backups WHERE id = ?", (backup_id,))
        await db.commit()

# --- 🌐 System backup (butun platforma: users/bots/servers/transactions/...) ---
async def create_system_backup(created_by_telegram_id: int) -> int:
    ts = utcnow().strftime("%Y%m%d_%H%M%S")
    path = BACKUPS_DIR / "system" / f"system_{ts}.json.gz"
    dump = {}
    async with db_connect() as db:
        for table in SYSTEM_BACKUP_TABLES:
            dump[table] = await _dump_table(db, table)
    payload = json.dumps({"tables": dump, "created_at": utcnow().isoformat()}).encode()
    with gzip.open(path, "wb") as f:
        f.write(payload)
    path, encrypted = await _finalize_backup_file(path)
    checksum = _sha256_file(path)
    size = path.stat().st_size
    return await db_create_backup_record("system", 0, "full", str(path), size, checksum,
                                          "ready", created_by_telegram_id, encrypted=encrypted)

async def restore_system_backup(backup_id: int, requesting_telegram_id: int) -> tuple[bool, str]:
    backup = await db_get_backup(backup_id)
    if not backup or backup["owner_type"] != "system":
        return False, "Backup topilmadi"
    path = Path(backup["file_path"])
    if not path.exists():
        return False, "Backup fayli diskda topilmadi"
    if _sha256_file(path) != backup["checksum"]:
        return False, "⚠️ Checksum mos emas — fayl buzilgan yoki o'zgartirilgan bo'lishi mumkin"
    # Restore'dan oldin joriy holatning avtomatik xavfsizlik nusxasi olinadi
    await create_system_backup(requesting_telegram_id)
    raw = _read_backup_bytes(path, bool(backup["encrypted"]))
    dump = json.loads(gzip.decompress(raw))["tables"]
    async with db_connect() as db:
        for table, rows in dump.items():
            if table not in SYSTEM_BACKUP_TABLES:
                continue  # noma'lum jadval — whitelist tashqarisida, o'tkazib yuboriladi
            await db.execute(f"DELETE FROM {table}")
            if rows:
                restored_rows = [_row_from_jsonable(r) for r in rows]
                cols = list(restored_rows[0].keys())
                placeholders = ", ".join("?" for _ in cols)
                col_list = ", ".join(cols)
                await db.executemany(
                    f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})",
                    [tuple(r.get(c) for c in cols) for r in restored_rows],
                )
        await db.commit()
    await db_update_backup_status(backup_id, "ready", restored_at=utcnow().isoformat())
    return True, "✅ System backup tiklandi"

# --- 🤖 Bot backup (faqat bitta bot: kodi, .env, data.db, AI sozlamalari) ---
async def create_bot_backup(bot_id: int, created_by_telegram_id: int) -> int:
    bot_row = await db_get_bot(bot_id)
    settings = await db_get_bot_settings(bot_id)
    ts = utcnow().strftime("%Y%m%d_%H%M%S")
    zip_path = BACKUPS_DIR / "bots" / f"bot_{bot_id}_{ts}.zip"
    meta = {"bot": _row_to_jsonable(bot_row), "bot_settings": _row_to_jsonable(settings)}
    code_dir = Path(f"managed_bots/bot_{bot_id}")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("meta.json", json.dumps(meta))
        if code_dir.exists():
            for file_path in code_dir.rglob("*"):
                if file_path.is_file():
                    zf.write(file_path, arcname=str(file_path.relative_to(code_dir.parent)))
    zip_path, encrypted = await _finalize_backup_file(zip_path)
    checksum = _sha256_file(zip_path)
    size = zip_path.stat().st_size
    return await db_create_backup_record("bot", bot_id, "bot_data", str(zip_path), size, checksum,
                                          "ready", created_by_telegram_id, encrypted=encrypted)

async def restore_bot_backup(backup_id: int, requesting_telegram_id: int) -> tuple[bool, str]:
    backup = await db_get_backup(backup_id)
    if not backup or backup["owner_type"] != "bot":
        return False, "Backup topilmadi"
    bot_id = backup["owner_id"]
    bot_row = await db_get_bot(bot_id)
    if not bot_row:
        return False, "Bot topilmadi (o'chirilgan bo'lishi mumkin)"
    # Egalik tekshiruvi: faqat bot egasi yoki admin tiklay oladi
    requester = await db_get_user_by_telegram_id(requesting_telegram_id)
    is_owner = bool(requester and bot_row["owner_id"] == requester["id"])
    if not (is_owner or await is_admin(requesting_telegram_id)):
        return False, "❌ Ruxsat yo'q — bu backup sizga tegishli emas"
    path = Path(backup["file_path"])
    if not path.exists():
        return False, "Backup fayli diskda topilmadi"
    if _sha256_file(path) != backup["checksum"]:
        return False, "⚠️ Checksum mos emas — fayl buzilgan bo'lishi mumkin"
    # Restore'dan oldin botning joriy holatidan xavfsizlik nusxasi olinadi
    await create_bot_backup(bot_id, requesting_telegram_id)
    prefix = f"bot_{bot_id}/"
    raw = _read_backup_bytes(path, bool(backup["encrypted"]))
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        meta = json.loads(zf.read("meta.json"))
        settings_data = _row_from_jsonable(meta.get("bot_settings", {}))
        for field in ("character", "response_style", "system_prompt", "language",
                      "response_length", "memory_enabled", "api_fallback_enabled"):
            if field in settings_data:
                await db_update_bot_setting(bot_id, field, settings_data[field])
        # Faqat shu botga tegishli fayllar olinadi (bot_<id>/... prefiksi) — boshqa
        # hech narsa (users/transactions/servers va boshqa botlar) tiklanmaydi.
        for name in zf.namelist():
            if name == "meta.json" or not name.startswith(prefix):
                continue
            zf.extract(name, path="managed_bots")
    await db_update_backup_status(backup_id, "ready", restored_at=utcnow().isoformat())
    return True, "✅ Bot ma'lumotlari tiklandi (kod/.env/data.db/AI sozlamalari)"

# --- 👤 User backup (profil/balans/botlar ro'yxati/AI kalitlari metadata) ---
async def create_user_backup(user_id: int, created_by_telegram_id: int) -> int:
    user_row = await db_get_user_by_id(user_id)
    ts = utcnow().strftime("%Y%m%d_%H%M%S")
    path = BACKUPS_DIR / "users" / f"user_{user_id}_{ts}.json.gz"
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM bots WHERE owner_id = ?", (user_id,)) as cur:
            bots = [_row_to_jsonable(dict(r)) for r in await cur.fetchall()]
        async with db.execute("SELECT * FROM user_api_keys WHERE user_id = ?", (user_id,)) as cur:
            ai_keys = [_row_to_jsonable(dict(r)) for r in await cur.fetchall()]
    dump = {"user": _row_to_jsonable(user_row), "bots": bots, "user_api_keys": ai_keys}
    payload = json.dumps({"data": dump, "created_at": utcnow().isoformat()}).encode()
    with gzip.open(path, "wb") as f:
        f.write(payload)
    path, encrypted = await _finalize_backup_file(path)
    checksum = _sha256_file(path)
    size = path.stat().st_size
    return await db_create_backup_record("user", user_id, "user_data", str(path), size, checksum,
                                          "ready", created_by_telegram_id, encrypted=encrypted)
# NOT: User backup hozircha faqat yaratish+ro'yxat uchun. Balans/profilni tiklash
# moliyaviy ta'sir qiladigan amal bo'lgani uchun alohida ishonchli restore oqimi
# keyingi bosqichda qo'shiladi (hozircha "Backup/Restore" bo'limidagi ochiq band).

# --- Backup sozlamalari (avtomatik backup) ---
async def db_get_backup_settings() -> dict:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM backup_settings WHERE id = 1") as cur:
            return dict(await cur.fetchone())

async def db_update_backup_settings(**fields):
    ALLOWED = {"auto_backup_enabled", "interval_days", "retention_count", "last_auto_backup_at", "encryption_enabled"}
    updates = {k: v for k, v in fields.items() if k in ALLOWED}
    if not updates:
        return
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    async with db_connect() as db:
        await db.execute(f"UPDATE backup_settings SET {set_clause} WHERE id = 1", tuple(updates.values()))
        await db.commit()

async def enforce_backup_retention(owner_type: str, owner_id: int | None, keep: int):
    """Eng eski backuplarni saqlash sonidan oshib ketganda o'chiradi."""
    rows, total = await db_list_backups(owner_type, owner_id, page=0, page_size=10_000)
    if total <= keep:
        return
    for row in rows[keep:]:
        await db_delete_backup_record(row["id"])

# ===================== PROVIDER MANAGER =====================
class ProviderError(Exception):
    def __init__(self, category: str, message: str):
        self.category = category
        super().__init__(message)

# ===================== UNIVERSAL AI PROVIDER KATALOGI =====================
# Yangi OpenAI-mos AI xizmatini qo'shish uchun BU YERGA bitta yozuv qo'shish
# kifoya — kod boshqa joyda o'zgartirilmaydi ("gemini_api_key" kabi qattiq
# bog'lanish YO'Q, hamma joyda provider/model/api_key/base_url universal
# maydonlar sifatida ishlatiladi).
#   kind="gemini"/"anthropic" — o'ziga xos (native) API formati.
#   kind="openai_compat"      — OpenAI Chat Completions formatini ishlatadi
#                                (OpenAI'ning o'zi ham shu formatga kiradi).
#   base_url=None + kind="openai_compat" — foydalanuvchi/admin base_url'ni
#                                O'ZI kiritishi SHART ("other" — Boshqa AI).
PROVIDER_CATALOG = {
    "gemini":     {"label": "Google Gemini", "kind": "gemini",        "default_model": "gemini-2.0-flash",             "base_url": None},
    "openai":     {"label": "OpenAI",        "kind": "openai_compat", "default_model": "gpt-4o-mini",                  "base_url": "https://api.openai.com/v1"},
    "anthropic":  {"label": "Anthropic",     "kind": "anthropic",     "default_model": "claude-3-5-haiku-20241022",    "base_url": None},
    "deepseek":   {"label": "DeepSeek",      "kind": "openai_compat", "default_model": "deepseek-chat",                "base_url": "https://api.deepseek.com/v1"},
    "groq":       {"label": "Groq",          "kind": "openai_compat", "default_model": "llama-3.3-70b-versatile",      "base_url": "https://api.groq.com/openai/v1"},
    "mistral":    {"label": "Mistral",       "kind": "openai_compat", "default_model": "mistral-small-latest",         "base_url": "https://api.mistral.ai/v1"},
    "openrouter": {"label": "OpenRouter",    "kind": "openai_compat", "default_model": "openrouter/auto",              "base_url": "https://openrouter.ai/api/v1"},
    "other":      {"label": "➕ Boshqa AI",   "kind": "openai_compat", "default_model": "",                             "base_url": None},
}
# Eski nom bilan moslik uchun saqlanadi — boshqa joylardagi DEFAULT_MODELS.get(...)
# chaqiruvlari o'zgarishsiz ishlayveradi.
DEFAULT_MODELS = {key: info["default_model"] for key, info in PROVIDER_CATALOG.items()}

def provider_label(provider: str) -> str:
    return PROVIDER_CATALOG.get(provider, {}).get("label", provider)

def provider_needs_base_url(provider: str) -> bool:
    """True bo'lsa — bu provider uchun base_url foydalanuvchi/admin tomonidan
    KIRITILISHI SHART (kataloglda standart base_url yo'q, masalan 'other')."""
    info = PROVIDER_CATALOG.get(provider)
    return bool(info) and info["kind"] == "openai_compat" and not info["base_url"]

def _normalize_result(ok: bool, provider: str, model: str, text: str = None,
                       usage: dict = None, error: str = None) -> dict:
    return {"ok": ok, "text": text, "provider": provider, "model": model, "usage": usage or {}, "error": error}

async def _call_provider_api(provider: str, api_key: str, model: str, messages: list[dict],
                              timeout: int = 30, base_url: str | None = None) -> dict:
    info = PROVIDER_CATALOG.get(provider)
    if not info:
        return _normalize_result(False, provider, model, error="unsupported_provider")
    effective_base_url = base_url or info["base_url"]
    try:
        if info["kind"] == "gemini":
            return await _call_gemini(api_key, model, messages, timeout)
        elif info["kind"] == "anthropic":
            return await _call_anthropic(api_key, model, messages, timeout)
        elif info["kind"] == "openai_compat":
            if not effective_base_url:
                return _normalize_result(False, provider, model, error="base_url_required")
            return await _call_openai_compatible(provider, api_key, model, messages, timeout, effective_base_url)
        return _normalize_result(False, provider, model, error="unsupported_provider")
    except ProviderError as e:
        logger.warning(f"Provider xatosi: provider={provider} model={model} category={e.category}")
        return _normalize_result(False, provider, model, error=e.category)
    except asyncio.TimeoutError:
        logger.warning(f"Provider timeout: provider={provider} model={model}")
        return _normalize_result(False, provider, model, error="timeout")
    except Exception:
        logger.exception(f"Provider kutilmagan xato: provider={provider} model={model}")
        return _normalize_result(False, provider, model, error="unknown_error")

async def _call_gemini(api_key: str, model: str, messages: list[dict], timeout: int) -> dict:
    # MUHIM (xavfsizlik): API kalit URL query-parametr sifatida EMAS,
    # x-goog-api-key HEADER orqali yuboriladi. Shunda tarmoq xatosi
    # (masalan aiohttp ClientConnectorError) exception matnida URL chiqib
    # qolsa ham, kalit hech qachon URL ichida bo'lmagani uchun logga sizib
    # ketmaydi.
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    headers = {"x-goog-api-key": api_key}
    contents = [{"role": "user" if m["role"] == "user" else "model", "parts": [{"text": m["content"]}]} for m in messages]
    async with aiohttp_client.ClientSession(timeout=aiohttp_client.ClientTimeout(total=timeout)) as session:
        async with session.post(url, json={"contents": contents}, headers=headers) as resp:
            data = await resp.json()
            if resp.status == 429: raise ProviderError("rate_limit", "Gemini limit")
            if resp.status in (401, 403): raise ProviderError("invalid_key", "Gemini auth xatosi")
            if resp.status >= 400: raise ProviderError("provider_error", f"Gemini xatosi: {resp.status}")
            text = data["candidates"][0]["content"]["parts"][0]["text"]
            return _normalize_result(True, "gemini", model, text=text, usage=data.get("usageMetadata", {}))

async def _call_anthropic(api_key: str, model: str, messages: list[dict], timeout: int) -> dict:
    url = "https://api.anthropic.com/v1/messages"
    headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01"}
    body = {"model": model, "max_tokens": 1024, "messages": messages}
    async with aiohttp_client.ClientSession(timeout=aiohttp_client.ClientTimeout(total=timeout)) as session:
        async with session.post(url, json=body, headers=headers) as resp:
            data = await resp.json()
            if resp.status == 429: raise ProviderError("rate_limit", "Anthropic limit")
            if resp.status == 401: raise ProviderError("invalid_key", "Anthropic auth xatosi")
            if resp.status >= 400: raise ProviderError("provider_error", f"Anthropic xatosi: {resp.status}")
            text = data["content"][0]["text"]
            return _normalize_result(True, "anthropic", model, text=text, usage=data.get("usage", {}))

async def _call_openai_compatible(provider: str, api_key: str, model: str, messages: list[dict],
                                   timeout: int, base_url: str) -> dict:
    """OpenAI Chat Completions formatini ishlatuvchi BARCHA providerlar uchun
    UMUMIY adapter (OpenAI, DeepSeek, Groq, Mistral, OpenRouter, va
    foydalanuvchi qo'shgan istalgan 'Boshqa AI') — faqat base_url farq
    qiladi. Yangi OpenAI-mos xizmat qo'shish uchun BU FUNKSIYA o'zgarmaydi,
    faqat PROVIDER_CATALOG'ga (yoki foydalanuvchi/admin FSM orqali) yangi
    yozuv qo'shiladi."""
    url = f"{base_url.rstrip('/')}/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}"}
    async with aiohttp_client.ClientSession(timeout=aiohttp_client.ClientTimeout(total=timeout)) as session:
        async with session.post(url, json={"model": model, "messages": messages}, headers=headers) as resp:
            data = await resp.json()
            if resp.status == 429: raise ProviderError("rate_limit", f"{provider} limit")
            if resp.status == 401: raise ProviderError("invalid_key", f"{provider} auth xatosi")
            if resp.status >= 400: raise ProviderError("provider_error", f"{provider} xatosi: {resp.status}")
            text = data["choices"][0]["message"]["content"]
            return _normalize_result(True, provider, model, text=text, usage=data.get("usage", {}))

async def call_with_fallback(key_pool: list[dict], messages: list[dict]) -> dict:
    last_result = None
    for key_row in key_pool:
        secret = decrypt_token(key_row["api_key_encrypted"])
        result = await _call_provider_api(
            provider=key_row["provider"], api_key=secret,
            model=key_row.get("model_name") or DEFAULT_MODELS.get(key_row["provider"]),
            messages=messages, base_url=key_row.get("base_url"),
        )
        if result["ok"]:
            return result
        last_result = result
        if result["error"] in ("rate_limit", "invalid_key", "provider_error", "timeout"):
            continue
        break
    return last_result or _normalize_result(False, "none", "none", error="no_keys_available")

async def db_get_admin_ai_pool() -> list[dict]:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM api_keys WHERE status = 'active' ORDER BY priority ASC"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]


# ===================== DATABASE: ADMIN AI API POOL (CRUD) =====================
# Jadval: api_keys (Admin AI'ning butun kalit hovuzi shu yerda saqlanadi;
# bot_settings/db_get_selectable_models ham shu jadvaldan is_user_selectable=1
# bo'lganlarini o'qiydi — ikkalasi bitta manba).

async def db_get_admin_pool_all() -> list[dict]:
    """Barcha (faol + nofaol) kalitlar, fallback tartibida (priority ASC)."""
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM api_keys ORDER BY priority ASC, id ASC") as cur:
            return [dict(r) for r in await cur.fetchall()]

async def db_get_admin_pool_key(key_id: int) -> dict | None:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

async def db_next_admin_pool_priority() -> int:
    """Yangi kalitga navbatdagi priority raqamini beradi (oxiriga qo'shiladi)."""
    async with db_connect() as db:
        async with db.execute("SELECT COALESCE(MAX(priority), 0) FROM api_keys") as cur:
            (max_p,) = await cur.fetchone()
            return max_p + 1

async def db_create_admin_pool_key(provider: str, model_name: str, display_name: str,
                                    api_key: str, priority: int, is_user_selectable: bool = False,
                                    base_url: str | None = None) -> int:
    async with db_connect() as db:
        cur = await db.execute(
            """INSERT INTO api_keys (provider, model_name, display_name, api_key_encrypted,
                                      priority, status, is_user_selectable, base_url, updated_at)
               VALUES (?, ?, ?, ?, ?, 'active', ?, ?, CURRENT_TIMESTAMP)""",
            (provider, model_name, display_name, encrypt_token(api_key),
             priority, int(is_user_selectable), base_url),
        )
        await db.commit()
        return cur.lastrowid

async def db_update_admin_pool_key(key_id: int, **fields):
    """Whitelist orqali qisman yangilash. api_key berilsa, saqlashdan oldin shifrlanadi."""
    ALLOWED = {"provider", "model_name", "display_name", "api_key_encrypted",
               "priority", "status", "is_user_selectable", "last_checked_at", "last_error", "base_url"}
    if "api_key" in fields:
        fields["api_key_encrypted"] = encrypt_token(fields.pop("api_key"))
    updates = {k: v for k, v in fields.items() if k in ALLOWED}
    if not updates:
        return
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    async with db_connect() as db:
        await db.execute(
            f"UPDATE api_keys SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (*updates.values(), key_id),
        )
        await db.commit()

async def db_count_active_admin_pool_keys(exclude_id: int | None = None) -> int:
    async with db_connect() as db:
        if exclude_id is None:
            async with db.execute("SELECT COUNT(*) FROM api_keys WHERE status = 'active'") as cur:
                (c,) = await cur.fetchone()
        else:
            async with db.execute(
                "SELECT COUNT(*) FROM api_keys WHERE status = 'active' AND id != ?", (exclude_id,)
            ) as cur:
                (c,) = await cur.fetchone()
        return c

async def db_delete_admin_pool_key(key_id: int):
    async with db_connect() as db:
        await db.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        # Bu kalitni model sifatida tanlagan botlar bo'lsa, tanlovni tozalaymiz
        # (kalit o'chgach eski FK "osilib qolmasin").
        await db.execute("UPDATE bot_settings SET model_key_id = NULL WHERE model_key_id = ?", (key_id,))
        await db.commit()

async def db_set_admin_pool_priority(key_id: int, priority: int):
    async with db_connect() as db:
        await db.execute(
            "UPDATE api_keys SET priority = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (priority, key_id),
        )
        await db.commit()

async def call_admin_ai_pool(prompt: str) -> str:
    pool = await db_get_admin_ai_pool()
    result = await call_with_fallback(pool, messages=[{"role": "user", "content": prompt}])
    if not result["ok"]:
        raise RuntimeError(f"Admin AI pool ishlamadi: {result['error']}")
    return result["text"]

async def call_user_ai(bot_id: int, prompt: str) -> dict:
    """User AI chaqiruvi — TO'LIQ fallback zanjiri bilan (foydalanuvchi
    talabi bo'yicha):
      1) bot uchun tanlangan ASOSIY kalit (bot_settings.user_api_key_id)
      2) foydalanuvchining boshqa FAOL (is_active=1) kalitlari, navbat bilan
      3) agar bot_settings.api_fallback_enabled=1 bo'lsa — Admin AI Pool
      4) hech biri ishlamasa — "AI vaqtincha ishlamaydi" (error qaytariladi)
    3-qadam ATAYLAB bot sozlamasiga bog'liq: foydalanuvchi buni o'chirib
    qo'ysa, o'z kalitlari ishlamagach AI shu bot uchun umuman javob bermaydi
    (Admin AI Pool resurslari sarflanmaydi)."""
    settings = await db_get_bot_settings(bot_id)
    bot_row = await db_get_bot(bot_id)
    if not bot_row:
        return _normalize_result(False, "none", "none", error="bot_not_found")
    owner = await db_get_user_by_id(bot_row["owner_id"])
    if not owner:
        return _normalize_result(False, "none", "none", error="owner_not_found")

    all_keys = await db_get_user_api_keys(owner["id"])
    active_keys = [k for k in all_keys if k.get("is_active", 1)]
    primary_id = settings.get("user_api_key_id")
    # Bot uchun tanlangan ASOSIY kalit birinchi navbatda, qolganlari keyin
    # o'z global priority tartibida (0 — birinchi sinaladi).
    ordered = sorted(active_keys, key=lambda k: (0 if k["id"] == primary_id else 1, k.get("priority", 0)))

    result = _normalize_result(False, "none", "none", error="no_key_selected")
    if ordered:
        result = await call_with_fallback(ordered, messages=[{"role": "user", "content": prompt}])
        if result["ok"]:
            return result

    if not settings.get("api_fallback_enabled", 1):
        return result

    pool = await db_get_admin_ai_pool()
    if not pool:
        return _normalize_result(False, "none", "none", error="ai_unavailable")
    return await call_with_fallback(pool, messages=[{"role": "user", "content": prompt}])

async def test_provider_connection(provider: str, model: str, api_key: str, base_url: str | None = None) -> str:
    model = model or DEFAULT_MODELS.get(provider, "")
    result = await _call_provider_api(provider=provider, api_key=api_key, model=model,
                                       messages=[{"role": "user", "content": "test"}], timeout=15, base_url=base_url)
    if result["ok"]: return "active"
    if result["error"] == "rate_limit": return "limited"
    if result["error"] == "invalid_key": return "invalid"
    return "error"

async def test_user_api_key(key_id: int, user_id: int) -> dict:
    """Haqiqiy provider so'rovi yuboradi va natijaga qarab status/last_error/
    last_checked_at'ni yangilaydi (test_admin_pool_key bilan bir xil naqsh).
    Kalitning o'zi hech qachon qaytarilmaydi/loglanmaydi — faqat xato
    KATEGORIYASI (masalan 'invalid_key') saqlanadi."""
    key_row = await db_get_user_api_key(key_id, user_id)
    if not key_row:
        return {"ok": False, "status": None, "error_label": "Kalit topilmadi"}
    secret = decrypt_token(key_row["api_key_encrypted"])
    model = key_row["model_name"] or DEFAULT_MODELS.get(key_row["provider"], "")
    result = await _call_provider_api(
        provider=key_row["provider"], api_key=secret, model=model,
        messages=[{"role": "user", "content": "test"}], timeout=15, base_url=key_row.get("base_url"),
    )
    if result["ok"]:
        new_status, error_label = "active", None
    else:
        error_key = result.get("error") or "unknown_error"
        error_label = USER_KEY_ERROR_LABEL.get(error_key, error_key)
        new_status = "limited" if error_key == "rate_limit" else ("invalid" if error_key == "invalid_key" else "error")
    await db_update_user_api_key(
        key_id, user_id, status=new_status, last_error=error_label,
        last_checked_at=utcnow().isoformat(sep=" ", timespec="seconds"),
    )
    return {"ok": result["ok"], "status": new_status, "error_label": error_label}

def _extract_last_error_block(log_text: str, max_lines: int = 15) -> str:
    """Log matnidan oxirgi xatolik blokini ajratib oladi — oddiy kalit-so'z
    evristikasi (Traceback/Error/Exception/Critical). Keyinchalik sozlanadigan
    qilinishi mumkin (PROJECT_BRIEF'da ochiq band sifatida qayd etilgan)."""
    if not log_text:
        return ""
    lines = log_text.splitlines()
    error_keywords = ("traceback", "error", "exception", "critical")
    last_idx = None
    for i, line in enumerate(lines):
        if any(kw in line.lower() for kw in error_keywords):
            last_idx = i
    if last_idx is None:
        return ""
    start = max(0, last_idx - 2)
    end = min(len(lines), last_idx + max_lines)
    return "\n".join(lines[start:end]).strip()


# ===================== DATABASE: bot_ai_monitor_state =====================
async def db_get_bot_ai_monitor_state(bot_id: int) -> dict | None:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM bot_ai_monitor_state WHERE bot_id = ?", (bot_id,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

async def db_upsert_bot_ai_monitor_state(bot_id: int, **fields):
    existing = await db_get_bot_ai_monitor_state(bot_id)
    async with db_connect() as db:
        if existing:
            set_clause = ", ".join(f"{k} = ?" for k in fields)
            await db.execute(f"UPDATE bot_ai_monitor_state SET {set_clause} WHERE bot_id = ?",
                              (*fields.values(), bot_id))
        else:
            cols = ", ".join(["bot_id"] + list(fields.keys()))
            placeholders = ", ".join(["?"] * (len(fields) + 1))
            await db.execute(f"INSERT INTO bot_ai_monitor_state ({cols}) VALUES ({placeholders})",
                              (bot_id, *fields.values()))
        await db.commit()


USER_AI_MONITOR_COOLDOWN_MINUTES = 30  # bir xil xatolik uchun qayta AI chaqirmaslik oralig'i

async def user_ai_monitor_loop(interval_seconds: int = 300):
    """Kuzatuv yoqilgan (bot_settings.watching_enabled=1 VA ai_enabled=1)
    botlar loglarini tekshiradi. Yangi xatolik topilsa User AI'dan
    (foydalanuvchining o'z API kaliti bilan) tavsiya so'raydi va egasiga
    yuboradi — kodni o'zgartirmaydi, faqat maslahat beradi. Bir xil xatolik
    (hash bo'yicha) cooldown ichida qayta-qayta AI'ni chaqirmaydi (API
    limitni tejash uchun). task_analyze_errors/task_recommend — bot
    sozlamasidagi granular AI vazifalari (🧠 AI sozlamalari ekranida
    ko'rsatiladi): birinchisi o'chiq bo'lsa xatolik butunlay e'tiborga
    olinmaydi, ikkinchisi o'chiq bo'lsa xatolik ANIQLANADI (holat/hash
    yozib boriladi) lekin AI chaqirilmaydi/tavsiya yuborilmaydi."""
    await asyncio.sleep(15)
    while True:
        try:
            watched_bots = await db_get_watched_bots()
            for bot_row in watched_bots:
                try:
                    settings = await db_get_bot_settings(bot_row["id"])
                    if not settings.get("task_analyze_errors", 1):
                        continue
                    if not bot_row.get("server_id"):
                        continue
                    server_row = await db_get_server(bot_row["server_id"])
                    if not server_row:
                        continue
                    pm = get_process_manager(server_row)
                    log_tail = await pm.tail_log(bot_row, server_row, lines=60)
                    error_block = _extract_last_error_block(log_tail)
                    if not error_block:
                        continue

                    error_hash = hashlib.sha256(error_block.encode()).hexdigest()
                    state = await db_get_bot_ai_monitor_state(bot_row["id"])
                    now = utcnow()

                    if state and state["last_error_hash"] == error_hash and state["last_ai_call_at"]:
                        elapsed_min = (now - datetime.fromisoformat(state["last_ai_call_at"])).total_seconds() / 60
                        if elapsed_min < USER_AI_MONITOR_COOLDOWN_MINUTES:
                            await db_upsert_bot_ai_monitor_state(
                                bot_row["id"],
                                consecutive_same_error=(state["consecutive_same_error"] or 0) + 1,
                            )
                            continue

                    if not settings.get("task_recommend", 1):
                        # Xatolik qayd etiladi (keyingi tsikllarda takrorlanishini
                        # bilish uchun), lekin AI chaqirilmaydi/tavsiya yuborilmaydi.
                        await db_upsert_bot_ai_monitor_state(
                            bot_row["id"], last_error_hash=error_hash,
                            last_notified_at=now.isoformat(sep=" ", timespec="seconds"),
                            consecutive_same_error=1,
                        )
                        continue

                    result = await call_user_ai(
                        bot_row["id"],
                        "Quyidagi Telegram bot logidagi xatolikni tahlil qil va o'zbek tilida "
                        "qisqa tavsiya ber (kodni o'zgartirmang, faqat maslahat bering):\n\n" + error_block,
                    )
                    await db_upsert_bot_ai_monitor_state(
                        bot_row["id"],
                        last_error_hash=error_hash,
                        last_notified_at=now.isoformat(sep=" ", timespec="seconds"),
                        last_ai_call_at=now.isoformat(sep=" ", timespec="seconds"),
                        consecutive_same_error=1,
                    )

                    owner = await db_get_user_by_id(bot_row["owner_id"])
                    if not owner:
                        continue
                    if result.get("ok"):
                        text = f"🚨 '{bot_row['name']}' botida xatolik aniqlandi.\n\n💡 Tavsiya:\n{result['text'][:800]}"
                    else:
                        text = (f"🚨 '{bot_row['name']}' botida xatolik aniqlandi, lekin AI tavsiya "
                                f"bera olmadi ({result.get('error', 'nomalum xato')}). API kalitingizni tekshiring.")
                    try:
                        await bot.send_message(owner["telegram_id"], text)
                    except Exception:
                        pass
                except Exception:
                    logger.exception(f"user_ai_monitor_loop: bot_id={bot_row.get('id')} uchun xato")
        except Exception:
            logger.exception("user_ai_monitor_loop global xato")
        await asyncio.sleep(interval_seconds)


# ===================== ADMIN AI: RUXSAT ETILGAN AMALLAR + MONITORING =====================
# Qattiq kodlangan whitelist — Admin AI faqat shu ro'yxatdagi texnik amallarni
# avtonom bajara oladi. Admin huquqi berish, billingga tegish, xavfsizlikni
# o'chirish HECH QACHON shu ro'yxatga qo'shilmaydi (PROJECT_BRIEF talabi).
ADMIN_AI_ALLOWED_ACTIONS = {"restart_bot", "stop_bot"}

async def execute_admin_ai_action(action: str, bot_row: dict, reason: str) -> tuple[bool, str]:
    """Admin AI tomonidan so'ralgan amalni whitelist orqali tekshirib bajaradi.
    Har bir urinish (ruxsat berilgan yoki bloklangan) admin_logs'ga yoziladi."""
    if action not in ADMIN_AI_ALLOWED_ACTIONS:
        await log_admin_action(actor="admin_ai", action=action, result="BLOCKED",
                                reason="whitelistda yo'q", target=f"bot_{bot_row['id']}")
        return False, "action whitelistda yo'q"

    if action == "restart_bot":
        await _stop_bot_process(bot_row, reason="admin_ai_restart")
        ok, msg = await _start_bot_process(bot_row)
    elif action == "stop_bot":
        await _stop_bot_process(bot_row, reason="admin_ai_stop")
        ok, msg = True, "OK"
    else:
        ok, msg = False, "amalga oshirilmagan action"

    await log_admin_action(actor="admin_ai", action=action, result="OK" if ok else "FAILED",
                            reason=reason, target=f"bot_{bot_row['id']}")
    return ok, msg

async def ai_diagnose_failure(bot_row: dict, log_tail: str) -> dict:
    """Admin AI pool orqali nosozlikni tashxislaydi. JSON javob kutiladi:
    {"diagnosis": "...", "recommended_action": "restart_bot|stop_bot|none", "confidence": 0-100}."""
    prompt = (
        "Sen Telegram bot hosting platformasi uchun texnik diagnost yordamchisisan. "
        "Quyidagi bot log xatoligini tahlil qil va FAQAT JSON formatda javob ber, "
        "boshqa hech narsa yozma: "
        '{"diagnosis": "qisqa tashxis (o\'zbek tilida)", '
        '"recommended_action": "restart_bot" yoki "stop_bot" yoki "none", '
        '"confidence": 0 dan 100 gacha butun son}\n\n'
        f"LOG:\n{log_tail[-2000:]}"
    )
    try:
        raw = await call_admin_ai_pool(prompt)
        cleaned = raw.strip().strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:].strip()
        data = json.loads(cleaned)
        action = data.get("recommended_action")
        return {
            "diagnosis": str(data.get("diagnosis", ""))[:500],
            "recommended_action": action if action in ADMIN_AI_ALLOWED_ACTIONS else None,
            "confidence": int(data.get("confidence", 0) or 0),
        }
    except Exception as e:
        logger.exception("ai_diagnose_failure: AI javobini olish/parslashda xato")
        return {"diagnosis": f"AI diagnostika muvaffaqiyatsiz: {e}", "recommended_action": None, "confidence": 0}

ADMIN_AI_AUTO_ACTION_CONFIDENCE_THRESHOLD = 60

async def admin_ai_monitor_loop(interval_seconds: int = 180):
    """24/7: 'running' deb belgilangan botlarning jarayoni haqiqatan ishlab
    turganini tekshiradi. Kutilmagan to'xtash aniqlansa — sozlamalar yoqilgan
    bo'lsa AI orqali tashxislaydi, ruxsat etilgan va yetarli ishonchli bo'lsa
    avtomatik tuzatadi (faqat ADMIN_AI_ALLOWED_ACTIONS doirasida), aks holda
    asosiy/barcha adminlarga eskalatsiya qiladi."""
    await asyncio.sleep(10)
    while True:
        try:
            settings = await db_get_all_settings()
            if not (settings.get("admin_ai_enabled", True) and settings.get("admin_ai_monitoring_enabled", True)):
                await asyncio.sleep(interval_seconds)
                continue

            running_bots = await db_get_running_bots()
            for bot_row in running_bots:
                try:
                    if not bot_row.get("server_id"):
                        continue
                    server_row = await db_get_server(bot_row["server_id"])
                    if not server_row:
                        continue
                    pm = get_process_manager(server_row)
                    alive = await pm.is_running(bot_row, server_row)

                    if alive:
                        if bot_row["health"] != "ok":
                            await db_set_bot_health(bot_row["id"], "ok", "")
                        continue

                    await db_set_bot_health(bot_row["id"], "error", "Jarayon kutilmaganda to'xtadi")
                    log_tail = await pm.tail_log(bot_row, server_row, lines=40)

                    diagnosis = {"diagnosis": "", "recommended_action": None, "confidence": 0}
                    if settings.get("admin_ai_auto_diagnosis_enabled", True):
                        diagnosis = await ai_diagnose_failure(bot_row, log_tail)

                    handled = False
                    if (settings.get("admin_ai_auto_restart_enabled", True)
                            and diagnosis["recommended_action"] == "restart_bot"
                            and diagnosis["confidence"] >= ADMIN_AI_AUTO_ACTION_CONFIDENCE_THRESHOLD):
                        ok, _ = await execute_admin_ai_action(
                            "restart_bot", bot_row, reason=diagnosis["diagnosis"] or "avtomatik qayta ishga tushirish")
                        handled = ok

                    if not handled:
                        await db_update_bot_status(bot_row["id"], "stopped")
                        await db_set_stop_reason(bot_row["id"], "crashed")
                        if settings.get("admin_ai_alerts_enabled", True):
                            text = (f"🚨 Bot #{bot_row['id']} ({bot_row['name']}) kutilmaganda to'xtadi.\n"
                                    f"Diagnostika: {diagnosis['diagnosis'] or 'AI diagnostika mavjud emas'}\n"
                                    f"Ishonch: {diagnosis['confidence']}%")
                            for admin in await db_get_all_admins():
                                try:
                                    await bot.send_message(admin["telegram_id"], text)
                                except Exception:
                                    pass
                except Exception:
                    logger.exception(f"admin_ai_monitor_loop: bot_id={bot_row.get('id')} uchun xato")
        except Exception:
            logger.exception("admin_ai_monitor_loop global xato")
        await asyncio.sleep(interval_seconds)


# status: 'active' (🟢), 'limited' (🟡), 'invalid' / 'error' / 'disabled' (🔴)
ADMIN_POOL_STATUS_EMOJI = {"active": "🟢", "limited": "🟡", "invalid": "🔴", "error": "🔴", "disabled": "🔴"}
ADMIN_POOL_STATUS_LABEL = {
    "active": "🟢 Active", "limited": "🟡 Limit / vaqtinchalik muammo",
    "invalid": "🔴 Invalid", "error": "🔴 Provider xatosi", "disabled": "🔴 Disabled",
}
ADMIN_POOL_ERROR_LABEL = {
    "rate_limit": "rate limit", "invalid_key": "invalid key",
    "provider_error": "provider xatosi", "timeout": "timeout",
    "unsupported_provider": "provider qo'llab-quvvatlanmaydi", "unknown_error": "noma'lum xato",
}
# 🧠 Mening AI API'larim (User AI CRUD, 28-bosqich) — xuddi shu status
# to'plamidan foydalanadi, ustiga "unchecked" (hali test qilinmagan) qo'shiladi.
USER_KEY_STATUS_EMOJI = {**ADMIN_POOL_STATUS_EMOJI, "unchecked": "⚪"}
USER_KEY_STATUS_LABEL = {**ADMIN_POOL_STATUS_LABEL, "unchecked": "⚪ Tekshirilmagan"}
USER_KEY_ERROR_LABEL = {**ADMIN_POOL_ERROR_LABEL, "no_key_selected": "kalit tanlanmagan",
                         "key_not_found": "kalit topilmadi", "ai_unavailable": "AI vaqtincha ishlamaydi",
                         "base_url_required": "Base URL kiritilmagan"}

async def test_admin_pool_key(key_id: int) -> dict:
    """Haqiqiy provider so'rovi yuboradi va natijaga qarab status/last_error/
    last_checked_at'ni yangilaydi. Kalitning o'zi hech qachon qaytarilmaydi."""
    key_row = await db_get_admin_pool_key(key_id)
    if not key_row:
        return {"ok": False, "status": None, "error_label": "Kalit topilmadi"}
    secret = decrypt_token(key_row["api_key_encrypted"])
    model = key_row["model_name"] or DEFAULT_MODELS.get(key_row["provider"], "")
    result = await _call_provider_api(
        provider=key_row["provider"], api_key=secret, model=model,
        messages=[{"role": "user", "content": "test"}], timeout=15, base_url=key_row.get("base_url"),
    )
    if result["ok"]:
        new_status, error_label = "active", None
    else:
        error_key = result.get("error") or "unknown_error"
        error_label = ADMIN_POOL_ERROR_LABEL.get(error_key, error_key)
        new_status = "limited" if error_key == "rate_limit" else ("invalid" if error_key == "invalid_key" else "error")
    await db_update_admin_pool_key(
        key_id, status=new_status, last_error=error_label,
        last_checked_at=utcnow().isoformat(),
    )
    return {"ok": result["ok"], "status": new_status, "error_label": error_label}

# ===================== SERVER MANAGER =====================
class ProcessManager(ABC):
    @abstractmethod
    async def start(self, bot_row: dict, server_row: dict) -> int: ...
    @abstractmethod
    async def stop(self, bot_row: dict, server_row: dict) -> None: ...
    @abstractmethod
    async def is_running(self, bot_row: dict, server_row: dict) -> bool: ...
    @abstractmethod
    async def tail_log(self, bot_row: dict, server_row: dict, lines: int = 30) -> str: ...

    async def bulk_is_running(self, bot_rows: list[dict], server_row: dict) -> dict[int, bool]:
        """Standart: bittalab tekshiradi (Local uchun yetarli — os.kill
        arzon, subprocess spawn qilmaydi). Ko'p bot bilan qimmat bo'lgan
        backendlar (masalan Docker) buni bitta so'rov bilan override qiladi."""
        result = {}
        for b in bot_rows:
            try:
                result[b["id"]] = await self.is_running(b, server_row)
            except Exception:
                result[b["id"]] = False
        return result

    async def bulk_get_ram_usage_mb(self, bot_rows: list[dict], server_row: dict) -> dict[int, float]:
        """Standart: real o'lchov yo'q — allocated_ram_mb qaytariladi
        (overage = 0). Faqat real monitoring beruvchi backendlar override qiladi."""
        return {b["id"]: float(b["allocated_ram_mb"]) for b in bot_rows}


class LocalProcessManager(ProcessManager):
    def _log_path(self, bot_id: int) -> Path: return LOGS_DIR / f"bot_{bot_id}.log"
    def _bot_dir(self, bot_id: int) -> Path: return Path(f"managed_bots/bot_{bot_id}")
    def _script_path(self, bot_id: int) -> Path: return self._bot_dir(bot_id) / "user_code" / "run.py"
    def _env_path(self, bot_id: int) -> Path: return self._bot_dir(bot_id) / ".env"

    @staticmethod
    def _load_env_file(path: Path) -> dict:
        """.env faylini qo'lda o'qiydi va dict qaytaradi. Bola jarayonga
        ANIQ shu qiymatlar beriladi — ota jarayonning o'z muhiti
        (os.environ, jumladan TOKEN_ENCRYPTION_KEY va asosiy BOT_TOKEN)
        UNGA HECH QACHON o'tmaydi (foydalanuvchi o'zi yuklagan kod
        ishga tushadigan joy — bu yerda izolyatsiya majburiy)."""
        result: dict = {}
        if not path.exists():
            return result
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip().strip('"').strip("'")
        return result

    async def start(self, bot_row: dict, server_row: dict) -> int:
        script = self._script_path(bot_row["id"])
        if not script.exists():
            raise RuntimeError(f"Bot skripti topilmadi: {script}")
        child_env = self._load_env_file(self._env_path(bot_row["id"]))
        child_env["BOT_ID"] = str(bot_row["id"])
        # Minimal xavfsiz PATH — ota jarayonning boshqa hech qanday
        # o'zgaruvchisi (maxfiy kalitlar, DB yo'li va h.k.) bolaga o'tmaydi.
        child_env.setdefault("PATH", os.environ.get("PATH", "/usr/bin:/bin"))
        with open(self._log_path(bot_row["id"]), "ab") as log_file:
            process = await asyncio.create_subprocess_exec(
                "python3", str(script.resolve()), stdout=log_file, stderr=log_file,
                cwd=str(script.parent.resolve()),
                env=child_env,
            )
        return process.pid

    async def stop(self, bot_row: dict, server_row: dict) -> None:
        pid = bot_row.get("pid")
        if not pid: return
        try: os.kill(pid, signal.SIGTERM)
        except ProcessLookupError: pass

    async def is_running(self, bot_row: dict, server_row: dict) -> bool:
        pid = bot_row.get("pid")
        if not pid: return False
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False

    async def tail_log(self, bot_row: dict, server_row: dict, lines: int = 30) -> str:
        log_path = self._log_path(bot_row["id"])
        if not log_path.exists(): return "Log hali yo'q."
        text = log_path.read_text(errors="replace")
        return "\n".join(text.splitlines()[-lines:]) or "Log bo'sh."


class DockerProcessManager(ProcessManager):
    """Har bir bot alohida Docker konteynerida — --read-only, izolyatsiya qilingan tarmoq.
    Hard limit emas (allocated*3 'tom'), overage resource_monitor_loop orqali billinglanadi."""
    def _container_name(self, bot_id: int) -> str: return f"bot_{bot_id}"

    async def start(self, bot_row: dict, server_row: dict) -> int:
        name = self._container_name(bot_row["id"])
        code_dir = Path(f"managed_bots/bot_{bot_row['id']}/user_code")
        env_file = Path(f"managed_bots/bot_{bot_row['id']}/.env")
        hard_ceiling_mb = bot_row["allocated_ram_mb"] * 3
        cmd = [
            "docker", "run", "-d", "--name", name,
            "--memory", f"{hard_ceiling_mb}m", "--cpus", "1",
            "--network", "bot_isolated_net", "--read-only",
            "-v", f"{code_dir.resolve()}:/app/user_code:ro",
            "-v", f"{env_file.resolve()}:/app/.env:ro",
            "--env-file", str(env_file), "--restart", "no",
            "platform-bot-runner:latest",
        ]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(stderr.decode().strip())
        return stdout.decode().strip()  # container_id -> bots.pid ustuniga string sifatida

    async def stop(self, bot_row: dict, server_row: dict) -> None:
        name = self._container_name(bot_row["id"])
        await asyncio.create_subprocess_exec("docker", "stop", "-t", "10", name)
        await asyncio.create_subprocess_exec("docker", "rm", "-f", name)

    async def is_running(self, bot_row: dict, server_row: dict) -> bool:
        name = self._container_name(bot_row["id"])
        proc = await asyncio.create_subprocess_exec("docker", "inspect", "-f", "{{.State.Running}}", name,
                                                      stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        stdout, _ = await proc.communicate()
        return stdout.decode().strip() == "true"

    async def bulk_is_running(self, bot_rows: list[dict], server_row: dict) -> dict[int, bool]:
        """BITTA 'docker ps' chaqiruvi — N ta alohida 'docker inspect' o'rniga.
        Bot soni 100/200/300 bo'lsa ham server boshiga bitta subprocess spawn."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "ps", "--format", "{{.Names}}",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            stdout, _ = await proc.communicate()
            running_names = set(stdout.decode().split())
        except Exception:
            logger.exception("DockerProcessManager.bulk_is_running: 'docker ps' xato")
            return {b["id"]: False for b in bot_rows}
        return {b["id"]: self._container_name(b["id"]) in running_names for b in bot_rows}

    async def bulk_get_ram_usage_mb(self, bot_rows: list[dict], server_row: dict) -> dict[int, float]:
        """BITTA 'docker stats' chaqiruvi — barcha konteynerlar uchun bir yo'la."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "stats", "--no-stream", "--format", "{{.Name}}:{{.MemUsage}}",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            stdout, _ = await proc.communicate()
            usage_by_name = {}
            for line in stdout.decode().splitlines():
                if ":" not in line:
                    continue
                name, mem_part = line.split(":", 1)
                used_str = mem_part.split("/")[0].strip()
                usage_by_name[name] = _parse_mem_to_mb(used_str)
        except Exception:
            logger.exception("DockerProcessManager.bulk_get_ram_usage_mb: 'docker stats' xato")
            usage_by_name = {}
        return {
            b["id"]: usage_by_name.get(self._container_name(b["id"]), float(b["allocated_ram_mb"]))
            for b in bot_rows
        }

    async def tail_log(self, bot_row: dict, server_row: dict, lines: int = 30) -> str:
        name = self._container_name(bot_row["id"])
        proc = await asyncio.create_subprocess_exec("docker", "logs", "--tail", str(lines), name,
                                                      stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        stdout, _ = await proc.communicate()
        return stdout.decode(errors="replace") or "Log bo'sh."

    async def get_ram_usage_mb(self, bot_id: int) -> float:
        name = self._container_name(bot_id)
        proc = await asyncio.create_subprocess_exec("docker", "stats", "--no-stream", "--format", "{{.MemUsage}}", name,
                                                      stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        stdout, _ = await proc.communicate()
        raw = stdout.decode().strip().split("/")[0].strip()
        return _parse_mem_to_mb(raw)


def _parse_mem_to_mb(raw: str) -> float:
    raw = raw.strip()
    if raw.endswith("GiB"): return float(raw[:-3]) * 1024
    if raw.endswith("MiB"): return float(raw[:-3])
    if raw.endswith("KiB"): return float(raw[:-3]) / 1024
    return 0.0


async def db_charge_bot_usage(user_id: int, bot_id: int, amount: int, description: str):
    """Tizim tomonidan avtomatik hisoblangan xarajat (masalan RAM overage).
    db_adjust_user_balance'dan farqli — bu yerda admin_logs'ga 'admin:0' kabi
    yolg'on admin amali yozilmaydi, o'z transaction turi (`usage_overage`) bilan."""
    await write_queue.execute_transaction([
        ("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, user_id)),
        ("""INSERT INTO transactions (user_id, bot_id, type, amount, status, description)
            VALUES (?, ?, 'usage_overage', ?, 'paid', ?)""",
         (user_id, bot_id, -amount, description)),
    ])


async def _estimate_server_usage(bot_row: dict, server_row: dict) -> float:
    """Bot uchun joriy RAM sarfini (MB) taxminan aniqlaydi.
    Faqat DockerProcessManager real o'lchov beradi (`docker stats`).
    Local/SSH bosqichida hali real monitoring agenti yo'q — shu sababli
    ishlab turgan botlar uchun allocated_ram_mb qaytariladi (overage = 0),
    bu PROJECT_BRIEF'da ochiq band sifatida qayd etilgan taxminiy yechim."""
    pm = get_process_manager(server_row)
    if isinstance(pm, DockerProcessManager):
        try:
            return await pm.get_ram_usage_mb(bot_row["id"])
        except Exception:
            logger.exception(f"RAM usage o'lchashda xato: bot_id={bot_row['id']}")
            return float(bot_row["allocated_ram_mb"])
    return float(bot_row["allocated_ram_mb"])


async def resource_monitor_loop(interval_seconds: int = 300):
    """Har bir ishlayotgan bot uchun RAM sarfini tekshiradi. allocated_ram_mb'dan
    oshgan qism uchun overage_rate_per_gb bo'yicha egasining balansidan yechiladi
    (metered billing — bot hech qachon shu sabab bilan to'xtatilmaydi, faqat
    ogohlantiriladi). Narx manbai: bot.overage_rate_per_gb, agar u yo'q/0 bo'lsa
    system_settings.default_ram_price fallback sifatida ishlatiladi."""
    await asyncio.sleep(5)  # db_init tugashini kutish
    while True:
        try:
            running_bots = await db_get_running_bots()
            by_server: dict[int, list[dict]] = {}
            for b in running_bots:
                if b.get("server_id"):
                    by_server.setdefault(b["server_id"], []).append(b)

            for server_id, bots_on_server in by_server.items():
                try:
                    server_row = await db_get_server(server_id)
                    if not server_row:
                        continue
                    pm = get_process_manager(server_row)
                    # BITTA bulk chaqiruv — server boshiga (Docker'da 1 ta
                    # 'docker stats'), N ta alohida so'rov o'rniga.
                    usage_map = await pm.bulk_get_ram_usage_mb(bots_on_server, server_row)
                    for bot_row in bots_on_server:
                        try:
                            await _bill_ram_overage(bot_row, usage_map.get(bot_row["id"], 0.0))
                        except Exception:
                            logger.exception(f"resource_monitor_loop: bot_id={bot_row['id']} billingida xato")
                except Exception:
                    logger.exception(f"resource_monitor_loop: server_id={server_id} uchun xato")
        except Exception:
            logger.exception("resource_monitor_loop global xato")
        await asyncio.sleep(interval_seconds)


async def _bill_ram_overage(bot_row: dict, used_mb: float):
    """Bitta bot uchun RAM overage hisoblab, kerak bo'lsa balansdan yechadi
    (avval resource_monitor_loop tanasida edi — endi alohida funksiya,
    bulk usage_map bilan chaqiriladi)."""
    allocated_mb = float(bot_row["allocated_ram_mb"])
    overage_mb = max(0.0, used_mb - allocated_mb)
    if overage_mb <= 0:
        return
    rate_per_gb = bot_row.get("overage_rate_per_gb") or 0
    if not rate_per_gb:
        rate_per_gb = await db_get_setting("default_ram_price", 0)
    if not rate_per_gb:
        return
    cost = round((overage_mb / 1024) * rate_per_gb)
    if cost <= 0:
        return
    owner = await db_get_user_by_id(bot_row["owner_id"])
    if not owner:
        return
    await db_charge_bot_usage(
        owner["id"], bot_row["id"], cost,
        description=f"RAM overage: bot #{bot_row['id']} ({overage_mb:.0f} MB ortiqcha)",
    )
    logger.info(f"RAM overage billed: bot_id={bot_row['id']} -{cost} so'm")


class SSHProcessManager(ProcessManager):
    """2-bosqich uchun joy — hozircha ishlatilmaydi. asyncssh/paramiko bilan to'ldiriladi."""
    async def start(self, bot_row, server_row): raise NotImplementedError("2-bosqichda amalga oshiriladi")
    async def stop(self, bot_row, server_row): raise NotImplementedError
    async def is_running(self, bot_row, server_row): raise NotImplementedError
    async def tail_log(self, bot_row, server_row, lines=30): raise NotImplementedError


def get_process_manager(server_row: dict) -> ProcessManager:
    if server_row and server_row.get("provider") == "vps":
        return SSHProcessManager()
    return LocalProcessManager()  # yoki DockerProcessManager() — konfiguratsiyaga qarab tanlanadi

_bot_process_locks: dict[int, asyncio.Lock] = {}

def _get_bot_process_lock(bot_id: int) -> asyncio.Lock:
    """Har bir bot uchun alohida qulf — bitta botni bir vaqtda ikki marta
    ishga tushirib yuborish (masalan tugma ikki marta bosilganda, yoki
    admin Restart bosayotganda Supervisor xuddi shu botni tiklamoqchi
    bo'lsa) imkonsiz bo'lishi uchun. Xotirada saqlanadi — jarayon qayta
    ishga tushganda tozalanadi, bu yetarli (faqat shu jarayon davomidagi
    poyga holatlarini oldini olish kerak)."""
    lock = _bot_process_locks.get(bot_id)
    if lock is None:
        lock = asyncio.Lock()
        _bot_process_locks[bot_id] = lock
    return lock


async def _stop_bot_process(bot_row: dict, reason: str):
    """Bot jarayonini to'xtatadi va DB holatini yangilaydi. Billing/admin
    force-stop kabi tizim darajasidagi to'xtatishlar uchun umumiy helper —
    'Botlarim' bo'limidagi qo'lda start/stop handlerlari ham shuni qayta ishlatadi.
    Bu funksiya HAR DOIM qasddan (deliberate) to'xtatish uchun chaqiriladi —
    Supervisor crash aniqlaganda buni chaqirmaydi (jarayon allaqachon o'lik),
    shu sababli bu yerda desired_state doim 'stopped'ga o'tadi: 'ataylab
    to'xtatilgan bot Supervisor tomonidan qayta yoqilmaydi' qoidasi shu orqali
    ta'minlanadi. _start_bot_process bilan bir xil qulfdan foydalanadi —
    start va stop bitta bot uchun hech qachon bir vaqtda ishlamaydi."""
    async with _get_bot_process_lock(bot_row["id"]):
        server_row = await db_get_server(bot_row["server_id"]) if bot_row.get("server_id") else None
        pm = get_process_manager(server_row)
        try:
            await pm.stop(bot_row, server_row)
        except Exception:
            logger.exception(f"Bot to'xtatishda xato: bot_id={bot_row['id']}")
        await db_update_bot_process(bot_row["id"], status="stopped", pid=None,
                                     stopped_at=utcnow().isoformat(sep=" ", timespec="seconds"))
        await db_set_stop_reason(bot_row["id"], reason)
        await db_set_bot_desired_state(bot_row["id"], "stopped")
        if reason != "crashed":
            # Bu qasddan/tizim tomonidan to'xtatish (billing, admin, admin_ai) —
            # Supervisor'ning ketma-ket crash hisoblagichi shu yerda tozalanadi,
            # aks holda eski crash tarixi keyingi tasodifiy to'xtashga qo'shilib ketadi.
            await db_reset_bot_crash_state(bot_row["id"])


async def _start_bot_process(bot_row: dict) -> tuple[bool, str]:
    """Bot jarayonini ishga tushiradi. Muvaffaqiyatli/xato holatini qaytaradi.
    Har qanday chaqiruvchi (qo'lda Start/Restart, billing auto-restart,
    admin_ai restart, Supervisor'ning crash-recovery'si) uchun umumiy —
    muvaffaqiyatli bo'lsa desired_state='running'ga o'tadi (bot ENDI ishlab
    turishi KERAK deb belgilanadi) va total_restarts oshadi.

    Bot boshiga qulf bilan himoyalangan: ikkita chaqiruvchi (masalan tugma
    ikki marta bosilishi, yoki Restart bilan Supervisor'ning tiklashi) bir
    vaqtda kelib qolsa, ikkinchisi birinchisi tugaguncha kutadi va so'ng
    DB'dan ENG YANGI holatni qayta o'qiydi — shu bilan bitta bot uchun
    ikkita jarayon (ikkalasi ham bir xil haqiqiy token bilan) hech qachon
    parallel ishga tushmaydi."""
    async with _get_bot_process_lock(bot_row["id"]):
        fresh = await db_get_bot(bot_row["id"])
        if fresh and fresh["status"] == "running":
            return True, "Allaqachon ishlayapti"
        bot_row = fresh or bot_row
        server_row = await db_get_server(bot_row["server_id"]) if bot_row.get("server_id") else None
        if not server_row:
            return False, "Server topilmadi"
        pm = get_process_manager(server_row)
        try:
            pid = await pm.start(bot_row, server_row)
        except Exception as e:
            logger.exception(f"Bot ishga tushirishda xato: bot_id={bot_row['id']}")
            await db_set_bot_health(bot_row["id"], "error", str(e)[:300])
            return False, str(e)
        await db_update_bot_process(bot_row["id"], status="running", pid=pid,
                                     started_at=utcnow().isoformat(sep=" ", timespec="seconds"))
        await db_set_stop_reason(bot_row["id"], None)
        await db_set_bot_desired_state(bot_row["id"], "running")
        await db_increment_bot_total_restarts(bot_row["id"])
        return True, "OK"


# ===================== BOT SUPERVISOR =====================
# Process-darajasidagi deterministik sog'liq nazorati: 'running' deb
# belgilangan botlarning jarayoni haqiqatan tirikligini tekshiradi, kutilmagan
# to'xtashni (crash) backoff jadvali bilan avtomatik tuzatadi, va ketma-ket
# muvaffaqiyatsiz urinishlarda bot egasi + adminlarga ogohlantirish yuboradi.
#
# Bir vaqtning o'zida bu ham "server/platforma qayta ishga tushgandan keyin
# botlarni avtomatik tiklash" vazifasini bajaradi: platforma qayta yuklansa,
# DB'da 'running' deb qolgan botlarning eski PID/jarayoni topilmaydi —
# supervisor buni oddiy crash sifatida aniqlaydi va xuddi shu backoff yo'li
# bilan qayta ishga tushiradi, alohida "startup" logikasi shart emas.
#
# MUHIM: bu loop admin_ai_monitor_loop'dan ATAYLAB mustaqil ishlaydi (foydalanuvchi
# talabi bilan alohida loop sifatida yozildi). Ular hozircha bir-biriga
# to'sqinlik qilmaydi, chunki admin_ai_monitor_loop faqat status='running'
# botlarni ko'radi — supervisor crashni aniqlashi bilan botni 'stopped'ga
# o'tkazadi, shu bilan admin_ai_monitor_loop'ning eski (raw) crash-aniqlash
# tarmog'i endi deyarli hech qachon ishga tushmaydi. Ikkalasini ongli ravishda
# birlashtirish (masalan: supervisor ketma-ket urinishlardan keyin AI
# diagnostikasini so'rashi) — rejadagi "User AI + Admin AI'ni Supervisor bilan
# ulash" bosqichida qilinadi, hozircha ataylab tegilmadi.
SUPERVISOR_INTERVAL_SECONDS = 30
SUPERVISOR_BACKOFF_SCHEDULE = [10, 30, 60]  # soniyalarda, crash tartib raqami bo'yicha
SUPERVISOR_CRASH_ALERT_EVERY = 3  # necha ketma-ket crashda ogohlantirish yuborilsin

SUPERVISOR_MAX_CONCURRENT_CHECKS = 20  # bir vaqtda ko'pi bilan shuncha bot holati qayta ishlanadi

async def supervisor_loop(interval_seconds: int = SUPERVISOR_INTERVAL_SECONDS):
    await asyncio.sleep(8)
    while True:
        try:
            running_bots = await db_get_running_bots()
            by_server: dict[int, list[dict]] = {}
            for b in running_bots:
                if b.get("server_id"):
                    by_server.setdefault(b["server_id"], []).append(b)

            sem = asyncio.Semaphore(SUPERVISOR_MAX_CONCURRENT_CHECKS)
            tasks = []
            for server_id, bots_on_server in by_server.items():
                server_row = await db_get_server(server_id)
                if not server_row:
                    continue
                pm = get_process_manager(server_row)
                try:
                    # BITTA bulk chaqiruv — server boshiga (Docker'da 1 ta
                    # 'docker ps'), N ta alohida 'is_running' o'rniga.
                    alive_map = await pm.bulk_is_running(bots_on_server, server_row)
                except Exception:
                    logger.exception(f"supervisor_loop: bulk_is_running xato server_id={server_id}")
                    continue
                for bot_row in bots_on_server:
                    tasks.append(_supervisor_bounded_apply(bot_row, alive_map.get(bot_row["id"], False), sem))
            if tasks:
                await asyncio.gather(*tasks)
        except Exception:
            logger.exception("supervisor_loop global xato")
        await asyncio.sleep(interval_seconds)


async def _supervisor_bounded_apply(bot_row: dict, alive: bool, sem: asyncio.Semaphore):
    async with sem:
        try:
            await _supervisor_apply_status(bot_row, alive)
        except Exception:
            logger.exception(f"supervisor_loop: bot_id={bot_row.get('id')} tekshiruvida xato")


async def _supervisor_apply_status(bot_row: dict, alive: bool):
    """Avvalgi _supervisor_check_bot bilan bir xil mantiq — faqat is_running
    natijasi endi tayyor holda keladi (server boshiga bitta bulk so'rovdan),
    har bot uchun alohida pm.is_running() chaqirilmaydi."""
    if alive:
        if (bot_row.get("consecutive_crash_count") or 0) > 0:
            await db_reset_bot_crash_state(bot_row["id"])
        if bot_row.get("health") != "ok":
            await db_set_bot_health(bot_row["id"], "ok", "")
        return

    # Kutilmagan to'xtash — crash sifatida qayd etiladi
    new_count = (bot_row.get("consecutive_crash_count") or 0) + 1
    await db_record_bot_crash(bot_row["id"], new_count)
    await db_update_bot_process(bot_row["id"], status="stopped", pid=None,
                                 stopped_at=utcnow().isoformat(sep=" ", timespec="seconds"))
    await db_set_bot_health(bot_row["id"], "error", "Jarayon kutilmaganda to'xtadi (crash)")
    await db_set_stop_reason(bot_row["id"], "crashed")
    await log_admin_action(actor="supervisor", action="crash_detected", result="OK",
                            reason=f"consecutive={new_count}", target=f"bot_{bot_row['id']}")

    if new_count % SUPERVISOR_CRASH_ALERT_EVERY == 0:
        await _supervisor_alert_crash(bot_row, new_count)

    delay = SUPERVISOR_BACKOFF_SCHEDULE[min(new_count, len(SUPERVISOR_BACKOFF_SCHEDULE)) - 1]
    asyncio.create_task(_supervisor_delayed_restart(bot_row["id"], delay, new_count))


async def _supervisor_delayed_restart(bot_id: int, delay: int, crash_count: int):
    """Backoff kutib botni qayta ishga tushiradi. Alohida asyncio task sifatida
    ishga tushadi — supervisor_loop navbatdagi botlarni tekshirishda
    to'xtab qolmasligi uchun (ko'p bot bir vaqtda crash bo'lsa ham loop bloklanmaydi)."""
    await asyncio.sleep(delay)
    bot_row = await db_get_bot(bot_id)
    if not bot_row:
        return
    # Kutish oralig'ida foydalanuvchi/admin/billing qo'lda boshqa amal qilgan
    # bo'lishi mumkin (masalan balans tugab yoki admin force-stop qilib
    # to'xtatgan, yoki foydalanuvchi ⏹ Stop bosgan) — bunday holatlarning
    # barchasida _stop_bot_process() desired_state='stopped' qilib qo'ygan
    # bo'ladi, shu sababli asosiy tekshiruv shu maydon orqali amalga oshadi.
    # stopped_reason=='crashed' tekshiruvi qo'shimcha xavfsizlik qatlami.
    if bot_row.get("desired_state") != "running" or bot_row.get("stopped_reason") != "crashed":
        return
    ok, msg = await _start_bot_process(bot_row)
    if ok:
        await log_admin_action(actor="supervisor", action="auto_restart", result="OK",
                                reason=f"backoff={delay}s, crash_count={crash_count}", target=f"bot_{bot_id}")
    else:
        await log_admin_action(actor="supervisor", action="auto_restart", result="FAILED",
                                reason=msg, target=f"bot_{bot_id}")


async def _supervisor_alert_crash(bot_row: dict, crash_count: int):
    """Ketma-ket SUPERVISOR_CRASH_ALERT_EVERY marta crash bo'lganda bot egasi
    va barcha adminlarga ogohlantirish yuboradi."""
    owner = await db_get_user_by_id(bot_row["owner_id"])
    owner_text = (
        f"🚨 '{bot_row['name']}' boti ketma-ket {crash_count} marta kutilmaganda to'xtadi (crash).\n"
        f"Kodingizni tekshirib ko'ring. Bot avtomatik qayta ishga tushirilmoqda, "
        f"lekin muammo davom etsa \"🤖 Botlarim\" bo'limidan holatini kuzating."
    )
    if owner:
        try:
            await bot.send_message(owner["telegram_id"], owner_text)
        except Exception:
            pass

    admin_text = (f"🚨 [Supervisor] Bot #{bot_row['id']} ({bot_row['name']}, "
                  f"egasi telegram_id={owner['telegram_id'] if owner else '?'}) "
                  f"ketma-ket {crash_count} marta crash bo'ldi.")
    for admin in await db_get_all_admins():
        try:
            await bot.send_message(admin["telegram_id"], admin_text)
        except Exception:
            pass


async def billing_monitor_loop(interval_seconds: int = 900):
    """Balans grace-period nazorati (billing_settings bo'yicha sozlanadi):
    balans <=0 bo'lganda balance_zero_at o'rnatiladi -> 1-ogohlantirish darhol
    -> grace_period tugashiga warning_2_hours_before qolganda 2-ogohlantirish
    -> grace_period tugagach auto-stop (auto_stop_enabled bo'lsa). Balans
    qayta to'lsa (>0) va bot 'balance_zero' sababli to'xtagan bo'lsa
    auto_restart_enabled bo'yicha avtomatik qayta ishga tushadi."""
    await asyncio.sleep(5)
    while True:
        try:
            settings = await db_get_billing_settings()
            grace_hours = settings["grace_period_hours"]
            warn2_before_hours = settings["warning_2_hours_before"]
            now = utcnow()

            users = await db_get_users_needing_billing_check()
            for user in users:
                try:
                    if user["balance"] > 0:
                        # Balans tiklandi — grace-period holatini tozalash + auto-restart
                        if user["balance_zero_at"]:
                            await db_set_billing_state(user["id"], balance_zero_at=None,
                                                        warning_1_sent=0, warning_2_sent=0,
                                                        stop_notified=0)
                            if settings["auto_restart_enabled"]:
                                for bot_row in await db_get_bots_by_owner_id(user["id"]):
                                    if bot_row["status"] == "stopped" and bot_row.get("stopped_reason") == "balance_zero":
                                        ok, _ = await _start_bot_process(bot_row)
                                        if ok:
                                            try:
                                                await bot.send_message(
                                                    user["telegram_id"],
                                                    f"✅ Balansingiz to'ldi. '{bot_row['name']}' avtomatik qayta ishga tushirildi."
                                                )
                                            except Exception:
                                                pass
                        continue

                    # balance <= 0
                    if not user["balance_zero_at"]:
                        zero_at = now.isoformat(sep=" ", timespec="seconds")
                        await db_set_billing_state(user["id"], balance_zero_at=zero_at,
                                                    warning_1_sent=1, warning_2_sent=0)
                        if settings["warning_1_enabled"]:
                            try:
                                await bot.send_message(
                                    user["telegram_id"],
                                    f"⚠️ Balansingiz tugadi. {grace_hours} soat ichida to'ldirmasangiz, "
                                    f"botlaringiz avtomatik to'xtatiladi."
                                )
                            except Exception:
                                pass
                        continue

                    zero_at = datetime.fromisoformat(user["balance_zero_at"])
                    stop_at = zero_at + timedelta(hours=grace_hours)
                    warn2_at = stop_at - timedelta(hours=warn2_before_hours)

                    if settings["warning_2_enabled"] and not user["warning_2_sent"] and now >= warn2_at and now < stop_at:
                        await db_set_billing_state(user["id"], balance_zero_at=user["balance_zero_at"],
                                                    warning_1_sent=user["warning_1_sent"], warning_2_sent=1)
                        try:
                            hours_left = max(0, int((stop_at - now).total_seconds() // 3600))
                            await bot.send_message(
                                user["telegram_id"],
                                f"⚠️ Oxirgi ogohlantirish: {hours_left} soatdan so'ng balansingiz "
                                f"to'lmasa botlaringiz to'xtatiladi."
                            )
                        except Exception:
                            pass

                    if settings["auto_stop_enabled"] and now >= stop_at:
                        for bot_row in await db_get_bots_by_owner_id(user["id"]):
                            if bot_row["status"] == "running":
                                await _stop_bot_process(bot_row, reason="balance_zero")
                        if not user["stop_notified"]:
                            await db_set_billing_state(
                                user["id"], balance_zero_at=user["balance_zero_at"],
                                warning_1_sent=user["warning_1_sent"],
                                warning_2_sent=user["warning_2_sent"], stop_notified=1
                            )
                            try:
                                await bot.send_message(
                                    user["telegram_id"],
                                    "⛔ Balansingiz uzoq vaqt to'ldirilmagani sababli botlaringiz to'xtatildi. "
                                    "Balansni to'ldirsangiz, botlar avtomatik qayta ishga tushadi."
                                )
                            except Exception:
                                pass
                except Exception:
                    logger.exception(f"billing_monitor_loop: user_id={user.get('id')} uchun xato")
        except Exception:
            logger.exception("billing_monitor_loop global xato")
        await asyncio.sleep(interval_seconds)


# ===================== DATABASE: SERVERS =====================
async def db_get_server(server_id: int) -> dict | None:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM servers WHERE id = ?", (server_id,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

async def db_get_all_servers() -> list[dict]:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM servers ORDER BY created_at DESC") as cur:
            return [dict(r) for r in await cur.fetchall()]

async def db_count_server_bots(server_id: int) -> int:
    async with db_connect() as db:
        async with db.execute("SELECT COUNT(*) FROM bots WHERE server_id = ?", (server_id,)) as cur:
            (c,) = await cur.fetchone(); return c

async def db_count_server_active_bots(server_id: int) -> int:
    async with db_connect() as db:
        async with db.execute("SELECT COUNT(*) FROM bots WHERE server_id = ? AND status = 'running'", (server_id,)) as cur:
            (c,) = await cur.fetchone(); return c

async def db_create_server(**fields) -> int:
    cols = ", ".join(fields.keys())
    placeholders = ", ".join("?" for _ in fields)
    async with db_connect() as db:
        cur = await db.execute(f"INSERT INTO servers ({cols}) VALUES ({placeholders})", list(fields.values()))
        await db.commit()
        return cur.lastrowid

async def db_update_server(server_id: int, **fields):
    ALLOWED = {"name", "ip", "ssh_port", "ssh_user", "ssh_key_encrypted", "os", "cpu_cores",
               "ram_gb", "disk_gb", "bandwidth", "monthly_price", "bot_limit",
               "storage_limit_gb", "status", "provider"}
    updates = {k: v for k, v in fields.items() if k in ALLOWED}
    if not updates: return
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    async with db_connect() as db:
        await db.execute(f"UPDATE servers SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                          (*updates.values(), server_id))
        await db.commit()

async def db_delete_server(server_id: int) -> tuple[bool, str]:
    active = await db_count_server_active_bots(server_id)
    total = await db_count_server_bots(server_id)
    if total > 0:
        return False, f"Bu serverda {total} ta bot mavjud ({active} tasi ishlayapti). Avval botlarni boshqa serverga ko'chiring."
    async with db_connect() as db:
        await db.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        await db.commit()
    return True, "O'chirildi"

async def db_get_available_servers_for_bot() -> list[dict]:
    servers = await db_get_all_servers()
    result = []
    for s in servers:
        if s["status"] != "available": continue
        if await db_count_server_bots(s["id"]) < s["bot_limit"]:
            result.append(s)
    return result


# ===================== DATABASE: BOTS =====================
async def db_get_bot(bot_id: int) -> dict | None:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM bots WHERE id = ?", (bot_id,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

async def db_get_user_bots(owner_telegram_id: int) -> list[dict]:
    user = await db_get_user_by_telegram_id(owner_telegram_id)
    if not user: return []
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM bots WHERE owner_id = ?", (user["id"],)) as cur:
            return [dict(r) for r in await cur.fetchall()]

async def db_get_running_bots() -> list[dict]:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM bots WHERE status = 'running'") as cur:
            return [dict(r) for r in await cur.fetchall()]

async def db_get_watched_bots() -> list[dict]:
    """user_ai_monitor_loop uchun — FAQAT AI umuman yoqilgan (ai_enabled=1)
    VA Monitoring alohida yoqilgan (watching_enabled=1) botlar."""
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT bots.* FROM bots JOIN bot_settings ON bot_settings.bot_id = bots.id
            WHERE bot_settings.watching_enabled = 1 AND bot_settings.ai_enabled = 1
        """) as cur:
            return [dict(r) for r in await cur.fetchall()]

async def db_create_bot(owner_id: int, name: str, username: str, token_encrypted: bytes, server_id: int) -> int:
    lastrowid, _ = await write_queue.execute(
        """INSERT INTO bots (owner_id, name, username, token_encrypted, server_id)
           VALUES (?, ?, ?, ?, ?)""",
        (owner_id, name, username, token_encrypted, server_id),
    )
    return lastrowid

async def db_get_bot_by_username(username: str) -> dict | None:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM bots WHERE username = ?", (username,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

async def db_update_bot_status(bot_id: int, status: str):
    await write_queue.execute("UPDATE bots SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (status, bot_id))

async def db_update_bot_process(bot_id: int, *, status: str, pid=None, started_at=None, stopped_at=None):
    await write_queue.execute(
        """UPDATE bots SET status = ?, pid = ?, started_at = COALESCE(?, started_at),
           stopped_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
        (status, pid, started_at, stopped_at, bot_id),
    )

async def db_set_stop_reason(bot_id: int, reason: str | None):
    await write_queue.execute("UPDATE bots SET stopped_reason = ? WHERE id = ?", (reason, bot_id))

async def db_set_bot_health(bot_id: int, health: str, reason: str = ""):
    await write_queue.execute("UPDATE bots SET health = ?, health_reason = ? WHERE id = ?", (health, reason, bot_id))

async def db_record_bot_crash(bot_id: int, consecutive_crash_count: int):
    """Supervisor: yangi crash aniqlanganda hisoblagichni oshiradi va vaqtini yozadi."""
    await write_queue.execute(
        "UPDATE bots SET consecutive_crash_count = ?, last_crash_at = ? WHERE id = ?",
        (consecutive_crash_count, utcnow().isoformat(sep=" ", timespec="seconds"), bot_id),
    )

async def db_reset_bot_crash_state(bot_id: int):
    """Bot sog'lom ekani tasdiqlangach yoki qasddan to'xtatilgach ketma-ket
    crash hisoblagichini nolga tushiradi."""
    await write_queue.execute(
        "UPDATE bots SET consecutive_crash_count = 0, last_crash_at = NULL WHERE id = ?", (bot_id,)
    )

async def db_set_bot_desired_state(bot_id: int, desired_state: str):
    """'running'/'stopped' — foydalanuvchi/tizim NIYATI. Supervisor faqat
    desired_state='running' bo'lgan botlarni crashdan keyin avtomatik tiklaydi."""
    await write_queue.execute("UPDATE bots SET desired_state = ? WHERE id = ?", (desired_state, bot_id))

async def db_increment_bot_total_restarts(bot_id: int):
    await write_queue.execute("UPDATE bots SET total_restarts = total_restarts + 1 WHERE id = ?", (bot_id,))

async def db_delete_bot(bot_id: int):
    """Bot yozuvini va unga bog'liq qatorlarni (bot_settings, bot_ai_monitor_state)
    o'chiradi. Diskdagi managed_bots/bot_<id>/ papkasi bu funksiyaga kirmaydi —
    uni chaqiruvchi (mybot_delete_do) alohida, backup olingandan keyin o'chiradi."""
    await write_queue.execute_transaction([
        ("DELETE FROM bot_settings WHERE bot_id = ?", (bot_id,)),
        ("DELETE FROM bot_ai_monitor_state WHERE bot_id = ?", (bot_id,)),
        ("DELETE FROM bots WHERE id = ?", (bot_id,)),
    ])

async def _get_owned_bot(telegram_id: int, bot_id: int) -> dict | None:
    user = await db_get_user_by_telegram_id(telegram_id)
    bot_row = await db_get_bot(bot_id)
    if not bot_row or not user or bot_row["owner_id"] != user["id"]:
        return None
    return bot_row


# ===================== DATABASE: ADMIN BOTLAR (platforma bo'yicha) =====================
ADMIN_BOTS_PAGE_SIZE = 5

async def db_admin_bots_query(filter_type: str, search: str | None, page: int,
                               page_size: int = ADMIN_BOTS_PAGE_SIZE) -> tuple[list[dict], int]:
    conditions, params = [], []
    if filter_type == "running":
        conditions.append("bots.status = 'running'")
    elif filter_type == "stopped":
        conditions.append("bots.status = 'stopped' AND (bots.stopped_reason IS NULL OR bots.stopped_reason NOT LIKE 'admin_force_stop%')")
    elif filter_type == "error":
        conditions.append("bots.health != 'ok'")
    elif filter_type == "no_balance":
        conditions.append("(bots.stopped_reason LIKE 'no_balance%' OR bots.stopped_reason LIKE '%balans%')")
    if search:
        conditions.append("(bots.name LIKE ? OR bots.username LIKE ? OR users.username LIKE ? OR CAST(users.telegram_id AS TEXT) LIKE ?)")
        like = f"%{search}%"
        params += [like, like, like, like]
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    from_clause = f"FROM bots JOIN users ON users.id = bots.owner_id LEFT JOIN servers ON servers.id = bots.server_id {where}"
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(f"SELECT COUNT(*) {from_clause}", params) as cur:
            (total,) = await cur.fetchone()
        async with db.execute(
            f"""SELECT bots.*, users.username AS owner_username, users.telegram_id AS owner_telegram_id,
                       users.balance AS owner_balance, servers.name AS server_name
                {from_clause} ORDER BY bots.created_at DESC LIMIT ? OFFSET ?""",
            params + [page_size, page * page_size],
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
    return rows, total

async def db_admin_get_bot_full(bot_id: int) -> dict | None:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """SELECT bots.*, users.username AS owner_username, users.telegram_id AS owner_telegram_id,
                      users.balance AS owner_balance, servers.name AS server_name
               FROM bots JOIN users ON users.id = bots.owner_id
               LEFT JOIN servers ON servers.id = bots.server_id
               WHERE bots.id = ?""",
            (bot_id,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

async def db_admin_switch_bot_server(bot_id: int, new_server_id: int):
    async with db_connect() as db:
        await db.execute(
            """UPDATE bots SET server_id = ?, status = 'stopped', pid = NULL,
               stopped_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
            (new_server_id, bot_id),
        )
        await db.commit()


# ===================== DATABASE: bot_settings / user_api_keys =====================
async def db_get_bot_settings(bot_id: int) -> dict:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM bot_settings WHERE bot_id = ?", (bot_id,)) as cur:
            row = await cur.fetchone()
            if row: return dict(row)
        await db.execute("INSERT INTO bot_settings (bot_id) VALUES (?)", (bot_id,))
        await db.commit()
        async with db.execute("SELECT * FROM bot_settings WHERE bot_id = ?", (bot_id,)) as cur:
            return dict(await cur.fetchone())

async def db_update_bot_setting(bot_id: int, field: str, value):
    ALLOWED_FIELDS = {"model_key_id", "character", "response_style", "system_prompt",
                       "language", "response_length", "memory_enabled", "api_fallback_enabled",
                       "user_api_key_id", "watching_enabled", "ai_enabled", "model_override",
                       "task_analyze_errors", "task_recommend"}
    if field not in ALLOWED_FIELDS:
        raise ValueError("Ruxsat etilmagan maydon")
    async with db_connect() as db:
        await db.execute(f"UPDATE bot_settings SET {field} = ?, updated_at = CURRENT_TIMESTAMP WHERE bot_id = ?",
                          (value, bot_id))
        await db.commit()

async def db_get_selectable_models() -> list[dict]:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""SELECT id, provider, model_name, display_name FROM api_keys
                                  WHERE status = 'active' AND is_user_selectable = 1 ORDER BY priority ASC""") as cur:
            return [dict(r) for r in await cur.fetchall()]

async def db_get_user_api_keys(user_id: int) -> list[dict]:
    """priority ASC — pastroq raqam = fallback zanjirida OLDINROQ sinaladi
    (Admin AI Pool bilan bir xil qoida)."""
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM user_api_keys WHERE user_id = ? ORDER BY priority ASC", (user_id,)) as cur:
            return [dict(r) for r in await cur.fetchall()]

async def db_get_user_api_key(key_id: int, user_id: int) -> dict | None:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM user_api_keys WHERE id = ? AND user_id = ?", (key_id, user_id)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

async def db_create_user_api_key(user_id: int, provider: str, label: str, api_key: str,
                                  model_name: str | None = None, base_url: str | None = None) -> int:
    """Yangi kalit avtomatik ravishda fallback navbatining OXIRIGA qo'shiladi
    (eng past priority + 1) — foydalanuvchidan alohida priority so'ralmaydi,
    keyin \"🔄 Priority\" bo'limidan ⬆️/⬇️ bilan qayta tartiblash mumkin."""
    async with db_connect() as db:
        async with db.execute("SELECT COALESCE(MAX(priority), -1) + 1 FROM user_api_keys WHERE user_id = ?", (user_id,)) as cur:
            next_priority = (await cur.fetchone())[0]
        cur = await db.execute(
            """INSERT INTO user_api_keys (user_id, provider, label, api_key_encrypted, model_name, base_url, priority)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (user_id, provider, label, encrypt_token(api_key), model_name, base_url, next_priority),
        )
        await db.commit()
        return cur.lastrowid

async def db_update_user_api_key(key_id: int, user_id: int, **fields):
    ALLOWED = {"provider", "model_name", "label", "api_key_encrypted", "status",
               "last_checked_at", "base_url", "is_active", "last_error"}
    if "api_key" in fields:
        fields["api_key_encrypted"] = encrypt_token(fields.pop("api_key"))
    updates = {k: v for k, v in fields.items() if k in ALLOWED}
    if not updates: return
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    async with db_connect() as db:
        await db.execute(f"UPDATE user_api_keys SET {set_clause} WHERE id = ? AND user_id = ?",
                          (*updates.values(), key_id, user_id))
        await db.commit()

async def db_swap_user_api_key_priority(user_id: int, key_id_a: int, key_id_b: int):
    """Ikki kalitning priority qiymatlarini almashtiradi — ⬆️/⬇️ tugmalari
    fallback tartibini shu orqali boshqaradi."""
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT id, priority FROM user_api_keys WHERE id IN (?, ?) AND user_id = ?",
                               (key_id_a, key_id_b, user_id)) as cur:
            rows = {r["id"]: r["priority"] for r in await cur.fetchall()}
        if key_id_a not in rows or key_id_b not in rows:
            return
        await db.execute("UPDATE user_api_keys SET priority = ? WHERE id = ?", (rows[key_id_b], key_id_a))
        await db.execute("UPDATE user_api_keys SET priority = ? WHERE id = ?", (rows[key_id_a], key_id_b))
        await db.commit()

async def db_delete_user_api_key(key_id: int, user_id: int):
    async with db_connect() as db:
        await db.execute("DELETE FROM user_api_keys WHERE id = ? AND user_id = ?", (key_id, user_id))
        await db.execute("UPDATE bot_settings SET user_api_key_id = NULL, watching_enabled = 0 WHERE user_api_key_id = ?", (key_id,))
        await db.commit()

# ===================== WEB: TELEGRAM LOGIN + DASHBOARD =====================
AUTH_MAX_AGE = 86400

def check_telegram_auth(data: dict) -> bool:
    data = data.copy()
    received_hash = data.pop("hash", None)
    if not received_hash: return False
    if time.time() - int(data.get("auth_date", 0)) > AUTH_MAX_AGE: return False
    check_string = "\n".join(f"{k}={v}" for k, v in sorted(data.items()))
    secret_key = hashlib.sha256(BOT_TOKEN.encode()).digest()
    computed_hash = hmac.new(secret_key, check_string.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed_hash, received_hash)

def create_session_token(telegram_id: int, secret: str, ttl: int = 30 * 86400) -> str:
    payload = {"tid": telegram_id, "exp": int(time.time()) + ttl}
    raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    sig = hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"

def verify_session_token(token: str, secret: str) -> dict | None:
    try:
        raw, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(sig, hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()):
            return None
        payload = json.loads(base64.urlsafe_b64decode(raw.encode()))
        if payload["exp"] < time.time(): return None
        return {"telegram_id": payload["tid"]}
    except Exception:
        return None

async def handle_login_page(request: web.Request) -> web.Response:
    html = f"""<html><head><title>Kirish</title></head>
    <body style="display:flex;justify-content:center;align-items:center;height:100vh;background:#0f172a;">
      <script async src="https://telegram.org/js/telegram-widget.js?22"
        data-telegram-login="{BOT_USERNAME}" data-size="large"
        data-auth-url="/auth/telegram" data-request-access="write"></script>
    </body></html>"""
    return web.Response(text=html, content_type="text/html")

async def handle_auth_telegram(request: web.Request) -> web.Response:
    params = dict(request.query)
    if not check_telegram_auth(params):
        return web.Response(text="Autentifikatsiya muvaffaqiyatsiz", status=403)
    telegram_id = int(params["id"])
    user = await db_get_user_by_telegram_id(telegram_id)
    if not user:
        user = await db_create_user(telegram_id, params.get("first_name", ""), params.get("username", ""))
    settings = await db_get_all_settings()
    ttl_seconds = max(int(settings.get("session_timeout_minutes", 60)), 1) * 60
    session_token = create_session_token(telegram_id, SESSION_SECRET, ttl=ttl_seconds)
    response = web.HTTPFound("/dashboard")
    response.set_cookie("session", session_token, httponly=True, secure=True, samesite="Lax", max_age=ttl_seconds)
    return response

@web.middleware
async def rate_limit_middleware(request: web.Request, handler):
    # IP bo'yicha cheklaydi. request.remote proksi orqasida bo'lsa noto'g'ri
    # bo'lishi mumkin — reverse proxy ishlatilsa X-Forwarded-For'ni to'g'ri
    # sozlash (aiohttp'da trust qilingan proksidan) alohida vazifa.
    ip = request.remote or "unknown"
    if request.path == "/payment/notify":
        ok = rate_limiter.check(f"payment:{ip}", "payment_webhook")
    elif request.path.startswith("/api/") or request.path in ("/login", "/auth/telegram", "/dashboard"):
        ok = rate_limiter.check(f"web:{ip}", "web_api")
    else:
        ok = True
    if not ok:
        return web.json_response({"error": "too_many_requests"}, status=429)
    return await handler(request)

@web.middleware
async def auth_middleware(request: web.Request, handler):
    # Mini App o'z sessiyasini shu endpoint orqali o'rnatadi (initData bilan) —
    # shuning uchun bu yo'l cookie tekshiruvidan ISTISNO qilinadi.
    if request.path == "/api/miniapp/auth":
        return await handler(request)
    protected = ("/dashboard", "/bots", "/servers", "/settings", "/admin", "/api/")
    if any(request.path.startswith(p) for p in protected):
        token = request.cookies.get("session")
        user = verify_session_token(token, SESSION_SECRET) if token else None
        if not user:
            if request.path.startswith("/api/"):
                return web.json_response({"error": "unauthorized"}, status=401)
            return web.HTTPFound("/login")
        request["user"] = user
        is_admin_path = request.path.startswith("/admin") or request.path.startswith("/api/miniapp/admin")
        if is_admin_path and not await is_admin(user["telegram_id"]):
            if request.path.startswith("/api/"):
                return web.json_response({"error": "forbidden"}, status=403)
            return web.Response(text="Ruxsat yo'q", status=403)
    return await handler(request)

async def handle_dashboard(request: web.Request) -> web.Response:
    telegram_id = request["user"]["telegram_id"]
    user = await db_get_user_by_telegram_id(telegram_id)
    bots = await db_get_user_bots(telegram_id)
    servers = await db_get_all_servers()
    admin_link = '<a href="/admin" class="nav-item">Admin</a>' if user["is_admin"] else ""
    html = f"""<html><body style="font-family:sans-serif;background:#0f172a;color:#e2e8f0;">
      <h2>Salom, {user['first_name']}</h2>
      <p>Balans: {fmt_som(user['balance'])} so'm | Botlar: {len(bots)}</p>
      {admin_link}
    </body></html>"""
    return web.Response(text=html, content_type="text/html")


# ===================== WEB: TELEGRAM MINI APP =====================
# Bot + web panelning qulay interfeysi (botning o'rnini bosuvchi alohida
# tizim EMAS). Auth — Telegram WebApp initData orqali, Login Widget'dan
# FARQLI hash algoritmi bilan. Muvaffaqiyatli tekshiruvdan so'ng xuddi
# saytdagi kabi session cookie o'rnatiladi — shu bitta sessiya mexanizmi
# website va Mini App uchun umumiy ishlatiladi.

def verify_webapp_init_data(init_data: str, max_age: int = AUTH_MAX_AGE) -> dict | None:
    """Telegram Mini App initData'ni rasmiy algoritm bo'yicha tekshiradi:
    secret_key = HMAC-SHA256(key="WebAppData", msg=BOT_TOKEN)
    hash = HMAC-SHA256(key=secret_key, msg=data_check_string)
    (data_check_string — hash'dan tashqari barcha maydonlar alifbo tartibida
    "key=value" qilib \\n bilan birlashtirilgan). Muvaffaqiyatli bo'lsa
    {telegram_id, first_name, username} qaytaradi, aks holda None."""
    if not init_data:
        return None
    try:
        pairs = dict(urllib.parse.parse_qsl(init_data, strict_parsing=True))
    except ValueError:
        return None
    received_hash = pairs.pop("hash", None)
    if not received_hash:
        return None
    try:
        auth_date = int(pairs.get("auth_date", 0))
    except ValueError:
        return None
    if time.time() - auth_date > max_age:
        return None
    data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(pairs.items()))
    secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    computed_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(computed_hash, received_hash):
        return None
    try:
        user_data = json.loads(pairs.get("user", "{}"))
    except json.JSONDecodeError:
        user_data = {}
    if not user_data.get("id"):
        return None
    return {
        "telegram_id": int(user_data["id"]),
        "first_name": user_data.get("first_name", ""),
        "username": user_data.get("username", ""),
    }


async def handle_miniapp_auth(request: web.Request) -> web.Response:
    """POST /api/miniapp/auth — initData'ni tekshiradi, kerak bo'lsa
    foydalanuvchini yaratadi (xuddi /start bilan bir xil qoidalar:
    registration_enabled, maintenance_mode) va session cookie o'rnatadi."""
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "bad_request"}, status=400)

    webapp_user = verify_webapp_init_data(body.get("initData", ""))
    if not webapp_user:
        return web.json_response({"error": "invalid_init_data"}, status=403)

    telegram_id = webapp_user["telegram_id"]
    settings = await db_get_all_settings()
    user = await db_get_user_by_telegram_id(telegram_id)
    if not user:
        if not settings.get("registration_enabled", True):
            return web.json_response({"error": "registration_closed"}, status=403)
        user = await db_create_user(telegram_id, webapp_user.get("first_name", ""), webapp_user.get("username", ""))

    is_admin_user = bool(user["is_admin"])
    if settings.get("maintenance_mode", False) and not (is_admin_user and settings.get("maintenance_admin_bypass", True)):
        return web.json_response({
            "error": "maintenance",
            "message": settings.get("maintenance_message") or "Texnik xizmat ko'rsatilmoqda.",
        }, status=503)

    session_token = create_session_token(telegram_id, SESSION_SECRET, ttl=max(int(settings.get("session_timeout_minutes", 60)), 1) * 60)
    response = web.json_response({"ok": True})
    response.set_cookie("session", session_token, httponly=True, secure=True, samesite="Lax",
                         max_age=max(int(settings.get("session_timeout_minutes", 60)), 1) * 60)
    return response


async def handle_miniapp_me(request: web.Request) -> web.Response:
    """GET /api/miniapp/me — Bosh sahifa uchun profil/balans/hisoblar."""
    telegram_id = request["user"]["telegram_id"]
    user = await db_get_user_by_telegram_id(telegram_id)
    if not user:
        return web.json_response({"error": "user_not_found"}, status=404)
    bots = await db_get_user_bots(telegram_id)
    servers_count = len({b["server_id"] for b in bots if b.get("server_id")})
    return web.json_response({
        "first_name": user["first_name"],
        "username": user["username"] or "",
        "balance": user["balance"],
        "is_admin": bool(user["is_admin"]),
        "bots_count": len(bots),
        "servers_count": servers_count,
    })


MINIAPP_HTML = """<!DOCTYPE html>
<html lang="uz">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Platform</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<style>
  :root {
    --bg: #0b0f19; --surface: #131826; --surface-2: #1b2333;
    --text: #e7eaf0; --muted: #7c8598; --accent: #4c8dff;
    --success: #34c77b; --danger: #f1493d;
    --radius: 18px;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    padding: 16px 16px 32px; min-height: 100vh;
  }
  .greet { font-size: 15px; color: var(--muted); margin: 4px 0 16px; }
  .greet b { color: var(--text); }
  .balance-card {
    background: linear-gradient(135deg, var(--accent), #2f5fce);
    border-radius: var(--radius); padding: 20px; margin-bottom: 20px;
    box-shadow: 0 8px 24px rgba(76,141,255,0.25);
  }
  .balance-label { font-size: 13px; opacity: 0.85; margin-bottom: 6px; }
  .balance-value {
    font-family: ui-monospace, "SF Mono", "Roboto Mono", monospace;
    font-size: 32px; font-weight: 600; letter-spacing: -0.5px;
  }
  .balance-value span { font-size: 16px; font-weight: 400; opacity: 0.85; margin-left: 4px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .tile {
    background: var(--surface); border-radius: var(--radius); padding: 16px;
    display: flex; flex-direction: column; gap: 8px; cursor: pointer;
    border: 1px solid transparent; transition: border-color 0.15s, background 0.15s;
  }
  .tile:active { background: var(--surface-2); border-color: var(--accent); }
  .tile-icon { font-size: 22px; }
  .tile-label { font-size: 14px; color: var(--text); }
  .tile-count {
    font-family: ui-monospace, "SF Mono", "Roboto Mono", monospace;
    font-size: 20px; font-weight: 600; color: var(--muted);
  }
  .tile.admin { grid-column: 1 / -1; background: var(--surface-2); }
  #status { color: var(--muted); font-size: 14px; text-align: center; padding: 40px 0; }
  #toast {
    position: fixed; left: 50%; bottom: 24px; transform: translateX(-50%);
    background: var(--surface-2); color: var(--text); padding: 10px 16px;
    border-radius: 12px; font-size: 13px; opacity: 0; pointer-events: none;
    transition: opacity 0.2s;
  }
</style>
</head>
<body>
  <div id="status">⏳ Yuklanmoqda...</div>
  <div id="app" style="display:none">
    <div class="greet">👋 Salom, <b id="name"></b></div>
    <div class="balance-card">
      <div class="balance-label">💰 Balans</div>
      <div class="balance-value"><span id="balance">0</span><span>so'm</span></div>
    </div>
    <div class="grid">
      <div class="tile" data-target="bots">
        <div class="tile-icon">🤖</div>
        <div class="tile-label">Botlarim</div>
        <div class="tile-count" id="bots_count">0</div>
      </div>
      <div class="tile" data-target="servers">
        <div class="tile-icon">🖥️</div>
        <div class="tile-label">Serverlar</div>
        <div class="tile-count" id="servers_count">0</div>
      </div>
      <div class="tile" data-target="topup">
        <div class="tile-icon">💳</div>
        <div class="tile-label">Balansni to'ldirish</div>
      </div>
      <div class="tile" data-target="ai">
        <div class="tile-icon">🧠</div>
        <div class="tile-label">AI</div>
      </div>
      <div class="tile" data-target="backup">
        <div class="tile-icon">🗄️</div>
        <div class="tile-label">Backup</div>
      </div>
      <div class="tile" data-target="settings">
        <div class="tile-icon">⚙️</div>
        <div class="tile-label">Sozlamalar</div>
      </div>
      <div class="tile admin" id="admin_tile" data-target="admin" style="display:none">
        <div class="tile-icon">👑</div>
        <div class="tile-label">Admin panel</div>
      </div>
    </div>
  </div>
  <div id="toast"></div>

<script>
const tg = window.Telegram && window.Telegram.WebApp;

function showToast(text) {
  const t = document.getElementById('toast');
  t.textContent = text;
  t.style.opacity = '1';
  setTimeout(() => { t.style.opacity = '0'; }, 1800);
}

function applyTheme() {
  if (!tg || !tg.themeParams) return;
  const p = tg.themeParams;
  const root = document.documentElement.style;
  if (p.bg_color) root.setProperty('--bg', p.bg_color);
  if (p.text_color) root.setProperty('--text', p.text_color);
  if (p.hint_color) root.setProperty('--muted', p.hint_color);
  if (p.button_color) root.setProperty('--accent', p.button_color);
  if (p.secondary_bg_color) root.setProperty('--surface', p.secondary_bg_color);
}

async function init() {
  if (!tg || !tg.initData) {
    document.getElementById('status').textContent =
      '⚠️ Bu sahifa faqat Telegram ilovasi ichida ishlaydi.';
    return;
  }
  tg.ready();
  tg.expand();
  applyTheme();

  const authRes = await fetch('/api/miniapp/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ initData: tg.initData }),
  });
  if (!authRes.ok) {
    const err = await authRes.json().catch(() => ({}));
    document.getElementById('status').textContent =
      '⚠️ ' + (err.message || 'Kirishda xato. Qaytadan urinib ko\\'ring.');
    return;
  }

  const meRes = await fetch('/api/miniapp/me');
  if (!meRes.ok) {
    document.getElementById('status').textContent = '⚠️ Ma\\'lumotlarni yuklab bo\\'lmadi.';
    return;
  }
  const me = await meRes.json();

  document.getElementById('name').textContent = me.username ? '@' + me.username : me.first_name;
  document.getElementById('balance').textContent = Number(me.balance).toLocaleString('uz-UZ');
  document.getElementById('bots_count').textContent = me.bots_count;
  document.getElementById('servers_count').textContent = me.servers_count;
  if (me.is_admin) document.getElementById('admin_tile').style.display = 'flex';

  document.getElementById('status').style.display = 'none';
  document.getElementById('app').style.display = 'block';

  document.querySelectorAll('.tile').forEach(el => {
    el.addEventListener('click', () => {
      // Bosqichma-bosqich qo'shiladi: hozircha faqat Bosh sahifa tayyor.
      showToast('🔜 "' + el.querySelector('.tile-label').textContent + '" tez orada qo\\'shiladi');
      if (tg.HapticFeedback) tg.HapticFeedback.impactOccurred('light');
    });
  });
}

init();
</script>
</body>
</html>"""


async def handle_miniapp_page(request: web.Request) -> web.Response:
    return web.Response(text=MINIAPP_HTML, content_type="text/html")


# ===================== WEB: CLICK PAYMENT CALLBACK =====================
CLICK_ERROR_SUCCESS = 0
CLICK_ERROR_SIGN_FAILED = -1
CLICK_ERROR_AMOUNT_MISMATCH = -2
CLICK_ERROR_ACTION_NOT_FOUND = -3
CLICK_ERROR_ALREADY_PAID = -4
CLICK_ERROR_USER_NOT_FOUND = -5
CLICK_ERROR_TRANSACTION_NOT_FOUND = -6
CLICK_ERROR_REQUEST_FAILED = -8

async def db_get_click_settings() -> dict:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM click_settings WHERE id = 1") as cur:
            row = await cur.fetchone()
            return dict(row) if row else {}

def verify_click_sign(params: dict, secret_key: str, action: str) -> bool:
    """Click Merchant API imzo tekshiruvi (rasmiy formulaga ko'ra):
    Prepare (action=0): md5(click_trans_id+service_id+SECRET+merchant_trans_id+amount+action+sign_time)
    Complete (action=1): md5(click_trans_id+service_id+SECRET+merchant_trans_id+merchant_prepare_id+amount+action+sign_time)"""
    click_trans_id = params.get("click_trans_id", "")
    service_id = params.get("service_id", "")
    merchant_trans_id = params.get("merchant_trans_id", "")
    amount = params.get("amount", "")
    sign_time = params.get("sign_time", "")
    received_sign = params.get("sign_string", "")

    if action == "0":
        raw = f"{click_trans_id}{service_id}{secret_key}{merchant_trans_id}{amount}{action}{sign_time}"
    else:
        merchant_prepare_id = params.get("merchant_prepare_id", "")
        raw = f"{click_trans_id}{service_id}{secret_key}{merchant_trans_id}{merchant_prepare_id}{amount}{action}{sign_time}"

    computed = hashlib.md5(raw.encode()).hexdigest()
    return hmac.compare_digest(computed, received_sign)


async def db_get_pending_topup_by_merchant_trans_id(merchant_trans_id: str) -> dict | None:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM transactions WHERE merchant_trans_id = ? AND type = 'topup'",
            (merchant_trans_id,),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

async def db_get_transaction(transaction_id: int) -> dict | None:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM transactions WHERE id = ?", (transaction_id,)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

async def db_create_pending_topup(user_id: int, amount: int) -> dict:
    """Balans to'ldirish FSM: yangi 'pending' tranzaksiya yaratadi.
    merchant_trans_id — PK asosida ('tu{id}') generatsiya qilinadi, shu bilan
    100% noyob bo'lishi kafolatlanadi (Click callback aynan shu maydon orqali
    tranzaksiyani topadi — db_get_pending_topup_by_merchant_trans_id)."""
    async with db_connect() as db:
        cur = await db.execute(
            "INSERT INTO transactions (user_id, type, amount, status) VALUES (?, 'topup', ?, 'pending')",
            (user_id, amount),
        )
        transaction_id = cur.lastrowid
        merchant_trans_id = f"tu{transaction_id}"
        await db.execute("UPDATE transactions SET merchant_trans_id = ? WHERE id = ?",
                          (merchant_trans_id, transaction_id))
        await db.commit()
    return await db_get_transaction(transaction_id)

async def db_cancel_stale_pending_topups(user_id: int):
    """Foydalanuvchi yangi to'ldirish boshlaganda, uning eski ochiq (pending/
    prepared) topup'larini bekor qiladi — bir vaqtning o'zida bir nechta
    "ochiq" tranzaksiya yig'ilib qolmasligi uchun."""
    async with db_connect() as db:
        await db.execute(
            "UPDATE transactions SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP "
            "WHERE user_id = ? AND type = 'topup' AND status IN ('pending', 'prepared')",
            (user_id,),
        )
        await db.commit()

async def db_set_transaction_screenshot(transaction_id: int, file_id: str):
    async with db_connect() as db:
        await db.execute(
            "UPDATE transactions SET receipt_photo_id = ?, status = 'manual_review', "
            "updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (file_id, transaction_id),
        )
        await db.commit()

async def db_admin_approve_manual_topup(transaction_id: int) -> tuple[bool, dict | None]:
    """Qo'lda (skrinshot) tasdiqlash — ATOMIK: faqat status='manual_review'
    bo'lgan qatorni 'paid'ga o'tkazadi. Ikki admin bir vaqtda ✅ bossa ham,
    yoki bitta admin ikki marta bossa ham, balans FAQAT BIR MARTA oshadi."""
    txn = await db_get_transaction(transaction_id)
    if not txn:
        return False, None
    async with db_connect() as db:
        cur = await db.execute(
            "UPDATE transactions SET status = 'paid', updated_at = CURRENT_TIMESTAMP "
            "WHERE id = ? AND status = 'manual_review'",
            (transaction_id,),
        )
        applied = cur.rowcount == 1
        if applied:
            await db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (txn["amount"], txn["user_id"]))
        await db.commit()
    return applied, txn

async def db_admin_update_manual_topup_amount(transaction_id: int, new_amount_tiyin: int) -> dict | None:
    """Admin skrinshotni ko'rib, foydalanuvchi noto'g'ri summa kiritganini
    aniqlasa, tasdiqlashdan OLDIN summani to'g'rilashi uchun. Faqat hali
    'manual_review' holatidagi (ya'ni hali tasdiqlanmagan/rad etilmagan)
    tranzaksiyada ishlaydi — approve/reject bo'lib bo'lgan tranzaksiyaga
    tegilmaydi (approve/reject funksiyalaridagi bir xil atomiklik qoidasi)."""
    async with db_connect() as db:
        cur = await db.execute(
            "UPDATE transactions SET amount = ?, updated_at = CURRENT_TIMESTAMP "
            "WHERE id = ? AND status = 'manual_review'",
            (new_amount_tiyin, transaction_id),
        )
        applied = cur.rowcount == 1
        await db.commit()
    return await db_get_transaction(transaction_id) if applied else None

async def db_admin_reject_manual_topup(transaction_id: int) -> tuple[bool, dict | None]:
    """Qo'lda rad etish — ATOMIK: faqat status='manual_review' bo'lgan
    qatorni 'failed'ga o'tkazadi (idempotent, approve bilan bir xil qoida)."""
    txn = await db_get_transaction(transaction_id)
    if not txn:
        return False, None
    async with db_connect() as db:
        cur = await db.execute(
            "UPDATE transactions SET status = 'failed', updated_at = CURRENT_TIMESTAMP "
            "WHERE id = ? AND status = 'manual_review'",
            (transaction_id,),
        )
        applied = cur.rowcount == 1
        await db.commit()
    return applied, txn

async def db_get_user_transactions(user_id: int, limit: int, offset: int) -> list[dict]:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (user_id, limit, offset),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

async def db_count_user_transactions(user_id: int) -> int:
    async with db_connect() as db:
        async with db.execute("SELECT COUNT(*) FROM transactions WHERE user_id = ?", (user_id,)) as cur:
            row = await cur.fetchone()
            return row[0] if row else 0

def _build_click_pay_url(click_settings: dict, amount_tiyin: int, merchant_trans_id: str) -> str | None:
    merchant_id = click_settings.get("merchant_id")
    service_id = click_settings.get("service_id")
    if not merchant_id or not service_id:
        return None
    # Click Merchant API amount= so'mda kutiladi (tiyin emas) — bizda amount_tiyin
    # ichki saqlash birligi, shu sabab URL uchun 100'ga bo'lib so'mga aylantiramiz.
    amount_som = Decimal(amount_tiyin) / 100
    return (f"https://my.click.uz/services/pay?service_id={service_id}&merchant_id={merchant_id}"
            f"&amount={amount_som}&transaction_param={merchant_trans_id}")

async def db_mark_click_prepared(transaction_id: int, click_trans_id: str):
    async with db_connect() as db:
        await db.execute(
            """UPDATE transactions SET provider = 'click', provider_trans_id = ?,
               status = 'prepared', updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
            (click_trans_id, transaction_id),
        )
        await db.commit()

async def db_complete_click_topup(transaction_id: int, user_id: int, amount: int) -> bool:
    """Balansni ATOMIK ravishda oshiradi — FAQAT agar tranzaksiya hali ham
    'prepared' holatida bo'lsa (bitta shartli UPDATE, keyin cur.rowcount
    tekshiriladi). Bu SELECT'dan keyin alohida UPDATE qilishdan farqli —
    tekshirish va yozish BITTA atomik operatsiya, shu bilan Click'dan bir xil
    Complete so'rovi ikki marta (masalan tarmoq retry yoki parallel so'rov
    sabab) kelib qolsa ham, balans FAQAT BIR MARTA oshadi."""
    async with db_connect() as db:
        cur = await db.execute(
            "UPDATE transactions SET status = 'paid', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'prepared'",
            (transaction_id,),
        )
        applied = cur.rowcount == 1
        if applied:
            await db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))
        await db.commit()
        return applied

async def db_cancel_click_topup(transaction_id: int):
    async with db_connect() as db:
        await db.execute(
            "UPDATE transactions SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (transaction_id,),
        )
        await db.commit()

def _click_response(error: int, error_note: str, **extra) -> web.Response:
    return web.json_response({"error": error, "error_note": error_note, **extra})

async def handle_click_callback(request: web.Request) -> web.Response:
    """Click Merchant API: Prepare (action=0) va Complete (action=1).
    Balansga faqat SHU YERDA, server tomonidan imzosi (sign_string) rasmiy
    tekshirilgan tranzaksiya qo'shiladi. Ikki marta hisoblashdan himoya:
    Complete faqat status='prepared' bo'lgan qatorni 'paid'ga o'tkazadi,
    qayta kelsa CLICK_ERROR_ALREADY_PAID qaytaradi."""
    try:
        data = await request.post()
        params = dict(data)
    except Exception:
        return _click_response(CLICK_ERROR_REQUEST_FAILED, "So'rovni o'qib bo'lmadi")

    click_settings = await db_get_click_settings()
    if not click_settings.get("secret_key_encrypted"):
        return _click_response(CLICK_ERROR_REQUEST_FAILED, "Click sozlanmagan")
    secret_key = decrypt_token(click_settings["secret_key_encrypted"])

    action = str(params.get("action", ""))
    merchant_trans_id = params.get("merchant_trans_id", "")
    click_trans_id = params.get("click_trans_id", "")

    if not verify_click_sign(params, secret_key, action):
        return _click_response(CLICK_ERROR_SIGN_FAILED, "Imzo noto'g'ri")

    txn = await db_get_pending_topup_by_merchant_trans_id(merchant_trans_id)
    if not txn:
        return _click_response(CLICK_ERROR_TRANSACTION_NOT_FOUND, "Tranzaksiya topilmadi")

    user = await db_get_user_by_id(txn["user_id"])
    if not user:
        return _click_response(CLICK_ERROR_USER_NOT_FOUND, "Foydalanuvchi topilmadi")

    try:
        # Click "amount" parametrini so'mda yuboradi (masalan "50000.00") — bizda
        # ichki birlik tiyin, shu sabab *100 qilib txn["amount"] bilan solishtiramiz.
        received_amount = int((Decimal(str(params.get("amount", 0))) * 100).to_integral_value())
    except Exception:
        return _click_response(CLICK_ERROR_AMOUNT_MISMATCH, "Summani o'qib bo'lmadi")
    if received_amount != int(txn["amount"]):
        return _click_response(CLICK_ERROR_AMOUNT_MISMATCH, "Summa mos kelmadi")

    if action == "0":  # Prepare
        if txn["status"] != "pending":
            return _click_response(CLICK_ERROR_ALREADY_PAID, "Allaqachon qayta ishlangan")
        await db_mark_click_prepared(txn["id"], click_trans_id)
        return _click_response(CLICK_ERROR_SUCCESS, "Success", click_trans_id=click_trans_id,
                                merchant_trans_id=merchant_trans_id, merchant_prepare_id=txn["id"])

    elif action == "1":  # Complete
        merchant_prepare_id = params.get("merchant_prepare_id", "")
        if str(txn["id"]) != str(merchant_prepare_id):
            return _click_response(CLICK_ERROR_TRANSACTION_NOT_FOUND, "merchant_prepare_id mos emas")

        click_error = str(params.get("error", "0"))
        if click_error != "0":
            # Click tomonidan bekor qilingan (foydalanuvchi to'lovdan voz kechgan va h.k.)
            await db_cancel_click_topup(txn["id"])
            return _click_response(CLICK_ERROR_SUCCESS, "Success", click_trans_id=click_trans_id,
                                    merchant_trans_id=merchant_trans_id, merchant_confirm_id=txn["id"])

        if txn["status"] == "paid":
            return _click_response(CLICK_ERROR_ALREADY_PAID, "Allaqachon to'langan")
        if txn["status"] != "prepared":
            return _click_response(CLICK_ERROR_TRANSACTION_NOT_FOUND, "Avval Prepare bosqichi bajarilmagan")

        applied = await db_complete_click_topup(txn["id"], user["id"], int(txn["amount"]))
        if applied:
            try:
                await bot.send_message(user["telegram_id"], f"✅ Balansingiz {fmt_som(txn['amount'])} so'mga to'ldirildi.")
            except Exception:
                pass
        # applied=False bo'lsa ham Click'ga SUCCESS qaytariladi (parallel so'rov
        # allaqachon tugatgan bo'lishi mumkin) — lekin balans IKKINCHI marta
        # oshirilmaydi, chunki db_complete_click_topup shart bilan atomik ishlaydi.
        return _click_response(CLICK_ERROR_SUCCESS, "Success", click_trans_id=click_trans_id,
                                merchant_trans_id=merchant_trans_id, merchant_confirm_id=txn["id"])

    return _click_response(CLICK_ERROR_ACTION_NOT_FOUND, "action topilmadi")


def setup_web_routes(app: web.Application):
    # Tartib muhim: rate_limit_middleware BIRINCHI ishlashi kerak (auth
    # tekshiruvidan oldin so'rovni bloklash — noto'g'ri autentifikatsiya
    # qilingan spam ham limitga tushishi uchun).
    app.middlewares.append(rate_limit_middleware)
    app.middlewares.append(auth_middleware)
    app.router.add_get("/login", handle_login_page)
    app.router.add_get("/auth/telegram", handle_auth_telegram)
    app.router.add_get("/dashboard", handle_dashboard)
    app.router.add_post("/click/callback", handle_click_callback)
    app.router.add_post("/payment/notify", handle_payment_notify)
    app.router.add_get("/app", handle_miniapp_page)
    app.router.add_post("/api/miniapp/auth", handle_miniapp_auth)
    app.router.add_get("/api/miniapp/me", handle_miniapp_me)
    # TODO: /bots /servers /settings /admin sahifalari — suhbatda faqat backend
    # logikasi (Telegram bot tomoni) to'liq yozilgan, HTML sahifalar hali yo'q.
    # TODO: Mini App'ning qolgan ekranlari (Botlarim/Serverlar/Balans/AI/
    # Backup/Sozlamalar/Admin) — hozircha faqat Bosh sahifa ishlaydi,
    # bosqichma-bosqich qo'shiladi (PROJECT_BRIEF.md'ga qarang).


# ===================== DATABASE: PAYMENT MANAGER (karta-karta + SMS monitoring) =====================
# Click Merchant API'dan MUSTAQIL, alohida to'lov yo'li. Barcha summalar
# BUTUN SO'MDA (INTEGER) — kasrli summa kiritilsa YAXLITLANMAYDI, agar
# payment_settings.allow_fractional=0 bo'lsa oddiy rad etiladi (aniq hisob:
# taxminiy moslashtirish yo'q). PIN/CVV/OTP hech qachon saqlanmaydi —
# faqat karta raqamining o'zi encrypt_token() bilan shifrlanadi.

PAYMENT_SETTINGS_COLUMNS = {
    "min_amount", "max_amount", "payment_ttl_minutes", "max_concurrent_orders",
    "allow_fractional", "sms_monitoring_enabled", "ai_supervisor_enabled",
    "fraud_protection_enabled", "fraud_velocity_window_minutes",
    "fraud_velocity_max_orders", "fraud_large_amount_threshold",
}

async def db_get_payment_settings() -> dict:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        row = await db.execute("SELECT * FROM payment_settings WHERE id = 1")
        row = await row.fetchone()
        return dict(row) if row else {}

async def db_update_payment_settings(**fields) -> None:
    cols = {k: v for k, v in fields.items() if k in PAYMENT_SETTINGS_COLUMNS}
    if not cols:
        return
    set_clause = ", ".join(f"{col} = ?" for col in cols)
    async with db_connect() as db:
        await db.execute(f"UPDATE payment_settings SET {set_clause}, updated_at = ? WHERE id = 1",
                          (*cols.values(), utcnow().isoformat()))
        await db.commit()

def parse_exact_som_amount(text: str) -> int | None:
    """Foydalanuvchi kiritgan summani TIYINGA (int, 1 so'm = 100 tiyin) aylantiradi.
    2 xonagacha kasr qabul qilinadi (masalan '14.03' -> 1403 tiyin). 2 xonadan
    ortiq kasr YAXLITLANMAYDI — None qaytaradi, chaqiruvchi tomon buni rad etish
    sifatida ishlatadi (aniq hisob talabi, taxminiy moslashtirish yo'q)."""
    text = text.strip().replace(" ", "").replace("_", "").replace(",", ".")
    try:
        value = Decimal(text)
    except Exception:
        return None
    tiyin = value * 100
    if tiyin != tiyin.to_integral_value():
        return None  # 2 xonadan ortiq kasr — rad etiladi
    if tiyin <= 0:
        return None
    return int(tiyin)

def fmt_som(tiyin: int) -> str:
    """Tiyinni (int) o'qish uchun qulay so'm matniga aylantiradi: agar tiyin
    qismi 0 bo'lsa butun ko'rsatiladi (12 000 so'm), aks holda 2 xonali kasr
    bilan (12 000.05 so'm)."""
    tiyin = int(tiyin)
    som, rem = divmod(abs(tiyin), 100)
    sign = "-" if tiyin < 0 else ""
    if rem == 0:
        return f"{sign}{som:,}"
    return f"{sign}{som:,}.{rem:02d}"

# ---- Kartalar ----
async def db_get_active_card() -> dict | None:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        row = await db.execute("SELECT * FROM payment_cards WHERE status = 'active' ORDER BY id DESC LIMIT 1")
        row = await row.fetchone()
        return dict(row) if row else None

async def db_add_payment_card(card_number: str, monitor_device_name: str = "") -> dict:
    """Yangi kartani qo'shadi va uni yagona faol karta qiladi (avvalgi faol
    karta bo'lsa, avtomatik o'chiriladi — bir vaqtda bitta faol karta)."""
    last4 = card_number.replace(" ", "")[-4:]
    encrypted = encrypt_token(card_number.replace(" ", ""))
    async with db_connect() as db:
        await db.execute("UPDATE payment_cards SET status = 'disabled' WHERE status = 'active'")
        cur = await db.execute(
            """INSERT INTO payment_cards (card_number_encrypted, card_last4, status, monitor_device_name, updated_at)
               VALUES (?, ?, 'active', ?, ?)""",
            (encrypted, last4, monitor_device_name, utcnow().isoformat()),
        )
        await db.commit()
        card_id = cur.lastrowid
    return await db_get_card(card_id)

async def db_get_card(card_id: int) -> dict | None:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        row = await db.execute("SELECT * FROM payment_cards WHERE id = ?", (card_id,))
        row = await row.fetchone()
        return dict(row) if row else None

async def db_set_card_status(card_id: int, status: str) -> None:
    await write_queue.execute("UPDATE payment_cards SET status = ?, updated_at = ? WHERE id = ?",
                               (status, utcnow().isoformat(), card_id))

async def db_touch_card_notification(card_id: int, detected_transaction_id: str = "") -> None:
    """SMS-monitoring qurilmasidan bildirishnoma kelganda chaqiriladi (Payment
    Monitor ulanganda to'liq yoziladi) — oxirgi bildirishnoma vaqtini yangilaydi."""
    if detected_transaction_id:
        await write_queue.execute(
            "UPDATE payment_cards SET last_notification_at = ?, last_detected_transaction_id = ? WHERE id = ?",
            (utcnow().isoformat(), detected_transaction_id, card_id))
    else:
        await write_queue.execute("UPDATE payment_cards SET last_notification_at = ? WHERE id = ?",
                                   (utcnow().isoformat(), card_id))

# ---- To'lov buyurtmalari (payment_orders) ----
class PaymentOrderError(Exception):
    """Foydalanuvchiga ko'rsatiladigan aniq sabab bilan buyurtma yaratilmadi."""

async def db_count_active_orders(user_id: int) -> int:
    async with db_connect() as db:
        row = await db.execute(
            "SELECT COUNT(*) FROM payment_orders WHERE user_id = ? AND status IN ('draft','locked','awaiting_confirmation')",
            (user_id,))
        (count,) = await row.fetchone()
        return count

async def db_count_recent_orders(user_id: int, minutes: int) -> int:
    """Foydalanuvchi so'nggi N daqiqada nechta buyurtma ochganini sanaydi —
    🛡️ velocity (tezlik) qoidasi uchun."""
    cutoff = (utcnow() - timedelta(minutes=minutes)).isoformat()
    async with db_connect() as db:
        row = await db.execute(
            "SELECT COUNT(*) FROM payment_orders WHERE user_id = ? AND created_at >= ?",
            (user_id, cutoff))
        (count,) = await row.fetchone()
        return count

async def db_log_fraud_event(user_id: int | None, order_id: int | None, rule_key: str,
                              severity: str, details: str = "") -> None:
    """Har bir firibgarlik qoidasi ishga tushganda jurnalga yozadi — bu yozuv
    ham 🛡️ bo'limidagi ro'yxatga, ham 🤖 AI Supervisor hisobotiga asos bo'ladi."""
    await write_queue.execute(
        "INSERT INTO fraud_events (user_id, order_id, rule_key, severity, details) VALUES (?, ?, ?, ?, ?)",
        (user_id, order_id, rule_key, severity, details),
    )

async def db_create_payment_order(user_id: int, amount: int, bot_id: int | None = None,
                                   description: str = "") -> dict:
    settings = await db_get_payment_settings()
    if amount < settings["min_amount"]:
        raise PaymentOrderError(f"Minimal to'lov: {settings['min_amount']} so'm")
    if amount > settings["max_amount"]:
        raise PaymentOrderError(f"Maksimal to'lov: {settings['max_amount']} so'm")
    if await db_count_active_orders(user_id) >= settings["max_concurrent_orders"]:
        raise PaymentOrderError(
            f"Bir vaqtda faqat {settings['max_concurrent_orders']} ta aktiv to'lov buyurtmasi bo'lishi mumkin")

    # --- 🛡️ Firibgarlik himoyasi: velocity (tezlik) qoidasi ---
    # Bir foydalanuvchi qisqa vaqt ichida haddan tashqari ko'p to'lov
    # buyurtmasi ochsa — bu naqd oqim/fraud urinishi belgisi bo'lishi mumkin.
    if settings.get("fraud_protection_enabled"):
        window = settings.get("fraud_velocity_window_minutes") or 10
        max_orders = settings.get("fraud_velocity_max_orders") or 3
        recent_count = await db_count_recent_orders(user_id, window)
        if recent_count >= max_orders:
            await db_log_fraud_event(
                user_id, None, "velocity", "medium",
                f"So'nggi {window} daqiqada {recent_count} ta buyurtma (limit: {max_orders})",
            )
            raise PaymentOrderError(
                f"Juda ko'p to'lov so'rovi yuborildi. Iltimos {window} daqiqadan keyin qayta urinib ko'ring.")

    card = await db_get_active_card()
    if not card:
        raise PaymentOrderError("Hozircha faol to'lov kartasi sozlanmagan — admin bilan bog'laning")

    # --- 🛡️ Bir xil summa to'qnashuvi (collision) himoyasi ---
    # SMS-monitoring FAQAT summa bo'yicha moslashtiradi (bank SMS'ida kim
    # to'laganini aniq ko'rsatuvchi ishonchli maydon yo'q — karta raqami SMS
    # matnida bo'lishi shart emas va formati qurilma/bankka qarab farq qiladi,
    # shuning uchun uni "parse qilib user aniqlash" ishonchsiz yechim).
    # Shu sabab: agar xuddi shu summada boshqa FAOL buyurtma (locked yoki
    # awaiting_confirmation) allaqachon bo'lsa, bu buyurtmaning summasiga
    # 1 tiyindan qo'shib, ANIQ NOYOB qilib qo'yamiz — foydalanuvchiga
    # ko'rsatiladigan "ANIQ summa" shu (u aynan shuni o'tkazadi), shuning
    # uchun moslashtirish endi to'qnashuvsiz ishlaydi. Amaliyotda bu farq
    # (necha tiyin) sezilarli emas, lekin noyoblikni kafolatlaydi.
    final_amount = amount
    async with db_connect() as db:
        for _bump in range(1, 201):  # maksimal 2 so'mgacha (juda kam ehtimol)
            row = await db.execute(
                "SELECT 1 FROM payment_orders WHERE amount = ? AND status IN ('locked','awaiting_confirmation') LIMIT 1",
                (final_amount,))
            if not await row.fetchone():
                break
            final_amount = amount + _bump
        else:
            raise PaymentOrderError(
                "Hozir juda ko'p to'lov kutilmoqda, biroz vaqtdan so'ng qayta urinib ko'ring.")
    amount = final_amount

    # --- 🛡️ Firibgarlik himoyasi: katta/noodatiy summa qoidasi ---
    # Chegaradan katta summa bo'lsa, buyurtma odatdagidek yaratiladi (SMS
    # monitoring baribir ishlaydi), lekin bildirishnoma kelganda balans
    # AVTOMATIK oshirilmaydi — admin qo'lda tasdiqlashi shart
    # (process_payment_notification'dagi flagged_for_review shoxobchasi).
    flagged = 0
    flag_reason = None
    threshold = settings.get("fraud_large_amount_threshold") or 0
    if settings.get("fraud_protection_enabled") and threshold > 0 and amount >= threshold:
        flagged = 1
        flag_reason = f"Katta summa: {fmt_som(amount)} so'm (chegara: {fmt_som(threshold)} so'm)"
        await db_log_fraud_event(user_id, None, "large_amount", "high", flag_reason)

    order_ref = f"po_{secrets.token_hex(6)}"
    lock_expires_at = (utcnow() + timedelta(minutes=settings["payment_ttl_minutes"])).isoformat()
    await write_queue.execute(
        """INSERT INTO payment_orders (order_ref, user_id, bot_id, amount, provider, status,
                                        lock_card_id, lock_expires_at, description,
                                        flagged_for_review, flag_reason)
           VALUES (?, ?, ?, ?, 'manual_card', 'locked', ?, ?, ?, ?, ?)""",
        (order_ref, user_id, bot_id, amount, card["id"], lock_expires_at, description,
         flagged, flag_reason),
    )
    return await db_get_order_by_ref(order_ref)

async def db_get_order_by_ref(order_ref: str) -> dict | None:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        row = await db.execute("SELECT * FROM payment_orders WHERE order_ref = ?", (order_ref,))
        row = await row.fetchone()
        return dict(row) if row else None

async def db_get_order_by_id(order_id: int) -> dict | None:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        row = await db.execute("SELECT * FROM payment_orders WHERE id = ?", (order_id,))
        row = await row.fetchone()
        return dict(row) if row else None

async def db_get_order(order_id: int) -> dict | None:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        row = await db.execute("SELECT * FROM payment_orders WHERE id = ?", (order_id,))
        row = await row.fetchone()
        return dict(row) if row else None

async def db_expire_stale_orders() -> int:
    """Muddati tugagan (lock_expires_at < hozir) va hali yakunlanmagan
    buyurtmalarni 'expired'ga o'tkazadi hamda ularga bog'langan kartani
    bo'shatadi (fraud qoidasi: muddati tugagan payment AVTOMATIK
    kredit qilinmaydi). Payment Monitor har turida shu funksiyani chaqiradi."""
    now = utcnow().isoformat()
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        rows = await db.execute(
            "SELECT id, lock_card_id FROM payment_orders WHERE status IN ('locked','awaiting_confirmation') AND lock_expires_at < ?",
            (now,))
        rows = await rows.fetchall()
    if rows:
        await write_queue.execute_transaction([
            ("UPDATE payment_orders SET status = 'expired', updated_at = ? WHERE id = ?", (now, r["id"]))
            for r in rows
        ])
    return len(rows)

async def db_mark_order_awaiting_confirmation(order_id: int) -> None:
    """Foydalanuvchi '✅ To'lov qildim' bosganda — Payment Monitor endi
    kelayotgan bildirishnomalarni shu buyurtma bilan solishtiradi."""
    await write_queue.execute(
        "UPDATE payment_orders SET status = 'awaiting_confirmation', updated_at = ? WHERE id = ? AND status = 'locked'",
        (utcnow().isoformat(), order_id))

async def db_cancel_payment_order(order_id: int, reason: str = "user_cancelled") -> None:
    order = await db_get_order(order_id)
    await write_queue.execute("UPDATE payment_orders SET status = 'cancelled', updated_at = ? WHERE id = ?",
                               (utcnow().isoformat(), order_id))
    if order and order.get("lock_card_id"):
        await db_set_card_status(order["lock_card_id"], "active")

# ---- Provayder hodisalari (payment_transactions) — Payment Monitor shu orqali yozadi ----
async def db_record_payment_transaction(order_id: int, provider: str, event_type: str, amount: int,
                                         result: str, provider_trans_id: str = "", reason: str = "",
                                         raw_payload: str = "") -> dict | None:
    """Har bir tushumni/hodisani o'zgarmas jurnalga yozadi. Agar
    (provider, provider_trans_id) juftligi allaqachon mavjud bo'lsa — bu xuddi
    o'sha tranzaksiya ID qayta ishlatilmoqda degani (fraud qoidasi: bitta
    transaction ikki marta ishlatilmasin), None qaytaradi va yozuv qo'shilmaydi."""
    try:
        txn_id, _ = await write_queue.execute(
            """INSERT INTO payment_transactions (order_id, provider, provider_trans_id, event_type,
                                                   amount, result, reason, raw_payload)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (order_id, provider, provider_trans_id or None, event_type, amount, result, reason, raw_payload),
        )
    except aiosqlite.IntegrityError:
        return None  # duplicate provider_trans_id — rad etildi
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        row = await db.execute("SELECT * FROM payment_transactions WHERE id = ?", (txn_id,))
        row = await row.fetchone()
        return dict(row) if row else None

async def db_confirm_payment_order(order_id: int, confirmed_amount: int) -> bool:
    """YAGONA joy — balans shu funksiya orqaligina oshadi. Atomik: faqat
    status='awaiting_confirmation' BO'LGAN va summasi ANIQ mos keladigan
    buyurtmani 'paid'ga o'tkazadi (WHERE shartli UPDATE — bir vaqtda ikki
    marta chaqirilsa ham faqat bittasi rowcount=1 qaytaradi, ya'ni
    duplicate-credit imkonsiz). AI Payment Supervisor bu funksiyani
    to'g'ridan-to'g'ri chaqira olmaydi — faqat backend tekshiruvidan
    (summani solishtirish + status tekshiruvi) o'tgandan keyin chaqiriladi."""
    order = await db_get_order(order_id)
    if not order or order["amount"] != confirmed_amount:
        return False  # aniq hisob: summa bir tiyin ham farq qilsa kredit yo'q
    _, rowcount = await write_queue.execute(
        "UPDATE payment_orders SET status = 'paid', updated_at = ? WHERE id = ? AND status = 'awaiting_confirmation'",
        (utcnow().isoformat(), order_id))
    applied = rowcount == 1
    if applied:
        await write_queue.execute_transaction([
            ("UPDATE users SET balance = balance + ? WHERE id = ?", (confirmed_amount, order["user_id"])),
            ("""INSERT INTO transactions (user_id, type, provider, amount, status, description)
                VALUES (?, 'topup', 'manual_card', ?, 'paid', ?)""",
             (order["user_id"], confirmed_amount, f"Payment Manager: {order['order_ref']}")),
        ])
        if order.get("lock_card_id"):
            await db_set_card_status(order["lock_card_id"], "active")
    return applied

async def db_hold_order_for_review(order_id: int) -> None:
    """SMS moslik topildi, lekin buyurtma 🛡️ qoida bo'yicha belgilangan
    ('flagged_for_review') — balans hali oshirilmaydi, admin ✅/❌ bilan
    hal qilguncha 'flagged_review' holatida kutadi."""
    await write_queue.execute(
        "UPDATE payment_orders SET status = 'flagged_review', updated_at = ? WHERE id = ? AND status = 'awaiting_confirmation'",
        (utcnow().isoformat(), order_id),
    )

async def db_approve_flagged_order(order_id: int) -> bool:
    """Admin 'flagged_review' buyurtmani tasdiqlaydi: avval status
    'awaiting_confirmation'ga qaytariladi, so'ng db_confirm_payment_order
    (YAGONA kredit nuqtasi) chaqiriladi — shu bilan aniq-summa va
    atomiklik tekshiruvlari bu yo'lda ham to'liq ishlaydi."""
    order = await db_get_order_by_id(order_id)
    if not order or order["status"] != "flagged_review":
        return False
    _, rowcount = await write_queue.execute(
        "UPDATE payment_orders SET status = 'awaiting_confirmation' WHERE id = ? AND status = 'flagged_review'",
        (order_id,),
    )
    if rowcount != 1:
        return False
    return await db_confirm_payment_order(order_id, order["amount"])

async def db_reject_flagged_order(order_id: int) -> bool:
    """Admin 'flagged_review' buyurtmani rad etadi — balans OSHIRILMAYDI,
    holat 'rejected'ga o'tadi (qulflangan karta bo'lsa bo'shatiladi)."""
    order = await db_get_order_by_id(order_id)
    if not order or order["status"] != "flagged_review":
        return False
    _, rowcount = await write_queue.execute(
        "UPDATE payment_orders SET status = 'rejected', updated_at = ? WHERE id = ? AND status = 'flagged_review'",
        (utcnow().isoformat(), order_id),
    )
    applied = rowcount == 1
    if applied and order.get("lock_card_id"):
        await db_set_card_status(order["lock_card_id"], "active")
    return applied

async def db_get_payment_transaction(txn_id: int) -> dict | None:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        row = await db.execute("SELECT * FROM payment_transactions WHERE id = ?", (txn_id,))
        row = await row.fetchone()
        return dict(row) if row else None

async def db_manual_match_transaction(txn_id: int, order_id: int, admin_telegram_id: int) -> tuple[bool, str]:
    """🔍 Tekshiruv: admin 'unmatched' bildirishnomani qo'lda buyurtmaga
    bog'laydi. AI bu funksiyani hech qachon o'zi chaqira olmaydi — faqat
    admin qaroridan keyin ishga tushadi. Kredit ALBATTA order['amount']
    miqdorida beriladi (bildirishnomadagi xom summa emas) — db_confirm_
    payment_order YAGONA kredit nuqtasi bo'lib qolaveradi, aniq-summa va
    atomiklik tekshiruvlari bu yo'lda ham to'liq ishlaydi.
    Natija: (ok, xabar)."""
    txn = await db_get_payment_transaction(txn_id)
    if not txn or txn["result"] != "unmatched":
        return False, "Bu bildirishnoma allaqachon hal qilingan yoki topilmadi."
    order = await db_get_order_by_id(order_id)
    if not order or order["status"] not in ("locked", "awaiting_confirmation"):
        return False, "Bu buyurtma faol emas (allaqachon to'langan/muddati o'tgan/bekor qilingan)."

    if order["status"] == "locked":
        await write_queue.execute(
            "UPDATE payment_orders SET status = 'awaiting_confirmation', updated_at = ? WHERE id = ? AND status = 'locked'",
            (utcnow().isoformat(), order_id),
        )

    credited = await db_confirm_payment_order(order_id, order["amount"])
    if not credited:
        return False, "Kredit berilmadi — buyurtma holati kutilmaganda o'zgargan bo'lishi mumkin."

    await write_queue.execute(
        "UPDATE payment_transactions SET result = 'manual_matched', order_id = ?, "
        "reason = ? WHERE id = ?",
        (order_id, f"Admin qo'lda bog'ladi (admin:{admin_telegram_id})", txn_id),
    )
    await db_log_fraud_event(order["user_id"], order_id, "manual_match", "low",
                              f"Admin {admin_telegram_id} txn#{txn_id}ni order#{order_id}ga bog'ladi")
    return True, "✅ Bog'landi va kredit berildi."

async def db_dismiss_unmatched_transaction(txn_id: int, admin_telegram_id: int) -> bool:
    """Admin unmatched bildirishnomani ko'rib chiqdi va hech qanday buyurtmaga
    tegishli emas deb hisobladi (masalan boshqa maqsaddagi o'tkazma) —
    balansga hech narsa qo'shilmaydi, faqat 'ko'rib chiqilgan' deb belgilanadi."""
    txn = await db_get_payment_transaction(txn_id)
    if not txn or txn["result"] != "unmatched":
        return False
    await write_queue.execute(
        "UPDATE payment_transactions SET result = 'manual_rejected', "
        "reason = ? WHERE id = ?",
        (f"Admin rad etdi (admin:{admin_telegram_id})", txn_id),
    )
    return True


# ---- SMS/bildirishnoma monitoring (Payment Monitor) ----
# Arxitektura: telefon (MacroDroid yoki shunga o'xshash) bank/Click ilovasidan
# kelgan bildirishnomani ushlaydi -> HTTPS POST /payment/notify ga yuboradi ->
# shu yerda summaga aniq mos keladigan 'awaiting_confirmation' buyurtma
# izlanadi -> topilsa db_confirm_payment_order() (YAGONA kredit nuqtasi)
# chaqiriladi. Bot hech qachon bank SMS/OTP so'ramaydi, hech qachon chek
# talab qilmaydi — faqat summani solishtiradi.

async def db_find_awaiting_order_by_amount(amount_tiyin: int) -> dict | None:
    """Bildirishnoma summasiga ANIQ mos keladigan, eng eski
    'awaiting_confirmation' buyurtmani topadi (FIFO). Bir tiyin farq
    qilsa ham moslik hisoblanmaydi (aniq hisob qoidasi)."""
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        row = await db.execute(
            """SELECT * FROM payment_orders
               WHERE status = 'awaiting_confirmation' AND amount = ?
               ORDER BY created_at ASC LIMIT 1""",
            (amount_tiyin,),
        )
        row = await row.fetchone()
        return dict(row) if row else None

async def process_payment_notification(amount_tiyin: int, raw_text: str,
                                        provider_trans_id: str = "") -> dict:
    """Payment Monitor webhookining asosiy mantig'i:
    1) muddati tugagan buyurtmalarni tozalaydi (fraud qoidasi: kechikkan
       to'lov avtomatik kredit qilinmaydi),
    2) summaga aniq mos keladigan kutilayotgan buyurtmani izlaydi,
    3) har bir hodisani payment_transactions jurnaliga yozadi — moslik
       topilmasa ham (keyinchalik admin "Tekshiruv/Firibgarlik himoyasi"
       bo'limida ko'rib chiqishi uchun), takroriy provider_trans_id
       avtomatik rad etiladi (UNIQUE cheklovi orqali),
    4) topilsa db_confirm_payment_order orqali (yagona kredit nuqtasi)
       balansni oshiradi va foydalanuvchini xabardor qiladi.
    Natija: {"matched", "order_id", "credited", "reason"}."""
    await db_expire_stale_orders()

    if not provider_trans_id:
        # Ba'zi bildirishnomalarda tranzaksiya ID bo'lmaydi — summa+matndan
        # barqaror hash yasaladi, shu bilan UNIQUE(provider, provider_trans_id)
        # himoyasi baribir ishlaydi (bitta bildirishnoma ikki marta yuborilib
        # qolsa — masalan tarmoq qayta urinishi — takroriy hisoblanadi).
        digest_src = f"{amount_tiyin}:{raw_text}"
        provider_trans_id = "auto_" + hashlib.sha256(digest_src.encode()).hexdigest()[:24]

    order = await db_find_awaiting_order_by_amount(amount_tiyin)
    if not order:
        # order_id=0 — "hech qanday buyurtmaga bog'liq emas" degan sentinel
        # qiymat (jadval sxemasi order_id NOT NULL, lekin FK majburiy emas);
        # reason maydoni buni aniq izohlaydi.
        await db_record_payment_transaction(
            order_id=0, provider="sms_monitor", event_type="notification",
            amount=amount_tiyin, result="unmatched",
            reason="Mos kutilayotgan buyurtma topilmadi",
            provider_trans_id=provider_trans_id, raw_payload=raw_text,
        )
        return {"matched": False, "order_id": None, "credited": False, "reason": "no_matching_order"}

    # --- 🛡️ Firibgarlik himoyasi: katta summa uchun admin tasdig'i ---
    # db_create_payment_order bosqichida "flagged_for_review" belgilangan
    # buyurtma bo'lsa, summasi mos kelsa ham AVTOMATIK kredit BERILMAYDI —
    # holat 'flagged_review'ga o'tadi va admin ✅/❌ bilan hal qiladi.
    if order.get("flagged_for_review"):
        txn = await db_record_payment_transaction(
            order_id=order["id"], provider="sms_monitor", event_type="notification",
            amount=amount_tiyin, result="flagged_review",
            reason=order.get("flag_reason") or "",
            provider_trans_id=provider_trans_id, raw_payload=raw_text,
        )
        if txn is None:
            return {"matched": True, "order_id": order["id"], "credited": False, "reason": "duplicate_transaction"}
        await db_hold_order_for_review(order["id"])
        await db_log_fraud_event(order["user_id"], order["id"], "large_amount_notified", "high",
                                  f"Bildirishnoma keldi, admin tasdig'i kutilmoqda: {fmt_som(amount_tiyin)} so'm")
        if SUPER_ADMIN_TELEGRAM_ID:
            try:
                await bot.send_message(
                    SUPER_ADMIN_TELEGRAM_ID,
                    f"🛡️ Katta summali to'lov — tasdiq talab qilinadi!\n\n"
                    f"Buyurtma: #{order['order_ref']}\n"
                    f"Summa: {fmt_som(amount_tiyin)} so'm\n"
                    f"Foydalanuvchi ID (ichki): {order['user_id']}\n"
                    f"Sabab: {order.get('flag_reason') or '—'}",
                    reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                        [InlineKeyboardButton(text="✅ Tasdiqlash (kredit berish)",
                                               callback_data=f"fraudreview_approve:{order['id']}")],
                        [InlineKeyboardButton(text="❌ Rad etish", callback_data=f"fraudreview_reject:{order['id']}")],
                    ]),
                )
            except Exception:
                pass
        return {"matched": True, "order_id": order["id"], "credited": False, "reason": "flagged_review"}

    txn = await db_record_payment_transaction(
        order_id=order["id"], provider="sms_monitor", event_type="notification",
        amount=amount_tiyin, result="matched",
        provider_trans_id=provider_trans_id, raw_payload=raw_text,
    )
    if txn is None:
        # provider_trans_id allaqachon ishlatilgan — takroriy bildirishnoma,
        # hech narsa qilinmaydi (fraud/duplicate himoyasi)
        return {"matched": True, "order_id": order["id"], "credited": False, "reason": "duplicate_transaction"}

    credited = await db_confirm_payment_order(order["id"], amount_tiyin)
    if credited:
        user = await db_get_user_by_id(order["user_id"])
        if user:
            try:
                await bot.send_message(
                    user["telegram_id"],
                    f"✅ To'lovingiz aniqlandi! Balansingiz {fmt_som(amount_tiyin)} so'mga to'ldirildi.",
                )
            except Exception:
                pass
    return {"matched": True, "order_id": order["id"], "credited": credited,
            "reason": "ok" if credited else "confirm_failed"}

async def handle_payment_notify(request: web.Request) -> web.Response:
    """MacroDroid (yoki shunga o'xshash SMS/bildirishnoma-forward ilovasi) shu
    endpointga POST qiladi. OCHIQ, TEKSHIRUVSIZ endpoint EMAS — X-Payment-Secret
    headeri PAYMENT_WEBHOOK_SECRET bilan bit-baravar (constant-time) mos
    kelishi shart, aks holda 401. sms_monitoring_enabled o'chirilgan bo'lsa
    so'rov qabul qilinmaydi (503).

    Kutilgan JSON body: {"amount": "52014.03", "raw_text": "...", "transaction_id": "..."}
    amount — so'mda (kasr bilan), transaction_id ixtiyoriy."""
    secret = request.headers.get("X-Payment-Secret", "")
    if not PAYMENT_WEBHOOK_SECRET or not secrets.compare_digest(secret, PAYMENT_WEBHOOK_SECRET):
        return web.json_response({"ok": False, "error": "unauthorized"}, status=401)

    settings = await db_get_payment_settings()
    if not settings.get("sms_monitoring_enabled"):
        return web.json_response({"ok": False, "error": "monitoring_disabled"}, status=503)

    try:
        payload = await request.json()
    except Exception:
        return web.json_response({"ok": False, "error": "invalid_json"}, status=400)

    raw_text = str(payload.get("raw_text", ""))[:2000]
    provider_trans_id = str(payload.get("transaction_id") or "")[:128]

    amount_tiyin = parse_exact_som_amount(str(payload.get("amount", "")))
    if amount_tiyin is None:
        await db_record_payment_transaction(
            order_id=0, provider="sms_monitor", event_type="notification",
            amount=0, result="invalid_amount", reason="Summani o'qib bo'lmadi",
            provider_trans_id=provider_trans_id or None, raw_payload=raw_text,
        )
        return web.json_response({"ok": False, "error": "invalid_amount"}, status=400)

    card = await db_get_active_card()
    if card:
        await db_touch_card_notification(card["id"], provider_trans_id)

    result = await process_payment_notification(amount_tiyin, raw_text, provider_trans_id)
    return web.json_response({"ok": True, **result})


# --- 🛡️ 'flagged_review' buyurtmalar bo'yicha admin qarori (alert xabaridagi
# ✅/❌ tugmalari orqali) ---
@user_router.callback_query(F.data.startswith("fraudreview_approve:"))
async def fraud_review_approve(callback: CallbackQuery):
    if not await _require_admin(callback): return
    order_id = int(callback.data.split(":")[1])
    order = await db_get_order_by_id(order_id)
    if not order or order["status"] != "flagged_review":
        await callback.answer("Bu buyurtma allaqachon hal qilingan", show_alert=True)
        return
    credited = await db_approve_flagged_order(order_id)
    if credited:
        async with db_connect() as db:
            await db.execute(
                "UPDATE payment_transactions SET result = 'flagged_approved' WHERE order_id = ? AND result = 'flagged_review'",
                (order_id,))
            await db.commit()
        user = await db_get_user_by_id(order["user_id"])
        if user:
            try:
                await bot.send_message(
                    user["telegram_id"],
                    f"✅ To'lovingiz tasdiqlandi! Balansingiz {fmt_som(order['amount'])} so'mga to'ldirildi.",
                )
            except Exception:
                pass
        await log_admin_action(actor=f"admin:{callback.from_user.id}", action="fraud_review_approve",
                                result="OK", target=f"order_{order_id}")
        new_text = f"{callback.message.text}\n\n✅ TASDIQLANDI — kredit berildi."
    else:
        new_text = f"{callback.message.text}\n\n⚠️ Xatolik — kredit berilmadi (holat allaqachon o'zgargan bo'lishi mumkin)."
    try:
        await callback.message.edit_text(new_text)
    except Exception:
        pass
    await callback.answer()

@user_router.callback_query(F.data.startswith("fraudreview_reject:"))
async def fraud_review_reject(callback: CallbackQuery):
    if not await _require_admin(callback): return
    order_id = int(callback.data.split(":")[1])
    order = await db_get_order_by_id(order_id)
    ok = await db_reject_flagged_order(order_id)
    if not ok:
        await callback.answer("Bu buyurtma allaqachon hal qilingan", show_alert=True)
        return
    async with db_connect() as db:
        await db.execute(
            "UPDATE payment_transactions SET result = 'flagged_rejected' WHERE order_id = ? AND result = 'flagged_review'",
            (order_id,))
        await db.commit()
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="fraud_review_reject",
                            result="OK", target=f"order_{order_id}")
    if order:
        user = await db_get_user_by_id(order["user_id"])
        if user:
            try:
                await bot.send_message(
                    user["telegram_id"],
                    "⚠️ To'lovingiz qo'shimcha tekshiruvdan o'ta olmadi. Iltimos qo'llab-quvvatlash xizmatiga murojaat qiling.",
                )
            except Exception:
                pass
    try:
        await callback.message.edit_text(f"{callback.message.text}\n\n❌ RAD ETILDI.")
    except Exception:
        pass
    await callback.answer()


# ===================== MAIN =====================
async def start_web_server():
    app = web.Application()
    setup_web_routes(app)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, WEB_HOST, WEB_PORT)
    await site.start()
    logger.info(f"Web-server ishga tushdi: http://{WEB_HOST}:{WEB_PORT}")
    # MUHIM: site.start() serverni socket'ga ulab, DARHOL qaytadi (bu odatiy
    # aiohttp xatti-harakati — server o'zi orqa fonda ishlayveradi). Agar shu
    # funksiya shu yerda tugasa, main()dagi asyncio.wait(FIRST_COMPLETED)
    # buni "vazifa tugadi" deb hisoblab, BOT POLLING HALI BOSHLANMASDAN uni
    # ham bekor qilib yuboradi — aynan shu sabab bilan bot terminalda
    # xatosiz ishga tushib ko'rinsa ham, /start hech qachon javob bermagan
    # edi. Shuning uchun bu funksiya ataylab abadiy kutadi (faqat main()
    # boshqa sabab bilan to'xtaganda cancel qilinadi).
    await asyncio.Event().wait()

async def start_bot():
    logger.info("Telegram bot polling boshlandi")
    dp.message.outer_middleware(rate_limit_bot_middleware)
    dp.callback_query.outer_middleware(rate_limit_bot_middleware)
    dp.include_router(user_router)
    # Eski webhook yoki to'planib qolgan xabarlarni tozalash — aks holda bot
    # avval webhook rejimida ishlatilgan bo'lsa (yoki boshqa joyda setWebhook
    # chaqirilgan bo'lsa), polling "Conflict" xatosiga uchraydi va bu xato
    # aiogram tomonidan jim qayta-qayta urinish bilan yashirinib qoladi —
    # tashqaridan qaraganda "bot ishlayapti-yu, lekin javob bermayapti"
    # bo'lib ko'rinadi.
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)

async def main():
    # Muhim maxfiy sozlamalarni ishga tushishdan OLDIN tekshiramiz — aks holda
    # bot soatlab ishlab yuradi-yu, birinchi bot yaratilganda/karta
    # qo'shilganda chuqur ichkarida tushunarsiz AttributeError bilan yiqiladi.
    if _fernet is None:
        logger.error(
            "❌ TOKEN_ENCRYPTION_KEY .env faylida sozlanmagan. Bot tokenlari, SSH "
            "kalitlar va to'lov kartalari shifrlanadigan har qanday amal ishlamaydi. "
            "Generatsiya: python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        )
        raise SystemExit(1)
    await db_init()
    await write_queue.start()
    await db_ensure_super_admin()
    tasks = [
        asyncio.create_task(start_web_server(), name="web_server"),
        asyncio.create_task(start_bot(), name="bot_polling"),
        asyncio.create_task(supervisor_loop(), name="supervisor_loop"),
        asyncio.create_task(resource_monitor_loop(), name="resource_monitor_loop"),
        asyncio.create_task(billing_monitor_loop(), name="billing_monitor_loop"),
        asyncio.create_task(admin_ai_monitor_loop(), name="admin_ai_monitor_loop"),
        asyncio.create_task(user_ai_monitor_loop(), name="user_ai_monitor_loop"),
    ]
    try:
        # MUHIM: oddiy asyncio.gather() BARCHA vazifa tugashini kutadi. Lekin
        # Ctrl+C bosilganda aiogram buni o'zi ichkarida ushlab, FAQAT
        # bot_polling'ni to'xtatadi — supervisor_loop/billing_monitor_loop va
        # h.k. cheksiz tsikllar bo'lgani uchun ular abadiy davom etaveradi va
        # jarayon HECH QACHON chiqmay, "osilib" qoladi (aynan shu sabab bilan
        # avval Ctrl+C yetarli bo'lmay, Ctrl+Z bilan majburan to'xtatishga
        # to'g'ri kelgan va bu esa portni band holda qoldirib, keyingi
        # ishga tushirishni buzgan edi).
        #
        # Shuning uchun: istalgan BITTA vazifa tugasa (muvaffaqiyatli yoki
        # xato bilan — masalan Ctrl+C tufayli bot_polling tugasa, yoki
        # web_server port band bo'lgani uchun xato bersa), BARCHA qolgan
        # vazifalarni darhol bekor qilamiz, shunda jarayon har doim toza
        # va tezda chiqadi.
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        for t in done:
            exc = t.exception()
            if exc is not None:
                logger.error(f"Vazifa '{t.get_name()}' xato bilan tugadi: {exc}")
                raise exc
    finally:
        # Kod har qanday sababdan to'xtaganda (Ctrl+C, xato, yoki muvaffaqiyatli
        # yakun) HTTP sessiyasini toza yopamiz — aks holda Termux'da
        # "Unclosed client session" ogohlantirishi va oqib qolgan socket'lar
        # qolib ketishi mumkin.
        await write_queue.stop()
        await bot.session.close()
        logger.info("Bot sessiyasi va ulanishlar yopildi.")

# ===================== KEYBOARDS / START / NAV =====================
STATUS_EMOJI = {"running": "🟢", "stopped": "🔴", "restarting": "🟡"}

def main_menu_kb(is_admin_: bool) -> ReplyKeyboardMarkup:
    # Doimiy pastki panel (ReplyKeyboardMarkup). Reply tugmalar url= ni qo'llamaydi,
    # shu sabab "Websaytga qaytish" havolasi endi xush kelibsiz matnida beriladi.
    rows = []
    # Mini App tugmasi FAQAT WEB_DOMAIN haqiqiy (ochiq, HTTPS) domenga sozlangan
    # bo'lsagina qo'shiladi — aks holda Telegram "Wrong HTTP URL" xatosi bilan
    # BUTUN /start'ni yiqitib qo'yadi (localhost/127.0.0.1/bo'sh qiymatlarni
    # Telegram serveri qabul qilmaydi, chunki u tashqi tarmoqdan ochilishi kerak).
    if WEB_DOMAIN and WEB_DOMAIN not in ("localhost", "127.0.0.1") and not WEB_DOMAIN.startswith("localhost"):
        rows.append([KeyboardButton(text="📱 Mini App", web_app=WebAppInfo(url=f"https://{WEB_DOMAIN}/app"))])
    rows += [
        [KeyboardButton(text="➕ Bot yaratish"), KeyboardButton(text="🤖 Botlarim")],
        [KeyboardButton(text="💰 Balans"), KeyboardButton(text="💳 To'lovlarim")],
        [KeyboardButton(text="🔑 API kalitlarim"), KeyboardButton(text="🗄️ Backup")],
        [KeyboardButton(text="👤 Profil")],
    ]
    if is_admin_:
        rows.append([KeyboardButton(text="👑 Admin Panel")])
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True)

# 👑 ADMIN uchun doimiy pastki panel — foydalanuvchi panelidek ReplyKeyboardMarkup.
# Har bosishda admin "Admin Panel" inline menyusini qayta ochmasdan, to'g'ridan-to'g'ri
# bo'limga o'tadi (mavjud inline render funksiyalarini qayta ishlatib — kod
# dublikat qilinmagan). "🔙 Foydalanuvchi menyusi" — oddiy panelga qaytaradi.
ADMIN_MENU_ROWS = [
    ["👥 Foydalanuvchilar", "🖥️ Serverlar"],
    ["🤖 Botlar", "💳 Payment Manager"],
    ["🔍 Tekshiruv", "🤖 Admin AI"],
    ["📊 Statistika", "🗄️ Tizim Backup"],
    ["📋 Logs", "🔐 Xavfsizlik"],
    ["⚙️ Tizim sozlamalari", "💳 Click sozlamalari"],
    ["🔙 Foydalanuvchi menyusi"],
]

def admin_menu_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text=t) for t in row] for row in ADMIN_MENU_ROWS],
        resize_keyboard=True,
    )

def back_kb(target: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"nav:{target}")]])

def back_kb_to(target_callback: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="🔙 Orqaga", callback_data=target_callback)]])

@user_router.message(Command("start"))
async def cmd_start(message: Message):
    telegram_id = message.from_user.id
    user = await db_get_user_by_telegram_id(telegram_id)
    settings = await db_get_all_settings()
    is_admin_user = bool(user and user["is_admin"])

    if not user:
        if not settings.get("registration_enabled", True):
            await message.answer("⚠️ Hozircha yangi ro'yxatdan o'tish yopiq.")
            return
        user = await db_create_user(telegram_id, message.from_user.first_name or "", message.from_user.username or "")
        is_admin_user = bool(user["is_admin"])

    if settings.get("maintenance_mode", False) and not (is_admin_user and settings.get("maintenance_admin_bypass", True)):
        msg = settings.get("maintenance_message") or "🛠 Texnik xizmat ishlari olib borilmoqda."
        await message.answer(f"🛠 {msg}")
        return

    await message.answer(
        f"Salom, {user['first_name']} 👋\n🌐 Websayt: https://{WEB_DOMAIN}/dashboard",
        reply_markup=main_menu_kb(is_admin_user),
    )

@user_router.callback_query(F.data == "nav:main")
async def nav_main(callback: CallbackQuery):
    # ReplyKeyboardMarkup'ni mavjud xabarni edit_text qilib almashtirib bo'lmaydi
    # (Telegram Bot API buni faqat InlineKeyboardMarkup uchun qo'llaydi) — shu sabab
    # admin panel xabarini o'chirib, pastki panel bilan YANGI xabar yuboramiz.
    # O'chirish edit_reply_markup(None)dan yaxshiroq: xabar chatda "qolib ketmaydi".
    user = await db_get_user_by_telegram_id(callback.from_user.id)
    try:
        await callback.message.delete()
    except Exception:
        try:
            await callback.message.edit_reply_markup(reply_markup=None)
        except Exception:
            pass
    await callback.message.answer("Bosh menyu:", reply_markup=main_menu_kb(bool(user["is_admin"])))
    await callback.answer()

# ---- Pastki doimiy panel tugmalari (ReplyKeyboardMarkup) uchun handlerlar ----
# Har biri mos callback-handlerdagi bilan bir xil matn/klaviaturani ishlatadi,
# faqat edit_text() o'rniga message.answer() bilan yangi xabar yuboradi.

@user_router.message(F.text == "💰 Balans")
async def kb_show_balance(message: Message):
    user = await db_get_user_by_telegram_id(message.from_user.id)
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="➕ Balansni to'ldirish", callback_data="topup_start")],
        [InlineKeyboardButton(text="📜 To'lovlarim", callback_data="my_payments")],
    ])
    await message.answer(f"💰 Balansingiz: {fmt_som(user['balance'])} so'm", reply_markup=kb)

@user_router.message(F.text == "💳 To'lovlarim")
async def kb_show_my_payments(message: Message):
    user = await db_get_user_by_telegram_id(message.from_user.id)
    text, kb = await _render_my_payments(user["id"], 0)
    await message.answer(text, reply_markup=kb)

@user_router.message(F.text == "🤖 Botlarim")
async def kb_show_my_bots(message: Message):
    text, kb = await _render_my_bots_list(message.from_user.id, 0)
    await message.answer(text, reply_markup=kb)

@user_router.message(F.text == "🔑 API kalitlarim")
async def kb_show_my_api_keys(message: Message):
    text, kb = await _render_my_api_keys_list(message.from_user.id)
    await message.answer(text, reply_markup=kb)

@user_router.message(F.text == "👤 Profil")
async def kb_show_profile(message: Message):
    user = await db_get_user_by_telegram_id(message.from_user.id)
    text = (f"👤 Profil\n\nIsm: {user['first_name']}\nUsername: @{user['username'] or '—'}\n"
            f"Telegram ID: {user['telegram_id']}\nRo'yxatdan o'tgan: {user['created_at']}")
    await message.answer(text, reply_markup=back_kb("main"))

@user_router.message(F.text == "🗄️ Backup")
async def kb_show_user_backup_menu(message: Message):
    bots = await db_get_user_bots(message.from_user.id)
    if not bots:
        await message.answer("Sizda hali bot yo'q")
        return
    kb_rows = [[InlineKeyboardButton(text=f"🤖 {b['name']}", callback_data=f"userbackup_bot:{b['id']}")] for b in bots]
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="nav:main")])
    await message.answer("🗄️ Qaysi botingiz uchun backup?", reply_markup=InlineKeyboardMarkup(inline_keyboard=kb_rows))

@user_router.message(F.text == "👑 Admin Panel")
async def kb_show_admin_panel(message: Message):
    if not await is_admin(message.from_user.id):
        return
    await message.answer(
        "👑 ADMIN PANEL\n\nQuyidagi pastki panel orqali istalgan bo'limga to'g'ridan-to'g'ri o'ting.",
        reply_markup=admin_menu_kb(),
    )

@user_router.message(F.text == "🔙 Foydalanuvchi menyusi")
async def kb_admin_back_to_user_menu(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        return
    await state.clear()
    user = await db_get_user_by_telegram_id(message.from_user.id)
    is_admin_user = bool(user and user["is_admin"])
    await message.answer("🔙 Foydalanuvchi menyusiga qaytdingiz.", reply_markup=main_menu_kb(is_admin_user))

# ---- 👑 Admin pastki panel tugmalari — mavjud inline render funksiyalarini
# qayta ishlatadi (kod dublikat qilinmagan), faqat callback.message.edit_text
# o'rniga message.answer bilan yuboradi. ----
@user_router.message(F.text == "👥 Foydalanuvchilar")
async def kb_admin_users(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id): return
    await state.clear()
    await message.answer("👥 FOYDALANUVCHILAR — filtr tanlang:", reply_markup=admin_users_filter_kb())

@user_router.message(F.text == "🖥️ Serverlar")
async def kb_admin_servers(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id): return
    await state.clear()
    await message.answer("🖥️ SERVERLAR", reply_markup=admin_servers_menu_kb())

@user_router.message(F.text == "🤖 Botlar")
async def kb_admin_bots(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id): return
    await state.clear()
    await message.answer("🤖 BOTLAR — filtr tanlang:", reply_markup=admin_bots_filter_kb())

@user_router.message(F.text == "💳 Payment Manager")
async def kb_admin_payment_manager(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id): return
    await state.clear()
    await message.answer("💳 PAYMENT MANAGER", reply_markup=payment_manager_menu_kb())

@user_router.message(F.text == "🔍 Tekshiruv")
async def kb_admin_review(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id): return
    await state.clear()
    text, kb = await _render_pm_review()
    await message.answer(text, reply_markup=kb)

@user_router.message(F.text == "🤖 Admin AI")
async def kb_admin_ai(message: Message):
    if not await is_admin(message.from_user.id): return
    await message.answer("🤖 ADMIN AI", reply_markup=admin_ai_menu_kb())

@user_router.message(F.text == "📊 Statistika")
async def kb_admin_stats(message: Message):
    if not await is_admin(message.from_user.id): return
    text, kb = await _render_admin_stats()
    await message.answer(text, reply_markup=kb)

@user_router.message(F.text == "🗄️ Tizim Backup")
async def kb_admin_backup(message: Message):
    if not await is_admin(message.from_user.id): return
    await message.answer("🗄️ BACKUP / RESTORE", reply_markup=admin_backup_menu_kb())

@user_router.message(F.text == "📋 Logs")
async def kb_admin_logs(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id): return
    await state.clear()
    text, kb = await _render_admin_logs(0, "")
    await message.answer(text, reply_markup=kb)

@user_router.message(F.text == "🔐 Xavfsizlik")
async def kb_admin_security(message: Message):
    if not await is_admin(message.from_user.id): return
    settings = await db_get_all_settings()
    text, kb = await _render_sysset_submenu("sec", settings)
    await message.answer(text, reply_markup=kb)

@user_router.message(F.text == "⚙️ Tizim sozlamalari")
async def kb_admin_sysset(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id): return
    await state.clear()
    await message.answer("⚙️ TIZIM SOZLAMALARI", reply_markup=sysset_menu_kb())

@user_router.message(F.text == "💳 Click sozlamalari")
async def kb_admin_click_settings(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id): return
    await state.set_state(None)
    text, kb = await _render_click_menu(state)
    await message.answer(text, reply_markup=kb)

@user_router.message(F.text == "➕ Bot yaratish")
async def kb_bot_create_start(message: Message, state: FSMContext):
    await state.clear()
    await state.set_state(BotCreateStates.waiting_name)
    await message.answer(
        "➕ Yangi bot yaratish\n\n📝 Botingiz uchun nom kiriting (masalan: Mening Do'konim):",
        reply_markup=botcreate_cancel_kb(),
    )

@user_router.callback_query(F.data == "balance")
async def show_balance(callback: CallbackQuery):
    user = await db_get_user_by_telegram_id(callback.from_user.id)
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="➕ Balansni to'ldirish", callback_data="topup_start")],
        [InlineKeyboardButton(text="📜 To'lovlarim", callback_data="my_payments")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="nav:main")],
    ])
    await callback.message.edit_text(f"💰 Balansingiz: {fmt_som(user['balance'])} so'm", reply_markup=kb)
    await callback.answer()


# ===================== 💰 BALANS TO'LDIRISH FSM (29-bosqich) =====================
# Oqim: 💰 Balans to'ldirish -> 💵 Summa -> 📋 To'lov ma'lumotlari ->
#       💳 Click orqali to'lash -> ⏳ kutish -> ✅ webhook (handle_click_callback,
#       yuqorida) -> 💰 balans oshadi -> 📜 transactions.
# Click ishlamasa: 📷 skrinshot -> 👑 admin tasdiqlaydi -> 💰 balans oshadi.
# MUHIM QOIDA: foydalanuvchi "to'ladim" degani YETARLI EMAS — balans FAQAT
# (a) Click serverining imzolangan Complete callback'i (handle_click_callback)
# yoki (b) adminning ✅ Tasdiqlash bosishi orqali oshadi. Ikkalasi ham
# ATOMIK shartli UPDATE bilan idempotent (yuqoridagi db_complete_click_topup /
# db_admin_approve_manual_topup — bir xil tranzaksiya ikki marta hisoblanmaydi).
class BalanceTopupStates(StatesGroup):
    waiting_amount = State()      # 💵 Summa kiritish
    waiting_payment = State()     # 📋 To'lov ma'lumotlari ko'rsatilgan, ⏳ kutilmoqda
    waiting_screenshot = State()  # 📷 Click ishlamadi -> skrinshot kutilmoqda

class AdminTopupStates(StatesGroup):
    waiting_new_amount = State()  # 👑 Admin skrinshotdagi summani to'g'rilamoqchi

TOPUP_STATUS_LABEL = {
    "pending": "⏳ Kutilmoqda", "prepared": "⏳ Click tomonidan tayyorlanmoqda",
    "paid": "✅ To'landi", "failed": "❌ Muvaffaqiyatsiz",
    "cancelled": "🚫 Bekor qilindi", "manual_review": "👑 Admin ko'rib chiqmoqda",
}

@user_router.callback_query(F.data == "topup_start")
async def topup_choose_method(callback: CallbackQuery):
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="⚡ Payment Manager (tezkor, aniq summa)", callback_data="pm_topup_start")],
        [InlineKeyboardButton(text="📋 Click / admin tasdiqlash", callback_data="topup_legacy_start")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="nav:main")],
    ])
    await callback.message.edit_text(
        "💰 Balansni qanday to'ldirasiz?\n\n"
        "⚡ Payment Manager — karta raqami va ANIQ summa (tiyingacha) ko'rsatiladi, "
        "shu summani o'tkazsangiz avtomatik tekshiriladi.\n"
        "📋 Click / admin — Click orqali yoki to'lov skrinshotini yuborib, admin "
        "tasdiqlashi orqali.",
        reply_markup=kb,
    )
    await callback.answer()

@user_router.callback_query(F.data == "topup_legacy_start")
async def topup_start(callback: CallbackQuery, state: FSMContext):
    user = await db_get_user_by_telegram_id(callback.from_user.id)
    click_settings = await db_get_click_settings()
    min_a = click_settings.get("min_amount") or 5000
    max_a = click_settings.get("max_amount") or 5000000
    await db_cancel_stale_pending_topups(user["id"])
    await state.set_state(BalanceTopupStates.waiting_amount)
    await callback.message.edit_text(
        f"💵 Balansni to'ldirish summasini kiriting (so'mda).\n\n"
        f"Minimal: {fmt_som(min_a)} so'm\nMaksimal: {fmt_som(max_a)} so'm",
        reply_markup=back_kb_to("balance"),
    )
    await callback.answer()

@user_router.message(BalanceTopupStates.waiting_amount)
async def topup_receive_amount(message: Message, state: FSMContext):
    if not message.text:
        # Foydalanuvchi matn o'rniga rasm/fayl/sticker yuborgan — bu bosqichda
        # hali FAQAT summa (raqam) kutiladi, to'lov skrinshoti EMAS. Aniq va
        # tushunarli xabar beramiz, umumiy "kutilmagan xatolik" o'rniga.
        await message.answer("⚠️ Iltimos, avval summani RAQAMDA yozib yuboring (masalan: 50000). To'lov skrinshotini keyingi bosqichda so'raymiz.")
        return
    amount = parse_exact_som_amount(message.text)
    if amount is None:
        await message.answer("⚠️ Iltimos, aniq summa kiriting (masalan: 50000 yoki 50000.50). 2 xonadan ortiq kasr qabul qilinmaydi.")
        return
    click_settings = await db_get_click_settings()
    min_a = click_settings.get("min_amount") or 5000
    max_a = click_settings.get("max_amount") or 5000000
    if amount < min_a or amount > max_a:
        await message.answer(f"⚠️ Summa {fmt_som(min_a)} so'mdan {fmt_som(max_a)} so'mgacha bo'lishi kerak.")
        return
    user = await db_get_user_by_telegram_id(message.from_user.id)
    txn = await db_create_pending_topup(user["id"], amount)
    await state.set_state(BalanceTopupStates.waiting_payment)
    await state.update_data(transaction_id=txn["id"])
    click_settings = await db_get_click_settings()
    click_configured = bool(_build_click_pay_url(click_settings, txn["amount"], txn["merchant_trans_id"]))
    await message.answer(_topup_payment_text(txn, click_configured), reply_markup=await topup_payment_kb(txn))

def _topup_payment_text(txn: dict, click_configured: bool) -> str:
    click_note = ("\"💳 Click orqali to'lash\" tugmasini bosib to'lovni amalga oshiring. "
                  "To'lov muvaffaqiyatli bo'lsa, balansingiz AVTOMATIK to'ldiriladi va "
                  "sizga xabar keladi — buni kutib qolishingiz shart emas.") if click_configured else (
                  "⚠️ Click hozircha sozlanmagan. \"📷 Click ishlamadi\" tugmasi orqali "
                  "to'lov skrinshotini yuborib, admin tasdiqlashini kutishingiz mumkin.")
    return (
        f"📋 To'lov ma'lumotlari\n\n"
        f"Summa: {fmt_som(txn['amount'])} so'm\n"
        f"Buyurtma raqami: {txn['merchant_trans_id']}\n"
        f"Holat: {TOPUP_STATUS_LABEL.get(txn['status'], txn['status'])}\n\n"
        f"{click_note}"
    )

async def topup_payment_kb(txn: dict) -> InlineKeyboardMarkup:
    click_settings = await db_get_click_settings()
    pay_url = _build_click_pay_url(click_settings, txn["amount"], txn["merchant_trans_id"])
    rows = []
    if pay_url:
        rows.append([InlineKeyboardButton(text="💳 Click orqali to'lash", url=pay_url)])
    rows.append([InlineKeyboardButton(text="🔄 Holatni tekshirish", callback_data=f"topup_check:{txn['id']}")])
    rows.append([InlineKeyboardButton(text="📷 Click ishlamadi (skrinshot yuboraman)", callback_data=f"topup_manual:{txn['id']}")])
    rows.append([InlineKeyboardButton(text="❌ Bekor qilish", callback_data=f"topup_cancel:{txn['id']}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)

async def _get_owned_transaction(telegram_id: int, transaction_id: int) -> dict | None:
    user = await db_get_user_by_telegram_id(telegram_id)
    txn = await db_get_transaction(transaction_id)
    if not user or not txn or txn["user_id"] != user["id"]:
        return None
    return txn

# ---- 🔄 Holatni tekshirish (⏳ To'lov holatini kutish) ----
@user_router.callback_query(F.data.startswith("topup_check:"))
async def topup_check(callback: CallbackQuery, state: FSMContext):
    txn_id = int(callback.data.split(":")[1])
    txn = await _get_owned_transaction(callback.from_user.id, txn_id)
    if not txn:
        await callback.answer("❌ Tranzaksiya topilmadi", show_alert=True)
        return
    if txn["status"] == "paid":
        await state.clear()
        await callback.message.edit_text(
            f"✅ To'lov muvaffaqiyatli! Balansingiz {fmt_som(txn['amount'])} so'mga to'ldirildi.",
            reply_markup=back_kb("main"),
        )
        await callback.answer()
        return
    if txn["status"] in ("failed", "cancelled"):
        await state.clear()
        await callback.message.edit_text(
            f"{TOPUP_STATUS_LABEL.get(txn['status'], txn['status'])}\n\nQaytadan urinib ko'rishingiz mumkin.",
            reply_markup=back_kb_to("balance"),
        )
        await callback.answer()
        return
    await callback.answer(f"Holat: {TOPUP_STATUS_LABEL.get(txn['status'], txn['status'])}", show_alert=True)

# ---- ❌ Bekor qilish ----
@user_router.callback_query(F.data.startswith("topup_cancel:"))
async def topup_cancel(callback: CallbackQuery, state: FSMContext):
    txn_id = int(callback.data.split(":")[1])
    txn = await _get_owned_transaction(callback.from_user.id, txn_id)
    if txn and txn["status"] in ("pending", "prepared"):
        await db_cancel_click_topup(txn_id)
    await state.clear()
    await callback.message.edit_text("❌ Bekor qilindi.", reply_markup=back_kb_to("balance"))
    await callback.answer()

# ---- 📷 Click ishlamadi -> skrinshot oqimi ----
@user_router.callback_query(F.data.startswith("topup_manual:"))
async def topup_manual_start(callback: CallbackQuery, state: FSMContext):
    txn_id = int(callback.data.split(":")[1])
    txn = await _get_owned_transaction(callback.from_user.id, txn_id)
    if not txn:
        await callback.answer("❌ Tranzaksiya topilmadi", show_alert=True)
        return
    if txn["status"] not in ("pending", "prepared"):
        await callback.answer("Bu tranzaksiya bilan endi bu amalni bajarib bo'lmaydi.", show_alert=True)
        return
    await state.set_state(BalanceTopupStates.waiting_screenshot)
    await state.update_data(transaction_id=txn_id)
    await callback.message.edit_text(
        f"📷 To'lov skrinshotini (chek/screenshot) RASM sifatida yuboring.\n\n"
        f"Buyurtma raqami: {txn['merchant_trans_id']}\nSumma: {fmt_som(txn['amount'])} so'm",
        reply_markup=back_kb_to(f"topup_manual_back:{txn_id}"),
    )
    await callback.answer()

@user_router.callback_query(F.data.startswith("topup_manual_back:"))
async def topup_manual_back(callback: CallbackQuery, state: FSMContext):
    txn_id = int(callback.data.split(":")[1])
    txn = await _get_owned_transaction(callback.from_user.id, txn_id)
    if not txn:
        await callback.answer("❌ Tranzaksiya topilmadi", show_alert=True)
        return
    await state.set_state(BalanceTopupStates.waiting_payment)
    await state.update_data(transaction_id=txn_id)
    click_settings = await db_get_click_settings()
    click_configured = bool(_build_click_pay_url(click_settings, txn["amount"], txn["merchant_trans_id"]))
    await callback.message.edit_text(_topup_payment_text(txn, click_configured), reply_markup=await topup_payment_kb(txn))
    await callback.answer()

def _admintopup_kb(txn_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="✅ Tasdiqlash", callback_data=f"admintopup_approve:{txn_id}"),
            InlineKeyboardButton(text="❌ Rad etish", callback_data=f"admintopup_reject:{txn_id}"),
        ],
        [InlineKeyboardButton(text="✏️ Summani tahrirlash", callback_data=f"admintopup_edit:{txn_id}")],
    ])

def _admintopup_caption(user: dict, txn: dict) -> str:
    return (
        f"👑 Balans to'ldirish — qo'lda tasdiqlash so'raldi\n\n"
        f"Foydalanuvchi: {user['first_name']} (telegram_id={user['telegram_id']})\n"
        f"Summa: {fmt_som(txn['amount'])} so'm\nBuyurtma raqami: {txn['merchant_trans_id']}"
    )

@user_router.message(BalanceTopupStates.waiting_screenshot, F.photo)
async def topup_receive_screenshot(message: Message, state: FSMContext):
    data = await state.get_data()
    txn_id = data.get("transaction_id")
    txn = await _get_owned_transaction(message.from_user.id, txn_id)
    if not txn or txn["status"] not in ("pending", "prepared"):
        await state.clear()
        await message.answer("❌ Bu tranzaksiya bilan endi ishlab bo'lmaydi. Qaytadan boshlang.")
        return
    file_id = message.photo[-1].file_id
    await db_set_transaction_screenshot(txn_id, file_id)
    await state.clear()
    await message.answer(
        "✅ Skrinshot qabul qilindi va adminlarga yuborildi. Tasdiqlanishini kuting — "
        "tasdiqlangach balansingiz avtomatik to'ldiriladi va sizga xabar keladi.",
        reply_markup=back_kb("main"),
    )
    user = await db_get_user_by_telegram_id(message.from_user.id)
    for admin in await db_get_all_admins():
        try:
            await bot.send_photo(admin["telegram_id"], file_id,
                                  caption=_admintopup_caption(user, txn),
                                  reply_markup=_admintopup_kb(txn_id))
        except Exception:
            pass

@user_router.message(BalanceTopupStates.waiting_screenshot)
async def topup_receive_screenshot_wrong_type(message: Message):
    await message.answer("⚠️ Iltimos, to'lov skrinshotini RASM (photo) sifatida yuboring, matn emas.")


# ---- 👑 Admin: skrinshot orqali tasdiqlash/rad etish ----
@user_router.callback_query(F.data.startswith("admintopup_approve:"))
async def admintopup_approve(callback: CallbackQuery):
    if not await _require_admin(callback): return
    txn_id = int(callback.data.split(":")[1])
    applied, txn = await db_admin_approve_manual_topup(txn_id)
    if not txn:
        await callback.answer("❌ Tranzaksiya topilmadi", show_alert=True)
        return
    if not applied:
        await callback.answer("⚠️ Bu tranzaksiya allaqachon ko'rib chiqilgan (qayta bosilmasin).", show_alert=True)
        return
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="topup_approve",
                            result="OK", target=f"transaction_{txn_id}", reason=f"amount={txn['amount']}")
    user = await db_get_user_by_id(txn["user_id"])
    if user:
        try:
            await bot.send_message(user["telegram_id"],
                                    f"✅ Balansingiz {fmt_som(txn['amount'])} so'mga to'ldirildi (admin tomonidan tasdiqlandi).")
        except Exception:
            pass
    try:
        await callback.message.edit_caption(caption=(callback.message.caption or "") + "\n\n✅ TASDIQLANDI")
    except Exception:
        pass
    await callback.answer("✅ Tasdiqlandi")

@user_router.callback_query(F.data.startswith("admintopup_edit:"))
async def admintopup_edit_prompt(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    txn_id = int(callback.data.split(":")[1])
    txn = await db_get_transaction(txn_id)
    if not txn or txn["status"] != "manual_review":
        await callback.answer("⚠️ Bu tranzaksiya endi tahrirlanmaydi (allaqachon ko'rib chiqilgan).", show_alert=True)
        return
    await state.set_state(AdminTopupStates.waiting_new_amount)
    await state.update_data(
        edit_txn_id=txn_id,
        edit_chat_id=callback.message.chat.id,
        edit_message_id=callback.message.message_id,
    )
    await callback.message.answer(
        f"✏️ Skrinshotdagi HAQIQIY summani kiriting (so'mda, hozirgi qiymat: {fmt_som(txn['amount'])} so'm):"
    )
    await callback.answer()

@user_router.message(AdminTopupStates.waiting_new_amount)
async def admintopup_edit_receive(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        await state.clear()
        return
    data = await state.get_data()
    txn_id = data.get("edit_txn_id")
    new_amount = parse_exact_som_amount(message.text or "")
    if new_amount is None:
        await message.answer("⚠️ Noto'g'ri summa. Masalan: 50000 yoki 50000.50. Qaytadan yuboring:")
        return
    txn = await db_admin_update_manual_topup_amount(txn_id, new_amount)
    await state.clear()
    if not txn:
        await message.answer("❌ Bu tranzaksiya endi tahrirlanmaydi (allaqachon tasdiqlangan yoki rad etilgan bo'lishi mumkin).")
        return
    await message.answer(f"✅ Summa {fmt_som(new_amount)} so'mga o'zgartirildi.")
    chat_id, message_id = data.get("edit_chat_id"), data.get("edit_message_id")
    if chat_id and message_id:
        user = await db_get_user_by_id(txn["user_id"])
        try:
            await bot.edit_message_caption(
                chat_id=chat_id, message_id=message_id,
                caption=_admintopup_caption(user, txn),
                reply_markup=_admintopup_kb(txn_id),
            )
        except Exception:
            pass

@user_router.callback_query(F.data.startswith("admintopup_reject:"))
async def admintopup_reject(callback: CallbackQuery):
    if not await _require_admin(callback): return
    txn_id = int(callback.data.split(":")[1])
    applied, txn = await db_admin_reject_manual_topup(txn_id)
    if not txn:
        await callback.answer("❌ Tranzaksiya topilmadi", show_alert=True)
        return
    if not applied:
        await callback.answer("⚠️ Bu tranzaksiya allaqachon ko'rib chiqilgan (qayta bosilmasin).", show_alert=True)
        return
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="topup_reject",
                            result="OK", target=f"transaction_{txn_id}")
    user = await db_get_user_by_id(txn["user_id"])
    if user:
        try:
            await bot.send_message(user["telegram_id"],
                                    f"❌ Balans to'ldirish so'rovingiz rad etildi (buyurtma: {txn['merchant_trans_id']}). "
                                    f"Savol bo'lsa, admin bilan bog'laning.")
        except Exception:
            pass
    try:
        await callback.message.edit_caption(caption=(callback.message.caption or "") + "\n\n❌ RAD ETILDI")
    except Exception:
        pass
    await callback.answer("❌ Rad etildi")


# ===================== ⚡ PAYMENT MANAGER (karta-karta, aniq summa, SMS-monitoring) =====================
# Backend (payment_orders/payment_cards/db_confirm_payment_order va h.k.) allaqachon
# mavjud edi — bu yerda faqat FOYDALANUVCHI OQIMI ulanmoqda. MUHIM: hozircha SMS
# webhook (/payment/notify) va admin tomonidan qo'lda tasdiqlash paneli hali
# yozilmagan — shuning uchun buyurtma "⏳ Kutilmoqda" holatida qoladi, balans
# faqat db_confirm_payment_order() chaqirilganda oshadi (bu keyingi bosqich —
# admin panelga alohida ish olib borilganda ulanadi). Hozir foydalanuvchi
# to'lov qildim deganda buyurtma faqat awaiting_confirmation'ga o'tadi.
class PaymentManagerStates(StatesGroup):
    waiting_amount = State()

@user_router.callback_query(F.data == "pm_topup_start")
async def pm_topup_start(callback: CallbackQuery, state: FSMContext):
    settings = await db_get_payment_settings()
    await state.set_state(PaymentManagerStates.waiting_amount)
    await callback.message.edit_text(
        f"⚡ Payment Manager\n\n💵 Summani kiriting (so'mda, tiyingacha aniq bo'lishi mumkin).\n\n"
        f"Minimal: {fmt_som(settings['min_amount'])} so'm\n"
        f"Maksimal: {fmt_som(settings['max_amount'])} so'm",
        reply_markup=back_kb_to("topup_start"),
    )
    await callback.answer()

def pm_order_kb(order_ref: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ To'lov qildim", callback_data=f"pm_paid:{order_ref}")],
        [InlineKeyboardButton(text="🔄 Holatni tekshirish", callback_data=f"pm_check:{order_ref}")],
        [InlineKeyboardButton(text="❌ Bekor qilish", callback_data=f"pm_cancel:{order_ref}")],
    ])

def _pm_order_text(order: dict, card_number: str | None) -> str:
    minutes_left = ""
    try:
        left = datetime.fromisoformat(order["lock_expires_at"]) - utcnow()
        minutes_left = f"\n⏳ Amal qilish muddati: ~{max(0, int(left.total_seconds() // 60))} daqiqa"
    except Exception:
        pass
    card_line = f"💳 Karta: {card_number}" if card_number else "💳 Karta: (admin sozlashi kerak)"
    return (
        f"📋 To'lov buyurtmasi #{order['order_ref']}\n\n"
        f"{card_line}\n"
        f"💰 ANIQ summa: {fmt_som(order['amount'])} so'm\n\n"
        f"⚠️ Aynan shu summani (tiyingacha) o'tkazing — farq qilsa avtomatik "
        f"hisoblanmaydi.{minutes_left}\n\n"
        f"O'tkazgach \"✅ To'lov qildim\" tugmasini bosing."
    )

@user_router.message(PaymentManagerStates.waiting_amount)
async def pm_receive_amount(message: Message, state: FSMContext):
    amount = parse_exact_som_amount(message.text)
    if amount is None:
        await message.answer("⚠️ Iltimos, aniq summa kiriting (masalan: 50000 yoki 50000.50). 2 xonadan ortiq kasr qabul qilinmaydi.")
        return
    user = await db_get_user_by_telegram_id(message.from_user.id)
    try:
        order = await db_create_payment_order(user["id"], amount)
    except PaymentOrderError as e:
        await message.answer(f"⚠️ {e}", reply_markup=back_kb_to("topup_start"))
        return
    await state.clear()
    card = await db_get_card(order["lock_card_id"]) if order.get("lock_card_id") else None
    card_number = None
    if card:
        try:
            card_number = decrypt_token(card["card_number_encrypted"])
        except Exception:
            card_number = f"•••• {card['card_last4']}"
    await message.answer(_pm_order_text(order, card_number), reply_markup=pm_order_kb(order["order_ref"]))

async def _get_owned_order(telegram_id: int, order_ref: str) -> dict | None:
    user = await db_get_user_by_telegram_id(telegram_id)
    order = await db_get_order_by_ref(order_ref)
    if not user or not order or order["user_id"] != user["id"]:
        return None
    return order

@user_router.callback_query(F.data.startswith("pm_paid:"))
async def pm_mark_paid(callback: CallbackQuery, state: FSMContext):
    order_ref = callback.data.split(":", 1)[1]
    order = await _get_owned_order(callback.from_user.id, order_ref)
    if not order:
        await callback.answer("❌ Buyurtma topilmadi", show_alert=True)
        return
    if order["status"] != "locked":
        await callback.answer(f"Bu buyurtma holati: {order['status']}", show_alert=True)
        return
    await db_mark_order_awaiting_confirmation(order["id"])
    await state.clear()
    await callback.message.edit_text(
        f"⏳ Kutilmoqda...\n\nBuyurtma #{order['order_ref']} ({fmt_som(order['amount'])} so'm) "
        f"tekshirilmoqda. Tasdiqlangach xabar keladi.\n\n"
        f"ℹ️ Hozircha tasdiqlash admin tomonidan amalga oshiriladi.",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Holatni tekshirish", callback_data=f"pm_check:{order['order_ref']}")],
            [InlineKeyboardButton(text="🔙 Bosh menyu", callback_data="nav:main")],
        ]),
    )
    await callback.answer()

@user_router.callback_query(F.data.startswith("pm_check:"))
async def pm_check_status(callback: CallbackQuery):
    order_ref = callback.data.split(":", 1)[1]
    order = await _get_owned_order(callback.from_user.id, order_ref)
    if not order:
        await callback.answer("❌ Buyurtma topilmadi", show_alert=True)
        return
    if order["status"] == "paid":
        await callback.message.edit_text(
            f"✅ To'lov muvaffaqiyatli! Balansingiz {fmt_som(order['amount'])} so'mga to'ldirildi.",
            reply_markup=back_kb("main"),
        )
        await callback.answer()
        return
    if order["status"] in ("cancelled", "expired"):
        await callback.message.edit_text(
            f"{'🚫 Bekor qilindi' if order['status'] == 'cancelled' else '⌛ Muddati tugadi'}.\n\nQaytadan urinib ko'rishingiz mumkin.",
            reply_markup=back_kb_to("topup_start"),
        )
        await callback.answer()
        return
    await callback.answer(f"Holat: {order['status']}", show_alert=True)

@user_router.callback_query(F.data.startswith("pm_cancel:"))
async def pm_cancel_order(callback: CallbackQuery, state: FSMContext):
    order_ref = callback.data.split(":", 1)[1]
    order = await _get_owned_order(callback.from_user.id, order_ref)
    if order and order["status"] in ("locked", "awaiting_confirmation"):
        await db_cancel_payment_order(order["id"])
    await state.clear()
    await callback.message.edit_text("❌ Bekor qilindi.", reply_markup=back_kb_to("topup_start"))
    await callback.answer()


# ---- 📜 To'lovlarim (pagination) ----
MY_PAYMENTS_PAGE_SIZE = 5
PAYMENT_ROW_EMOJI = {"paid": "✅", "pending": "⏳", "prepared": "⏳", "manual_review": "👑",
                     "failed": "❌", "cancelled": "🚫"}

def _payment_row_text(t: dict) -> str:
    emoji = PAYMENT_ROW_EMOJI.get(t["status"], "⚪")
    sign = "+" if t["type"] == "topup" else "-"
    when = (t["created_at"] or "")[:16]
    return f"{emoji} {sign}{fmt_som(t['amount'])} so'm — {when}"

async def _render_my_payments(user_id: int, page: int) -> tuple[str, InlineKeyboardMarkup]:
    total = await db_count_user_transactions(user_id)
    rows = await db_get_user_transactions(user_id, MY_PAYMENTS_PAGE_SIZE, page * MY_PAYMENTS_PAGE_SIZE)
    lines = ["📜 To'lovlarim\n"] + [_payment_row_text(t) for t in rows]
    text = "\n".join(lines) if rows else "📜 To'lovlarim\n\nHali tranzaksiya yo'q."
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️ Oldingi", callback_data=f"my_payments:{page - 1}"))
    if (page + 1) * MY_PAYMENTS_PAGE_SIZE < total:
        nav.append(InlineKeyboardButton(text="Keyingi ➡️", callback_data=f"my_payments:{page + 1}"))
    kb_rows = [nav] if nav else []
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="nav:main")])
    return text, InlineKeyboardMarkup(inline_keyboard=kb_rows)

@user_router.callback_query(F.data == "my_payments")
async def show_my_payments(callback: CallbackQuery):
    user = await db_get_user_by_telegram_id(callback.from_user.id)
    text, kb = await _render_my_payments(user["id"], 0)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data.startswith("my_payments:"))
async def show_my_payments_page(callback: CallbackQuery):
    page = int(callback.data.split(":")[1])
    user = await db_get_user_by_telegram_id(callback.from_user.id)
    text, kb = await _render_my_payments(user["id"], page)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data == "profile")
async def show_profile(callback: CallbackQuery):
    user = await db_get_user_by_telegram_id(callback.from_user.id)
    text = (f"👤 Profil\n\nIsm: {user['first_name']}\nUsername: @{user['username'] or '—'}\n"
            f"Telegram ID: {user['telegram_id']}\nRo'yxatdan o'tgan: {user['created_at']}")
    await callback.message.edit_text(text, reply_markup=back_kb("main"))
    await callback.answer()

@user_router.callback_query(F.data == "admin_panel")
async def show_admin_panel(callback: CallbackQuery):
    if not await is_admin(callback.from_user.id):
        await callback.answer("❌ Ruxsat yo'q", show_alert=True)
        return
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="👥 Foydalanuvchilar", callback_data="admin_users")],
        [InlineKeyboardButton(text="🖥️ Serverlar", callback_data="admin_servers")],
        [InlineKeyboardButton(text="🤖 Botlar", callback_data="admin_bots")],
        [InlineKeyboardButton(text="🤖 Admin AI", callback_data="admin_ai")],
        [InlineKeyboardButton(text="📊 Statistika", callback_data="admin_stats")],
        [InlineKeyboardButton(text="🗄️ Backup / Restore", callback_data="admin_backup")],
        [InlineKeyboardButton(text="⚙️ Tizim sozlamalari", callback_data="sysset_menu")],
        [InlineKeyboardButton(text="💳 Payment Manager", callback_data="payment_manager")],
        [InlineKeyboardButton(text="💳 Click sozlamalari", callback_data="click_settings")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="nav:main")],
    ])
    await callback.message.edit_text("👑 ADMIN PANEL", reply_markup=kb)
    await callback.answer()


# ===================== ➕ BOT YARATISH FSM =====================
class BotCreateStates(StatesGroup):
    waiting_name = State()
    waiting_username = State()
    waiting_token = State()
    waiting_upload_choice = State()
    waiting_zip = State()
    waiting_files_code = State()
    waiting_files_env = State()
    waiting_files = State()

MAX_FILES_COUNT = 200

BOT_USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{3,30}[Bb][Oo][Tt]$")
BOT_TOKEN_RE = re.compile(r"^\d{6,10}:[A-Za-z0-9_-]{30,45}$")

MAX_ZIP_SIZE_MB = 50
MAX_UNCOMPRESSED_MB = 200
MAX_ZIP_FILES = 3000
ENTRY_CANDIDATES = ("run.py", "bot.py", "main.py")

TMP_UPLOADS_DIR = Path("tmp_uploads")
TMP_UPLOADS_DIR.mkdir(exist_ok=True)


async def _verify_bot_token(token: str) -> tuple[bool, str, str]:
    """Telegram getMe orqali tokenni tekshiradi. (ok, username_yoki_xato, first_name)."""
    url = f"https://api.telegram.org/bot{token}/getMe"
    try:
        async with aiohttp_client.ClientSession(timeout=aiohttp_client.ClientTimeout(total=10)) as session:
            async with session.get(url) as resp:
                data = await resp.json()
    except Exception as e:
        return False, f"Tekshirishda tarmoq xatosi: {e}", ""
    if not data.get("ok"):
        return False, data.get("description", "Token yaroqsiz"), ""
    result = data["result"]
    return True, result.get("username", ""), result.get("first_name", "")


def _zip_find_entry(names: list[str]) -> str | None:
    """run.py/bot.py/main.py'ni zip tub qismida yoki bitta ichki papkada qidiradi."""
    for depth in (1, 2):
        for candidate in ENTRY_CANDIDATES:
            for n in names:
                if n.endswith("/"):
                    continue
                parts = n.split("/")
                if len(parts) == depth and parts[-1] == candidate:
                    return n
    return None


def _validate_zip_safety(zip_path: Path) -> tuple[bool, str, list[str]]:
    """Zip xavfsizligini tekshiradi (hajm/fayl soni/path-traversal/zip-bomb) va
    kirish nuqtasini topadi. Muvaffaqiyatli bo'lsa (True, entry_arcname, names)."""
    size_mb = zip_path.stat().st_size / (1024 * 1024)
    if size_mb > MAX_ZIP_SIZE_MB:
        return False, f"Zip fayl juda katta ({size_mb:.1f}MB). Limit: {MAX_ZIP_SIZE_MB}MB.", []
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile:
        return False, "Fayl yaroqli .zip emas.", []
    with zf:
        names = zf.namelist()
        if len(names) > MAX_ZIP_FILES:
            return False, f"Zip ichida juda ko'p fayl ({len(names)}). Limit: {MAX_ZIP_FILES}.", []
        total_uncompressed = 0
        for info in zf.infolist():
            name = info.filename
            parts = Path(name).parts
            if name.startswith("/") or name.startswith("\\") or ".." in parts or (len(name) > 1 and name[1] == ":"):
                return False, f"Xavfsiz bo'lmagan yo'l aniqlandi: {name}", []
            total_uncompressed += info.file_size
            if total_uncompressed > MAX_UNCOMPRESSED_MB * 1024 * 1024:
                return False, f"Zip ochilgach juda katta bo'ladi (limit {MAX_UNCOMPRESSED_MB}MB).", []
        entry = _zip_find_entry(names)
        if not entry:
            return False, (
                "Zip ichida kirish nuqtasi topilmadi. Fayl nomi run.py, bot.py "
                "yoki main.py bo'lishi va zip tub qismida (yoki bitta ichki "
                "papkada) joylashgan bo'lishi kerak."
            ), []
    return True, entry, names


def _safe_extract_zip(zip_path: Path, dest_dir: Path):
    """Zipni dest_dir ichiga xavfsiz ochadi (ikkinchi qatlam path-traversal himoyasi)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest_dir.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.filename.endswith("/"):
                continue
            target = (dest_dir / info.filename).resolve()
            if not str(target).startswith(str(dest_resolved)):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                dst.write(src.read())


def _finalize_bot_code(bot_id: int, entry_arcname: str, bot_token: str):
    """user_code ichida run.py borligini ta'minlaydi (ProcessManager shuni kutadi)
    va .envni user_code'dan tashqariga, managed_bots/bot_<id>/.env'ga chiqaradi —
    Docker bosqichida user_code read-only mount qilinadi, .env alohida mount
    qilinadi. BOT_TOKEN doim FSM'da tasdiqlangan (va DB'da shifrlangan) token
    bilan ustunlik qiladi — zip ichidagi .env'da boshqa qiymat bo'lsa ham."""
    bot_dir = Path(f"managed_bots/bot_{bot_id}")
    code_dir = bot_dir / "user_code"
    entry_path = code_dir / entry_arcname
    run_path = code_dir / "run.py"
    if entry_path.resolve() != run_path.resolve():
        run_path.write_bytes(entry_path.read_bytes())

    env_data: dict[str, str] = {}
    for env_candidate in list(code_dir.rglob(".env")):
        try:
            for line in env_candidate.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                env_data[k.strip()] = v.strip()
        except Exception:
            pass
        env_candidate.unlink(missing_ok=True)
    env_data["BOT_TOKEN"] = bot_token
    (bot_dir / ".env").write_text("\n".join(f"{k}={v}" for k, v in env_data.items()))


def _find_entry_in_flat_files(filenames: list[str]) -> str | None:
    """Alohida yuborilgan (papkasiz, tekis) fayllar ro'yxatidan run.py/bot.py/
    main.py'ni qidiradi (ENTRY_CANDIDATES tartibida ustunlik bilan)."""
    for candidate in ENTRY_CANDIDATES:
        for n in filenames:
            if n == candidate:
                return n
    return None


def _safe_flat_filename(raw_name: str) -> str | None:
    """Telegramdan kelgan fayl nomini xavfsizlashtiradi: yo'l qismlarini olib
    tashlaydi (faqat asosiy fayl nomi qoladi — papka tuzilishi qo'llab-
    quvvatlanmaydi, buning uchun .zip tavsiya etiladi), bo'sh/maxsus nomlarni
    rad etadi."""
    name = Path(raw_name).name.strip()
    if not name or name in (".", ".."):
        return None
    return name


def botcreate_cancel_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="❌ Bekor qilish", callback_data="botcreate_cancel")]])

def botcreate_upload_choice_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📦 ZIP fayl", callback_data="botcreate_upload:zip")],
        [InlineKeyboardButton(text="📄 Fayllarni alohida", callback_data="botcreate_upload:files")],
        [InlineKeyboardButton(text="❌ Bekor qilish", callback_data="botcreate_cancel")],
    ])

def botcreate_files_kb(count: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=f"✅ Tayyor ({count} fayl)", callback_data="botcreate_files_done")],
        [InlineKeyboardButton(text="❌ Bekor qilish", callback_data="botcreate_cancel")],
    ])

def botcreate_server_kb(servers: list[dict]) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(
                text=f"🖥️ {s['name']} ({s['ram_gb']}GB RAM, {s['cpu_cores']} CPU)",
                callback_data=f"botcreate_server:{s['id']}",
            )] for s in servers]
    rows.append([InlineKeyboardButton(text="❌ Bekor qilish", callback_data="botcreate_cancel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)

def botcreate_confirm_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="💾 Yaratish", callback_data="botcreate_save")],
        [InlineKeyboardButton(text="❌ Bekor qilish", callback_data="botcreate_cancel")],
    ])


@user_router.callback_query(F.data == "bot_create")
async def bot_create_start(callback: CallbackQuery, state: FSMContext):
    await state.clear()
    await state.set_state(BotCreateStates.waiting_name)
    await callback.message.edit_text(
        "➕ Yangi bot yaratish\n\n📝 Botingiz uchun nom kiriting (masalan: Mening Do'konim):",
        reply_markup=botcreate_cancel_kb(),
    )
    await callback.answer()

@user_router.callback_query(F.data == "botcreate_cancel")
async def bot_create_cancel(callback: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    tmp_path = data.get("zip_tmp_path")
    if tmp_path:
        Path(tmp_path).unlink(missing_ok=True)
    files_dir = data.get("files_dir")
    if files_dir:
        shutil.rmtree(files_dir, ignore_errors=True)
    await state.clear()
    user = await db_get_user_by_telegram_id(callback.from_user.id)
    try:
        await callback.message.edit_reply_markup(reply_markup=None)
    except Exception:
        pass
    await callback.message.answer("❌ Bot yaratish bekor qilindi.", reply_markup=main_menu_kb(bool(user["is_admin"])))
    await callback.answer()

@user_router.message(BotCreateStates.waiting_name)
async def bot_create_receive_name(message: Message, state: FSMContext):
    name = (message.text or "").strip()
    if not (2 <= len(name) <= 64):
        await message.answer("⚠️ Nom 2 dan 64 belgigacha bo'lishi kerak. Qayta kiriting:")
        return
    await state.update_data(name=name)
    await state.set_state(BotCreateStates.waiting_username)
    await message.answer(
        "👤 Bot username'ini kiriting (masalan: mening_dokonim_bot).\n"
        "Username 5-32 belgi va 'bot' bilan tugashi shart.",
        reply_markup=botcreate_cancel_kb(),
    )

@user_router.message(BotCreateStates.waiting_username)
async def bot_create_receive_username(message: Message, state: FSMContext):
    username = (message.text or "").strip().lstrip("@")
    if not BOT_USERNAME_RE.match(username) or not (5 <= len(username) <= 32):
        await message.answer(
            "⚠️ Noto'g'ri format. Username 5-32 belgi, harf bilan boshlanishi, "
            "faqat harf/raqam/pastki chiziqdan iborat bo'lishi va 'bot' bilan "
            "tugashi kerak. Qayta kiriting:"
        )
        return
    existing = await db_get_bot_by_username(username)
    if existing:
        await message.answer("⚠️ Bu username band. Boshqa username kiriting:")
        return
    await state.update_data(username=username)
    await state.set_state(BotCreateStates.waiting_token)
    await message.answer(
        "🔑 Bot tokenini yuboring (@BotFather'dan olingan).\n\n"
        "⚠️ Xabaringiz yuborilgach avtomatik o'chiriladi (xavfsizlik uchun).",
        reply_markup=botcreate_cancel_kb(),
    )

@user_router.message(BotCreateStates.waiting_token)
async def bot_create_receive_token(message: Message, state: FSMContext):
    token = (message.text or "").strip()
    try:
        await message.delete()
    except Exception:
        pass
    if not BOT_TOKEN_RE.match(token):
        await message.answer("⚠️ Token formati noto'g'ri. Qaytadan yuboring:", reply_markup=botcreate_cancel_kb())
        return
    data = await state.get_data()
    checking = await message.answer("⏳ Token tekshirilmoqda...")
    ok, result, _first_name = await _verify_bot_token(token)
    if not ok:
        await checking.edit_text(f"⚠️ Token yaroqsiz: {result}\n\nQaytadan yuboring:", reply_markup=botcreate_cancel_kb())
        return
    if result.lower() != data["username"].lower():
        await checking.edit_text(
            f"⚠️ Bu token @{result} botiga tegishli, lekin siz @{data['username']} "
            f"deb kiritgan edingiz. To'g'ri tokenni yuboring:",
            reply_markup=botcreate_cancel_kb(),
        )
        return
    await state.update_data(token=token)
    await state.set_state(BotCreateStates.waiting_upload_choice)
    await checking.edit_text(
        "✅ Token tasdiqlandi.\n\n📦 Qanday yuborasiz?",
        reply_markup=botcreate_upload_choice_kb(),
    )

@user_router.callback_query(F.data.startswith("botcreate_upload:"), BotCreateStates.waiting_upload_choice)
async def bot_create_choose_upload_mode(callback: CallbackQuery, state: FSMContext):
    mode = callback.data.split(":")[1]
    if mode == "zip":
        await state.update_data(upload_mode="zip")
        await state.set_state(BotCreateStates.waiting_zip)
        await callback.message.edit_text(
            "📦 Bot kodini .zip fayl sifatida yuboring.\n\n"
            "Talab: zip ichida (tub qismida yoki bitta ichki papkada) run.py, bot.py "
            "yoki main.py fayllaridan biri bo'lishi kerak. .env fayl ham qo'shishingiz "
            "mumkin (ichidagi BOT_TOKEN avtomatik almashtiriladi).",
            reply_markup=botcreate_cancel_kb(),
        )
    else:
        files_dir = TMP_UPLOADS_DIR / f"files_{callback.from_user.id}_{int(time.time())}"
        files_dir.mkdir(parents=True, exist_ok=True)
        await state.update_data(upload_mode="files", files_dir=str(files_dir), files_names=[])
        await state.set_state(BotCreateStates.waiting_files_code)
        await callback.message.edit_text(
            "📄 Fayllarni bosqichma-bosqich yuboramiz — bu ASOSIY KOD bilan MAXFIY "
            "(.env) faylni chalkashtirmaslik uchun.\n\n"
            "1️⃣-QADAM: Botingizning ASOSIY KOD faylini yuboring "
            "(fayl nomi: bot.py, main.py yoki run.py bo'lishi shart).",
            reply_markup=botcreate_cancel_kb(),
        )
    await callback.answer()

async def _save_flat_file(message: Message, state: FSMContext, safe_name: str) -> Path | None:
    """Faylni files_dir'ga yuklab oladi, hajm limitlarini tekshiradi. Xato bo'lsa
    None qaytaradi (xabar allaqachon foydalanuvchiga yuborilgan bo'ladi)."""
    doc = message.document
    data = await state.get_data()
    files_dir = Path(data["files_dir"])
    if doc.file_size and doc.file_size > MAX_ZIP_SIZE_MB * 1024 * 1024:
        await message.answer(f"⚠️ Fayl juda katta (limit {MAX_ZIP_SIZE_MB}MB). Boshqa fayl yuboring.")
        return None
    dest = files_dir / safe_name
    try:
        file = await bot.get_file(doc.file_id)
        await bot.download_file(file.file_path, destination=dest)
    except Exception as e:
        await message.answer(f"⚠️ Faylni yuklab olishda xato: {e}\n\nQaytadan yuboring:")
        return None
    total_size_mb = sum(f.stat().st_size for f in files_dir.iterdir() if f.is_file()) / (1024 * 1024)
    if total_size_mb > MAX_UNCOMPRESSED_MB:
        dest.unlink(missing_ok=True)
        await message.answer(f"⚠️ Jami hajm limitdan oshdi (limit {MAX_UNCOMPRESSED_MB}MB). Bu fayl qabul qilinmadi.")
        return None
    return dest

def botcreate_skip_env_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="⏭ .env yo'q, o'tkazib yuborish", callback_data="botcreate_skip_env")],
        [InlineKeyboardButton(text="❌ Bekor qilish", callback_data="botcreate_cancel")],
    ])

@user_router.message(BotCreateStates.waiting_files_code, F.document)
async def bot_create_receive_code_file(message: Message, state: FSMContext):
    doc = message.document
    raw_name = _safe_flat_filename(doc.file_name or "")
    # Har qanday .py faylni qabul qilamiz, run.py sifatida saqlaymiz
    if not raw_name or not raw_name.lower().endswith(".py"):
        await message.answer(
            "⚠️ Bu ASOSIY KOD fayli uchun noto'g'ri format. "
            "Istalgan .py fayl (bot.py, main.py, run.py, app.py va h.k.) yuboring.\n\n"
            "(.env faylni keyingi qadamda so'raymiz.)"
        )
        return
    # Kirish nuqtasi har doim run.py sifatida saqlanadi (ProcessManager shu nomni kutadi)
    save_as = "run.py"
    dest = await _save_flat_file(message, state, save_as)
    if dest is None:
        return
    await state.update_data(zip_entry=save_as, files_names=[save_as])
    await state.set_state(BotCreateStates.waiting_files_env)
    orig = f" ({raw_name})" if raw_name != save_as else ""
    await message.answer(
        f"✅ Asosiy kod qabul qilindi: {save_as}{orig}\n\n"
        "2️⃣-QADAM: Endi MAXFIY (.env) faylni yuboring — unda BOT_TOKEN va boshqa "
        "maxfiy sozlamalar bo'ladi. Agar .env fayli bo'lmasa, pastdagi tugmani bosing.",
        reply_markup=botcreate_skip_env_kb(),
    )

@user_router.message(BotCreateStates.waiting_files_code)
async def bot_create_code_wrong_type(message: Message, state: FSMContext):
    await message.answer(
        "⚠️ Iltimos, ASOSIY KOD faylini (bot.py / main.py / run.py) document "
        "sifatida yuboring.",
        reply_markup=botcreate_cancel_kb(),
    )

async def _advance_to_extra_files(target_message: Message, state: FSMContext):
    await state.set_state(BotCreateStates.waiting_files)
    await target_message.answer(
        "3️⃣-QADAM (ixtiyoriy): Qo'shimcha fayllar bo'lsa (masalan requirements.txt, "
        "boshqa .py modullar) yuboring. Bo'lmasa, pastdagi ✅ Tayyor tugmasini bosing.",
        reply_markup=botcreate_files_kb(len((await state.get_data()).get("files_names", []))),
    )

@user_router.callback_query(F.data == "botcreate_skip_env", BotCreateStates.waiting_files_env)
async def bot_create_skip_env(callback: CallbackQuery, state: FSMContext):
    await _advance_to_extra_files(callback.message, state)
    await callback.answer()

def _is_env_file(file_name: str) -> bool:
    """Istalgan .env yoki env-ga o'xshash faylni aniqlaydi:
    .env, .env.txt, 1.env.txt, config.env, env.txt, environment va h.k."""
    n = file_name.strip().lower()
    return (
        n == ".env"
        or n.endswith(".env")
        or n.endswith(".env.txt")
        or "env" in n
    )

@user_router.message(BotCreateStates.waiting_files_env, F.document)
async def bot_create_receive_env_file(message: Message, state: FSMContext):
    doc = message.document
    raw_name = (doc.file_name or "").strip()
    if not _is_env_file(raw_name):
        await message.answer(
            "⚠️ Bu fayl .env fayl emas. Maxfiy sozlamalar faylini yuboring:\n"
            "• <code>.env</code>\n"
            "• <code>.env.txt</code>\n"
            "• <code>config.env</code> va shunga o'xshash\n\n"
            "Agar .env fayl kerak bo'lmasa, pastdagi tugmani bosing.",
            reply_markup=botcreate_skip_env_kb(),
            parse_mode="HTML",
        )
        return
    dest = await _save_flat_file(message, state, ".env")
    if dest is None:
        return
    data = await state.get_data()
    names: list[str] = data.get("files_names", [])
    if ".env" not in names:
        names.append(".env")
    await state.update_data(files_names=names)
    await message.answer("✅ .env fayli qabul qilindi.")
    await _advance_to_extra_files(message, state)

@user_router.message(BotCreateStates.waiting_files_env)
async def bot_create_env_wrong_type(message: Message, state: FSMContext):
    await message.answer(
        "⚠️ Iltimos, .env faylini document sifatida yuboring, yoki \"⏭ .env yo'q\" tugmasini bosing.",
        reply_markup=botcreate_skip_env_kb(),
    )

@user_router.message(BotCreateStates.waiting_files, F.document)
async def bot_create_receive_file(message: Message, state: FSMContext):
    doc = message.document
    safe_name = _safe_flat_filename(doc.file_name or "")
    if not safe_name:
        await message.answer("⚠️ Fayl nomi yaroqsiz. Boshqa fayl yuboring.")
        return
    if safe_name.lower().endswith(".zip"):
        await message.answer(
            "⚠️ .zip fayl bu rejimda qabul qilinmaydi. Zip yuborish uchun bekor qilib, "
            "\"📦 ZIP fayl\" rejimini tanlang, yoki ichidagi fayllarni ochib, birma-bir yuboring."
        )
        return
    if safe_name.lower() == ".env":
        await message.answer("⚠️ .env fayli allaqachon qabul qilindi (yoki o'tkazib yuborildi). Bu qadamda faqat qo'shimcha fayllarni yuboring.")
        return
    data = await state.get_data()
    names: list[str] = data.get("files_names", [])
    if len(names) >= MAX_FILES_COUNT:
        await message.answer(f"⚠️ Fayllar soni limiti ({MAX_FILES_COUNT}) tugadi. ✅ Tayyor tugmasini bosing.")
        return
    dest = await _save_flat_file(message, state, safe_name)
    if dest is None:
        return
    if safe_name not in names:
        names.append(safe_name)
    await state.update_data(files_names=names)
    await message.answer(f"✅ Qabul qilindi: {safe_name}", reply_markup=botcreate_files_kb(len(names)))

@user_router.message(BotCreateStates.waiting_files)
async def bot_create_files_wrong_type(message: Message, state: FSMContext):
    data = await state.get_data()
    count = len(data.get("files_names", []))
    await message.answer("⚠️ Iltimos, faylni document sifatida yuboring, yoki ✅ Tayyor tugmasini bosing.",
                          reply_markup=botcreate_files_kb(count))

@user_router.callback_query(F.data == "botcreate_files_done", BotCreateStates.waiting_files)
async def bot_create_files_done(callback: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    names: list[str] = data.get("files_names", [])
    entry = data.get("zip_entry")
    if not entry:
        await callback.answer("⚠️ Asosiy kod fayli topilmadi, qaytadan boshlang.", show_alert=True)
        return
    servers = await db_get_available_servers_for_bot()
    if not servers:
        await callback.message.edit_text(
            "⚠️ Hozircha bo'sh server yo'q. Admin bilan bog'laning yoki keyinroq urinib ko'ring.",
            reply_markup=botcreate_cancel_kb(),
        )
        await callback.answer()
        return
    await state.set_state(BotCreateStates.waiting_zip)  # server tanlash/tasdiqlash bosqichlarini qayta ishlatamiz
    await callback.message.edit_text("✅ Fayllar qabul qilindi.\n\n🖥️ Serverni tanlang:", reply_markup=botcreate_server_kb(servers))
    await callback.answer()

@user_router.message(BotCreateStates.waiting_zip, F.document)
async def bot_create_receive_zip(message: Message, state: FSMContext):
    doc = message.document
    if not (doc.file_name or "").lower().endswith(".zip"):
        await message.answer("⚠️ Faqat .zip fayl qabul qilinadi. Qaytadan yuboring:", reply_markup=botcreate_cancel_kb())
        return
    if doc.file_size and doc.file_size > MAX_ZIP_SIZE_MB * 1024 * 1024:
        await message.answer(f"⚠️ Fayl juda katta (limit {MAX_ZIP_SIZE_MB}MB). Qaytadan yuboring:", reply_markup=botcreate_cancel_kb())
        return

    checking = await message.answer("⏳ Zip fayl tekshirilmoqda...")
    tmp_path = TMP_UPLOADS_DIR / f"{message.from_user.id}_{int(time.time())}.zip"
    try:
        file = await bot.get_file(doc.file_id)
        await bot.download_file(file.file_path, destination=tmp_path)
    except Exception as e:
        await checking.edit_text(f"⚠️ Faylni yuklab olishda xato: {e}\n\nQaytadan yuboring:", reply_markup=botcreate_cancel_kb())
        return

    ok, msg_or_entry, _names = _validate_zip_safety(tmp_path)
    if not ok:
        tmp_path.unlink(missing_ok=True)
        await checking.edit_text(f"⚠️ {msg_or_entry}\n\nTuzatib, qaytadan yuboring:", reply_markup=botcreate_cancel_kb())
        return

    await state.update_data(zip_tmp_path=str(tmp_path), zip_entry=msg_or_entry)
    servers = await db_get_available_servers_for_bot()
    if not servers:
        tmp_path.unlink(missing_ok=True)
        await checking.edit_text(
            "⚠️ Hozircha bo'sh server yo'q. Admin bilan bog'laning yoki keyinroq urinib ko'ring.",
            reply_markup=botcreate_cancel_kb(),
        )
        return
    await checking.edit_text("✅ Zip fayl tasdiqlandi.\n\n🖥️ Serverni tanlang:", reply_markup=botcreate_server_kb(servers))

@user_router.message(BotCreateStates.waiting_zip)
async def bot_create_zip_wrong_type(message: Message):
    await message.answer("⚠️ Iltimos, .zip faylni fayl (document) sifatida yuboring.", reply_markup=botcreate_cancel_kb())

@user_router.callback_query(F.data.startswith("botcreate_server:"), BotCreateStates.waiting_zip)
async def bot_create_choose_server(callback: CallbackQuery, state: FSMContext):
    server_id = int(callback.data.split(":")[1])
    server = await db_get_server(server_id)
    if not server or server["status"] != "available":
        await callback.answer("⚠️ Server band bo'lib qoldi, boshqasini tanlang.", show_alert=True)
        return
    await state.update_data(server_id=server_id)
    data = await state.get_data()
    text = (
        "📋 Ma'lumotlarni tekshiring:\n\n"
        f"📝 Nom: {data['name']}\n"
        f"👤 Username: @{data['username']}\n"
        f"🔑 Token: {mask_token(data['token'])}\n"
        f"🖥️ Server: {server['name']}\n\n"
        "⚠️ Bot yaratilgach, resurs sarfi limitdan oshsa balansingizdan "
        "proporsional yechiladi (hard limit yo'q). Davom etasizmi?"
    )
    await callback.message.edit_text(text, reply_markup=botcreate_confirm_kb())
    await callback.answer()

@user_router.callback_query(F.data == "botcreate_save", BotCreateStates.waiting_zip)
async def bot_create_save(callback: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    if "server_id" not in data:
        await callback.answer("⚠️ Avval serverni tanlang.", show_alert=True)
        return
    upload_mode = data.get("upload_mode", "zip")
    tmp_path = Path(data["zip_tmp_path"]) if upload_mode == "zip" else None
    files_dir = Path(data["files_dir"]) if upload_mode == "files" else None
    if upload_mode == "zip" and not tmp_path.exists():
        await callback.answer("⚠️ Zip fayl topilmadi, qaytadan boshlang.", show_alert=True)
        await state.clear()
        return
    if upload_mode == "files" and not files_dir.exists():
        await callback.answer("⚠️ Yuborilgan fayllar topilmadi, qaytadan boshlang.", show_alert=True)
        await state.clear()
        return

    user = await db_get_user_by_telegram_id(callback.from_user.id)
    token_encrypted = encrypt_token(data["token"])
    bot_id = await db_create_bot(
        owner_id=user["id"], name=data["name"], username=data["username"],
        token_encrypted=token_encrypted, server_id=data["server_id"],
    )

    try:
        code_dir = Path(f"managed_bots/bot_{bot_id}/user_code")
        if upload_mode == "zip":
            _safe_extract_zip(tmp_path, code_dir)
        else:
            code_dir.mkdir(parents=True, exist_ok=True)
            for f in files_dir.iterdir():
                if f.is_file():
                    shutil.copy2(f, code_dir / f.name)
        _finalize_bot_code(bot_id, data["zip_entry"], data["token"])
    except Exception as e:
        logger.exception(f"Bot kodi joylashtirishda xato: bot_id={bot_id}")
        if tmp_path:
            tmp_path.unlink(missing_ok=True)
        if files_dir:
            shutil.rmtree(files_dir, ignore_errors=True)
        await state.clear()
        await log_admin_action(actor=f"user:{callback.from_user.id}", action="bot_create",
                                result="FAILED", target=f"bot_{bot_id}", reason=str(e)[:300])
        await callback.message.edit_text(
            f"⚠️ Bot DB'da yaratildi, lekin kod joylashtirishda xato: {e}\n"
            f"🤖 Botlarim bo'limidan kodni qayta yuklashga urinib ko'ring yoki botni o'chiring.",
            reply_markup=back_kb("main"),
        )
        await callback.answer()
        return

    if tmp_path:
        tmp_path.unlink(missing_ok=True)
    if files_dir:
        shutil.rmtree(files_dir, ignore_errors=True)
    await state.clear()
    await log_admin_action(actor=f"user:{callback.from_user.id}", action="bot_create",
                            result="OK", target=f"bot_{bot_id}")
    new_bot = await db_get_bot(bot_id)
    await callback.message.edit_text(
        f"✅ Bot yaratildi: {new_bot['name']} (@{new_bot['username']})\n\n"
        f"Uni ishga tushirish uchun 🤖 Botlarim bo'limiga o'ting.",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🤖 Botlarim", callback_data="my_bots")],
            [InlineKeyboardButton(text="🔙 Bosh menyu", callback_data="nav:main")],
        ]),
    )
    await callback.answer()


# ===================== 🤖 BOTLARIM (foydalanuvchi, Supervisor bilan ulangan) =====================
MYBOTS_PAGE_SIZE = 5
MYBOT_STATUS_LABEL = {"running": "Ishlayapti", "stopped": "To'xtatilgan", "restarting": "Qayta ishga tushmoqda"}

def _my_bot_row_label(row: dict) -> str:
    emoji = STATUS_EMOJI.get(row["status"], "⚪")
    return f"{emoji} {row['name']}"

async def _render_my_bots_list(telegram_id: int, page: int) -> tuple[str, InlineKeyboardMarkup]:
    bots = await db_get_user_bots(telegram_id)
    total = len(bots)
    page_bots = bots[page * MYBOTS_PAGE_SIZE:(page + 1) * MYBOTS_PAGE_SIZE]
    kb_rows = [[InlineKeyboardButton(text=_my_bot_row_label(b), callback_data=f"mybot_view:{b['id']}:{page}")]
               for b in page_bots]
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️ Oldingi", callback_data=f"my_bots:{page - 1}"))
    if (page + 1) * MYBOTS_PAGE_SIZE < total:
        nav.append(InlineKeyboardButton(text="Keyingi ➡️", callback_data=f"my_bots:{page + 1}"))
    if nav:
        kb_rows.append(nav)
    kb_rows.append([InlineKeyboardButton(text="➕ Bot yaratish", callback_data="bot_create")])
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="nav:main")])
    text = "🤖 Mening botlarim" if total else "🤖 Sizda hali bot yo'q. Yangi bot yaratishingiz mumkin."
    return text, InlineKeyboardMarkup(inline_keyboard=kb_rows)

@user_router.callback_query(F.data == "my_bots")
async def show_my_bots(callback: CallbackQuery):
    text, kb = await _render_my_bots_list(callback.from_user.id, 0)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data.startswith("my_bots:"))
async def show_my_bots_page(callback: CallbackQuery):
    page = int(callback.data.split(":")[1])
    text, kb = await _render_my_bots_list(callback.from_user.id, page)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()


def _mybot_detail_text(row: dict, server_name: str | None) -> str:
    emoji = STATUS_EMOJI.get(row["status"], "⚪")
    status_label = MYBOT_STATUS_LABEL.get(row["status"], row["status"])
    return (f"{emoji} {row['name']}\n"
            f"Server: {server_name or '—'}\n"
            f"Holat: {status_label}")

def mybot_detail_kb(bot_id: int, page: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="⚙️ Boshqarish", callback_data=f"mybot_manage:{bot_id}:{page}")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"my_bots:{page}")],
    ])

@user_router.callback_query(F.data.startswith("mybot_view:"))
async def mybot_view(callback: CallbackQuery):
    _, bot_id_s, page_s = callback.data.split(":")
    bot_id, page = int(bot_id_s), int(page_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    server = await db_get_server(row["server_id"]) if row.get("server_id") else None
    await callback.message.edit_text(_mybot_detail_text(row, server["name"] if server else None),
                                      reply_markup=mybot_detail_kb(bot_id, page))
    await callback.answer()


def mybot_manage_kb(row: dict, page: int) -> InlineKeyboardMarkup:
    """▶️ Start / ⏹ Stop+🔄 Restart — holatga qarab bittasi ko'rsatiladi.
    Barcha amallar Supervisor bilan bir xil _start_bot_process()/
    _stop_bot_process() orqali ishlaydi — alohida logika yozilmaydi."""
    rows = []
    if row["status"] == "running":
        rows.append([InlineKeyboardButton(text="⏹ Stop", callback_data=f"mybot_stop_ask:{row['id']}:{page}")])
        rows.append([InlineKeyboardButton(text="🔄 Restart", callback_data=f"mybot_restart:{row['id']}:{page}")])
    else:
        rows.append([InlineKeyboardButton(text="▶️ Start", callback_data=f"mybot_start:{row['id']}:{page}")])
    rows.append([InlineKeyboardButton(text="📊 Statistika", callback_data=f"mybot_stats:{row['id']}:{page}")])
    rows.append([InlineKeyboardButton(text="🧠 AI sozlamalari", callback_data=f"mybot_ai:{row['id']}:{page}")])
    rows.append([InlineKeyboardButton(text="🗄️ Backup", callback_data=f"userbackup_bot:{row['id']}")])
    rows.append([InlineKeyboardButton(text="🗑️ O'chirish", callback_data=f"mybot_delete_ask:{row['id']}:{page}")])
    rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"mybot_view:{row['id']}:{page}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)

@user_router.callback_query(F.data.startswith("mybot_manage:"))
async def mybot_manage(callback: CallbackQuery):
    _, bot_id_s, page_s = callback.data.split(":")
    bot_id, page = int(bot_id_s), int(page_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    await callback.message.edit_text(f"⚙️ {row['name']} — boshqarish", reply_markup=mybot_manage_kb(row, page))
    await callback.answer()


# ---------- ▶️ Start ----------
@user_router.callback_query(F.data.startswith("mybot_start:"))
async def mybot_start(callback: CallbackQuery):
    _, bot_id_s, page_s = callback.data.split(":")
    bot_id, page = int(bot_id_s), int(page_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    if row["status"] == "running":
        await callback.answer("Bot allaqachon ishlayapti", show_alert=True)
        return
    await callback.answer("⏳ Ishga tushirilmoqda...")
    # _start_bot_process() muvaffaqiyatli bo'lsa desired_state='running'ga
    # o'tadi — shundan keyin bot crash bo'lsa Supervisor uni avtomatik tiklaydi.
    ok, msg = await _start_bot_process(row)
    await log_admin_action(actor=f"user:{callback.from_user.id}", action="bot_start",
                            result="OK" if ok else "FAILED", target=f"bot_{bot_id}",
                            reason="" if ok else msg)
    row = await db_get_bot(bot_id)
    text = "✅ Bot ishga tushirildi." if ok else f"⚠️ Ishga tushirishda xato: {msg}"
    await callback.message.edit_text(f"⚙️ {row['name']} — boshqarish\n\n{text}",
                                      reply_markup=mybot_manage_kb(row, page))


# ---------- ⏹ Stop (xavfli amal — tasdiqlash orqali) ----------
def mybot_stop_confirm_kb(bot_id: int, page: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="✅ Ha, to'xtatish", callback_data=f"mybot_stop_do:{bot_id}:{page}"),
        InlineKeyboardButton(text="❌ Bekor qilish", callback_data=f"mybot_manage:{bot_id}:{page}"),
    ]])

@user_router.callback_query(F.data.startswith("mybot_stop_ask:"))
async def mybot_stop_ask(callback: CallbackQuery):
    _, bot_id_s, page_s = callback.data.split(":")
    bot_id, page = int(bot_id_s), int(page_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    await callback.message.edit_text(
        f"⏹ '{row['name']}' botini to'xtatasizmi?\n\n"
        f"Bot to'xtaydi va siz qayta ▶️ Start bosmaguningizcha ishlamaydi — "
        f"Supervisor ataylab to'xtatilgan botni avtomatik qayta yoqmaydi.",
        reply_markup=mybot_stop_confirm_kb(bot_id, page),
    )
    await callback.answer()

@user_router.callback_query(F.data.startswith("mybot_stop_do:"))
async def mybot_stop_do(callback: CallbackQuery):
    _, bot_id_s, page_s = callback.data.split(":")
    bot_id, page = int(bot_id_s), int(page_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    await callback.answer("⏳ To'xtatilmoqda...")
    # reason="user_stop" — _stop_bot_process() ichida desired_state='stopped'ga
    # o'tadi, shu bilan Supervisor bu botni endi tegmaydi (crash-recovery ishlamaydi).
    await _stop_bot_process(row, reason="user_stop")
    await log_admin_action(actor=f"user:{callback.from_user.id}", action="bot_stop",
                            result="OK", target=f"bot_{bot_id}")
    row = await db_get_bot(bot_id)
    await callback.message.edit_text(f"⚙️ {row['name']} — boshqarish\n\n⏹ Bot to'xtatildi.",
                                      reply_markup=mybot_manage_kb(row, page))


# ---------- 🔄 Restart ----------
@user_router.callback_query(F.data.startswith("mybot_restart:"))
async def mybot_restart(callback: CallbackQuery):
    _, bot_id_s, page_s = callback.data.split(":")
    bot_id, page = int(bot_id_s), int(page_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    await callback.answer("⏳ Qayta ishga tushirilmoqda...")
    if row["status"] == "running":
        await _stop_bot_process(row, reason="user_restart")
        row = await db_get_bot(bot_id)
    ok, msg = await _start_bot_process(row)
    await log_admin_action(actor=f"user:{callback.from_user.id}", action="bot_restart",
                            result="OK" if ok else "FAILED", target=f"bot_{bot_id}",
                            reason="" if ok else msg)
    row = await db_get_bot(bot_id)
    text = "✅ Bot qayta ishga tushirildi." if ok else f"⚠️ Qayta ishga tushirishda xato: {msg}"
    await callback.message.edit_text(f"⚙️ {row['name']} — boshqarish\n\n{text}",
                                      reply_markup=mybot_manage_kb(row, page))


# ---------- 📊 Statistika ----------
def _format_uptime(started_at_str: str | None) -> str:
    if not started_at_str:
        return "—"
    try:
        started = datetime.fromisoformat(started_at_str)
    except ValueError:
        return "—"
    total_seconds = max(0, int((utcnow() - started).total_seconds()))
    days, rem = divmod(total_seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days} kun")
    if hours:
        parts.append(f"{hours} soat")
    parts.append(f"{minutes} daq")
    return " ".join(parts)

@user_router.callback_query(F.data.startswith("mybot_stats:"))
async def mybot_stats(callback: CallbackQuery):
    _, bot_id_s, page_s = callback.data.split(":")
    bot_id, page = int(bot_id_s), int(page_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    server = await db_get_server(row["server_id"]) if row.get("server_id") else None
    ram_usage = None
    if row["status"] == "running" and server:
        try:
            ram_usage = await _estimate_server_usage(row, server)
        except Exception:
            logger.exception(f"mybot_stats: RAM taxmin qilishda xato bot_id={bot_id}")
    emoji = STATUS_EMOJI.get(row["status"], "⚪")
    health_line = "🟢 Sog'lom" if row["health"] == "ok" else f"🔴 Muammo: {row['health_reason'] or '—'}"
    uptime = _format_uptime(row["started_at"]) if row["status"] == "running" else "—"
    text = (
        f"📊 {row['name']} — statistika\n\n"
        f"Holat: {emoji} {MYBOT_STATUS_LABEL.get(row['status'], row['status'])}\n"
        f"Sog'ligi: {health_line}\n"
        f"Uptime: {uptime}\n"
        f"Jami ishga tushirilgan: {row.get('total_restarts', 0)} marta\n"
        f"Ketma-ket crashlar: {row.get('consecutive_crash_count', 0)}\n"
        f"Oxirgi crash: {row.get('last_crash_at') or '—'}\n"
        f"Ajratilgan RAM: {row['allocated_ram_mb']} MB\n"
    )
    if ram_usage is not None:
        text += f"Joriy RAM (taxminiy): {int(ram_usage)} MB\n"
    await callback.message.edit_text(text, reply_markup=back_kb_to(f"mybot_manage:{bot_id}:{page}"))
    await callback.answer()


# ---------- 🧠 AI sozlamalari (botning to'liq AI konfiguratsiyasi) ----------
CHARACTER_PRESETS = [
    ("neytral", "😐 Neytral"), ("dostona", "😊 Do'stona"), ("rasmiy", "🎩 Rasmiy"),
    ("hazilkash", "😄 Hazilkash"), ("qisqa", "✂️ Qisqa va aniq"),
]
CHARACTER_LABELS = dict(CHARACTER_PRESETS)

def _bool_emoji(v) -> str:
    return "🟢" if v else "🔴"

class BotAISettingsStates(StatesGroup):
    waiting_system_prompt = State()

async def _mybot_ai_text(bot_row: dict, settings: dict) -> str:
    key_row = None
    if settings.get("user_api_key_id"):
        key_row = await db_get_user_api_key(settings["user_api_key_id"], bot_row["owner_id"])
    provider = provider_label(key_row["provider"]) if key_row else "—"
    if key_row:
        model = key_row["model_name"] or DEFAULT_MODELS.get(key_row["provider"], "—")
    else:
        model = "—"
    api_label = key_row["label"] if key_row else "tanlanmagan"
    prompt_preview = settings.get("system_prompt") or "—"
    if len(prompt_preview) > 150:
        prompt_preview = prompt_preview[:150] + "…"
    ai_on = bool(settings.get("ai_enabled", 1))
    ai_status_label = "Yoqilgan" if ai_on else "O'chirilgan"
    return (
        f"🧠 AI SOZLAMALARI — {bot_row['name']}\n\n"
        f"Holat: {_bool_emoji(ai_on)} {ai_status_label}\n"
        f"Provider: {provider}\n"
        f"Model: {model}\n"
        f"API: {api_label}\n\n"
        f"👁️ Monitoring: {_bool_emoji(settings.get('watching_enabled', 0))}\n"
        f"🚨 Xatolarni tahlil: {_bool_emoji(settings.get('task_analyze_errors', 1))}\n"
        f"💡 Tavsiya: {_bool_emoji(settings.get('task_recommend', 1))}\n\n"
        f"🎭 Xarakter: {CHARACTER_LABELS.get(settings.get('character'), settings.get('character') or '—')}\n"
        f"📝 System Prompt: {prompt_preview}"
    )

def mybot_ai_kb(bot_id: int, page: int, settings: dict) -> InlineKeyboardMarkup:
    ai_on = bool(settings.get("ai_enabled", 1))
    mon_on = bool(settings.get("watching_enabled", 0))
    task_err_on = bool(settings.get("task_analyze_errors", 1))
    task_rec_on = bool(settings.get("task_recommend", 1))
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=f"👁️ Monitoring: {_bool_emoji(mon_on)}", callback_data=f"mybotai_mon:{bot_id}:{page}")],
        [InlineKeyboardButton(text=f"🚨 Xatolarni tahlil: {_bool_emoji(task_err_on)}", callback_data=f"mybotai_task:{bot_id}:{page}:analyze")],
        [InlineKeyboardButton(text=f"💡 Tavsiya: {_bool_emoji(task_rec_on)}", callback_data=f"mybotai_task:{bot_id}:{page}:recommend")],
        [InlineKeyboardButton(text="🔑 API kalit", callback_data=f"mybotai_pickkey:{bot_id}:{page}")],
        [InlineKeyboardButton(text="🎭 Xarakter", callback_data=f"mybotai_char:{bot_id}:{page}")],
        [InlineKeyboardButton(text="📝 System Prompt", callback_data=f"mybotai_prompt:{bot_id}:{page}")],
        [InlineKeyboardButton(text="🧪 AI test", callback_data=f"mybotai_test:{bot_id}:{page}")],
        [InlineKeyboardButton(text=("🔌 AI o'chirish" if ai_on else "🔌 AI yoqish"), callback_data=f"mybotai_toggle:{bot_id}:{page}")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"mybot_manage:{bot_id}:{page}")],
    ])

@user_router.callback_query(F.data.startswith("mybot_ai:"))
async def mybot_ai_menu(callback: CallbackQuery):
    _, bot_id_s, page_s = callback.data.split(":")
    bot_id, page = int(bot_id_s), int(page_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    settings = await db_get_bot_settings(bot_id)
    await callback.message.edit_text(await _mybot_ai_text(row, settings), reply_markup=mybot_ai_kb(bot_id, page, settings))
    await callback.answer()

@user_router.callback_query(F.data.startswith("mybotai_toggle:"))
async def mybotai_toggle_ai(callback: CallbackQuery):
    _, bot_id_s, page_s = callback.data.split(":")
    bot_id, page = int(bot_id_s), int(page_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    settings = await db_get_bot_settings(bot_id)
    await db_update_bot_setting(bot_id, "ai_enabled", 0 if settings.get("ai_enabled", 1) else 1)
    settings = await db_get_bot_settings(bot_id)
    await callback.message.edit_text(await _mybot_ai_text(row, settings), reply_markup=mybot_ai_kb(bot_id, page, settings))
    await callback.answer()

@user_router.callback_query(F.data.startswith("mybotai_mon:"))
async def mybotai_toggle_monitoring(callback: CallbackQuery):
    _, bot_id_s, page_s = callback.data.split(":")
    bot_id, page = int(bot_id_s), int(page_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    settings = await db_get_bot_settings(bot_id)
    await db_update_bot_setting(bot_id, "watching_enabled", 0 if settings.get("watching_enabled", 0) else 1)
    settings = await db_get_bot_settings(bot_id)
    await callback.message.edit_text(await _mybot_ai_text(row, settings), reply_markup=mybot_ai_kb(bot_id, page, settings))
    await callback.answer()

@user_router.callback_query(F.data.startswith("mybotai_task:"))
async def mybotai_toggle_task(callback: CallbackQuery):
    _, bot_id_s, page_s, task = callback.data.split(":")
    bot_id, page = int(bot_id_s), int(page_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    field = "task_analyze_errors" if task == "analyze" else "task_recommend"
    settings = await db_get_bot_settings(bot_id)
    await db_update_bot_setting(bot_id, field, 0 if settings.get(field, 1) else 1)
    settings = await db_get_bot_settings(bot_id)
    await callback.message.edit_text(await _mybot_ai_text(row, settings), reply_markup=mybot_ai_kb(bot_id, page, settings))
    await callback.answer()

# ---- 🔑 API kalit — botning o'z saqlangan kalitlaridan birini tanlash ----
@user_router.callback_query(F.data.startswith("mybotai_pickkey:"))
async def mybotai_pickkey(callback: CallbackQuery):
    _, bot_id_s, page_s = callback.data.split(":")
    bot_id, page = int(bot_id_s), int(page_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    user = await db_get_user_by_telegram_id(callback.from_user.id)
    keys = await db_get_user_api_keys(user["id"])
    if not keys:
        await callback.answer("Sizda hali saqlangan API kalit yo'q. Avval \"🧠 Mening AI API'larim\"dan qo'shing.", show_alert=True)
        return
    kb_rows = [[InlineKeyboardButton(
        text=f"{USER_KEY_STATUS_EMOJI.get(k['status'], '⚪')} {provider_label(k['provider'])} — {k['label']}",
        callback_data=f"mybotai_pickkey_set:{bot_id}:{page}:{k['id']}",
    )] for k in keys]
    kb_rows.append([InlineKeyboardButton(text="❌ Hech qaysi (o'chirish)", callback_data=f"mybotai_pickkey_set:{bot_id}:{page}:0")])
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"mybot_ai:{bot_id}:{page}")])
    await callback.message.edit_text("🔑 Bu bot uchun qaysi API kalit ishlatilsin?", reply_markup=InlineKeyboardMarkup(inline_keyboard=kb_rows))
    await callback.answer()

@user_router.callback_query(F.data.startswith("mybotai_pickkey_set:"))
async def mybotai_pickkey_set(callback: CallbackQuery):
    _, bot_id_s, page_s, key_id_s = callback.data.split(":")
    bot_id, page, key_id = int(bot_id_s), int(page_s), int(key_id_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    if key_id:
        user = await db_get_user_by_telegram_id(callback.from_user.id)
        key_row = await db_get_user_api_key(key_id, user["id"])
        if not key_row:
            await callback.answer("❌ Kalit topilmadi", show_alert=True)
            return
    await db_update_bot_setting(bot_id, "user_api_key_id", key_id or None)
    settings = await db_get_bot_settings(bot_id)
    await callback.message.edit_text(await _mybot_ai_text(row, settings), reply_markup=mybot_ai_kb(bot_id, page, settings))
    await callback.answer("✅ Yangilandi")

# ---- 🎭 Xarakter ----
@user_router.callback_query(F.data.startswith("mybotai_char:"))
async def mybotai_char_menu(callback: CallbackQuery):
    _, bot_id_s, page_s = callback.data.split(":")
    bot_id, page = int(bot_id_s), int(page_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    kb_rows = [[InlineKeyboardButton(text=label, callback_data=f"mybotai_char_set:{bot_id}:{page}:{key}")]
               for key, label in CHARACTER_PRESETS]
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"mybot_ai:{bot_id}:{page}")])
    await callback.message.edit_text("🎭 Botning AI xarakterini tanlang:", reply_markup=InlineKeyboardMarkup(inline_keyboard=kb_rows))
    await callback.answer()

@user_router.callback_query(F.data.startswith("mybotai_char_set:"))
async def mybotai_char_set(callback: CallbackQuery):
    _, bot_id_s, page_s, preset = callback.data.split(":")
    bot_id, page = int(bot_id_s), int(page_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    await db_update_bot_setting(bot_id, "character", preset)
    settings = await db_get_bot_settings(bot_id)
    await callback.message.edit_text(await _mybot_ai_text(row, settings), reply_markup=mybot_ai_kb(bot_id, page, settings))
    await callback.answer("✅ Yangilandi")

# ---- 📝 System Prompt ----
@user_router.callback_query(F.data.startswith("mybotai_prompt:"))
async def mybotai_prompt_start(callback: CallbackQuery, state: FSMContext):
    _, bot_id_s, page_s = callback.data.split(":")
    bot_id, page = int(bot_id_s), int(page_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    await state.set_state(BotAISettingsStates.waiting_system_prompt)
    await state.update_data(bot_id=bot_id, page=page)
    await callback.message.edit_text(
        "📝 Yangi System Prompt matnini yuboring (tozalash uchun \"-\" yuboring):",
        reply_markup=back_kb_to(f"mybot_ai:{bot_id}:{page}"),
    )
    await callback.answer()

@user_router.message(BotAISettingsStates.waiting_system_prompt)
async def mybotai_prompt_receive(message: Message, state: FSMContext):
    data = await state.get_data()
    bot_id, page = data["bot_id"], data["page"]
    row = await _get_owned_bot(message.from_user.id, bot_id)
    await state.clear()
    if not row:
        await message.answer("❌ Ruxsat yo'q yoki bot topilmadi")
        return
    text = message.text.strip()
    await db_update_bot_setting(bot_id, "system_prompt", None if text == "-" else text)
    settings = await db_get_bot_settings(bot_id)
    await message.answer(await _mybot_ai_text(row, settings), reply_markup=mybot_ai_kb(bot_id, page, settings))

# ---- 🧪 AI test ----
@user_router.callback_query(F.data.startswith("mybotai_test:"))
async def mybotai_test(callback: CallbackQuery):
    _, bot_id_s, page_s = callback.data.split(":")
    bot_id, page = int(bot_id_s), int(page_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    await callback.answer("⏳ AI tekshirilmoqda...")
    result = await call_user_ai(bot_id, "Salom! Bu ulanishni tekshirish uchun test xabari. Bir qisqa jumla bilan javob ber.")
    if result.get("ok"):
        text = f"🧪 AI test — ✅ Muvaffaqiyatli\n\nProvider: {provider_label(result['provider'])}\nJavob: {result['text'][:300]}"
    else:
        text = f"🧪 AI test — ⚠️ Muvaffaqiyatsiz\n\nXato: {USER_KEY_ERROR_LABEL.get(result.get('error'), result.get('error') or 'nomalum')}"
    await callback.message.edit_text(text, reply_markup=back_kb_to(f"mybot_ai:{bot_id}:{page}"))


# ---------- 🗑️ O'chirish (xavfli amal — tasdiqlash + avtomatik backup) ----------
def mybot_delete_confirm_kb(bot_id: int, page: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="✅ Ha, o'chirish", callback_data=f"mybot_delete_do:{bot_id}:{page}"),
        InlineKeyboardButton(text="❌ Bekor qilish", callback_data=f"mybot_manage:{bot_id}:{page}"),
    ]])

@user_router.callback_query(F.data.startswith("mybot_delete_ask:"))
async def mybot_delete_ask(callback: CallbackQuery):
    _, bot_id_s, page_s = callback.data.split(":")
    bot_id, page = int(bot_id_s), int(page_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    await callback.message.edit_text(
        f"🗑️ '{row['name']}' (@{row['username']}) butunlay o'chirilsinmi?\n\n"
        f"⚠️ Bot to'xtatiladi va ma'lumotlar bazasidan o'chiriladi. O'chirishdan "
        f"oldin kod/.env/ma'lumotlar bazasi avtomatik zaxira (backup) qilinadi — "
        f"kerak bo'lsa \"🗄️ Backup\" bo'limidan tiklashingiz mumkin bo'ladi.",
        reply_markup=mybot_delete_confirm_kb(bot_id, page),
    )
    await callback.answer()

@user_router.callback_query(F.data.startswith("mybot_delete_do:"))
async def mybot_delete_do(callback: CallbackQuery):
    _, bot_id_s, page_s = callback.data.split(":")
    bot_id, page = int(bot_id_s), int(page_s)
    row = await _get_owned_bot(callback.from_user.id, bot_id)
    if not row:
        await callback.answer("❌ Ruxsat yo'q yoki bot topilmadi", show_alert=True)
        return
    await callback.answer("⏳ O'chirilmoqda...")
    if row["status"] == "running":
        await _stop_bot_process(row, reason="deleted")
    # Backup siyosati: o'chirishdan oldin avtomatik zaxira — muvaffaqiyatsiz
    # bo'lsa ham o'chirish davom etadi (foydalanuvchi buni to'xtata olmasligi
    # kerak, faqat loglanadi).
    try:
        await create_bot_backup(bot_id, callback.from_user.id)
    except Exception:
        logger.exception(f"O'chirishdan oldingi avtomatik backupda xato: bot_id={bot_id}")
    code_dir = Path(f"managed_bots/bot_{bot_id}")
    if code_dir.exists():
        shutil.rmtree(code_dir, ignore_errors=True)
    await db_delete_bot(bot_id)
    await log_admin_action(actor=f"user:{callback.from_user.id}", action="bot_delete",
                            result="OK", target=f"bot_{bot_id}", reason=row["name"])
    text, kb = await _render_my_bots_list(callback.from_user.id, 0)
    await callback.message.edit_text(f"✅ Bot o'chirildi (zaxira olindi).\n\n{text}", reply_markup=kb)


# ===================== 🧠 MENING AI API'LARIM (User AI CRUD, 28-bosqich) =====================
# Xavfsizlik: kalitning o'zi HECH QACHON to'liq holda ko'rsatilmaydi/loglanmaydi
# (mask_token orqali faqat oxirgi 4 belgi), DB'da faqat shifrlangan holda
# (encrypt_token/Fernet) saqlanadi. Providerlar PROVIDER_CATALOG orqali
# universal — Gemini bilan cheklanmaydi.
class UserAIKeyStates(StatesGroup):
    waiting_key = State()
    waiting_model = State()
    waiting_base_url = State()

def _uak_row_label(row: dict, rank: int) -> str:
    emoji = USER_KEY_STATUS_EMOJI.get(row["status"], "⚪")
    active_mark = "" if row.get("is_active", 1) else " (o'chirilgan)"
    suffix = " — asosiy" if rank == 0 else ""
    return f"{emoji} {provider_label(row['provider'])} — {row['label']}{suffix}{active_mark}"

async def _render_my_api_keys_list(telegram_id: int) -> tuple[str, InlineKeyboardMarkup]:
    user = await db_get_user_by_telegram_id(telegram_id)
    keys = await db_get_user_api_keys(user["id"]) if user else []
    kb_rows = [[InlineKeyboardButton(text=_uak_row_label(k, i), callback_data=f"uak_view:{k['id']}")]
               for i, k in enumerate(keys)]
    kb_rows.append([InlineKeyboardButton(text="➕ API qo'shish", callback_data="uak_add")])
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="nav:main")])
    text = "🧠 Mening AI API'larim" if keys else "🧠 Mening AI API'larim\n\nHali kalit qo'shilmagan."
    return text, InlineKeyboardMarkup(inline_keyboard=kb_rows)

@user_router.callback_query(F.data == "my_api_keys")
async def show_my_api_keys(callback: CallbackQuery):
    text, kb = await _render_my_api_keys_list(callback.from_user.id)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()


def _uak_view_text(row: dict) -> str:
    last_error = f"\nOxirgi xato: {USER_KEY_ERROR_LABEL.get(row['last_error'], row['last_error'])}" if row.get("last_error") else ""
    last_checked = f"\nOxirgi tekshiruv: {row['last_checked_at']}" if row.get("last_checked_at") else ""
    base_url = row.get("base_url") or PROVIDER_CATALOG.get(row["provider"], {}).get("base_url") or "—"
    active_label = "🟢 Faol" if row.get("is_active", 1) else "🔴 O'chirilgan (fallback zanjiridan chiqarilgan)"
    return (
        f"{USER_KEY_STATUS_EMOJI.get(row['status'], '⚪')} {row['label']}\n\n"
        f"Provider: {provider_label(row['provider'])}\n"
        f"Model: {row['model_name'] or DEFAULT_MODELS.get(row['provider'], '—')}\n"
        f"Base URL: {base_url}\n"
        f"Kalit: {mask_token(decrypt_token(row['api_key_encrypted']))}\n"
        f"Priority: {row['priority']}\n"
        f"Holat: {USER_KEY_STATUS_LABEL.get(row['status'], row['status'])}\n"
        f"Faollik: {active_label}"
        f"{last_error}{last_checked}"
    )

def uak_view_kb(row: dict) -> InlineKeyboardMarkup:
    active_toggle = "🔴 O'chirish (fallback'dan chiqarish)" if row.get("is_active", 1) else "🟢 Faollashtirish"
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✏️ Kalitni almashtirish", callback_data=f"uak_edit:{row['id']}:key")],
        [InlineKeyboardButton(text="🧩 Modelni tahrirlash", callback_data=f"uak_edit:{row['id']}:model")],
        [InlineKeyboardButton(text="🧪 Tekshirish", callback_data=f"uak_test:{row['id']}")],
        [InlineKeyboardButton(text=active_toggle, callback_data=f"uak_toggle:{row['id']}")],
        [InlineKeyboardButton(text="⬆️ Yuqoriga", callback_data=f"uak_moveup:{row['id']}"),
         InlineKeyboardButton(text="⬇️ Pastga", callback_data=f"uak_movedown:{row['id']}")],
        [InlineKeyboardButton(text="🗑️ O'chirish", callback_data=f"uak_delete_ask:{row['id']}")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="my_api_keys")],
    ])

@user_router.callback_query(F.data.startswith("uak_view:"))
async def uak_view(callback: CallbackQuery):
    key_id = int(callback.data.split(":")[1])
    user = await db_get_user_by_telegram_id(callback.from_user.id)
    row = await db_get_user_api_key(key_id, user["id"]) if user else None
    if not row:
        await callback.answer("❌ Kalit topilmadi", show_alert=True)
        return
    await callback.message.edit_text(_uak_view_text(row), reply_markup=uak_view_kb(row))
    await callback.answer()

# ---- 🟢/🔴 Faollashtirish (fallback zanjiriga kiritish/chiqarish) ----
@user_router.callback_query(F.data.startswith("uak_toggle:"))
async def uak_toggle(callback: CallbackQuery):
    key_id = int(callback.data.split(":")[1])
    user = await db_get_user_by_telegram_id(callback.from_user.id)
    row = await db_get_user_api_key(key_id, user["id"]) if user else None
    if not row:
        await callback.answer("❌ Kalit topilmadi", show_alert=True)
        return
    await db_update_user_api_key(key_id, user["id"], is_active=0 if row.get("is_active", 1) else 1)
    row = await db_get_user_api_key(key_id, user["id"])
    await callback.message.edit_text(_uak_view_text(row), reply_markup=uak_view_kb(row))
    await callback.answer()

# ---- ⬆️⬇️ Priority/fallback tartibini boshqarish ----
@user_router.callback_query(F.data.startswith("uak_moveup:"))
async def uak_moveup(callback: CallbackQuery):
    key_id = int(callback.data.split(":")[1])
    user = await db_get_user_by_telegram_id(callback.from_user.id)
    keys = await db_get_user_api_keys(user["id"]) if user else []
    idx = next((i for i, k in enumerate(keys) if k["id"] == key_id), None)
    if idx is None:
        await callback.answer("❌ Kalit topilmadi", show_alert=True)
        return
    if idx == 0:
        await callback.answer("Bu allaqachon eng yuqorida")
        return
    await db_swap_user_api_key_priority(user["id"], keys[idx]["id"], keys[idx - 1]["id"])
    row = await db_get_user_api_key(key_id, user["id"])
    await callback.message.edit_text(_uak_view_text(row), reply_markup=uak_view_kb(row))
    await callback.answer("✅ Ko'tarildi")

@user_router.callback_query(F.data.startswith("uak_movedown:"))
async def uak_movedown(callback: CallbackQuery):
    key_id = int(callback.data.split(":")[1])
    user = await db_get_user_by_telegram_id(callback.from_user.id)
    keys = await db_get_user_api_keys(user["id"]) if user else []
    idx = next((i for i, k in enumerate(keys) if k["id"] == key_id), None)
    if idx is None:
        await callback.answer("❌ Kalit topilmadi", show_alert=True)
        return
    if idx == len(keys) - 1:
        await callback.answer("Bu allaqachon eng pastda")
        return
    await db_swap_user_api_key_priority(user["id"], keys[idx]["id"], keys[idx + 1]["id"])
    row = await db_get_user_api_key(key_id, user["id"])
    await callback.message.edit_text(_uak_view_text(row), reply_markup=uak_view_kb(row))
    await callback.answer("✅ Tushirildi")

# ---- 🧪 Tekshirish ----
@user_router.callback_query(F.data.startswith("uak_test:"))
async def uak_test(callback: CallbackQuery):
    key_id = int(callback.data.split(":")[1])
    user = await db_get_user_by_telegram_id(callback.from_user.id)
    row = await db_get_user_api_key(key_id, user["id"]) if user else None
    if not row:
        await callback.answer("❌ Kalit topilmadi", show_alert=True)
        return
    await callback.answer("⏳ Tekshirilmoqda...")
    await test_user_api_key(key_id, user["id"])
    row = await db_get_user_api_key(key_id, user["id"])
    await callback.message.edit_text(_uak_view_text(row), reply_markup=uak_view_kb(row))

# ---- 🗑️ O'chirish ----
def uak_delete_confirm_kb(key_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="✅ Ha, o'chirish", callback_data=f"uak_delete_do:{key_id}"),
        InlineKeyboardButton(text="❌ Bekor qilish", callback_data=f"uak_view:{key_id}"),
    ]])

@user_router.callback_query(F.data.startswith("uak_delete_ask:"))
async def uak_delete_ask(callback: CallbackQuery):
    key_id = int(callback.data.split(":")[1])
    user = await db_get_user_by_telegram_id(callback.from_user.id)
    row = await db_get_user_api_key(key_id, user["id"]) if user else None
    if not row:
        await callback.answer("❌ Kalit topilmadi", show_alert=True)
        return
    await callback.message.edit_text(
        f"🗑️ '{row['label']}' ({provider_label(row['provider'])}) o'chirilsinmi?\n\n"
        f"⚠️ Bu kalitni ishlatayotgan botlar bo'lsa, ularning \"🔑 API kalit\" tanlovi "
        f"bekor qilinadi va Monitoring o'chiriladi.",
        reply_markup=uak_delete_confirm_kb(key_id),
    )
    await callback.answer()

@user_router.callback_query(F.data.startswith("uak_delete_do:"))
async def uak_delete_do(callback: CallbackQuery):
    key_id = int(callback.data.split(":")[1])
    user = await db_get_user_by_telegram_id(callback.from_user.id)
    row = await db_get_user_api_key(key_id, user["id"]) if user else None
    if not row:
        await callback.answer("❌ Kalit topilmadi", show_alert=True)
        return
    await db_delete_user_api_key(key_id, user["id"])
    text, kb = await _render_my_api_keys_list(callback.from_user.id)
    await callback.message.edit_text(f"✅ Kalit o'chirildi.\n\n{text}", reply_markup=kb)
    await callback.answer()


# ---- ➕ API qo'shish: Provider → API Key → Model → Base URL (kerak bo'lsa) → Test → Saqlash ----
def uak_provider_kb() -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(text=info["label"], callback_data=f"uak_add_prov:{key}")]
            for key, info in PROVIDER_CATALOG.items()]
    rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="my_api_keys")])
    return InlineKeyboardMarkup(inline_keyboard=rows)

@user_router.callback_query(F.data == "uak_add")
async def uak_add_start(callback: CallbackQuery, state: FSMContext):
    await state.clear()
    await callback.message.edit_text("🧠 Provider tanlang:", reply_markup=uak_provider_kb())
    await callback.answer()

@user_router.callback_query(F.data.startswith("uak_add_prov:"))
async def uak_add_provider_chosen(callback: CallbackQuery, state: FSMContext):
    provider = callback.data.split(":")[1]
    await state.update_data(mode="add", provider=provider)
    await state.set_state(UserAIKeyStates.waiting_key)
    await callback.message.edit_text(
        f"🔑 {provider_label(provider)} uchun API kalitni yuboring.\n\n"
        f"⚠️ Xabar avtomatik o'chiriladi — chatda ochiq qolmaydi.",
        reply_markup=back_kb_to("my_api_keys"),
    )
    await callback.answer()

@user_router.message(UserAIKeyStates.waiting_key)
async def uak_receive_key(message: Message, state: FSMContext):
    api_key = message.text.strip()
    await message.delete()  # kalit chatda ochiq turib qolmasin
    data = await state.get_data()
    user = await db_get_user_by_telegram_id(message.from_user.id)
    if data.get("mode") == "edit" and data.get("edit_field") == "key":
        key_id = data["edit_id"]
        await db_update_user_api_key(key_id, user["id"], api_key=api_key, status="unchecked", last_error=None)
        await state.clear()
        row = await db_get_user_api_key(key_id, user["id"])
        await message.answer("✅ Kalit yangilandi. Tekshirish tavsiya etiladi.", reply_markup=uak_view_kb(row))
        return
    await state.update_data(api_key=api_key)
    await state.set_state(UserAIKeyStates.waiting_model)
    provider = data["provider"]
    default_model = DEFAULT_MODELS.get(provider, "")
    await message.answer(
        f"🧩 Model nomini yuboring (masalan: {default_model or 'model-nomi'}).\n"
        f"Standart model uchun \"-\" yuboring.",
        reply_markup=back_kb_to("my_api_keys"),
    )

@user_router.message(UserAIKeyStates.waiting_model)
async def uak_receive_model(message: Message, state: FSMContext):
    model = message.text.strip()
    model = "" if model == "-" else model
    data = await state.get_data()
    user = await db_get_user_by_telegram_id(message.from_user.id)
    if data.get("mode") == "edit" and data.get("edit_field") == "model":
        key_id = data["edit_id"]
        row = await db_get_user_api_key(key_id, user["id"])
        await db_update_user_api_key(key_id, user["id"], model_name=model or DEFAULT_MODELS.get(row["provider"], ""))
        await state.clear()
        row = await db_get_user_api_key(key_id, user["id"])
        await message.answer("✅ Model yangilandi.", reply_markup=uak_view_kb(row))
        return
    provider = data["provider"]
    await state.update_data(model=model or DEFAULT_MODELS.get(provider, ""))
    if provider_needs_base_url(provider):
        await state.set_state(UserAIKeyStates.waiting_base_url)
        await message.answer(
            "🌐 Bu provider uchun Base URL MAJBURIY (masalan: https://api.myai.com/v1):",
            reply_markup=back_kb_to("my_api_keys"),
        )
        return
    await uak_run_test_and_confirm(message, state)

@user_router.message(UserAIKeyStates.waiting_base_url)
async def uak_receive_base_url(message: Message, state: FSMContext):
    base_url = message.text.strip()
    if not (base_url.startswith("http://") or base_url.startswith("https://")):
        await message.answer("⚠️ Base URL http:// yoki https:// bilan boshlanishi kerak. Qaytadan yuboring:")
        return
    data = await state.get_data()
    user = await db_get_user_by_telegram_id(message.from_user.id)
    if data.get("mode") == "edit" and data.get("edit_field") == "base_url":
        key_id = data["edit_id"]
        await db_update_user_api_key(key_id, user["id"], base_url=base_url)
        await state.clear()
        row = await db_get_user_api_key(key_id, user["id"])
        await message.answer("✅ Base URL yangilandi.", reply_markup=uak_view_kb(row))
        return
    await state.update_data(base_url=base_url)
    await uak_run_test_and_confirm(message, state)

async def uak_run_test_and_confirm(message: Message, state: FSMContext):
    """API kalitni saqlashdan OLDIN avtomatik tekshiradi va natijani ko'rsatadi
    (foydalanuvchi so'ragan aniq oqim: Test -> ✅ -> DB'ga shifrlangan saqlash)."""
    data = await state.get_data()
    status = await test_provider_connection(data["provider"], data["model"], data["api_key"],
                                             base_url=data.get("base_url"))
    await state.update_data(test_status=status)
    status_line = "✅ Muvaffaqiyatli ulandi" if status == "active" else f"⚠️ {USER_KEY_STATUS_LABEL.get(status, status)}"
    base_url_line = f"\nBase URL: {data['base_url']}" if data.get("base_url") else ""
    text = (
        f"🧪 Tekshiruv natijasi: {status_line}\n\n"
        f"Provider: {provider_label(data['provider'])}\n"
        f"Kalit: {mask_token(data['api_key'])}\n"
        f"Model: {data['model']}"
        f"{base_url_line}\n\n"
        f"Saqlansinmi?"
    )
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="💾 Saqlash", callback_data="uak_save")],
        [InlineKeyboardButton(text="❌ Bekor qilish", callback_data="my_api_keys")],
    ])
    await message.answer(text, reply_markup=kb)

@user_router.callback_query(F.data == "uak_save")
async def uak_save(callback: CallbackQuery, state: FSMContext):
    data = await state.get_data()
    user = await db_get_user_by_telegram_id(callback.from_user.id)
    label = f"{provider_label(data['provider'])} #{len(await db_get_user_api_keys(user['id'])) + 1}"
    key_id = await db_create_user_api_key(
        user_id=user["id"], provider=data["provider"], label=label, api_key=data["api_key"],
        model_name=data["model"], base_url=data.get("base_url"),
    )
    await db_update_user_api_key(key_id, user["id"], status=data.get("test_status", "unchecked"),
                                  last_checked_at=utcnow().isoformat(sep=" ", timespec="seconds"))
    await state.clear()
    row = await db_get_user_api_key(key_id, user["id"])
    await callback.message.edit_text(f"✅ '{label}' qo'shildi.\n\n{_uak_view_text(row)}", reply_markup=uak_view_kb(row))
    await callback.answer()

# ---- ✏️ Tahrirlash — kalit/model/base_url ----
@user_router.callback_query(F.data.startswith("uak_edit:"))
async def uak_edit_start(callback: CallbackQuery, state: FSMContext):
    _, key_id_s, field = callback.data.split(":")
    key_id = int(key_id_s)
    user = await db_get_user_by_telegram_id(callback.from_user.id)
    row = await db_get_user_api_key(key_id, user["id"]) if user else None
    if not row:
        await callback.answer("❌ Kalit topilmadi", show_alert=True)
        return
    await state.clear()
    await state.update_data(mode="edit", edit_field=field, edit_id=key_id)
    if field == "key":
        await state.set_state(UserAIKeyStates.waiting_key)
        prompt = "🔑 Yangi API kalitni yuboring (xabar avtomatik o'chiriladi):"
    elif field == "model":
        await state.set_state(UserAIKeyStates.waiting_model)
        prompt = "🧩 Yangi model nomini yuboring (standart uchun \"-\"):"
    else:
        await state.set_state(UserAIKeyStates.waiting_base_url)
        prompt = "🌐 Yangi Base URL yuboring:"
    await callback.message.edit_text(prompt, reply_markup=back_kb_to(f"uak_view:{key_id}"))
    await callback.answer()


# ===================== 👑 ADMIN PANEL: 🤖 BOTLAR (platforma bo'yicha) =====================
class AdminBotsStates(StatesGroup):
    waiting_search = State()
    waiting_force_stop_reason = State()

def admin_bots_filter_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔍 Qidirish", callback_data="adminbots_search")],
        [InlineKeyboardButton(text="🟢 Ishlayotganlar", callback_data="adminbots_list:f:running:0")],
        [InlineKeyboardButton(text="🔴 To'xtaganlar", callback_data="adminbots_list:f:stopped:0")],
        [InlineKeyboardButton(text="⚠️ Xatolikdagilar", callback_data="adminbots_list:f:error:0")],
        [InlineKeyboardButton(text="💰 Balansi tugaganlar", callback_data="adminbots_list:f:no_balance:0")],
        [InlineKeyboardButton(text="📋 Barchasi", callback_data="adminbots_list:f:all:0")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="admin_panel")],
    ])

def _admin_bot_row_label(row: dict) -> str:
    emoji = STATUS_EMOJI.get(row["status"], "⚪")
    owner = row["owner_username"] or str(row["owner_telegram_id"])
    return f"{emoji} {row['name']} — @{owner}"

def admin_bots_list_kb(rows: list[dict], mode: str, param: str, page: int, total: int) -> InlineKeyboardMarkup:
    kb_rows = [[InlineKeyboardButton(text=_admin_bot_row_label(r),
                                      callback_data=f"adminbots_view:{r['id']}:{mode}:{param}:{page}")] for r in rows]
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️ Oldingi", callback_data=f"adminbots_list:{mode}:{param}:{page - 1}"))
    if (page + 1) * ADMIN_BOTS_PAGE_SIZE < total:
        nav.append(InlineKeyboardButton(text="Keyingi ➡️", callback_data=f"adminbots_list:{mode}:{param}:{page + 1}"))
    if nav:
        kb_rows.append(nav)
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="admin_bots")])
    return InlineKeyboardMarkup(inline_keyboard=kb_rows)

def admin_bot_detail_kb(bot_id: int, mode: str, param: str, page: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔄 Restart", callback_data=f"adminbots_restart:{bot_id}:{mode}:{param}:{page}")],
        [InlineKeyboardButton(text="⛔ Majburiy to'xtatish", callback_data=f"adminbots_forcestop:{bot_id}:{mode}:{param}:{page}")],
        [InlineKeyboardButton(text="🖥 Serverni almashtirish", callback_data=f"adminbots_switchsrv:{bot_id}:{mode}:{param}:{page}")],
        [InlineKeyboardButton(text="📊 Statistika", callback_data=f"adminbots_stats:{bot_id}:{mode}:{param}:{page}")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"adminbots_list:{mode}:{param}:{page}")],
    ])

def _admin_bot_detail_text(row: dict, settings: dict) -> str:
    status_emoji = STATUS_EMOJI.get(row["status"], "⚪")
    health_line = "🟢 Sog'lom" if row["health"] == "ok" else f"🔴 Muammo: {row['health_reason'] or '—'}"
    ai_line = "👁 Kuzatilmoqda" if settings.get("watching_enabled") else "😴 Kuzatilmayapti"
    owner = row["owner_username"] or str(row["owner_telegram_id"])
    return (
        f"🤖 {row['name']} (@{row['username']})\n\n"
        f"Egasi: @{owner} (ID: {row['owner_telegram_id']})\n"
        f"Server: {row['server_name'] or '—'}\n"
        f"Holat: {status_emoji} {row['status']}\n"
        f"Sog'ligi: {health_line}\n"
        f"Egasining balansi: {fmt_som(row['owner_balance'])} so'm\n"
        f"AI holati: {ai_line}\n"
        f"Yaratilgan: {row['created_at']}"
    )

async def _render_admin_bots_list(mode: str, param: str, page: int) -> tuple[str, InlineKeyboardMarkup]:
    if mode == "f":
        rows, total = await db_admin_bots_query(param, None, page)
        title_map = {"all": "📋 Barchasi", "running": "🟢 Ishlayotganlar", "stopped": "🔴 To'xtaganlar",
                     "error": "⚠️ Xatolikdagilar", "no_balance": "💰 Balansi tugaganlar"}
        header = title_map.get(param, param)
    else:
        rows, total = await db_admin_bots_query("all", param, page)
        header = f"🔍 \"{param}\" bo'yicha natijalar"
    if not rows:
        text = f"{header}\n\nHech narsa topilmadi." if total == 0 else f"{header}\n\nBoshqa sahifa yo'q."
    else:
        text = f"{header} ({total} ta):"
    return text, admin_bots_list_kb(rows, mode, param, page, total)

# --- Kirish nuqtasi (Admin Panel -> 🤖 Botlar) ---
@user_router.callback_query(F.data == "admin_bots")
async def show_admin_bots_menu(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    await callback.message.edit_text("🤖 BOTLAR — filtr tanlang:", reply_markup=admin_bots_filter_kb())
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminbots_list:"))
async def show_admin_bots_list(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, mode, param, page = callback.data.split(":")
    text, kb = await _render_admin_bots_list(mode, param, int(page))
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

# --- 🔍 Qidirish ---
@user_router.callback_query(F.data == "adminbots_search")
async def admin_bots_search_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.set_state(AdminBotsStates.waiting_search)
    await callback.message.edit_text(
        "🔍 Bot nomi, username yoki egasining @username/ID sini yuboring:",
        reply_markup=back_kb_to("admin_bots"),
    )
    await callback.answer()

@user_router.message(AdminBotsStates.waiting_search)
async def admin_bots_search_receive(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        return
    try:
        await message.delete()
    except Exception:
        pass
    query = message.text.strip().replace(":", "")[:20]
    await state.clear()
    text, kb = await _render_admin_bots_list("s", query, 0)
    await message.answer(text, reply_markup=kb)

# --- Bitta bot kartochkasi ---
@user_router.callback_query(F.data.startswith("adminbots_view:"))
async def admin_bots_view(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, bot_id, mode, param, page = callback.data.split(":")
    bot_id = int(bot_id)
    row = await db_admin_get_bot_full(bot_id)
    if not row:
        await callback.answer("Bot topilmadi", show_alert=True)
        return
    settings = await db_get_bot_settings(bot_id)
    await callback.message.edit_text(_admin_bot_detail_text(row, settings),
                                      reply_markup=admin_bot_detail_kb(bot_id, mode, param, int(page)))
    await callback.answer()

# --- 🔄 Restart ---
@user_router.callback_query(F.data.startswith("adminbots_restart:"))
async def admin_bots_restart(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, bot_id, mode, param, page = callback.data.split(":")
    bot_id, page = int(bot_id), int(page)
    row = await db_get_bot(bot_id)
    if not row:
        await callback.answer("Bot topilmadi", show_alert=True)
        return
    server = await db_get_server(row["server_id"]) if row["server_id"] else None
    pm = get_process_manager(server)
    try:
        if row["status"] == "running":
            await pm.stop(row, server)
        pid = await pm.start(row, server)
        await db_update_bot_process(bot_id, status="running", pid=pid,
                                     started_at=utcnow().isoformat(), stopped_at=None)
        await db_set_stop_reason(bot_id, None)
        result_text = "✅ Bot qayta ishga tushirildi."
    except Exception as e:
        result_text = f"❌ Restart xato: {e}"
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="admin_restart_bot",
                            result=result_text, target=f"bot_{bot_id}")
    full = await db_admin_get_bot_full(bot_id)
    settings = await db_get_bot_settings(bot_id)
    await callback.message.edit_text(f"{result_text}\n\n{_admin_bot_detail_text(full, settings)}",
                                      reply_markup=admin_bot_detail_kb(bot_id, mode, param, page))
    await callback.answer()

# --- ⛔ Majburiy to'xtatish (sabab majburiy, audit logga alohida yoziladi) ---
@user_router.callback_query(F.data.startswith("adminbots_forcestop:"))
async def admin_bots_forcestop_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    _, bot_id, mode, param, page = callback.data.split(":")
    await state.update_data(force_stop_bot_id=int(bot_id), ctx_mode=mode, ctx_param=param, ctx_page=int(page))
    await state.set_state(AdminBotsStates.waiting_force_stop_reason)
    await callback.message.edit_text(
        "⛔ Majburiy to'xtatish sababini yozing (majburiy):",
        reply_markup=back_kb_to(f"adminbots_view:{bot_id}:{mode}:{param}:{page}"),
    )
    await callback.answer()

@user_router.message(AdminBotsStates.waiting_force_stop_reason)
async def admin_bots_forcestop_receive(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        return
    try:
        await message.delete()
    except Exception:
        pass
    reason = message.text.strip()
    data = await state.get_data()
    bot_id, mode, param, page = data["force_stop_bot_id"], data["ctx_mode"], data["ctx_param"], data["ctx_page"]
    await state.clear()
    row = await db_get_bot(bot_id)
    if not row:
        await message.answer("Bot topilmadi")
        return
    server = await db_get_server(row["server_id"]) if row["server_id"] else None
    pm = get_process_manager(server)
    try:
        await pm.stop(row, server)
    except Exception:
        pass
    await db_update_bot_process(bot_id, status="stopped", pid=None, stopped_at=utcnow().isoformat())
    await db_set_stop_reason(bot_id, f"admin_force_stop: {reason}")
    # Majburiy to'xtatish oddiy to'xtatishdan alohida, sababi bilan audit logga yoziladi
    await log_admin_action(actor=f"admin:{message.from_user.id}", action="admin_force_stop",
                            result="OK", reason=reason, target=f"bot_{bot_id}")
    full = await db_admin_get_bot_full(bot_id)
    settings = await db_get_bot_settings(bot_id)
    await message.answer(f"⛔ Majburiy to'xtatildi.\n\n{_admin_bot_detail_text(full, settings)}",
                          reply_markup=admin_bot_detail_kb(bot_id, mode, param, page))

# --- 🖥 Serverni almashtirish ---
@user_router.callback_query(F.data.startswith("adminbots_switchsrv:"))
async def admin_bots_switch_server_menu(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, bot_id, mode, param, page = callback.data.split(":")
    bot_id, page = int(bot_id), int(page)
    row = await db_get_bot(bot_id)
    if not row:
        await callback.answer("Bot topilmadi", show_alert=True)
        return
    servers = [s for s in await db_get_available_servers_for_bot() if s["id"] != row["server_id"]]
    if not servers:
        await callback.answer("Bo'sh joyli boshqa server yo'q", show_alert=True)
        return
    kb_rows = [[InlineKeyboardButton(
        text=f"{s['name']} ({s['ram_gb']}GB)",
        callback_data=f"adminbots_switchsrv_do:{bot_id}:{s['id']}:{mode}:{param}:{page}",
    )] for s in servers]
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"adminbots_view:{bot_id}:{mode}:{param}:{page}")])
    await callback.message.edit_text("🖥 Yangi serverni tanlang:", reply_markup=InlineKeyboardMarkup(inline_keyboard=kb_rows))
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminbots_switchsrv_do:"))
async def admin_bots_switch_server_do(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, bot_id, new_server_id, mode, param, page = callback.data.split(":")
    bot_id, new_server_id, page = int(bot_id), int(new_server_id), int(page)
    row = await db_get_bot(bot_id)
    if row and row["status"] == "running":
        old_server = await db_get_server(row["server_id"]) if row["server_id"] else None
        pm = get_process_manager(old_server)
        try:
            await pm.stop(row, old_server)
        except Exception:
            pass
    await db_admin_switch_bot_server(bot_id, new_server_id)
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="admin_switch_server",
                            result="OK", target=f"bot_{bot_id}", reason=f"-> server_{new_server_id}")
    full = await db_admin_get_bot_full(bot_id)
    settings = await db_get_bot_settings(bot_id)
    await callback.message.edit_text(
        f"✅ Server almashtirildi. Bot to'xtatilgan holatda — kerak bo'lsa qo'lda qayta ishga tushiring.\n\n"
        f"{_admin_bot_detail_text(full, settings)}",
        reply_markup=admin_bot_detail_kb(bot_id, mode, param, page),
    )
    await callback.answer()

# --- 📊 Statistika ---
@user_router.callback_query(F.data.startswith("adminbots_stats:"))
async def admin_bots_stats(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, bot_id, mode, param, page = callback.data.split(":")
    bot_id, page = int(bot_id), int(page)
    row = await db_get_bot(bot_id)
    if not row:
        await callback.answer("Bot topilmadi", show_alert=True)
        return
    server = await db_get_server(row["server_id"]) if row["server_id"] else None
    pm = get_process_manager(server)
    try:
        log_tail = await pm.tail_log(row, server, lines=10)
    except Exception:
        log_tail = "Log olinmadi."
    text = (
        f"📊 {row['name']} statistikasi\n\n"
        f"Ajratilgan RAM: {row['allocated_ram_mb']} MB\n"
        f"Overage narxi: {row['overage_rate_per_gb']:,} so'm/GB\n"
        f"Boshlangan: {row['started_at'] or '—'}\n"
        f"To'xtagan: {row['stopped_at'] or '—'}\n"
        f"To'xtash sababi: {row['stopped_reason'] or '—'}\n\n"
        f"📄 Oxirgi loglar:\n{log_tail[-800:]}"
    )
    await callback.message.edit_text(text, reply_markup=admin_bot_detail_kb(bot_id, mode, param, page))
    await callback.answer()


# ===================== 👑 ADMIN PANEL: 👥 FOYDALANUVCHILAR =====================
class AdminUsersStates(StatesGroup):
    waiting_search = State()
    waiting_balance_amount = State()

ADMIN_USERS_PAGE_SIZE = 5

def admin_users_filter_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔍 Qidirish", callback_data="adminusers_search")],
        [InlineKeyboardButton(text="📋 Barchasi", callback_data="adminusers_list:f:all:0")],
        [InlineKeyboardButton(text="🟢 Faol", callback_data="adminusers_list:f:active:0")],
        [InlineKeyboardButton(text="🔴 Bloklangan", callback_data="adminusers_list:f:blocked:0")],
        [InlineKeyboardButton(text="👑 Adminlar", callback_data="adminusers_list:f:admins:0")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="admin_panel")],
    ])

def _admin_user_row_label(row: dict) -> str:
    status = "👑" if row["is_admin"] else ("🟢" if row["is_active"] else "🔴")
    name = f"@{row['username']}" if row["username"] else (row["first_name"] or str(row["telegram_id"]))
    return f"{status} {name} — {fmt_som(row['balance'])} so'm"

def admin_users_list_kb(rows: list[dict], mode: str, param: str, page: int, total: int) -> InlineKeyboardMarkup:
    kb_rows = [[InlineKeyboardButton(text=_admin_user_row_label(r),
                                      callback_data=f"adminusers_view:{r['id']}:{mode}:{param}:{page}")] for r in rows]
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️ Oldingi", callback_data=f"adminusers_list:{mode}:{param}:{page - 1}"))
    if (page + 1) * ADMIN_USERS_PAGE_SIZE < total:
        nav.append(InlineKeyboardButton(text="Keyingi ➡️", callback_data=f"adminusers_list:{mode}:{param}:{page + 1}"))
    if nav:
        kb_rows.append(nav)
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="admin_users")])
    return InlineKeyboardMarkup(inline_keyboard=kb_rows)

async def _render_admin_users_list(mode: str, param: str, page: int) -> tuple[str, InlineKeyboardMarkup]:
    if mode == "f":
        rows, total = await db_search_users(None, param, page, ADMIN_USERS_PAGE_SIZE)
        title_map = {"all": "📋 Barchasi", "active": "🟢 Faol", "blocked": "🔴 Bloklangan", "admins": "👑 Adminlar"}
        header = title_map.get(param, param)
    else:
        rows, total = await db_search_users(param, "all", page, ADMIN_USERS_PAGE_SIZE)
        header = f"🔍 \"{param}\" bo'yicha natijalar"
    if not rows:
        text = f"{header}\n\nHech narsa topilmadi." if total == 0 else f"{header}\n\nBoshqa sahifa yo'q."
    else:
        text = f"{header} ({total} ta):"
    return text, admin_users_list_kb(rows, mode, param, page, total)

# --- Kirish nuqtasi (Admin Panel -> 👥 Foydalanuvchilar) ---
@user_router.callback_query(F.data == "admin_users")
async def show_admin_users_menu(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    await callback.message.edit_text("👥 FOYDALANUVCHILAR — filtr tanlang:", reply_markup=admin_users_filter_kb())
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminusers_list:"))
async def show_admin_users_list(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, mode, param, page = callback.data.split(":")
    text, kb = await _render_admin_users_list(mode, param, int(page))
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

# --- 🔍 Qidirish ---
@user_router.callback_query(F.data == "adminusers_search")
async def admin_users_search_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.set_state(AdminUsersStates.waiting_search)
    await callback.message.edit_text(
        "🔍 Username, ism yoki Telegram ID yuboring:",
        reply_markup=back_kb_to("admin_users"),
    )
    await callback.answer()

@user_router.message(AdminUsersStates.waiting_search)
async def admin_users_search_receive(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        return
    try:
        await message.delete()
    except Exception:
        pass
    query = message.text.strip().replace(":", "")[:32]
    await state.clear()
    text, kb = await _render_admin_users_list("s", query, 0)
    await message.answer(text, reply_markup=kb)

# --- Bitta foydalanuvchi kartochkasi ---
async def _admin_user_detail_text(row: dict) -> str:
    bots = await db_get_bots_by_owner_id(row["id"])
    status = "👑 Admin" if row["is_admin"] else ("🟢 Faol" if row["is_active"] else "🔴 Bloklangan")
    return (
        f"👤 {row['first_name'] or '—'} (@{row['username'] or '—'})\n\n"
        f"Telegram ID: {row['telegram_id']}\n"
        f"Balans: {fmt_som(row['balance'])} so'm\n"
        f"Botlar soni: {len(bots)}\n"
        f"Holati: {status}\n"
        f"Ro'yxatdan o'tgan: {row['created_at']}"
    )

def admin_user_detail_kb(user_id: int, mode: str, param: str, page: int, row: dict) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text="💰 Balansni boshqarish", callback_data=f"adminusers_balance:{user_id}:{mode}:{param}:{page}")],
        [InlineKeyboardButton(text="🤖 Botlarini ko'rish", callback_data=f"adminusers_bots:{user_id}:{mode}:{param}:{page}")],
    ]
    if row["telegram_id"] != SUPER_ADMIN_TELEGRAM_ID:
        block_label = "✅ Blokdan chiqarish" if not row["is_active"] else "🚫 Bloklash"
        rows.append([InlineKeyboardButton(text=block_label, callback_data=f"adminusers_toggleblock:{user_id}:{mode}:{param}:{page}")])
    rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"adminusers_list:{mode}:{param}:{page}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)

@user_router.callback_query(F.data.startswith("adminusers_view:"))
async def admin_users_view(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, user_id, mode, param, page = callback.data.split(":")
    user_id, page = int(user_id), int(page)
    row = await db_get_user_by_id(user_id)
    if not row:
        await callback.answer("Foydalanuvchi topilmadi", show_alert=True)
        return
    await callback.message.edit_text(await _admin_user_detail_text(row),
                                      reply_markup=admin_user_detail_kb(user_id, mode, param, page, row))
    await callback.answer()

# --- 🤖 Botlarini ko'rish ---
@user_router.callback_query(F.data.startswith("adminusers_bots:"))
async def admin_users_view_bots(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, user_id, mode, param, page = callback.data.split(":")
    user_id, page = int(user_id), int(page)
    bots = await db_get_bots_by_owner_id(user_id)
    if not bots:
        text = "🤖 Bu foydalanuvchining botlari yo'q."
    else:
        lines = [f"{STATUS_EMOJI.get(b['status'], '⚪')} {b['name']} (@{b['username']})" for b in bots]
        text = "🤖 Botlari:\n\n" + "\n".join(lines)
    await callback.message.edit_text(text, reply_markup=back_kb_to(f"adminusers_view:{user_id}:{mode}:{param}:{page}"))
    await callback.answer()

# --- 💰 Balansni boshqarish ---
@user_router.callback_query(F.data.startswith("adminusers_balance:"))
async def admin_users_balance_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    _, user_id, mode, param, page = callback.data.split(":")
    await state.update_data(ab_user_id=int(user_id), ab_mode=mode, ab_param=param, ab_page=int(page))
    await state.set_state(AdminUsersStates.waiting_balance_amount)
    await callback.message.edit_text(
        "💰 Balansni o'zgartirish\n\n"
        "Summani yuboring (masalan: +50000 qo'shish uchun, -20000 ayirish uchun; kasr ham mumkin, masalan +50000.50):",
        reply_markup=back_kb_to(f"adminusers_view:{user_id}:{mode}:{param}:{page}"),
    )
    await callback.answer()

@user_router.message(AdminUsersStates.waiting_balance_amount)
async def admin_users_balance_receive(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        return
    try:
        await message.delete()
    except Exception:
        pass
    data = await state.get_data()
    user_id, mode, param, page = data["ab_user_id"], data["ab_mode"], data["ab_param"], data["ab_page"]
    raw = message.text.strip()
    sign = -1 if raw.startswith("-") else 1
    magnitude_text = raw[1:] if raw and raw[0] in "+-" else raw
    tiyin = parse_exact_som_amount(magnitude_text)
    if tiyin is None:
        await message.answer("❌ Noto'g'ri summa. Masalan: +50000 yoki -20000 (2 xonadan ortiq kasr bo'lmasin). Qaytadan yuboring:")
        return
    amount = sign * tiyin
    await state.clear()
    await db_adjust_user_balance(user_id, amount, "admin_manual_adjustment", message.from_user.id)
    row = await db_get_user_by_id(user_id)
    sign_emoji = "➕" if amount > 0 else "➖"
    await message.answer(
        f"✅ Balans o'zgartirildi ({sign_emoji} {fmt_som(tiyin)} so'm).\n\n{await _admin_user_detail_text(row)}",
        reply_markup=admin_user_detail_kb(user_id, mode, param, page, row),
    )

# --- 🚫 Bloklash / ✅ Blokdan chiqarish ---
@user_router.callback_query(F.data.startswith("adminusers_toggleblock:"))
async def admin_users_toggle_block(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, user_id, mode, param, page = callback.data.split(":")
    user_id, page = int(user_id), int(page)
    row = await db_get_user_by_id(user_id)
    if not row:
        await callback.answer("Foydalanuvchi topilmadi", show_alert=True)
        return
    if row["telegram_id"] == SUPER_ADMIN_TELEGRAM_ID:
        await callback.answer("❌ Asosiy adminni bloklab bo'lmaydi", show_alert=True)
        return
    # 🔐 critical_action_confirmation_enabled: bloklash (unblock emas) — bu
    # yerda BLOKLASH yo'nalishi "muhim amal" deb hisoblanadi, chunki
    # foydalanuvchining kirishini cheklaydi. Yoqilgan bo'lsa qo'shimcha
    # tasdiq so'raladi.
    going_to_block = bool(row["is_active"])
    if going_to_block:
        settings = await db_get_all_settings()
        if settings.get("critical_action_confirmation_enabled", True):
            kb = InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🚫 Ha, bloklash",
                                       callback_data=f"adminusers_toggleblock_do:{user_id}:{mode}:{param}:{page}")],
                [InlineKeyboardButton(text="❌ Bekor qilish",
                                       callback_data=f"adminusers_view:{user_id}:{mode}:{param}:{page}")],
            ])
            name = f"@{row['username']}" if row["username"] else (row["first_name"] or str(row["telegram_id"]))
            await callback.message.edit_text(
                f"⚠️ Muhim amal tasdig'i yoqilgan (Tizim sozlamalari -> Xavfsizlik).\n\n"
                f"{name}ni bloklashni tasdiqlaysizmi?",
                reply_markup=kb)
            await callback.answer()
            return
    await _apply_user_block_toggle(callback, user_id, mode, param, page)

@user_router.callback_query(F.data.startswith("adminusers_toggleblock_do:"))
async def admin_users_toggle_block_confirmed(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, user_id, mode, param, page = callback.data.split(":")
    await _apply_user_block_toggle(callback, int(user_id), mode, param, int(page))

async def _apply_user_block_toggle(callback: CallbackQuery, user_id: int, mode: str, param: str, page: int):
    row = await db_get_user_by_id(user_id)
    if not row:
        await callback.answer("Foydalanuvchi topilmadi", show_alert=True)
        return
    new_active = not bool(row["is_active"])
    await db_set_user_active(user_id, new_active)
    await log_admin_action(actor=f"admin:{callback.from_user.id}",
                            action="unblock_user" if new_active else "block_user",
                            result="OK", target=f"user_{user_id}")
    row = await db_get_user_by_id(user_id)
    result_text = "✅ Blokdan chiqarildi." if new_active else "🚫 Bloklandi."
    await callback.message.edit_text(f"{result_text}\n\n{await _admin_user_detail_text(row)}",
                                      reply_markup=admin_user_detail_kb(user_id, mode, param, page, row))
    await callback.answer()


# ===================== 👑 ADMIN PANEL: 🖥️ SERVERLAR =====================
class AdminServerStates(StatesGroup):
    waiting_name = State()
    waiting_ip = State()
    waiting_ssh_port = State()
    waiting_ssh_user = State()
    waiting_os = State()
    waiting_cpu = State()
    waiting_ram = State()
    waiting_disk = State()
    waiting_bandwidth = State()
    waiting_price = State()
    waiting_bot_limit = State()
    waiting_storage_limit = State()
    waiting_provider = State()
    waiting_edit_value = State()

SERVER_STATUS_EMOJI = {"available": "🟢", "maintenance": "🟡", "offline": "🔴"}
ADMIN_SERVERS_PAGE_SIZE = 5

SERVER_EDIT_FIELDS = {
    "name": "Nomi", "ip": "IP", "ssh_port": "SSH port", "ssh_user": "SSH user",
    "os": "OS", "cpu_cores": "CPU (yadro)", "ram_gb": "RAM (GB)", "disk_gb": "Disk (GB)",
    "bandwidth": "Bandwidth", "monthly_price": "Oylik narx (so'm)", "bot_limit": "Bot limiti",
    "storage_limit_gb": "Storage limiti (GB)", "provider": "Provider",
}
SERVER_INT_FIELDS = {"ssh_port", "cpu_cores", "ram_gb", "disk_gb", "monthly_price", "bot_limit", "storage_limit_gb"}

def admin_servers_menu_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="➕ Qo'shish", callback_data="adminsrv_add_start")],
        [InlineKeyboardButton(text="📋 Ro'yxat", callback_data="adminsrv_list:0")],
        [InlineKeyboardButton(text="📦 Stock", callback_data="adminsrv_stock")],
        [InlineKeyboardButton(text="📊 Statistika", callback_data="adminsrv_stats")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="admin_panel")],
    ])

# --- Kirish nuqtasi (Admin Panel -> 🖥️ Serverlar) ---
@user_router.callback_query(F.data == "admin_servers")
async def show_admin_servers_menu(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    await callback.message.edit_text("🖥️ SERVERLAR", reply_markup=admin_servers_menu_kb())
    await callback.answer()

def _server_row_label(s: dict, bot_count: int) -> str:
    emoji = SERVER_STATUS_EMOJI.get(s["status"], "⚪")
    return f"{emoji} {s['name']} — {bot_count}/{s['bot_limit']} bot"

async def _render_admin_servers_list(page: int) -> tuple[str, InlineKeyboardMarkup]:
    servers = await db_get_all_servers()
    total = len(servers)
    start = page * ADMIN_SERVERS_PAGE_SIZE
    page_rows = servers[start:start + ADMIN_SERVERS_PAGE_SIZE]
    kb_rows = []
    for s in page_rows:
        bot_count = await db_count_server_bots(s["id"])
        kb_rows.append([InlineKeyboardButton(text=_server_row_label(s, bot_count),
                                              callback_data=f"adminsrv_view:{s['id']}:{page}")])
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️ Oldingi", callback_data=f"adminsrv_list:{page - 1}"))
    if start + ADMIN_SERVERS_PAGE_SIZE < total:
        nav.append(InlineKeyboardButton(text="Keyingi ➡️", callback_data=f"adminsrv_list:{page + 1}"))
    if nav:
        kb_rows.append(nav)
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="admin_servers")])
    text = f"🖥️ Serverlar ({total} ta):" if servers else "Hali server qo'shilmagan."
    return text, InlineKeyboardMarkup(inline_keyboard=kb_rows)

@user_router.callback_query(F.data.startswith("adminsrv_list:"))
async def admin_servers_list(callback: CallbackQuery):
    if not await _require_admin(callback): return
    page = int(callback.data.split(":")[1])
    text, kb = await _render_admin_servers_list(page)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

def admin_server_detail_text(s: dict, bot_count: int) -> str:
    emoji = SERVER_STATUS_EMOJI.get(s["status"], "⚪")
    return (
        f"🖥️ {s['name']}\n\n"
        f"IP: {s['ip']}:{s['ssh_port']} ({s['ssh_user']})\n"
        f"OS: {s['os'] or '—'}\n"
        f"CPU: {s['cpu_cores'] if s['cpu_cores'] is not None else '—'} yadro | "
        f"RAM: {s['ram_gb'] if s['ram_gb'] is not None else '—'} GB | "
        f"Disk: {s['disk_gb'] if s['disk_gb'] is not None else '—'} GB\n"
        f"Bandwidth: {s['bandwidth'] or '—'}\n"
        f"Oylik narx: {s['monthly_price']:,} so'm\n"
        f"Bot limiti: {bot_count}/{s['bot_limit']}\n"
        f"Storage limiti: {s['storage_limit_gb']} GB\n"
        f"Provider: {s['provider'] or '—'}\n"
        f"Holati: {emoji} {s['status']}\n"
        f"Qo'shilgan: {s['created_at']}"
    )

def admin_server_detail_kb(server_id: int, page: int, status: str) -> InlineKeyboardMarkup:
    cycle = {"available": "maintenance", "maintenance": "offline", "offline": "available"}
    next_status = cycle[status]
    next_label = {
        "maintenance": "🟡 Texnik xizmatga o'tkazish",
        "offline": "🔴 Offline qilish",
        "available": "🟢 Faollashtirish",
    }[next_status]
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✏️ Tahrirlash", callback_data=f"adminsrv_edit:{server_id}:{page}")],
        [InlineKeyboardButton(text=next_label, callback_data=f"adminsrv_setstatus:{server_id}:{next_status}:{page}")],
        [InlineKeyboardButton(text="🗑️ O'chirish", callback_data=f"adminsrv_delete_ask:{server_id}:{page}")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"adminsrv_list:{page}")],
    ])

@user_router.callback_query(F.data.startswith("adminsrv_view:"))
async def admin_server_view(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, server_id, page = callback.data.split(":")
    server_id, page = int(server_id), int(page)
    s = await db_get_server(server_id)
    if not s:
        await callback.answer("Server topilmadi", show_alert=True)
        return
    bot_count = await db_count_server_bots(server_id)
    await callback.message.edit_text(admin_server_detail_text(s, bot_count),
                                      reply_markup=admin_server_detail_kb(server_id, page, s["status"]))
    await callback.answer()

# --- 🔁 Holatni almashtirish ---
@user_router.callback_query(F.data.startswith("adminsrv_setstatus:"))
async def admin_server_set_status(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, server_id, new_status, page = callback.data.split(":")
    server_id, page = int(server_id), int(page)
    await db_update_server(server_id, status=new_status)
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="server_set_status",
                            result="OK", target=f"server_{server_id}", reason=new_status)
    s = await db_get_server(server_id)
    bot_count = await db_count_server_bots(server_id)
    await callback.message.edit_text(admin_server_detail_text(s, bot_count),
                                      reply_markup=admin_server_detail_kb(server_id, page, s["status"]))
    await callback.answer("✅ Holat yangilandi")

# --- 🗑️ O'chirish (tasdiqlash bilan) ---
@user_router.callback_query(F.data.startswith("adminsrv_delete_ask:"))
async def admin_server_delete_ask(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, server_id, page = callback.data.split(":")
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🗑️ Ha, o'chirish", callback_data=f"adminsrv_delete_do:{server_id}:{page}")],
        [InlineKeyboardButton(text="❌ Bekor qilish", callback_data=f"adminsrv_view:{server_id}:{page}")],
    ])
    await callback.message.edit_text("⚠️ Serverni o'chirishni tasdiqlaysizmi? Bu amalni orqaga qaytarib bo'lmaydi.", reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminsrv_delete_do:"))
async def admin_server_delete_do(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, server_id, page = callback.data.split(":")
    server_id, page = int(server_id), int(page)
    ok, msg = await db_delete_server(server_id)
    if ok:
        await log_admin_action(actor=f"admin:{callback.from_user.id}", action="server_delete",
                                result="OK", target=f"server_{server_id}")
        text, kb = await _render_admin_servers_list(page)
        await callback.message.edit_text(f"✅ {msg}\n\n{text}", reply_markup=kb)
    else:
        s = await db_get_server(server_id)
        await callback.message.edit_text(f"❌ {msg}", reply_markup=admin_server_detail_kb(server_id, page, s["status"]))
    await callback.answer()

# --- ✏️ Tahrirlash ---
def admin_server_edit_kb(server_id: int, page: int) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(text=label, callback_data=f"adminsrv_editfield:{server_id}:{key}:{page}")]
            for key, label in SERVER_EDIT_FIELDS.items()]
    rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"adminsrv_view:{server_id}:{page}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)

@user_router.callback_query(F.data.startswith("adminsrv_edit:"))
async def admin_server_edit_menu(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, server_id, page = callback.data.split(":")
    await callback.message.edit_text("✏️ Qaysi maydonni o'zgartirasiz?",
                                      reply_markup=admin_server_edit_kb(int(server_id), int(page)))
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminsrv_editfield:"))
async def admin_server_edit_field_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    _, server_id, field, page = callback.data.split(":")
    if field not in SERVER_EDIT_FIELDS:
        await callback.answer("Noma'lum maydon", show_alert=True)
        return
    await state.update_data(se_server_id=int(server_id), se_field=field, se_page=int(page))
    await state.set_state(AdminServerStates.waiting_edit_value)
    await callback.message.edit_text(f"✏️ {SERVER_EDIT_FIELDS[field]} uchun yangi qiymatni yuboring:",
                                      reply_markup=back_kb_to(f"adminsrv_edit:{server_id}:{page}"))
    await callback.answer()

@user_router.message(AdminServerStates.waiting_edit_value)
async def admin_server_edit_field_receive(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        return
    try:
        await message.delete()
    except Exception:
        pass
    data = await state.get_data()
    server_id, field, page = data["se_server_id"], data["se_field"], data["se_page"]
    value = message.text.strip()
    if field in SERVER_INT_FIELDS:
        if not value.lstrip("-").isdigit():
            await message.answer("❌ Butun son kiriting. Qaytadan yuboring:")
            return
        value = int(value)
    await state.clear()
    await db_update_server(server_id, **{field: value})
    await log_admin_action(actor=f"admin:{message.from_user.id}", action="server_edit",
                            result="OK", target=f"server_{server_id}", reason=f"{field}={value}")
    s = await db_get_server(server_id)
    bot_count = await db_count_server_bots(server_id)
    await message.answer(f"✅ Yangilandi.\n\n{admin_server_detail_text(s, bot_count)}",
                          reply_markup=admin_server_detail_kb(server_id, page, s["status"]))

# --- ➕ Qo'shish (ketma-ket FSM) ---
@user_router.callback_query(F.data == "adminsrv_add_start")
async def admin_server_add_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    await state.set_state(AdminServerStates.waiting_name)
    await callback.message.edit_text("➕ Yangi server\n\n📝 Server nomini kiriting:", reply_markup=back_kb_to("admin_servers"))
    await callback.answer()

@user_router.message(AdminServerStates.waiting_name)
async def admin_server_add_name(message: Message, state: FSMContext):
    await state.update_data(srv_name=message.text.strip()[:64])
    await state.set_state(AdminServerStates.waiting_ip)
    await message.answer("🌐 IP manzilini kiriting:")

@user_router.message(AdminServerStates.waiting_ip)
async def admin_server_add_ip(message: Message, state: FSMContext):
    await state.update_data(srv_ip=message.text.strip()[:64])
    await state.set_state(AdminServerStates.waiting_ssh_port)
    await message.answer("🔌 SSH port (standart uchun \"-\" yuboring, ya'ni 22):")

@user_router.message(AdminServerStates.waiting_ssh_port)
async def admin_server_add_ssh_port(message: Message, state: FSMContext):
    text = message.text.strip()
    port = 22
    if text != "-":
        if not text.isdigit():
            await message.answer("❌ Butun son kiriting yoki \"-\":")
            return
        port = int(text)
    await state.update_data(srv_ssh_port=port)
    await state.set_state(AdminServerStates.waiting_ssh_user)
    await message.answer("👤 SSH user (standart uchun \"-\", ya'ni root):")

@user_router.message(AdminServerStates.waiting_ssh_user)
async def admin_server_add_ssh_user(message: Message, state: FSMContext):
    text = message.text.strip()
    await state.update_data(srv_ssh_user=("root" if text == "-" else text[:32]))
    await state.set_state(AdminServerStates.waiting_os)
    await message.answer("💿 OS nomini kiriting (masalan Ubuntu 22.04):")

@user_router.message(AdminServerStates.waiting_os)
async def admin_server_add_os(message: Message, state: FSMContext):
    await state.update_data(srv_os=message.text.strip()[:64])
    await state.set_state(AdminServerStates.waiting_cpu)
    await message.answer("🧮 CPU yadrolar sonini kiriting:")

@user_router.message(AdminServerStates.waiting_cpu)
async def admin_server_add_cpu(message: Message, state: FSMContext):
    if not message.text.strip().isdigit():
        await message.answer("❌ Butun son kiriting:")
        return
    await state.update_data(srv_cpu=int(message.text.strip()))
    await state.set_state(AdminServerStates.waiting_ram)
    await message.answer("💾 RAM (GB) kiriting:")

@user_router.message(AdminServerStates.waiting_ram)
async def admin_server_add_ram(message: Message, state: FSMContext):
    if not message.text.strip().isdigit():
        await message.answer("❌ Butun son kiriting:")
        return
    await state.update_data(srv_ram=int(message.text.strip()))
    await state.set_state(AdminServerStates.waiting_disk)
    await message.answer("💽 Disk (GB) kiriting:")

@user_router.message(AdminServerStates.waiting_disk)
async def admin_server_add_disk(message: Message, state: FSMContext):
    if not message.text.strip().isdigit():
        await message.answer("❌ Butun son kiriting:")
        return
    await state.update_data(srv_disk=int(message.text.strip()))
    await state.set_state(AdminServerStates.waiting_bandwidth)
    await message.answer("📶 Bandwidth (masalan \"unlimited\" yoki \"10TB\"):")

@user_router.message(AdminServerStates.waiting_bandwidth)
async def admin_server_add_bandwidth(message: Message, state: FSMContext):
    await state.update_data(srv_bandwidth=message.text.strip()[:32])
    await state.set_state(AdminServerStates.waiting_price)
    await message.answer("💰 Oylik narxini so'mda kiriting (masalan 500000):")

@user_router.message(AdminServerStates.waiting_price)
async def admin_server_add_price(message: Message, state: FSMContext):
    if not message.text.strip().isdigit():
        await message.answer("❌ Butun son kiriting:")
        return
    await state.update_data(srv_price=int(message.text.strip()))
    await state.set_state(AdminServerStates.waiting_bot_limit)
    await message.answer("🤖 Nechta bot sig'adi (bot limiti)?")

@user_router.message(AdminServerStates.waiting_bot_limit)
async def admin_server_add_bot_limit(message: Message, state: FSMContext):
    if not message.text.strip().isdigit():
        await message.answer("❌ Butun son kiriting:")
        return
    await state.update_data(srv_bot_limit=int(message.text.strip()))
    await state.set_state(AdminServerStates.waiting_storage_limit)
    await message.answer("🗄️ Storage limiti (GB)?")

@user_router.message(AdminServerStates.waiting_storage_limit)
async def admin_server_add_storage_limit(message: Message, state: FSMContext):
    if not message.text.strip().isdigit():
        await message.answer("❌ Butun son kiriting:")
        return
    await state.update_data(srv_storage_limit=int(message.text.strip()))
    await state.set_state(AdminServerStates.waiting_provider)
    await message.answer("🏢 Provider nomini kiriting (masalan Hetzner, DigitalOcean; \"-\" agar noma'lum bo'lsa):")

@user_router.message(AdminServerStates.waiting_provider)
async def admin_server_add_provider(message: Message, state: FSMContext):
    text = message.text.strip()
    provider = None if text == "-" else text[:32]
    data = await state.get_data()
    await state.clear()
    server_id = await db_create_server(
        name=data["srv_name"], ip=data["srv_ip"], ssh_port=data["srv_ssh_port"],
        ssh_user=data["srv_ssh_user"], os=data["srv_os"], cpu_cores=data["srv_cpu"],
        ram_gb=data["srv_ram"], disk_gb=data["srv_disk"], bandwidth=data["srv_bandwidth"],
        monthly_price=data["srv_price"], bot_limit=data["srv_bot_limit"],
        storage_limit_gb=data["srv_storage_limit"], provider=provider, status="available",
    )
    await log_admin_action(actor=f"admin:{message.from_user.id}", action="server_create",
                            result="OK", target=f"server_{server_id}")
    s = await db_get_server(server_id)
    await message.answer(f"✅ Server qo'shildi!\n\n{admin_server_detail_text(s, 0)}",
                          reply_markup=admin_server_detail_kb(server_id, 0, s["status"]))

# --- 📦 Stock ---
@user_router.callback_query(F.data == "adminsrv_stock")
async def admin_servers_stock(callback: CallbackQuery):
    if not await _require_admin(callback): return
    servers = await db_get_all_servers()
    available = [s for s in servers if s["status"] == "available"]
    if not available:
        text = "📦 Stock\n\nHozircha bo'sh joyli (available) server yo'q."
    else:
        lines = []
        for s in available:
            used = await db_count_server_bots(s["id"])
            lines.append(f"🟢 {s['name']} — {used}/{s['bot_limit']} bot, {s['ram_gb']}GB RAM")
        text = "📦 Stock (available serverlar):\n\n" + "\n".join(lines)
    await callback.message.edit_text(text, reply_markup=back_kb_to("admin_servers"))
    await callback.answer()

# --- 📊 Statistika ---
@user_router.callback_query(F.data == "adminsrv_stats")
async def admin_servers_stats(callback: CallbackQuery):
    if not await _require_admin(callback): return
    stats = await db_stats_servers()
    servers = await db_get_all_servers()
    maintenance = sum(1 for s in servers if s["status"] == "maintenance")
    total_bots = 0
    for s in servers:
        total_bots += await db_count_server_bots(s["id"])
    text = (
        f"📊 Serverlar statistikasi\n\n"
        f"Jami: {stats['total']}\n"
        f"🟢 Faol: {max(stats['active'] - maintenance, 0)}\n"
        f"🟡 Texnik xizmatda: {maintenance}\n"
        f"🔴 Offline: {stats['offline']}\n"
        f"Jami joylashgan botlar: {total_bots}"
    )
    await callback.message.edit_text(text, reply_markup=back_kb_to("admin_servers"))
    await callback.answer()


# ===================== 👑 ADMIN PANEL: 💳 PAYMENT MANAGER =====================
# 7 bo'limli boshqaruv markazi: 1) Karta ma'lumotlari, 2) SMS Monitoring,
# 3) To'lov qoidalari, 4) Tekshiruv, 5) To'lovlar tarixi, 6) Firibgarlik
# himoyasi, 7) AI Payment Supervisor. Bu bosqichda 1-3-5-2-7 to'liq ishlaydi
# (mavjud DB qatlamlarga tayanadi); 4 (Tekshiruv) va 6 (Firibgarlik himoyasi)
# hozircha jonli ma'lumot bilan skelet holatda — to'liq amallar (qo'lda
# moslashtirish, bloklash qoidalari) keyingi bosqichda shu tuzilishga ulanadi.
class AdminPaymentManagerStates(StatesGroup):
    waiting_card_number = State()
    waiting_card_device_name = State()
    waiting_rule_value = State()
    waiting_fraud_rule_value = State()

def payment_manager_menu_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="💳 Karta ma'lumotlari", callback_data="pm_card")],
        [InlineKeyboardButton(text="📱 SMS Monitoring", callback_data="pm_sms")],
        [InlineKeyboardButton(text="⚙️ To'lov qoidalari", callback_data="pm_rules")],
        [InlineKeyboardButton(text="🔍 Tekshiruv", callback_data="pm_review")],
        [InlineKeyboardButton(text="📜 To'lovlar tarixi", callback_data="pm_history:0")],
        [InlineKeyboardButton(text="🛡️ Firibgarlik himoyasi", callback_data="pm_fraud")],
        [InlineKeyboardButton(text="🤖 AI Payment Supervisor", callback_data="pm_ai")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="admin_panel")],
    ])

@user_router.callback_query(F.data == "payment_manager")
async def show_payment_manager_menu(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    await callback.message.edit_text("💳 PAYMENT MANAGER", reply_markup=payment_manager_menu_kb())
    await callback.answer()


# ---- 1) 💳 Karta ma'lumotlari ----
def pm_card_kb(has_card: bool) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(text="➕ Yangi karta qo'shish/almashtirish", callback_data="pmcard_add_start")]]
    if has_card:
        rows.append([InlineKeyboardButton(text="🔴 O'chirish (disable)", callback_data="pmcard_disable")])
    rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="payment_manager")])
    return InlineKeyboardMarkup(inline_keyboard=rows)

async def _render_pm_card() -> tuple[str, InlineKeyboardMarkup]:
    card = await db_get_active_card()
    if not card:
        return "💳 Karta ma'lumotlari\n\n⚠️ Hozircha faol karta sozlanmagan.", pm_card_kb(False)
    status_label = "🟢 Faol" if card["status"] == "active" else "🔴 O'chirilgan"
    text = (
        f"💳 Karta ma'lumotlari\n\n"
        f"Karta: •••• •••• •••• {card['card_last4']}\n"
        f"Holati: {status_label}\n"
        f"Monitoring qurilmasi: {card['monitor_device_name'] or '—'}\n"
        f"Oxirgi bildirishnoma: {card['last_notification_at'] or '—'}\n"
        f"Qo'shilgan: {card['created_at']}"
    )
    return text, pm_card_kb(True)

@user_router.callback_query(F.data == "pm_card")
async def show_pm_card(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    text, kb = await _render_pm_card()
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data == "pmcard_add_start")
async def pm_card_add_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.set_state(AdminPaymentManagerStates.waiting_card_number)
    await callback.message.edit_text(
        "💳 Yangi karta raqamini kiriting (16 raqam, masalan: 8600123456789012).\n\n"
        "⚠️ Xabaringiz yuborilgach xavfsizlik uchun avtomatik o'chiriladi. "
        "Eski faol karta avtomatik o'chiriladi — bir vaqtda faqat bitta faol karta bo'ladi.",
        reply_markup=back_kb_to("pm_card"),
    )
    await callback.answer()

@user_router.message(AdminPaymentManagerStates.waiting_card_number)
async def pm_card_add_receive_number(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        return
    raw = (message.text or "").strip()
    digits = raw.replace(" ", "").replace("-", "")
    try:
        await message.delete()
    except Exception:
        pass
    if not digits.isdigit() or len(digits) != 16:
        await message.answer("⚠️ Noto'g'ri format. Karta 16 ta raqamdan iborat bo'lishi kerak. Qaytadan yuboring:",
                              reply_markup=back_kb_to("pm_card"))
        return
    await state.update_data(pm_card_number=digits)
    await state.set_state(AdminPaymentManagerStates.waiting_card_device_name)
    await message.answer(
        "📱 Monitoring qurilmasi nomini kiriting (masalan: \"Samsung A12 - MacroDroid\"), "
        "yoki \"-\" yuborib o'tkazib yuboring:",
        reply_markup=back_kb_to("pm_card"),
    )

@user_router.message(AdminPaymentManagerStates.waiting_card_device_name)
async def pm_card_add_receive_device(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        return
    text = (message.text or "").strip()
    device_name = "" if text == "-" else text[:64]
    data = await state.get_data()
    await state.clear()
    card = await db_add_payment_card(data["pm_card_number"], device_name)
    await log_admin_action(actor=f"admin:{message.from_user.id}", action="payment_card_add",
                            result="OK", target=f"card_{card['id']}")
    text_out, kb = await _render_pm_card()
    await message.answer(f"✅ Karta qo'shildi/almashtirildi.\n\n{text_out}", reply_markup=kb)

@user_router.callback_query(F.data == "pmcard_disable")
async def pm_card_disable(callback: CallbackQuery):
    if not await _require_admin(callback): return
    card = await db_get_active_card()
    if not card:
        await callback.answer("Faol karta yo'q", show_alert=True)
        return
    await db_set_card_status(card["id"], "disabled")
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="payment_card_disable",
                            result="OK", target=f"card_{card['id']}")
    text_out, kb = await _render_pm_card()
    await callback.message.edit_text(f"🔴 Karta o'chirildi.\n\n{text_out}", reply_markup=kb)
    await callback.answer()


# ---- 2) 📱 SMS Monitoring ----
def pm_sms_kb(enabled: bool) -> InlineKeyboardMarkup:
    toggle_label = "🔴 O'chirish" if enabled else "🟢 Yoqish"
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=toggle_label, callback_data="pmsms_toggle")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="payment_manager")],
    ])

async def _render_pm_sms() -> tuple[str, InlineKeyboardMarkup]:
    settings = await db_get_payment_settings()
    card = await db_get_active_card()
    enabled = bool(settings.get("sms_monitoring_enabled"))
    status_label = "🟢 Yoqilgan" if enabled else "🔴 O'chirilgan"
    webhook_url = f"https://{WEB_DOMAIN}/payment/notify"
    secret_status = "✅ sozlangan" if PAYMENT_WEBHOOK_SECRET else "❌ sozlanmagan (.env'da PAYMENT_WEBHOOK_SECRET yo'q)"
    device_name = card["monitor_device_name"] if card and card["monitor_device_name"] else "—"
    last_notif = card["last_notification_at"] if card and card["last_notification_at"] else "—"
    text = (
        f"📱 SMS Monitoring\n\n"
        f"Holati: {status_label}\n"
        f"Webhook URL: {webhook_url}\n"
        f"Maxfiy kalit: {secret_status}\n"
        f"Monitoring qurilmasi: {device_name}\n"
        f"Oxirgi bildirishnoma: {last_notif}\n\n"
        f"⚠️ MacroDroid so'rovi \"X-Payment-Secret\" headerida shu maxfiy kalitni yuborishi shart."
    )
    return text, pm_sms_kb(enabled)

@user_router.callback_query(F.data == "pm_sms")
async def show_pm_sms(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    text, kb = await _render_pm_sms()
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data == "pmsms_toggle")
async def pm_sms_toggle(callback: CallbackQuery):
    if not await _require_admin(callback): return
    settings = await db_get_payment_settings()
    new_val = 0 if settings.get("sms_monitoring_enabled") else 1
    await db_update_payment_settings(sms_monitoring_enabled=new_val)
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="sms_monitoring_toggle",
                            result="OK", reason=str(new_val))
    text, kb = await _render_pm_sms()
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer("✅ Holat yangilandi")


# ---- 3) ⚙️ To'lov qoidalari ----
PM_RULE_FIELDS = {
    "min_amount": "Minimal summa (so'm)",
    "max_amount": "Maksimal summa (so'm)",
    "payment_ttl_minutes": "To'lov vaqti (daqiqa)",
    "max_concurrent_orders": "Bir vaqtdagi aktiv buyurtmalar soni",
}

def pm_rules_kb(settings: dict) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(text=f"✏️ {label}", callback_data=f"pmrule_edit:{key}")]
            for key, label in PM_RULE_FIELDS.items()]
    frac_label = "✅ Kasrli summa: yoqilgan" if settings.get("allow_fractional") else "❌ Kasrli summa: o'chirilgan"
    rows.append([InlineKeyboardButton(text=frac_label, callback_data="pmrule_toggle_fractional")])
    rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="payment_manager")])
    return InlineKeyboardMarkup(inline_keyboard=rows)

def _pm_rules_text(settings: dict) -> str:
    frac_state = "yoqilgan" if settings.get("allow_fractional") else "o'chirilgan"
    return (
        f"⚙️ To'lov qoidalari\n\n"
        f"Minimal summa: {fmt_som(settings['min_amount'])} so'm\n"
        f"Maksimal summa: {fmt_som(settings['max_amount'])} so'm\n"
        f"To'lov vaqti: {settings['payment_ttl_minutes']} daqiqa\n"
        f"Bir vaqtdagi aktiv buyurtmalar: {settings['max_concurrent_orders']}\n"
        f"Kasrli summa: {frac_state}"
    )

@user_router.callback_query(F.data == "pm_rules")
async def show_pm_rules(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    settings = await db_get_payment_settings()
    await callback.message.edit_text(_pm_rules_text(settings), reply_markup=pm_rules_kb(settings))
    await callback.answer()

@user_router.callback_query(F.data == "pmrule_toggle_fractional")
async def pm_rule_toggle_fractional(callback: CallbackQuery):
    if not await _require_admin(callback): return
    settings = await db_get_payment_settings()
    new_val = 0 if settings.get("allow_fractional") else 1
    await db_update_payment_settings(allow_fractional=new_val)
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="payment_rule_toggle_fractional",
                            result="OK", reason=str(new_val))
    settings = await db_get_payment_settings()
    await callback.message.edit_text(_pm_rules_text(settings), reply_markup=pm_rules_kb(settings))
    await callback.answer("✅ Yangilandi")

@user_router.callback_query(F.data.startswith("pmrule_edit:"))
async def pm_rule_edit_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    field = callback.data.split(":")[1]
    if field not in PM_RULE_FIELDS:
        await callback.answer("Noma'lum maydon", show_alert=True)
        return
    await state.update_data(pm_rule_field=field)
    await state.set_state(AdminPaymentManagerStates.waiting_rule_value)
    hint = " (so'mda, masalan 50000)" if field in ("min_amount", "max_amount") else ""
    await callback.message.edit_text(f"✏️ {PM_RULE_FIELDS[field]} uchun yangi qiymatni yuboring{hint}:",
                                      reply_markup=back_kb_to("pm_rules"))
    await callback.answer()

@user_router.message(AdminPaymentManagerStates.waiting_rule_value)
async def pm_rule_edit_receive(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        return
    data = await state.get_data()
    field = data["pm_rule_field"]
    raw = message.text.strip()
    if field in ("min_amount", "max_amount"):
        tiyin = parse_exact_som_amount(raw)
        if tiyin is None:
            await message.answer("❌ Noto'g'ri summa (2 xonadan ortiq kasr bo'lmasin). Qaytadan yuboring:")
            return
        value = tiyin
    else:
        if not raw.isdigit() or int(raw) <= 0:
            await message.answer("❌ Musbat butun son kiriting. Qaytadan yuboring:")
            return
        value = int(raw)
    await state.clear()
    await db_update_payment_settings(**{field: value})
    await log_admin_action(actor=f"admin:{message.from_user.id}", action="payment_rule_edit",
                            result="OK", reason=f"{field}={value}")
    settings = await db_get_payment_settings()
    await message.answer(f"✅ Yangilandi.\n\n{_pm_rules_text(settings)}", reply_markup=pm_rules_kb(settings))


# ---- 4) 🔍 Tekshiruv — qo'lda moslashtirish UI ----
# Admin bu yerda: (a) mos kelmagan (unmatched) bildirishnomalarni ko'rib,
# ularni qo'lda biror buyurtmaga bog'laydi yoki rad etadi; (b) 🛡️ qoida
# bo'yicha belgilangan (flagged_review) shubhali to'lovlarni tasdiqlaydi/rad
# etadi; (c) allaqachon ko'rib chiqilganlar tarixini ko'radi. AI (keyingi
# bosqichda) faqat TAVSIYA beradi — yakuniy bog'lash/rad etish har doim
# shu yerda, admin qo'lida qoladi.
class TekshiruvStates(StatesGroup):
    waiting_txn_search = State()
    waiting_order_ref_search = State()
    waiting_user_bind_search = State()

TKR_PAGE_SIZE = 6
PM_REVIEW_RESOLVED_RESULTS = ("manual_matched", "manual_rejected", "flagged_approved", "flagged_rejected")

def tkr_menu_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🟡 Unmatched to'lovlar", callback_data="tkr_unmatched:0")],
        [InlineKeyboardButton(text="🔴 Shubhali to'lovlar", callback_data="tkr_suspicious:0")],
        [InlineKeyboardButton(text="🟢 Tekshirilganlar", callback_data="tkr_resolved:0")],
        [InlineKeyboardButton(text="🔎 Qidirish", callback_data="tkr_search")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="payment_manager")],
    ])

async def _render_pm_review() -> tuple[str, InlineKeyboardMarkup]:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        row1 = await db.execute("SELECT COUNT(*) AS c FROM payment_transactions WHERE result = 'unmatched'")
        unmatched_n = (await row1.fetchone())["c"]
        row2 = await db.execute("SELECT COUNT(*) AS c FROM payment_orders WHERE status = 'flagged_review'")
        suspicious_n = (await row2.fetchone())["c"]
        ph = ",".join("?" * len(PM_REVIEW_RESOLVED_RESULTS))
        row3 = await db.execute(f"SELECT COUNT(*) AS c FROM payment_transactions WHERE result IN ({ph})",
                                 PM_REVIEW_RESOLVED_RESULTS)
        resolved_n = (await row3.fetchone())["c"]
    text = (
        f"🔍 Tekshiruv\n\n"
        f"🟡 Unmatched to'lovlar — {unmatched_n} ta\n"
        f"🔴 Shubhali to'lovlar — {suspicious_n} ta\n"
        f"🟢 Tekshirilganlar — {resolved_n} ta"
    )
    return text, tkr_menu_kb()

@user_router.callback_query(F.data == "pm_review")
async def show_pm_review(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    text, kb = await _render_pm_review()
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()


# ---- 🟡 Unmatched ro'yxati ----
def _tkr_pagination_kb(prefix: str, page: int, total: int, back_to: str = "pm_review") -> InlineKeyboardMarkup:
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️ Oldingi", callback_data=f"{prefix}:{page - 1}"))
    if (page + 1) * TKR_PAGE_SIZE < total:
        nav.append(InlineKeyboardButton(text="Keyingi ➡️", callback_data=f"{prefix}:{page + 1}"))
    rows = [nav] if nav else []
    rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data=back_to)])
    return InlineKeyboardMarkup(inline_keyboard=rows)

async def _render_tkr_unmatched(page: int) -> tuple[str, InlineKeyboardMarkup]:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        total_row = await db.execute("SELECT COUNT(*) AS c FROM payment_transactions WHERE result = 'unmatched'")
        total = (await total_row.fetchone())["c"]
        rows = await db.execute(
            "SELECT * FROM payment_transactions WHERE result = 'unmatched' ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (TKR_PAGE_SIZE, page * TKR_PAGE_SIZE))
        rows = [dict(r) for r in await rows.fetchall()]
    if not rows:
        text = "🟡 Unmatched to'lovlar\n\nHozircha yo'q. 🎉" if total == 0 else "🟡 Unmatched to'lovlar\n\nBoshqa sahifa yo'q."
        kb_rows = [[InlineKeyboardButton(text="🔙 Orqaga", callback_data="pm_review")]]
        return text, InlineKeyboardMarkup(inline_keyboard=kb_rows)
    kb_rows = [[InlineKeyboardButton(text=f"💳 {fmt_som(r['amount'])} so'm — {r['created_at']}",
                                      callback_data=f"tkr_view:{r['id']}")] for r in rows]
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️ Oldingi", callback_data=f"tkr_unmatched:{page - 1}"))
    if (page + 1) * TKR_PAGE_SIZE < total:
        nav.append(InlineKeyboardButton(text="Keyingi ➡️", callback_data=f"tkr_unmatched:{page + 1}"))
    if nav:
        kb_rows.append(nav)
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="pm_review")])
    return f"🟡 Unmatched to'lovlar ({total} ta):", InlineKeyboardMarkup(inline_keyboard=kb_rows)

@user_router.callback_query(F.data.startswith("tkr_unmatched:"))
async def show_tkr_unmatched(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    page = int(callback.data.split(":")[1])
    text, kb = await _render_tkr_unmatched(page)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()


# ---- Bitta unmatched bildirishnoma kartochkasi ----
def _tkr_txn_detail_text(txn: dict) -> str:
    return (
        f"💳 To'lov: {fmt_som(txn['amount'])} so'm\n"
        f"🕐 Vaqt: {txn['created_at']}\n"
        f"🧾 Transaction ID: {txn['provider_trans_id'] or '—'}\n"
        f"📱 Manba: {txn['provider']}\n"
        f"📝 Xom matn: {(txn['raw_payload'] or '—')[:300]}\n\n"
        f"Qaysi buyurtmaga bog'laymiz?"
    )

def tkr_txn_detail_kb(txn_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🤖 AI tavsiyasi", callback_data=f"tkr_ai_suggest:{txn_id}")],
        [InlineKeyboardButton(text="📦 Buyurtmalar ro'yxati", callback_data=f"tkr_bindlist:{txn_id}:0")],
        [InlineKeyboardButton(text="💰 Summa bo'yicha moslarini ko'rsatish", callback_data=f"tkr_bindamount:{txn_id}:0")],
        [InlineKeyboardButton(text="🔎 Buyurtma ID bo'yicha qidirish", callback_data=f"tkr_bindbyid:{txn_id}")],
        [InlineKeyboardButton(text="👤 Foydalanuvchi bo'yicha qidirish", callback_data=f"tkr_bindbyuser:{txn_id}")],
        [InlineKeyboardButton(text="🚫 Hech qaysisiga tegishli emas (rad etish)", callback_data=f"tkr_dismiss:{txn_id}")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="tkr_unmatched:0")],
    ])

# ---- 6️⃣ Admin AI Engine: AI Payment Matching (Unmatched Payment Recommendation) ----
# 🛡️/🔍 mexanizmi tayyor bo'lgach, endi AI shu ustiga TAVSIYA qatlami sifatida
# quriladi. QAT'IY QOIDA: AI hech qachon o'zi bog'lamaydi/kredit bermaydi —
# faqat moslik foizini hisoblab, eng yaxshi nomzodlarni ko'rsatadi; yakuniy
# bog'lash tugmasi bosilganda ham xuddi shu tkr_pick/tkr_bindconfirm oqimi
# ishlaydi (db_manual_match_transaction — yagona kredit nuqtasi orqali).
def compute_match_score(txn: dict, order: dict, competing_count: int = 1) -> dict:
    """Sof funksiya (test qilish oson) — 0-100 oralig'ida heuristik moslik
    bahosini hisoblaydi. Og'irliklar: 💰 summa (40), 🕐 vaqt (25), 📦 buyurtma
    holati (15), 🔁 raqobatchi nomzodlar yo'qligi (10), 🧾 transaction ID
    mavjudligi (10). Jami=100.
    ESLATMA: 👤 foydalanuvchi/telefon va 💳/📱 karta-SMS matn tahlili hozircha
    ishonchli xom ma'lumot yo'qligi sabab kiritilmagan (soxta aniqlik
    ko'rsatmaslik uchun) — SMS matn-tahlili kengaytirilganda qo'shiladi."""
    # 💰 Summa mosligi (40)
    if order["amount"] == txn["amount"]:
        amount_score = 40
    else:
        diff_ratio = abs(order["amount"] - txn["amount"]) / max(order["amount"], 1)
        amount_score = max(0, round(40 * (1 - min(diff_ratio, 1))))

    # 🕐 Vaqt mosligi (25) — txn va order yaratilgan vaqt orasidagi farq
    try:
        t_order = datetime.fromisoformat(order["created_at"])
        t_txn = datetime.fromisoformat(txn["created_at"])
        gap_minutes = abs((t_txn - t_order).total_seconds()) / 60
    except Exception:
        gap_minutes = 999
    if gap_minutes <= 2:
        time_score = 25
    elif gap_minutes <= 5:
        time_score = 20
    elif gap_minutes <= 15:
        time_score = 12
    elif gap_minutes <= 60:
        time_score = 5
    else:
        time_score = 0

    # 📦 Buyurtma statusi (15) — foydalanuvchi "to'lov qildim" bosganmi
    status_score = 15 if order["status"] == "awaiting_confirmation" else 8

    # 🔁 Raqobatchi nomzodlar (10) — bir xil summali boshqa faol buyurtma
    # qancha ko'p bo'lsa, aynan shuni tanlash shuncha noaniq
    if competing_count <= 1:
        ambiguity_score = 10
    elif competing_count == 2:
        ambiguity_score = 6
    elif competing_count == 3:
        ambiguity_score = 3
    else:
        ambiguity_score = 0

    # 🧾 Transaction ID mavjudligi (10) — kuchsiz signal, faqat borligi hisobga olinadi
    trans_id = txn.get("provider_trans_id") or ""
    ref_score = 10 if (trans_id and not trans_id.startswith("auto_")) else 4

    total = amount_score + time_score + status_score + ambiguity_score + ref_score
    return {
        "score": min(total, 100),
        "breakdown": {"amount": amount_score, "time": time_score, "status": status_score,
                      "ambiguity": ambiguity_score, "reference": ref_score},
    }

async def ai_suggest_matches(txn_id: int, limit: int = 3) -> list[dict]:
    """Berilgan unmatched tranzaksiya uchun eng mos faol buyurtmalarni
    top-N tartibida qaytaradi: [{"order", "score", "breakdown"}, ...]."""
    txn = await db_get_payment_transaction(txn_id)
    if not txn:
        return []
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        rows = await db.execute(
            "SELECT * FROM payment_orders WHERE status IN ('locked','awaiting_confirmation') "
            "ORDER BY created_at DESC LIMIT 200")
        orders = [dict(r) for r in await rows.fetchall()]
    amount_counts: dict[int, int] = {}
    for o in orders:
        amount_counts[o["amount"]] = amount_counts.get(o["amount"], 0) + 1

    scored = []
    for o in orders:
        result = compute_match_score(txn, o, competing_count=amount_counts.get(o["amount"], 1))
        scored.append({"order": o, "score": result["score"], "breakdown": result["breakdown"]})
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[:limit]

def _score_level_label(score: int) -> str:
    if score >= 95:
        return "🟢 Kuchli tavsiya"
    elif score >= 80:
        return "🟡 Tekshirish tavsiya qilinadi"
    else:
        return "🔴 Qo'lda tekshirish tavsiya qilinadi"

def _match_line(rank_emoji: str, item: dict) -> str:
    o, score, bd = item["order"], item["score"], item["breakdown"]
    amount_mark = "✓" if bd["amount"] >= 35 else ("≈" if bd["amount"] > 0 else "✗")
    lines = [
        f"{rank_emoji} #{o['order_ref']} — {score}% mos",
        f"   💰 Summa: {fmt_som(o['amount'])} so'm {amount_mark}",
        f"   🕐 Vaqt mosligi: {bd['time']}/25 ball",
        f"   📦 Holati: {o['status']}",
    ]
    return "\n".join(lines)

@user_router.callback_query(F.data.startswith("tkr_ai_suggest:"))
async def show_tkr_ai_suggest(callback: CallbackQuery):
    if not await _require_admin(callback): return
    txn_id = int(callback.data.split(":")[1])
    txn = await db_get_payment_transaction(txn_id)
    if not txn or txn["result"] != "unmatched":
        await callback.answer("Bu bildirishnoma allaqachon hal qilingan", show_alert=True)
        return
    settings = await db_get_payment_settings()
    if not settings.get("ai_supervisor_enabled"):
        await callback.message.edit_text(
            "🤖 AI Payment Supervisor hozircha o'chirilgan.\n\n"
            "Uni Payment Manager -> 🤖 AI Payment Supervisor bo'limidan yoqishingiz mumkin.",
            reply_markup=back_kb_to(f"tkr_view:{txn_id}"))
        await callback.answer()
        return

    matches = await ai_suggest_matches(txn_id, limit=3)
    if not matches:
        await callback.message.edit_text(
            "🤖 AI tavsiyasi\n\nHozircha mos bo'lishi mumkin bo'lgan faol buyurtma topilmadi.",
            reply_markup=back_kb_to(f"tkr_view:{txn_id}"))
        await callback.answer()
        return

    rank_emojis = ["🥇", "🥈", "🥉"]
    lines = [f"🤖 AI tavsiyasi\n💳 {fmt_som(txn['amount'])} so'mlik to'lov aniqlandi.\n"]
    for i, m in enumerate(matches):
        lines.append(_match_line(rank_emojis[i] if i < len(rank_emojis) else "•", m))
        lines.append("")
    top = matches[0]
    lines.append(_score_level_label(top["score"]))
    lines.append("⚠️ Bu — heuristik baho, yakuniy qaror har doim admin tomonidan tasdiqlanadi.")
    text = "\n".join(lines)

    kb_rows = [[InlineKeyboardButton(
        text=f"✅ #{top['order']['order_ref']}ga bog'lash ({top['score']}%)",
        callback_data=f"tkr_pick:{txn_id}:{top['order']['id']}")]]
    kb_rows.append([InlineKeyboardButton(text="🔍 Batafsil tekshirish", callback_data=f"tkr_view:{txn_id}")])
    kb_rows.append([InlineKeyboardButton(text="❌ Rad etish", callback_data=f"tkr_dismiss:{txn_id}")])
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"tkr_view:{txn_id}")])
    await callback.message.edit_text(text, reply_markup=InlineKeyboardMarkup(inline_keyboard=kb_rows))
    await callback.answer()


@user_router.callback_query(F.data.startswith("tkr_view:"))
async def show_tkr_txn_view(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    txn_id = int(callback.data.split(":")[1])
    txn = await db_get_payment_transaction(txn_id)
    if not txn or txn["result"] != "unmatched":
        await callback.answer("Bu bildirishnoma allaqachon hal qilingan", show_alert=True)
        return
    await callback.message.edit_text(_tkr_txn_detail_text(txn), reply_markup=tkr_txn_detail_kb(txn_id))
    await callback.answer()


# ---- Buyurtma tanlash usullari ----
def _order_pick_line(o: dict) -> str:
    return f"#{o['id']} {o['order_ref']} — {fmt_som(o['amount'])} so'm — {o['status']}"

async def _render_order_pick_list(txn_id: int, orders: list[dict], page: int, total: int,
                                   prefix: str) -> tuple[str, InlineKeyboardMarkup]:
    if not orders:
        text = "Mos buyurtma topilmadi." if total == 0 else "Boshqa sahifa yo'q."
        kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"tkr_view:{txn_id}")]])
        return text, kb
    kb_rows = [[InlineKeyboardButton(text=_order_pick_line(o), callback_data=f"tkr_pick:{txn_id}:{o['id']}")] for o in orders]
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️ Oldingi", callback_data=f"{prefix}:{txn_id}:{page - 1}"))
    if (page + 1) * TKR_PAGE_SIZE < total:
        nav.append(InlineKeyboardButton(text="Keyingi ➡️", callback_data=f"{prefix}:{txn_id}:{page + 1}"))
    if nav:
        kb_rows.append(nav)
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"tkr_view:{txn_id}")])
    return f"📦 Buyurtmani tanlang ({total} ta):", InlineKeyboardMarkup(inline_keyboard=kb_rows)

@user_router.callback_query(F.data.startswith("tkr_bindlist:"))
async def show_tkr_bind_list(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, txn_id, page = callback.data.split(":")
    txn_id, page = int(txn_id), int(page)
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        total_row = await db.execute("SELECT COUNT(*) AS c FROM payment_orders WHERE status IN ('locked','awaiting_confirmation')")
        total = (await total_row.fetchone())["c"]
        rows = await db.execute(
            "SELECT * FROM payment_orders WHERE status IN ('locked','awaiting_confirmation') "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?", (TKR_PAGE_SIZE, page * TKR_PAGE_SIZE))
        orders = [dict(r) for r in await rows.fetchall()]
    text, kb = await _render_order_pick_list(txn_id, orders, page, total, "tkr_bindlist")
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data.startswith("tkr_bindamount:"))
async def show_tkr_bind_by_amount(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, txn_id, page = callback.data.split(":")
    txn_id, page = int(txn_id), int(page)
    txn = await db_get_payment_transaction(txn_id)
    if not txn:
        await callback.answer("Bildirishnoma topilmadi", show_alert=True)
        return
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        total_row = await db.execute(
            "SELECT COUNT(*) AS c FROM payment_orders WHERE status IN ('locked','awaiting_confirmation') AND amount = ?",
            (txn["amount"],))
        total = (await total_row.fetchone())["c"]
        rows = await db.execute(
            "SELECT * FROM payment_orders WHERE status IN ('locked','awaiting_confirmation') AND amount = ? "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?", (txn["amount"], TKR_PAGE_SIZE, page * TKR_PAGE_SIZE))
        orders = [dict(r) for r in await rows.fetchall()]
    text, kb = await _render_order_pick_list(txn_id, orders, page, total, "tkr_bindamount")
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data.startswith("tkr_bindbyid:"))
async def tkr_bind_by_id_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    txn_id = int(callback.data.split(":")[1])
    await state.update_data(tkr_txn_id=txn_id)
    await state.set_state(TekshiruvStates.waiting_order_ref_search)
    await callback.message.edit_text("🔎 Buyurtma ID yoki order_ref (masalan po_ab12cd34) yuboring:",
                                      reply_markup=back_kb_to(f"tkr_view:{txn_id}"))
    await callback.answer()

@user_router.message(TekshiruvStates.waiting_order_ref_search)
async def tkr_bind_by_id_receive(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        return
    data = await state.get_data()
    txn_id = data["tkr_txn_id"]
    query = message.text.strip()
    order = None
    if query.isdigit():
        order = await db_get_order_by_id(int(query))
    if not order:
        order = await db_get_order_by_ref(query)
    await state.clear()
    if not order:
        await message.answer("⚠️ Bunday buyurtma topilmadi. Qaytadan urinib ko'ring:",
                              reply_markup=back_kb_to(f"tkr_view:{txn_id}"))
        return
    text, kb = await _render_tkr_confirm(txn_id, order["id"])
    if text is None:
        await message.answer(kb, reply_markup=back_kb_to(f"tkr_view:{txn_id}"))
        return
    await message.answer(text, reply_markup=kb)

@user_router.callback_query(F.data.startswith("tkr_bindbyuser:"))
async def tkr_bind_by_user_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    txn_id = int(callback.data.split(":")[1])
    await state.update_data(tkr_txn_id=txn_id)
    await state.set_state(TekshiruvStates.waiting_user_bind_search)
    await callback.message.edit_text("👤 Username, ism yoki Telegram ID yuboring:",
                                      reply_markup=back_kb_to(f"tkr_view:{txn_id}"))
    await callback.answer()

@user_router.message(TekshiruvStates.waiting_user_bind_search)
async def tkr_bind_by_user_receive(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        return
    data = await state.get_data()
    txn_id = data["tkr_txn_id"]
    query = message.text.strip().replace(":", "")[:32]
    await state.clear()
    users, total = await db_search_users(query, "all", 0, 5)
    if not users:
        await message.answer("⚠️ Foydalanuvchi topilmadi. Qaytadan urinib ko'ring:",
                              reply_markup=back_kb_to(f"tkr_view:{txn_id}"))
        return
    if len(users) == 1:
        await _show_user_orders_for_bind(message, txn_id, users[0]["id"], 0)
        return
    kb_rows = [[InlineKeyboardButton(
        text=f"@{u['username']}" if u["username"] else (u["first_name"] or str(u["telegram_id"])),
        callback_data=f"tkr_binduser_orders:{txn_id}:{u['id']}:0")] for u in users]
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"tkr_view:{txn_id}")])
    await message.answer(f"{total} ta foydalanuvchi topildi, birini tanlang:",
                          reply_markup=InlineKeyboardMarkup(inline_keyboard=kb_rows))

async def _show_user_orders_for_bind(target, txn_id: int, user_id: int, page: int):
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        total_row = await db.execute(
            "SELECT COUNT(*) AS c FROM payment_orders WHERE user_id = ? AND status IN ('locked','awaiting_confirmation')",
            (user_id,))
        total = (await total_row.fetchone())["c"]
        rows = await db.execute(
            "SELECT * FROM payment_orders WHERE user_id = ? AND status IN ('locked','awaiting_confirmation') "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?", (user_id, TKR_PAGE_SIZE, page * TKR_PAGE_SIZE))
        orders = [dict(r) for r in await rows.fetchall()]
    text, kb = await _render_order_pick_list(txn_id, orders, page, total, f"tkr_binduser_orders:{user_id}")
    if hasattr(target, "edit_text"):
        await target.edit_text(text, reply_markup=kb)
    else:
        await target.answer(text, reply_markup=kb)

@user_router.callback_query(F.data.startswith("tkr_binduser_orders:"))
async def show_tkr_bind_user_orders(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, txn_id, user_id, page = callback.data.split(":")
    await _show_user_orders_for_bind(callback.message, int(txn_id), int(user_id), int(page))
    await callback.answer()


# ---- Bog'lashni tasdiqlash ----
async def _render_tkr_confirm(txn_id: int, order_id: int):
    txn = await db_get_payment_transaction(txn_id)
    order = await db_get_order_by_id(order_id)
    if not txn or txn["result"] != "unmatched":
        return None, "Bu bildirishnoma allaqachon hal qilingan."
    if not order or order["status"] not in ("locked", "awaiting_confirmation"):
        return None, "Bu buyurtma faol emas."
    warn = ""
    if order["amount"] != txn["amount"]:
        warn = (f"\n\n⚠️ Diqqat: kelgan summa {fmt_som(txn['amount'])} so'm, "
                f"buyurtma summasi {fmt_som(order['amount'])} so'm — FARQ BOR. "
                f"Bog'lansa {fmt_som(order['amount'])} so'm kredit beriladi.")
    text = (
        f"📋 Tasdiqlash\n\n"
        f"Bildirishnoma: {fmt_som(txn['amount'])} so'm ({txn['created_at']})\n"
        f"Buyurtma: #{order['order_ref']} — {fmt_som(order['amount'])} so'm — {order['status']}"
        f"{warn}"
    )
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Bog'lash", callback_data=f"tkr_bindconfirm:{txn_id}:{order_id}")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"tkr_view:{txn_id}")],
    ])
    return text, kb

@user_router.callback_query(F.data.startswith("tkr_pick:"))
async def show_tkr_pick_confirm(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, txn_id, order_id = callback.data.split(":")
    text, kb = await _render_tkr_confirm(int(txn_id), int(order_id))
    if text is None:
        await callback.answer(kb, show_alert=True)
        return
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data.startswith("tkr_bindconfirm:"))
async def tkr_bind_confirm(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, txn_id, order_id = callback.data.split(":")
    txn_id, order_id = int(txn_id), int(order_id)
    ok, msg = await db_manual_match_transaction(txn_id, order_id, callback.from_user.id)
    if ok:
        await log_admin_action(actor=f"admin:{callback.from_user.id}", action="manual_match",
                                result="OK", target=f"txn_{txn_id}_order_{order_id}")
        order = await db_get_order_by_id(order_id)
        if order:
            user = await db_get_user_by_id(order["user_id"])
            if user:
                try:
                    await bot.send_message(
                        user["telegram_id"],
                        f"✅ To'lovingiz tasdiqlandi! Balansingiz {fmt_som(order['amount'])} so'mga to'ldirildi.",
                    )
                except Exception:
                    pass
    await callback.message.edit_text(f"{msg}", reply_markup=back_kb_to("tkr_unmatched:0"))
    await callback.answer()

@user_router.callback_query(F.data.startswith("tkr_dismiss:"))
async def tkr_dismiss(callback: CallbackQuery):
    if not await _require_admin(callback): return
    txn_id = int(callback.data.split(":")[1])
    ok = await db_dismiss_unmatched_transaction(txn_id, callback.from_user.id)
    if not ok:
        await callback.answer("Bu bildirishnoma allaqachon hal qilingan", show_alert=True)
        return
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="manual_dismiss",
                            result="OK", target=f"txn_{txn_id}")
    await callback.message.edit_text("🚫 Rad etildi — hech qanday buyurtmaga bog'lanmadi.",
                                      reply_markup=back_kb_to("tkr_unmatched:0"))
    await callback.answer()


# ---- 🔴 Shubhali to'lovlar (flagged_review) ----
async def _render_tkr_suspicious(page: int) -> tuple[str, InlineKeyboardMarkup]:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        total_row = await db.execute("SELECT COUNT(*) AS c FROM payment_orders WHERE status = 'flagged_review'")
        total = (await total_row.fetchone())["c"]
        rows = await db.execute(
            "SELECT * FROM payment_orders WHERE status = 'flagged_review' ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (TKR_PAGE_SIZE, page * TKR_PAGE_SIZE))
        orders = [dict(r) for r in await rows.fetchall()]
    if not orders:
        text = "🔴 Shubhali to'lovlar\n\nHozircha yo'q." if total == 0 else "🔴 Shubhali to'lovlar\n\nBoshqa sahifa yo'q."
        return text, InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="🔙 Orqaga", callback_data="pm_review")]])
    kb_rows = [[InlineKeyboardButton(text=f"#{o['order_ref']} — {fmt_som(o['amount'])} so'm",
                                      callback_data=f"tkr_susview:{o['id']}")] for o in orders]
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️ Oldingi", callback_data=f"tkr_suspicious:{page - 1}"))
    if (page + 1) * TKR_PAGE_SIZE < total:
        nav.append(InlineKeyboardButton(text="Keyingi ➡️", callback_data=f"tkr_suspicious:{page + 1}"))
    if nav:
        kb_rows.append(nav)
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="pm_review")])
    return f"🔴 Shubhali to'lovlar ({total} ta):", InlineKeyboardMarkup(inline_keyboard=kb_rows)

@user_router.callback_query(F.data.startswith("tkr_suspicious:"))
async def show_tkr_suspicious(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    page = int(callback.data.split(":")[1])
    text, kb = await _render_tkr_suspicious(page)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data.startswith("tkr_susview:"))
async def show_tkr_suspicious_view(callback: CallbackQuery):
    if not await _require_admin(callback): return
    order_id = int(callback.data.split(":")[1])
    order = await db_get_order_by_id(order_id)
    if not order or order["status"] != "flagged_review":
        await callback.answer("Bu buyurtma allaqachon hal qilingan", show_alert=True)
        return
    text = (
        f"🔴 Shubhali to'lov\n\n"
        f"Buyurtma: #{order['order_ref']}\n"
        f"Summa: {fmt_som(order['amount'])} so'm\n"
        f"Sabab: {order.get('flag_reason') or '—'}\n"
        f"Foydalanuvchi (ichki ID): {order['user_id']}\n"
        f"Yaratilgan: {order['created_at']}"
    )
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Tasdiqlash (kredit berish)", callback_data=f"fraudreview_approve:{order_id}")],
        [InlineKeyboardButton(text="❌ Rad etish", callback_data=f"fraudreview_reject:{order_id}")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="tkr_suspicious:0")],
    ])
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()


# ---- 🟢 Tekshirilganlar (admin allaqachon hal qilgan hodisalar) ----
TKR_RESOLVED_EMOJI = {"manual_matched": "✅", "manual_rejected": "🚫",
                       "flagged_approved": "✅", "flagged_rejected": "❌"}

@user_router.callback_query(F.data.startswith("tkr_resolved:"))
async def show_tkr_resolved(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    page = int(callback.data.split(":")[1])
    ph = ",".join("?" * len(PM_REVIEW_RESOLVED_RESULTS))
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        total_row = await db.execute(f"SELECT COUNT(*) AS c FROM payment_transactions WHERE result IN ({ph})",
                                      PM_REVIEW_RESOLVED_RESULTS)
        total = (await total_row.fetchone())["c"]
        rows = await db.execute(
            f"SELECT * FROM payment_transactions WHERE result IN ({ph}) ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (*PM_REVIEW_RESOLVED_RESULTS, TKR_PAGE_SIZE, page * TKR_PAGE_SIZE))
        rows = [dict(r) for r in await rows.fetchall()]
    if not rows:
        text = "🟢 Tekshirilganlar\n\nHali yo'q." if total == 0 else "🟢 Tekshirilganlar\n\nBoshqa sahifa yo'q."
    else:
        lines = [f"{TKR_RESOLVED_EMOJI.get(r['result'], '•')} {fmt_som(r['amount'])} so'm — "
                 f"{r['result']} — {r['created_at']}" for r in rows]
        text = f"🟢 Tekshirilganlar ({total} ta):\n\n" + "\n".join(lines)
    kb = _tkr_pagination_kb("tkr_resolved", page, total)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()


# ---- 🔎 Qidirish (unmatched ro'yxatida summa/matn/ID bo'yicha) ----
@user_router.callback_query(F.data == "tkr_search")
async def tkr_search_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.set_state(TekshiruvStates.waiting_txn_search)
    await callback.message.edit_text("🔎 Summa (masalan 50000), matn qismi yoki bildirishnoma ID yuboring:",
                                      reply_markup=back_kb_to("pm_review"))
    await callback.answer()

@user_router.message(TekshiruvStates.waiting_txn_search)
async def tkr_search_receive(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        return
    query = message.text.strip()
    await state.clear()
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        if query.isdigit() and len(query) <= 6:
            # ID sifatida qidirish
            row = await db.execute("SELECT * FROM payment_transactions WHERE id = ? AND result = 'unmatched'", (int(query),))
            rows = [dict(r) for r in await row.fetchall()]
        else:
            amount_tiyin = parse_exact_som_amount(query)
            if amount_tiyin is not None:
                rows_cur = await db.execute(
                    "SELECT * FROM payment_transactions WHERE result = 'unmatched' AND amount = ? "
                    "ORDER BY created_at DESC LIMIT ?", (amount_tiyin, TKR_PAGE_SIZE))
            else:
                rows_cur = await db.execute(
                    "SELECT * FROM payment_transactions WHERE result = 'unmatched' AND raw_payload LIKE ? "
                    "ORDER BY created_at DESC LIMIT ?", (f"%{query}%", TKR_PAGE_SIZE))
            rows = [dict(r) for r in await rows_cur.fetchall()]
    if not rows:
        await message.answer("Hech narsa topilmadi.", reply_markup=back_kb_to("pm_review"))
        return
    kb_rows = [[InlineKeyboardButton(text=f"💳 {fmt_som(r['amount'])} so'm — {r['created_at']}",
                                      callback_data=f"tkr_view:{r['id']}")] for r in rows]
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="pm_review")])
    await message.answer(f"{len(rows)} ta natija:", reply_markup=InlineKeyboardMarkup(inline_keyboard=kb_rows))


# ---- 5) 📜 To'lovlar tarixi ----
PM_HISTORY_PAGE_SIZE = 8
PM_RESULT_EMOJI = {"matched": "✅", "unmatched": "❓", "duplicate_transaction": "🔁",
                    "invalid_amount": "⚠️", "confirmed": "✅"}

async def _render_pm_history(page: int) -> tuple[str, InlineKeyboardMarkup]:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        total_row = await db.execute("SELECT COUNT(*) AS c FROM payment_transactions")
        total = (await total_row.fetchone())["c"]
        rows = await db.execute(
            "SELECT * FROM payment_transactions ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (PM_HISTORY_PAGE_SIZE, page * PM_HISTORY_PAGE_SIZE),
        )
        rows = [dict(r) for r in await rows.fetchall()]
    if not rows:
        text = "📜 To'lovlar tarixi\n\nHali hodisalar yo'q." if total == 0 else "📜 To'lovlar tarixi\n\nBoshqa sahifa yo'q."
    else:
        lines = []
        for r in rows:
            emoji = PM_RESULT_EMOJI.get(r["result"], "•")
            lines.append(f"{emoji} #{r['id']} — {fmt_som(r['amount'])} so'm — {r['result']} — {r['created_at']}")
        text = f"📜 To'lovlar tarixi ({total} ta):\n\n" + "\n".join(lines)
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️ Oldingi", callback_data=f"pm_history:{page - 1}"))
    if (page + 1) * PM_HISTORY_PAGE_SIZE < total:
        nav.append(InlineKeyboardButton(text="Keyingi ➡️", callback_data=f"pm_history:{page + 1}"))
    kb_rows = [nav] if nav else []
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="payment_manager")])
    return text, InlineKeyboardMarkup(inline_keyboard=kb_rows)

@user_router.callback_query(F.data.startswith("pm_history:"))
async def show_pm_history(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    page = int(callback.data.split(":")[1])
    text, kb = await _render_pm_history(page)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()


# ---- 6) 🛡️ Firibgarlik himoyasi — qoidalarga asoslangan xavfsizlik dvigateli ----
# Bu qoidalar DETERMINISTIK: chegara oshsa ANIQ bir amal bajariladi (blok yoki
# admin tasdig'iga yuborish). AI Payment Supervisor (7-bo'lim) esa buning
# ustida ishlaydigan tahliliy qatlam — o'zi hech qachon kredit/blok qarorini
# to'g'ridan-to'g'ri qabul qilmaydi.
FRAUD_RULE_FIELDS = {
    "fraud_velocity_window_minutes": "Velocity oynasi (daqiqa)",
    "fraud_velocity_max_orders": "Velocity limiti (buyurtma soni)",
    "fraud_large_amount_threshold": "Katta summa chegarasi (so'm, 0=o'chiq)",
}

def pm_fraud_kb(settings: dict) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(text=f"✏️ {label}", callback_data=f"pmfraud_edit:{key}")]
            for key, label in FRAUD_RULE_FIELDS.items()]
    master_label = "🟢 Qo'shimcha qoidalar: yoqilgan" if settings.get("fraud_protection_enabled") else "🔴 Qo'shimcha qoidalar: o'chirilgan"
    rows.append([InlineKeyboardButton(text=master_label, callback_data="pmfraud_toggle_master")])
    rows.append([InlineKeyboardButton(text="📋 Hodisalar jurnali", callback_data="pmfraud_events:0")])
    rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="payment_manager")])
    return InlineKeyboardMarkup(inline_keyboard=rows)

async def _render_pm_fraud() -> tuple[str, InlineKeyboardMarkup]:
    settings = await db_get_payment_settings()
    threshold = settings.get("fraud_large_amount_threshold") or 0
    threshold_line = f"{fmt_som(threshold)} so'm" if threshold > 0 else "o'chirilgan"
    async with db_connect() as db:
        row = await db.execute("SELECT COUNT(*) FROM fraud_events WHERE created_at >= ?",
                                ((utcnow() - timedelta(hours=24)).isoformat(),))
        (events_24h,) = await row.fetchone()
    text = (
        f"🛡️ Firibgarlik himoyasi\n\n"
        f"— Doim yoqilgan (o'chirib bo'lmaydi):\n"
        f"• Har bir provider_trans_id faqat bir marta ishlatiladi\n"
        f"• Faqat aniq summa mosligida kredit beriladi (1 tiyin farq ham yo'q)\n"
        f"• Muddati o'tgan buyurtmalar avtomatik bekor qilinadi\n"
        f"• Webhook faqat maxfiy kalit bilan qabul qilinadi\n\n"
        f"— Sozlanadigan qoidalar:\n"
        f"• Velocity: {settings['fraud_velocity_window_minutes']} daqiqada "
        f"{settings['fraud_velocity_max_orders']} tadan ortiq buyurtma bo'lsa — bloklanadi\n"
        f"• Katta summa chegarasi: {threshold_line} — oshsa avtomatik kredit "
        f"berilmaydi, admin ✅/❌ bilan tasdiqlaydi\n\n"
        f"So'nggi 24 soatda qayd etilgan hodisalar: {events_24h}"
    )
    return text, pm_fraud_kb(settings)

@user_router.callback_query(F.data == "pm_fraud")
async def show_pm_fraud(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    text, kb = await _render_pm_fraud()
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data == "pmfraud_toggle_master")
async def pm_fraud_toggle_master(callback: CallbackQuery):
    if not await _require_admin(callback): return
    settings = await db_get_payment_settings()
    new_val = 0 if settings.get("fraud_protection_enabled") else 1
    await db_update_payment_settings(fraud_protection_enabled=new_val)
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="fraud_protection_toggle",
                            result="OK", reason=str(new_val))
    text, kb = await _render_pm_fraud()
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer("✅ Holat yangilandi")

@user_router.callback_query(F.data.startswith("pmfraud_edit:"))
async def pm_fraud_edit_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    field = callback.data.split(":")[1]
    if field not in FRAUD_RULE_FIELDS:
        await callback.answer("Noma'lum maydon", show_alert=True)
        return
    await state.update_data(pm_fraud_field=field)
    await state.set_state(AdminPaymentManagerStates.waiting_fraud_rule_value)
    hint = " (so'mda, 0 = o'chirish)" if field == "fraud_large_amount_threshold" else ""
    await callback.message.edit_text(f"✏️ {FRAUD_RULE_FIELDS[field]} uchun yangi qiymatni yuboring{hint}:",
                                      reply_markup=back_kb_to("pm_fraud"))
    await callback.answer()

@user_router.message(AdminPaymentManagerStates.waiting_fraud_rule_value)
async def pm_fraud_edit_receive(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        return
    data = await state.get_data()
    field = data["pm_fraud_field"]
    raw = message.text.strip()
    if field == "fraud_large_amount_threshold":
        if raw == "0":
            value = 0
        else:
            tiyin = parse_exact_som_amount(raw)
            if tiyin is None:
                await message.answer("❌ Noto'g'ri summa (yoki o'chirish uchun 0 yuboring). Qaytadan yuboring:")
                return
            value = tiyin
    else:
        if not raw.isdigit() or int(raw) <= 0:
            await message.answer("❌ Musbat butun son kiriting. Qaytadan yuboring:")
            return
        value = int(raw)
    await state.clear()
    await db_update_payment_settings(**{field: value})
    await log_admin_action(actor=f"admin:{message.from_user.id}", action="fraud_rule_edit",
                            result="OK", reason=f"{field}={value}")
    text, kb = await _render_pm_fraud()
    await message.answer(f"✅ Yangilandi.\n\n{text}", reply_markup=kb)

FRAUD_EVENTS_PAGE_SIZE = 8
FRAUD_SEVERITY_EMOJI = {"low": "🟡", "medium": "🟠", "high": "🔴"}

@user_router.callback_query(F.data.startswith("pmfraud_events:"))
async def show_pm_fraud_events(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    page = int(callback.data.split(":")[1])
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        total_row = await db.execute("SELECT COUNT(*) AS c FROM fraud_events")
        total = (await total_row.fetchone())["c"]
        rows = await db.execute(
            "SELECT * FROM fraud_events ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (FRAUD_EVENTS_PAGE_SIZE, page * FRAUD_EVENTS_PAGE_SIZE),
        )
        rows = [dict(r) for r in await rows.fetchall()]
    if not rows:
        text = "📋 Hodisalar jurnali\n\nHali hodisalar yo'q." if total == 0 else "📋 Hodisalar jurnali\n\nBoshqa sahifa yo'q."
    else:
        lines = []
        for r in rows:
            emoji = FRAUD_SEVERITY_EMOJI.get(r["severity"], "•")
            lines.append(f"{emoji} #{r['id']} — {r['rule_key']} — {r['details'] or ''} — {r['created_at']}")
        text = f"📋 Hodisalar jurnali ({total} ta):\n\n" + "\n".join(lines)
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️ Oldingi", callback_data=f"pmfraud_events:{page - 1}"))
    if (page + 1) * FRAUD_EVENTS_PAGE_SIZE < total:
        nav.append(InlineKeyboardButton(text="Keyingi ➡️", callback_data=f"pmfraud_events:{page + 1}"))
    kb_rows = [nav] if nav else []
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="pm_fraud")])
    await callback.message.edit_text(text, reply_markup=InlineKeyboardMarkup(inline_keyboard=kb_rows))
    await callback.answer()


# ---- 7) 🤖 AI Payment Supervisor — 🛡️ ustidagi tahliliy/kuzatuv qatlam ----
# MUHIM CHEGARA: bu bo'lim hech qachon kreditni to'g'ridan-to'g'ri bermaydi
# yoki bloklamaydi — faqat fraud_events/payment_transactions'ni tahlil qilib,
# xavf darajasi va tavsiya chiqaradi. Haqiqiy karor har doim 🛡️ qoidalar
# yoki admin qo'lida qoladi. Hozircha heuristik (qoidaviy) hisob-kitob;
# haqiqiy LLM-tahlil Admin AI Engine bosqichida Provider Manager orqali
# ulanadi (shu paytgacha "AI xulosasi" — statistik xulosa, model chaqiruvi
# emas, matnda ham shu aniq ko'rsatiladi).
def pm_ai_kb(enabled: bool) -> InlineKeyboardMarkup:
    toggle_label = "🔴 O'chirish" if enabled else "🟢 Yoqish"
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=toggle_label, callback_data="pmai_toggle")],
        [InlineKeyboardButton(text="📊 Hisobot (so'nggi 24 soat)", callback_data="pmai_report")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="payment_manager")],
    ])

async def _render_pm_ai() -> tuple[str, InlineKeyboardMarkup]:
    settings = await db_get_payment_settings()
    enabled = bool(settings.get("ai_supervisor_enabled"))
    status_label = "🟢 Yoqilgan" if enabled else "🔴 O'chirilgan"
    text = (
        f"🤖 AI Payment Supervisor\n\n"
        f"Holati: {status_label}\n\n"
        f"ℹ️ 🛡️ Firibgarlik himoyasi qat'iy qoidalarga asoslanadi (chegara "
        f"oshsa — blok/tasdiqqa yuborish). Bu qatlam esa shu qoidalar "
        f"yozgan hodisalar + to'lovlar tarixini tahlil qilib, umumiy xavf "
        f"darajasini va tavsiyani chiqaradi — o'zi hech qachon kredit "
        f"berish yoki bloklash qarorini qabul qilmaydi.\n\n"
        f"Hozircha hisobot heuristik (qoidaviy statistika) asosida "
        f"tuziladi; to'liq LLM-tahlil Admin AI Engine bosqichida ulanadi."
    )
    return text, pm_ai_kb(enabled)

@user_router.callback_query(F.data == "pm_ai")
async def show_pm_ai(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    text, kb = await _render_pm_ai()
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data == "pmai_toggle")
async def pm_ai_toggle(callback: CallbackQuery):
    if not await _require_admin(callback): return
    settings = await db_get_payment_settings()
    new_val = 0 if settings.get("ai_supervisor_enabled") else 1
    await db_update_payment_settings(ai_supervisor_enabled=new_val)
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="ai_payment_supervisor_toggle",
                            result="OK", reason=str(new_val))
    text, kb = await _render_pm_ai()
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer("✅ Holat yangilandi")

def compute_fraud_risk_report(events: list[dict], txns: list[dict]) -> dict:
    """Sof funksiya (test qilish oson) — hodisalar+tranzaksiyalar ro'yxatidan
    heuristik xavf bahosini hisoblaydi. Og'irlik: high=5, medium=2, low=1;
    shuningdek mos kelmagan/noto'g'ri bildirishnomalar nisbati ham qo'shiladi.
    Natija: {"score", "level", "top_rules": [...], "top_users": [...], "summary"}."""
    weight = {"high": 5, "medium": 2, "low": 1}
    score = sum(weight.get(e.get("severity"), 1) for e in events)

    total_notif = len(txns)
    bad_notif = sum(1 for t in txns if t.get("result") in ("unmatched", "invalid_amount", "duplicate_transaction"))
    bad_ratio = (bad_notif / total_notif) if total_notif else 0.0
    score += int(bad_ratio * 20)  # nisbat qancha yuqori bo'lsa, shuncha qo'shimcha ball

    if score >= 25:
        level = "🔴 Yuqori"
    elif score >= 10:
        level = "🟠 O'rta"
    elif score > 0:
        level = "🟡 Past"
    else:
        level = "🟢 Xavfsiz"

    rule_counts: dict[str, int] = {}
    user_counts: dict[int, int] = {}
    for e in events:
        rk = e.get("rule_key") or "unknown"
        rule_counts[rk] = rule_counts.get(rk, 0) + 1
        uid = e.get("user_id")
        if uid:
            user_counts[uid] = user_counts.get(uid, 0) + 1

    top_rules = sorted(rule_counts.items(), key=lambda kv: kv[1], reverse=True)[:3]
    top_users = sorted(user_counts.items(), key=lambda kv: kv[1], reverse=True)[:3]

    if score >= 25:
        recommendation = "Zudlik bilan hodisalar jurnalini qo'lda ko'rib chiqish tavsiya etiladi."
    elif score >= 10:
        recommendation = "Kuzatishni davom ettiring, takrorlanuvchi foydalanuvchilarga e'tibor bering."
    else:
        recommendation = "Alohida amal talab qilinmaydi."

    return {
        "score": score, "level": level, "top_rules": top_rules,
        "top_users": top_users, "bad_ratio": bad_ratio,
        "total_notif": total_notif, "recommendation": recommendation,
    }

@user_router.callback_query(F.data == "pmai_report")
async def pm_ai_report(callback: CallbackQuery):
    if not await _require_admin(callback): return
    since = (utcnow() - timedelta(hours=24)).isoformat()
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        events_rows = await db.execute("SELECT * FROM fraud_events WHERE created_at >= ?", (since,))
        events = [dict(r) for r in await events_rows.fetchall()]
        txn_rows = await db.execute(
            "SELECT * FROM payment_transactions WHERE event_type = 'notification' AND created_at >= ?", (since,))
        txns = [dict(r) for r in await txn_rows.fetchall()]
    report = compute_fraud_risk_report(events, txns)
    rules_line = ", ".join(f"{k} ({v})" for k, v in report["top_rules"]) or "yo'q"
    users_line = ", ".join(f"user#{u} ({c})" for u, c in report["top_users"]) or "yo'q"
    text = (
        f"📊 AI Payment Supervisor hisoboti (so'nggi 24 soat)\n\n"
        f"Xavf darajasi: {report['level']} (ball: {report['score']})\n"
        f"Jami bildirishnomalar: {report['total_notif']}\n"
        f"Mos kelmagan/xato nisbati: {report['bad_ratio'] * 100:.0f}%\n"
        f"Eng ko'p qoidalar: {rules_line}\n"
        f"Eng ko'p qayd etilgan foydalanuvchilar (ichki ID): {users_line}\n\n"
        f"💡 Tavsiya: {report['recommendation']}\n\n"
        f"ℹ️ Bu — heuristik (qoidaviy) hisobot, LLM chaqiruvi emas."
    )
    await callback.message.edit_text(text, reply_markup=back_kb_to("pm_ai"))
    await callback.answer()


# ===================== 👑 ADMIN PANEL: 📊 PLATFORM STATISTIKASI =====================
# Alohida jadval/hisoblovchi yo'q — hammasi mavjud users/bots/servers/transactions
# jadvallaridan real vaqtda hisoblab chiqariladi, shuning uchun raqamlar hech qachon
# DB holatidan chetlashmaydi.

async def db_stats_users() -> dict:
    async with db_connect() as db:
        async with db.execute("SELECT COUNT(*), SUM(is_active = 1), SUM(is_active = 0) FROM users") as cur:
            total, active, blocked = await cur.fetchone()
    return {"total": total or 0, "active": active or 0, "blocked": blocked or 0}

async def db_stats_bots() -> dict:
    async with db_connect() as db:
        async with db.execute(
            "SELECT COUNT(*), SUM(status = 'running'), SUM(status = 'stopped') FROM bots"
        ) as cur:
            total, running, stopped = await cur.fetchone()
    return {"total": total or 0, "running": running or 0, "stopped": stopped or 0}

async def db_stats_servers() -> dict:
    async with db_connect() as db:
        async with db.execute(
            "SELECT COUNT(*), SUM(status != 'offline'), SUM(status = 'offline') FROM servers"
        ) as cur:
            total, active, offline = await cur.fetchone()
    return {"total": total or 0, "active": active or 0, "offline": offline or 0}

async def db_stats_finance() -> dict:
    # Faqat haqiqiy daromad hisoblanadi: admin balans tuzatishlari (admin_adjustment)
    # daromad emas, shu sababli hisobga kirmaydi.
    async with db_connect() as db:
        async with db.execute(
            """SELECT COALESCE(SUM(amount), 0) FROM transactions
               WHERE status = 'paid' AND type != 'admin_adjustment'
               AND date(created_at) = date('now')"""
        ) as cur:
            (today,) = await cur.fetchone()
        async with db.execute(
            """SELECT COALESCE(SUM(amount), 0) FROM transactions
               WHERE status = 'paid' AND type != 'admin_adjustment'
               AND strftime('%Y-%m', created_at) = strftime('%Y-%m', 'now')"""
        ) as cur:
            (month,) = await cur.fetchone()
        async with db.execute(
            """SELECT COALESCE(SUM(amount), 0) FROM transactions
               WHERE status = 'paid' AND type != 'admin_adjustment'"""
        ) as cur:
            (total,) = await cur.fetchone()
    return {"today": today, "month": month, "total": total}

def admin_stats_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔄 Yangilash", callback_data="admin_stats")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="admin_panel")],
    ])

async def _render_admin_stats() -> tuple[str, InlineKeyboardMarkup]:
    users = await db_stats_users()
    bots = await db_stats_bots()
    servers = await db_stats_servers()
    finance = await db_stats_finance()
    text = (
        f"📊 PLATFORM STATISTIKASI\n\n"
        f"👥 Foydalanuvchilar\n"
        f"   Jami: {users['total']:,}\n"
        f"   🟢 Faol: {users['active']:,}\n"
        f"   🔴 Bloklangan: {users['blocked']:,}\n\n"
        f"🤖 Botlar\n"
        f"   Jami: {bots['total']:,}\n"
        f"   🟢 Ishlayapti: {bots['running']:,}\n"
        f"   🔴 To'xtagan: {bots['stopped']:,}\n\n"
        f"🖥️ Serverlar\n"
        f"   Jami: {servers['total']:,}\n"
        f"   🟢 Faol: {servers['active']:,}\n"
        f"   🔴 Offline: {servers['offline']:,}\n\n"
        f"💰 Moliya\n"
        f"   Bugungi daromad: {fmt_som(finance['today'])} so'm\n"
        f"   Oylik daromad: {fmt_som(finance['month'])} so'm\n"
        f"   Umumiy daromad: {fmt_som(finance['total'])} so'm\n\n"
        f"📈 Keyinchalik qo'shiladi: daromad grafigi, yangi foydalanuvchilar/botlar "
        f"dinamikasi, server bandligi, API ishlatilishi, to'lovlar tahlili."
    )
    return text, admin_stats_kb()

@user_router.callback_query(F.data == "admin_stats")
async def show_admin_stats(callback: CallbackQuery):
    if not await _require_admin(callback): return
    text, kb = await _render_admin_stats()
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()


# ===================== 👑 ADMIN AI: 🔑 API POOL (CRUD) =====================
class AdminAIPoolStates(StatesGroup):
    waiting_key = State()
    waiting_model = State()
    waiting_base_url = State()
    waiting_priority = State()

# PROVIDER_CATALOG'dan hosil qilinadi — universal (28-bosqich): yangi provider
# qo'shish uchun faqat PROVIDER_CATALOG'ga yozuv qo'shiladi, bu yerga tegilmaydi.
ADMIN_POOL_PROVIDERS = [(key, info["label"]) for key, info in PROVIDER_CATALOG.items()]
ADMIN_POOL_PAGE_SIZE = 5

def admin_ai_menu_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔑 API Pool", callback_data="adminai_pool")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="admin_panel")],
    ])

def admin_pool_menu_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="➕ API qo'shish", callback_data="adminai_pool_add")],
        [InlineKeyboardButton(text="📋 API kalitlar", callback_data="adminai_pool_list:0")],
        [InlineKeyboardButton(text="🔄 Fallback tartibi", callback_data="adminai_pool_fallback")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="admin_ai")],
    ])

def admin_pool_provider_kb() -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(text=label, callback_data=f"adminai_padd_prov:{key}")]
            for key, label in ADMIN_POOL_PROVIDERS]
    rows.append([InlineKeyboardButton(text="🔙 Bekor qilish", callback_data="adminai_pool")])
    return InlineKeyboardMarkup(inline_keyboard=rows)

def admin_pool_priority_choice_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔚 Oxiriga qo'shish (tavsiya)", callback_data="adminai_padd_prio_auto")],
        [InlineKeyboardButton(text="🔢 Qo'lda kiritish", callback_data="adminai_padd_prio_manual")],
    ])

def admin_pool_confirm_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="💾 Saqlash", callback_data="adminai_padd_save")],
        [InlineKeyboardButton(text="❌ Bekor qilish", callback_data="adminai_pool")],
    ])

def _pool_row_label(row: dict) -> str:
    emoji = ADMIN_POOL_STATUS_EMOJI.get(row["status"], "⚪")
    return f"{emoji} #{row['priority']} {row['display_name']}"

def admin_pool_list_kb(rows: list[dict], page: int, total: int) -> InlineKeyboardMarkup:
    kb_rows = [[InlineKeyboardButton(text=_pool_row_label(r), callback_data=f"adminai_pool_view:{r['id']}")]
               for r in rows]
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️ Oldingi", callback_data=f"adminai_pool_list:{page - 1}"))
    if (page + 1) * ADMIN_POOL_PAGE_SIZE < total:
        nav.append(InlineKeyboardButton(text="Keyingi ➡️", callback_data=f"adminai_pool_list:{page + 1}"))
    if nav:
        kb_rows.append(nav)
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="adminai_pool")])
    return InlineKeyboardMarkup(inline_keyboard=kb_rows)

def admin_pool_view_kb(row: dict) -> InlineKeyboardMarkup:
    toggle_text = "🔴 O'chirib qo'yish" if row["status"] != "disabled" else "🟢 Yoqish"
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✏️ Keyni almashtirish", callback_data=f"adminai_pool_editkey:{row['id']}")],
        [InlineKeyboardButton(text="🧠 Model", callback_data=f"adminai_pool_editmodel:{row['id']}")],
        [InlineKeyboardButton(text="🌐 Base URL", callback_data=f"adminai_pool_editbaseurl:{row['id']}")],
        [InlineKeyboardButton(text="🔢 Priority", callback_data=f"adminai_pool_editpriority:{row['id']}")],
        [InlineKeyboardButton(text=toggle_text, callback_data=f"adminai_pool_toggle:{row['id']}")],
        [InlineKeyboardButton(text="🧪 Tekshirish", callback_data=f"adminai_pool_test:{row['id']}")],
        [InlineKeyboardButton(text="🗑 O'chirish", callback_data=f"adminai_pool_delete:{row['id']}")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="adminai_pool_list:0")],
    ])

def _pool_view_text(row: dict) -> str:
    last_error = f"\nOxirgi xato: {row['last_error']}" if row.get("last_error") else ""
    last_checked = f"\nOxirgi tekshiruv: {row['last_checked_at']}" if row.get("last_checked_at") else ""
    base_url = row.get("base_url") or PROVIDER_CATALOG.get(row["provider"], {}).get("base_url") or "—"
    return (
        f"🔑 {row['display_name']}\n\n"
        f"Provider: {provider_label(row['provider'])}\n"
        f"Key: {mask_token(decrypt_token(row['api_key_encrypted']))}\n"
        f"Model: {row['model_name'] or '—'}\n"
        f"Base URL: {base_url}\n"
        f"Priority: {row['priority']}\n"
        f"Status: {ADMIN_POOL_STATUS_LABEL.get(row['status'], row['status'])}"
        f"{last_error}{last_checked}"
    )

async def _require_admin(callback: CallbackQuery) -> bool:
    if not await is_admin(callback.from_user.id):
        await callback.answer("❌ Ruxsat yo'q", show_alert=True)
        return False
    return True

# --- Admin AI asosiy menyu ---
@user_router.callback_query(F.data == "admin_ai")
async def show_admin_ai_menu(callback: CallbackQuery):
    if not await _require_admin(callback): return
    await callback.message.edit_text("🤖 ADMIN AI", reply_markup=admin_ai_menu_kb())
    await callback.answer()

# --- Pool asosiy menyu ---
@user_router.callback_query(F.data == "adminai_pool")
async def show_admin_pool_menu(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    await callback.message.edit_text("🔑 ADMIN AI API POOL", reply_markup=admin_pool_menu_kb())
    await callback.answer()

# --- 📋 Ro'yxat ---
@user_router.callback_query(F.data.startswith("adminai_pool_list:"))
async def show_admin_pool_list(callback: CallbackQuery):
    if not await _require_admin(callback): return
    page = int(callback.data.split(":")[1])
    all_rows = await db_get_admin_pool_all()
    total = len(all_rows)
    start = page * ADMIN_POOL_PAGE_SIZE
    page_rows = all_rows[start:start + ADMIN_POOL_PAGE_SIZE]
    if not page_rows:
        text = "📋 Hozircha API kalit yo'q." if total == 0 else "Boshqa sahifa yo'q."
    else:
        text = f"📋 API kalitlar ({total} ta):"
    await callback.message.edit_text(text, reply_markup=admin_pool_list_kb(page_rows, page, total))
    await callback.answer()

# --- Bitta kalitni ko'rish/boshqarish ---
@user_router.callback_query(F.data.startswith("adminai_pool_view:"))
async def show_admin_pool_view(callback: CallbackQuery):
    if not await _require_admin(callback): return
    key_id = int(callback.data.split(":")[1])
    row = await db_get_admin_pool_key(key_id)
    if not row:
        await callback.answer("Kalit topilmadi (o'chirilgan bo'lishi mumkin)", show_alert=True)
        return
    await callback.message.edit_text(_pool_view_text(row), reply_markup=admin_pool_view_kb(row))
    await callback.answer()

# ---------- ➕ API qo'shish FSM ----------
@user_router.callback_query(F.data == "adminai_pool_add")
async def admin_pool_add_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    await state.update_data(mode="add")
    await callback.message.edit_text("➕ API qo'shish\n\nProvider tanlang:", reply_markup=admin_pool_provider_kb())
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminai_padd_prov:"))
async def admin_pool_add_provider(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    provider = callback.data.split(":")[1]
    await state.update_data(provider=provider)
    await state.set_state(AdminAIPoolStates.waiting_key)
    await callback.message.edit_text(
        f"Provider: {provider}\n\n🔑 API key'ni yuboring:",
        reply_markup=back_kb_to("adminai_pool"),
    )
    await callback.answer()

@user_router.message(AdminAIPoolStates.waiting_key)
async def admin_pool_add_receive_key(message: Message, state: FSMContext):
    api_key = message.text.strip()
    await message.delete()  # kalit chatda ochiq turib qolmasin
    data = await state.get_data()
    if data.get("mode") == "edit" and data.get("edit_field") == "key":
        key_id = data["edit_id"]
        await db_update_admin_pool_key(key_id, api_key=api_key)
        await state.clear()
        row = await db_get_admin_pool_key(key_id)
        await message.answer("✅ Key yangilandi.", reply_markup=admin_pool_view_kb(row))
        return
    await state.update_data(api_key=api_key)
    await state.set_state(AdminAIPoolStates.waiting_model)
    default_model = DEFAULT_MODELS.get(data.get("provider"), "")
    await message.answer(
        f"🧠 Model nomini yuboring (masalan: {default_model or 'model-nomi'}).\n"
        f"Standart model uchun \"-\" yuboring.",
        reply_markup=back_kb_to("adminai_pool"),
    )

@user_router.message(AdminAIPoolStates.waiting_model)
async def admin_pool_add_receive_model(message: Message, state: FSMContext):
    model = message.text.strip()
    data = await state.get_data()
    provider = data.get("provider") if data.get("mode") != "edit" else (await db_get_admin_pool_key(data["edit_id"]))["provider"]
    model = "" if model == "-" else model
    if data.get("mode") == "edit" and data.get("edit_field") == "model":
        key_id = data["edit_id"]
        await db_update_admin_pool_key(key_id, model_name=model or DEFAULT_MODELS.get(provider, ""))
        await state.clear()
        row = await db_get_admin_pool_key(key_id)
        await message.answer("✅ Model yangilandi.", reply_markup=admin_pool_view_kb(row))
        return
    await state.update_data(model=model or DEFAULT_MODELS.get(provider, ""))
    if provider_needs_base_url(provider):
        await state.set_state(AdminAIPoolStates.waiting_base_url)
        await message.answer(
            "🌐 Bu provider uchun Base URL MAJBURIY (masalan: https://api.myai.com/v1):",
            reply_markup=back_kb_to("adminai_pool"),
        )
        return
    await message.answer("🔢 Fallback priority:", reply_markup=admin_pool_priority_choice_kb())

@user_router.message(AdminAIPoolStates.waiting_base_url)
async def admin_pool_add_receive_base_url(message: Message, state: FSMContext):
    base_url = message.text.strip()
    if not (base_url.startswith("http://") or base_url.startswith("https://")):
        await message.answer("⚠️ Base URL http:// yoki https:// bilan boshlanishi kerak. Qaytadan yuboring:")
        return
    data = await state.get_data()
    if data.get("mode") == "edit" and data.get("edit_field") == "base_url":
        key_id = data["edit_id"]
        await db_update_admin_pool_key(key_id, base_url=base_url)
        await state.clear()
        row = await db_get_admin_pool_key(key_id)
        await message.answer("✅ Base URL yangilandi.", reply_markup=admin_pool_view_kb(row))
        return
    await state.update_data(base_url=base_url)
    await message.answer("🔢 Fallback priority:", reply_markup=admin_pool_priority_choice_kb())

@user_router.callback_query(F.data == "adminai_padd_prio_auto")
async def admin_pool_add_priority_auto(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    priority = await db_next_admin_pool_priority()
    await state.update_data(priority=priority)
    await _admin_pool_show_confirm(callback.message, state, edit=True)
    await callback.answer()

@user_router.callback_query(F.data == "adminai_padd_prio_manual")
async def admin_pool_add_priority_manual(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.set_state(AdminAIPoolStates.waiting_priority)
    await callback.message.edit_text("🔢 Priority raqamini kiriting (1 = eng birinchi):",
                                      reply_markup=back_kb_to("adminai_pool"))
    await callback.answer()

@user_router.message(AdminAIPoolStates.waiting_priority)
async def admin_pool_receive_priority(message: Message, state: FSMContext):
    text = message.text.strip()
    if not text.isdigit():
        await message.answer("Iltimos, faqat raqam kiriting.")
        return
    priority = int(text)
    data = await state.get_data()
    if data.get("mode") == "edit" and data.get("edit_field") == "priority":
        key_id = data["edit_id"]
        await db_set_admin_pool_priority(key_id, priority)
        await state.clear()
        row = await db_get_admin_pool_key(key_id)
        await message.answer("✅ Priority yangilandi.", reply_markup=admin_pool_view_kb(row))
        return
    await state.update_data(priority=priority)
    await _admin_pool_show_confirm(message, state, edit=False)

async def _admin_pool_show_confirm(message: Message, state: FSMContext, edit: bool):
    data = await state.get_data()
    base_url_line = f"\nBase URL: {data['base_url']}" if data.get("base_url") else ""
    text = (
        f"Tasdiqlang:\n\n"
        f"Provider: {provider_label(data['provider'])}\n"
        f"Key: {mask_token(data['api_key'])}\n"
        f"Model: {data['model']}"
        f"{base_url_line}\n"
        f"Priority: {data['priority']}\n"
        f"Status: 🟢 Active"
    )
    if edit:
        await message.edit_text(text, reply_markup=admin_pool_confirm_kb())
    else:
        await message.answer(text, reply_markup=admin_pool_confirm_kb())

@user_router.callback_query(F.data == "adminai_padd_save")
async def admin_pool_add_save(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    data = await state.get_data()
    display_name = f"{provider_label(data['provider'])} #{data['priority']}"
    key_id = await db_create_admin_pool_key(
        provider=data["provider"], model_name=data["model"], display_name=display_name,
        api_key=data["api_key"], priority=data["priority"], is_user_selectable=False,
        base_url=data.get("base_url"),
    )
    await state.clear()
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="admin_ai_pool_add",
                            result="OK", target=f"api_key_{key_id}")
    row = await db_get_admin_pool_key(key_id)
    await callback.message.edit_text(f"✅ Qo'shildi:\n\n{_pool_view_text(row)}", reply_markup=admin_pool_view_kb(row))
    await callback.answer()

# ---------- ✏️ Tahrirlash (mavjud kalit uchun) ----------
@user_router.callback_query(F.data.startswith("adminai_pool_editkey:"))
async def admin_pool_edit_key_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    key_id = int(callback.data.split(":")[1])
    await state.clear()
    await state.update_data(mode="edit", edit_field="key", edit_id=key_id)
    await state.set_state(AdminAIPoolStates.waiting_key)
    await callback.message.edit_text("🔑 Yangi API key'ni yuboring:",
                                      reply_markup=back_kb_to(f"adminai_pool_view:{key_id}"))
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminai_pool_editmodel:"))
async def admin_pool_edit_model_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    key_id = int(callback.data.split(":")[1])
    await state.clear()
    await state.update_data(mode="edit", edit_field="model", edit_id=key_id)
    await state.set_state(AdminAIPoolStates.waiting_model)
    await callback.message.edit_text("🧠 Yangi model nomini yuboring (standart uchun \"-\"):",
                                      reply_markup=back_kb_to(f"adminai_pool_view:{key_id}"))
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminai_pool_editbaseurl:"))
async def admin_pool_edit_baseurl_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    key_id = int(callback.data.split(":")[1])
    await state.clear()
    await state.update_data(mode="edit", edit_field="base_url", edit_id=key_id)
    await state.set_state(AdminAIPoolStates.waiting_base_url)
    await callback.message.edit_text(
        "🌐 Yangi Base URL yuboring (masalan: https://api.myai.com/v1):",
        reply_markup=back_kb_to(f"adminai_pool_view:{key_id}"),
    )
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminai_pool_editpriority:"))
async def admin_pool_edit_priority_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    key_id = int(callback.data.split(":")[1])
    await state.clear()
    await state.update_data(mode="edit", edit_field="priority", edit_id=key_id)
    await state.set_state(AdminAIPoolStates.waiting_priority)
    await callback.message.edit_text("🔢 Yangi priority raqamini kiriting:",
                                      reply_markup=back_kb_to(f"adminai_pool_view:{key_id}"))
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminai_pool_toggle:"))
async def admin_pool_toggle_status(callback: CallbackQuery):
    if not await _require_admin(callback): return
    key_id = int(callback.data.split(":")[1])
    row = await db_get_admin_pool_key(key_id)
    if not row:
        await callback.answer("Kalit topilmadi", show_alert=True)
        return
    if row["status"] != "disabled":
        active_others = await db_count_active_admin_pool_keys(exclude_id=key_id)
        if active_others == 0:
            await callback.answer(
                "⚠️ Bu — yagona faol API kalit. O'chirib qo'ysangiz, Admin AI'da faol kalit qolmaydi.",
                show_alert=True,
            )
        new_status = "disabled"
    else:
        new_status = "active"
    await db_update_admin_pool_key(key_id, status=new_status)
    row = await db_get_admin_pool_key(key_id)
    await callback.message.edit_text(_pool_view_text(row), reply_markup=admin_pool_view_kb(row))
    await callback.answer("✅ Holat yangilandi")

# ---------- 🧪 Tekshirish ----------
@user_router.callback_query(F.data.startswith("adminai_pool_test:"))
async def admin_pool_test(callback: CallbackQuery):
    if not await _require_admin(callback): return
    key_id = int(callback.data.split(":")[1])
    await callback.answer("🧪 Tekshirilmoqda...")
    result = await test_admin_pool_key(key_id)
    row = await db_get_admin_pool_key(key_id)
    if not row:
        return
    if result["ok"]:
        note = "✅ Ishlayapti"
    else:
        note = f"🔴 API ishlamayapti\nSabab: {result['error_label']}"
    await callback.message.edit_text(f"{note}\n\n{_pool_view_text(row)}", reply_markup=admin_pool_view_kb(row))

# ---------- 🗑 O'chirish ----------
@user_router.callback_query(F.data.startswith("adminai_pool_delete:"))
async def admin_pool_delete_confirm_screen(callback: CallbackQuery):
    if not await _require_admin(callback): return
    key_id = int(callback.data.split(":")[1])
    row = await db_get_admin_pool_key(key_id)
    if not row:
        await callback.answer("Kalit topilmadi", show_alert=True)
        return
    warning = ""
    if row["status"] == "active" and await db_count_active_admin_pool_keys(exclude_id=key_id) == 0:
        warning = "\n\n⚠️ Bu — yagona faol API. O'chirilsa, Admin AI hech qanday faol kalitsiz qoladi."
    text = f"⚠️ {row['display_name']} ni o'chirish?\n\nBu API Admin AI fallback tizimidan chiqariladi.{warning}"
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🗑 Ha, o'chirish", callback_data=f"adminai_pool_delete_confirm:{key_id}")],
        [InlineKeyboardButton(text="❌ Bekor qilish", callback_data=f"adminai_pool_view:{key_id}")],
    ])
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminai_pool_delete_confirm:"))
async def admin_pool_delete_execute(callback: CallbackQuery):
    if not await _require_admin(callback): return
    key_id = int(callback.data.split(":")[1])
    row = await db_get_admin_pool_key(key_id)
    await db_delete_admin_pool_key(key_id)
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="admin_ai_pool_delete",
                            result="OK", target=f"api_key_{key_id}",
                            reason=row["display_name"] if row else "")
    await callback.message.edit_text("🗑 O'chirildi.", reply_markup=admin_pool_menu_kb())
    await callback.answer()

# ---------- 🔄 Fallback tartibi ----------
def admin_pool_fallback_kb(rows: list[dict]) -> InlineKeyboardMarkup:
    kb_rows = []
    for i, r in enumerate(rows):
        emoji = ADMIN_POOL_STATUS_EMOJI.get(r["status"], "⚪")
        label = f"{i + 1}️⃣ {r['display_name']} {emoji}"
        move_row = [InlineKeyboardButton(text=label, callback_data=f"adminai_pool_view:{r['id']}")]
        arrows = []
        if i > 0:
            arrows.append(InlineKeyboardButton(text="⬆️", callback_data=f"adminai_pool_moveup:{r['id']}"))
        if i < len(rows) - 1:
            arrows.append(InlineKeyboardButton(text="⬇️", callback_data=f"adminai_pool_movedown:{r['id']}"))
        kb_rows.append(move_row)
        if arrows:
            kb_rows.append(arrows)
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="adminai_pool")])
    return InlineKeyboardMarkup(inline_keyboard=kb_rows)

@user_router.callback_query(F.data == "adminai_pool_fallback")
async def admin_pool_fallback_view(callback: CallbackQuery):
    if not await _require_admin(callback): return
    rows = await db_get_admin_pool_all()
    if not rows:
        await callback.message.edit_text("Hozircha API kalit yo'q.", reply_markup=admin_pool_menu_kb())
        await callback.answer()
        return
    text = "🔄 Fallback tartibi\n\nAdmin AI #1'dan foydalanadi. Xatolik bo'lsa keyingisiga o'tadi."
    await callback.message.edit_text(text, reply_markup=admin_pool_fallback_kb(rows))
    await callback.answer()

async def _swap_priority(key_id: int, direction: int):
    """direction: -1 = yuqoriga, +1 = pastga."""
    rows = await db_get_admin_pool_all()
    idx = next((i for i, r in enumerate(rows) if r["id"] == key_id), None)
    if idx is None: return
    swap_idx = idx + direction
    if swap_idx < 0 or swap_idx >= len(rows): return
    a, b = rows[idx], rows[swap_idx]
    await db_set_admin_pool_priority(a["id"], b["priority"])
    await db_set_admin_pool_priority(b["id"], a["priority"])

@user_router.callback_query(F.data.startswith("adminai_pool_moveup:"))
async def admin_pool_move_up(callback: CallbackQuery):
    if not await _require_admin(callback): return
    key_id = int(callback.data.split(":")[1])
    await _swap_priority(key_id, -1)
    rows = await db_get_admin_pool_all()
    await callback.message.edit_text("🔄 Fallback tartibi\n\nAdmin AI #1'dan foydalanadi. Xatolik bo'lsa keyingisiga o'tadi.",
                                      reply_markup=admin_pool_fallback_kb(rows))
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminai_pool_movedown:"))
async def admin_pool_move_down(callback: CallbackQuery):
    if not await _require_admin(callback): return
    key_id = int(callback.data.split(":")[1])
    await _swap_priority(key_id, 1)
    rows = await db_get_admin_pool_all()
    await callback.message.edit_text("🔄 Fallback tartibi\n\nAdmin AI #1'dan foydalanadi. Xatolik bo'lsa keyingisiga o'tadi.",
                                      reply_markup=admin_pool_fallback_kb(rows))
    await callback.answer()


# ===================== 👑 ADMIN PANEL: 🗄️ BACKUP / RESTORE =====================
def _fmt_size(n: int | None) -> str:
    n = n or 0
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

BACKUP_STATUS_EMOJI = {"ready": "✅", "creating": "⏳", "failed": "❌", "restoring": "♻️"}

def _backup_row_label(r: dict) -> str:
    emoji = BACKUP_STATUS_EMOJI.get(r["status"], "•")
    return f"{emoji} {r['created_at'][:16]} — {_fmt_size(r['file_size'])}"

def _backup_detail_text(r: dict) -> str:
    type_label = {"system": "🌐 System", "bot": "🤖 Bot", "user": "👤 User"}.get(r["owner_type"], r["owner_type"])
    return (
        f"{type_label} Backup #{r['id']}\n\n"
        f"Turi: {r['backup_type']}\n"
        f"Holat: {BACKUP_STATUS_EMOJI.get(r['status'], '')} {r['status']}\n"
        f"Hajmi: {_fmt_size(r['file_size'])}\n"
        f"Checksum: {(r['checksum'] or '')[:16]}...\n"
        f"Yaratilgan: {r['created_at']}\n"
        f"Tiklangan: {r['restored_at'] or '—'}"
    )

def admin_backup_menu_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📦 System Backup yaratish", callback_data="adminbackup_create_system")],
        [InlineKeyboardButton(text="📋 System Backup ro'yxati", callback_data="adminbackup_list:system:0:0")],
        [InlineKeyboardButton(text="🤖 Bot Backup yaratish", callback_data="adminbackup_pickbot:create:0")],
        [InlineKeyboardButton(text="♻️ Bot Restore", callback_data="adminbackup_pickbot:restore:0")],
        [InlineKeyboardButton(text="🧹 Eski backuplarni tozalash", callback_data="adminbackup_cleanup")],
        [InlineKeyboardButton(text="⚙️ Backup sozlamalari", callback_data="adminbackup_settings")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="admin_panel")],
    ])

def admin_backup_list_kb(rows: list[dict], owner_type: str, owner_id: int, page: int, total: int) -> InlineKeyboardMarkup:
    kb_rows = [[InlineKeyboardButton(text=_backup_row_label(r),
                                      callback_data=f"adminbackup_view:{r['id']}:{owner_type}:{owner_id}:{page}")]
               for r in rows]
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️ Oldingi", callback_data=f"adminbackup_list:{owner_type}:{owner_id}:{page - 1}"))
    if (page + 1) * 5 < total:
        nav.append(InlineKeyboardButton(text="Keyingi ➡️", callback_data=f"adminbackup_list:{owner_type}:{owner_id}:{page + 1}"))
    if nav:
        kb_rows.append(nav)
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="admin_backup")])
    return InlineKeyboardMarkup(inline_keyboard=kb_rows)

def admin_backup_detail_kb(backup_id: int, owner_type: str, owner_id: int, page: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="♻️ Tiklash", callback_data=f"adminbackup_restore_ask:{backup_id}:{owner_type}:{owner_id}:{page}")],
        [InlineKeyboardButton(text="🗑 O'chirish", callback_data=f"adminbackup_delete_ask:{backup_id}:{owner_type}:{owner_id}:{page}")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"adminbackup_list:{owner_type}:{owner_id}:{page}")],
    ])

@user_router.callback_query(F.data == "admin_backup")
async def show_admin_backup_menu(callback: CallbackQuery):
    if not await _require_admin(callback): return
    await callback.message.edit_text("🗄️ BACKUP / RESTORE", reply_markup=admin_backup_menu_kb())
    await callback.answer()

@user_router.callback_query(F.data == "adminbackup_create_system")
async def admin_backup_create_system(callback: CallbackQuery):
    if not await _require_admin(callback): return
    await callback.answer("📦 Backup tayyorlanmoqda...")
    backup_id = await create_system_backup(callback.from_user.id)
    settings = await db_get_backup_settings()
    await enforce_backup_retention("system", 0, settings["retention_count"])
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="system_backup_create",
                            result="OK", target=f"backup_{backup_id}")
    row = await db_get_backup(backup_id)
    await callback.message.edit_text(f"✅ Tayyor:\n\n{_backup_detail_text(row)}",
                                      reply_markup=admin_backup_detail_kb(backup_id, "system", 0, 0))

@user_router.callback_query(F.data.startswith("adminbackup_list:"))
async def admin_backup_list(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, owner_type, owner_id, page = callback.data.split(":")
    owner_id, page = int(owner_id), int(page)
    rows, total = await db_list_backups(owner_type, owner_id, page)
    header = {"system": "📋 System Backup ro'yxati", "bot": f"📋 Bot #{owner_id} backuplari"}.get(owner_type, "📋 Backuplar")
    text = f"{header} ({total} ta):" if rows else (f"{header}\n\nHozircha backup yo'q." if total == 0 else f"{header}\n\nBoshqa sahifa yo'q.")
    await callback.message.edit_text(text, reply_markup=admin_backup_list_kb(rows, owner_type, owner_id, page, total))
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminbackup_view:"))
async def admin_backup_view(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, backup_id, owner_type, owner_id, page = callback.data.split(":")
    row = await db_get_backup(int(backup_id))
    if not row:
        await callback.answer("Backup topilmadi", show_alert=True)
        return
    await callback.message.edit_text(_backup_detail_text(row),
                                      reply_markup=admin_backup_detail_kb(int(backup_id), owner_type, int(owner_id), int(page)))
    await callback.answer()

# --- 🤖 Bot tanlash (backup yaratish / restore uchun) ---
def admin_backup_botpicker_kb(rows: list[dict], action: str, page: int, total: int) -> InlineKeyboardMarkup:
    kb_rows = [[InlineKeyboardButton(text=_admin_bot_row_label(r),
                                      callback_data=f"adminbackup_bot:{action}:{r['id']}:{page}")] for r in rows]
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️ Oldingi", callback_data=f"adminbackup_pickbot:{action}:{page - 1}"))
    if (page + 1) * 8 < total:
        nav.append(InlineKeyboardButton(text="Keyingi ➡️", callback_data=f"adminbackup_pickbot:{action}:{page + 1}"))
    if nav:
        kb_rows.append(nav)
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="admin_backup")])
    return InlineKeyboardMarkup(inline_keyboard=kb_rows)

@user_router.callback_query(F.data.startswith("adminbackup_pickbot:"))
async def admin_backup_pickbot(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, action, page = callback.data.split(":")
    page = int(page)
    rows, total = await db_admin_bots_query("all", None, page, page_size=8)
    title = "🤖 Backup yaratish uchun bot tanlang:" if action == "create" else "♻️ Restore uchun bot tanlang:"
    await callback.message.edit_text(title, reply_markup=admin_backup_botpicker_kb(rows, action, page, total))
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminbackup_bot:"))
async def admin_backup_bot_selected(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, action, bot_id, page = callback.data.split(":")
    bot_id = int(bot_id)
    if action == "create":
        await callback.answer("📦 Backup tayyorlanmoqda...")
        backup_id = await create_bot_backup(bot_id, callback.from_user.id)
        settings = await db_get_backup_settings()
        await enforce_backup_retention("bot", bot_id, settings["retention_count"])
        await log_admin_action(actor=f"admin:{callback.from_user.id}", action="bot_backup_create",
                                result="OK", target=f"bot_{bot_id}")
        row = await db_get_backup(backup_id)
        await callback.message.edit_text(f"✅ Tayyor:\n\n{_backup_detail_text(row)}",
                                          reply_markup=admin_backup_detail_kb(backup_id, "bot", bot_id, 0))
    else:
        rows, total = await db_list_backups("bot", bot_id, 0)
        text = f"📋 Bot #{bot_id} backuplari ({total} ta):" if rows else "Bu bot uchun hali backup yo'q."
        await callback.message.edit_text(text, reply_markup=admin_backup_list_kb(rows, "bot", bot_id, 0, total))
        await callback.answer()

# --- ♻️ Tiklash / 🗑 O'chirish (tasdiqlash bilan) ---
@user_router.callback_query(F.data.startswith("adminbackup_restore_ask:"))
async def admin_backup_restore_ask(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, backup_id, owner_type, owner_id, page = callback.data.split(":")
    text = ("⚠️ Ushbu backupni tiklashni tasdiqlaysizmi?\n\n"
            "Tiklashdan oldin joriy holatning avtomatik xavfsizlik nusxasi olinadi.")
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="♻️ Ha, tiklash", callback_data=f"adminbackup_restore_do:{backup_id}:{owner_type}:{owner_id}:{page}")],
        [InlineKeyboardButton(text="❌ Bekor qilish", callback_data=f"adminbackup_view:{backup_id}:{owner_type}:{owner_id}:{page}")],
    ])
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminbackup_restore_do:"))
async def admin_backup_restore_do(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, backup_id, owner_type, owner_id, page = callback.data.split(":")
    backup_id, owner_id, page = int(backup_id), int(owner_id), int(page)
    if owner_type == "system":
        ok, msg = await restore_system_backup(backup_id, callback.from_user.id)
    elif owner_type == "bot":
        ok, msg = await restore_bot_backup(backup_id, callback.from_user.id)
    else:
        ok, msg = False, "Bu backup turi uchun restore hali qo'llab-quvvatlanmaydi"
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action=f"{owner_type}_restore",
                            result=msg, target=f"backup_{backup_id}")
    row = await db_get_backup(backup_id)
    await callback.message.edit_text(f"{msg}\n\n{_backup_detail_text(row)}",
                                      reply_markup=admin_backup_detail_kb(backup_id, owner_type, owner_id, page))
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminbackup_delete_ask:"))
async def admin_backup_delete_ask(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, backup_id, owner_type, owner_id, page = callback.data.split(":")
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🗑 Ha, o'chirish", callback_data=f"adminbackup_delete_do:{backup_id}:{owner_type}:{owner_id}:{page}")],
        [InlineKeyboardButton(text="❌ Bekor qilish", callback_data=f"adminbackup_view:{backup_id}:{owner_type}:{owner_id}:{page}")],
    ])
    await callback.message.edit_text("⚠️ Backupni o'chirish? Bu amalni orqaga qaytarib bo'lmaydi.", reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminbackup_delete_do:"))
async def admin_backup_delete_do(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, backup_id, owner_type, owner_id, page = callback.data.split(":")
    backup_id, owner_id, page = int(backup_id), int(owner_id), int(page)
    await db_delete_backup_record(backup_id)
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="backup_delete",
                            result="OK", target=f"backup_{backup_id}")
    await callback.message.edit_text("🗑 O'chirildi.", reply_markup=admin_backup_menu_kb())
    await callback.answer()

# --- 🧹 Eski backuplarni tozalash ---
@user_router.callback_query(F.data == "adminbackup_cleanup")
async def admin_backup_cleanup(callback: CallbackQuery):
    if not await _require_admin(callback): return
    settings = await db_get_backup_settings()
    _, before_total = await db_list_backups("system", 0, 0, page_size=1)
    await enforce_backup_retention("system", 0, settings["retention_count"])
    _, after_total = await db_list_backups("system", 0, 0, page_size=1)
    await callback.answer(f"🧹 {before_total - after_total} ta eski system backup o'chirildi", show_alert=True)
    await callback.message.edit_text("🗄️ BACKUP / RESTORE", reply_markup=admin_backup_menu_kb())

# --- ⚙️ Backup sozlamalari ---
def admin_backup_settings_kb(settings: dict, back_to: str = "admin_backup") -> InlineKeyboardMarkup:
    auto_label = "✅ Yoqilgan" if settings["auto_backup_enabled"] else "❌ O'chirilgan"
    enc_label = "✅ Yoqilgan" if settings.get("encryption_enabled") else "❌ O'chirilgan"
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=f"Avtomatik backup: {auto_label}", callback_data="adminbackup_toggle_auto")],
        [InlineKeyboardButton(text=f"Interval: {settings['interval_days']} kun", callback_data="adminbackup_pick_interval")],
        [InlineKeyboardButton(text=f"Saqlash soni: {settings['retention_count']}", callback_data="adminbackup_pick_retention")],
        [InlineKeyboardButton(text=f"🔐 Shifrlash: {enc_label}", callback_data="adminbackup_toggle_encryption")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data=back_to)],
    ])

@user_router.callback_query(F.data == "adminbackup_settings")
async def admin_backup_settings_view(callback: CallbackQuery):
    if not await _require_admin(callback): return
    settings = await db_get_backup_settings()
    await callback.message.edit_text("⚙️ Backup sozlamalari", reply_markup=admin_backup_settings_kb(settings))
    await callback.answer()

@user_router.callback_query(F.data == "sysset_backup")
async def sysset_backup_settings_view(callback: CallbackQuery):
    if not await _require_admin(callback): return
    settings = await db_get_backup_settings()
    await callback.message.edit_text("⚙️ Backup sozlamalari", reply_markup=admin_backup_settings_kb(settings, back_to="sysset_menu"))
    await callback.answer()

@user_router.callback_query(F.data == "adminbackup_toggle_auto")
async def admin_backup_toggle_auto(callback: CallbackQuery):
    if not await _require_admin(callback): return
    settings = await db_get_backup_settings()
    await db_update_backup_settings(auto_backup_enabled=0 if settings["auto_backup_enabled"] else 1)
    settings = await db_get_backup_settings()
    await callback.message.edit_text("⚙️ Backup sozlamalari", reply_markup=admin_backup_settings_kb(settings))
    await callback.answer()

@user_router.callback_query(F.data == "adminbackup_toggle_encryption")
async def admin_backup_toggle_encryption(callback: CallbackQuery):
    if not await _require_admin(callback): return
    settings = await db_get_backup_settings()
    await db_update_backup_settings(encryption_enabled=0 if settings.get("encryption_enabled") else 1)
    settings = await db_get_backup_settings()
    await callback.message.edit_text("⚙️ Backup sozlamalari", reply_markup=admin_backup_settings_kb(settings))
    await callback.answer("✅ Yangilandi. Faqat KEYINGI backuplarga ta'sir qiladi.")

@user_router.callback_query(F.data == "adminbackup_pick_interval")
async def admin_backup_pick_interval(callback: CallbackQuery):
    if not await _require_admin(callback): return
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Kunlik (1)", callback_data="adminbackup_setinterval:1"),
         InlineKeyboardButton(text="Haftalik (7)", callback_data="adminbackup_setinterval:7")],
        [InlineKeyboardButton(text="Oylik (30)", callback_data="adminbackup_setinterval:30")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="adminbackup_settings")],
    ])
    await callback.message.edit_text("Interval tanlang:", reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminbackup_setinterval:"))
async def admin_backup_set_interval(callback: CallbackQuery):
    if not await _require_admin(callback): return
    days = int(callback.data.split(":")[1])
    await db_update_backup_settings(interval_days=days)
    settings = await db_get_backup_settings()
    await callback.message.edit_text("⚙️ Backup sozlamalari", reply_markup=admin_backup_settings_kb(settings))
    await callback.answer("✅ Yangilandi")

@user_router.callback_query(F.data == "adminbackup_pick_retention")
async def admin_backup_pick_retention(callback: CallbackQuery):
    if not await _require_admin(callback): return
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="3", callback_data="adminbackup_setretention:3"),
         InlineKeyboardButton(text="5", callback_data="adminbackup_setretention:5"),
         InlineKeyboardButton(text="7", callback_data="adminbackup_setretention:7"),
         InlineKeyboardButton(text="14", callback_data="adminbackup_setretention:14")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="adminbackup_settings")],
    ])
    await callback.message.edit_text("Nechta backup saqlansin?", reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data.startswith("adminbackup_setretention:"))
async def admin_backup_set_retention(callback: CallbackQuery):
    if not await _require_admin(callback): return
    count = int(callback.data.split(":")[1])
    await db_update_backup_settings(retention_count=count)
    settings = await db_get_backup_settings()
    await callback.message.edit_text("⚙️ Backup sozlamalari", reply_markup=admin_backup_settings_kb(settings))
    await callback.answer("✅ Yangilandi")


# ===================== 👤 USER: 🗄️ BOTIMGA BACKUP / TIKLASH =====================
@user_router.callback_query(F.data == "user_backup_menu")
async def show_user_backup_menu(callback: CallbackQuery):
    bots = await db_get_user_bots(callback.from_user.id)
    if not bots:
        await callback.answer("Sizda hali bot yo'q", show_alert=True)
        return
    kb_rows = [[InlineKeyboardButton(text=f"🤖 {b['name']}", callback_data=f"userbackup_bot:{b['id']}")] for b in bots]
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="nav:main")])
    await callback.message.edit_text("🗄️ Qaysi botingiz uchun backup?", reply_markup=InlineKeyboardMarkup(inline_keyboard=kb_rows))
    await callback.answer()

def user_backup_bot_menu_kb(bot_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📦 Backup yaratish", callback_data=f"userbackup_create:{bot_id}")],
        [InlineKeyboardButton(text="📋 Mening backuplarim", callback_data=f"userbackup_list:{bot_id}:0")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="user_backup_menu")],
    ])

@user_router.callback_query(F.data.startswith("userbackup_bot:"))
async def show_user_backup_bot_menu(callback: CallbackQuery):
    bot_id = int(callback.data.split(":")[1])
    if not await _get_owned_bot(callback.from_user.id, bot_id):
        await callback.answer("❌ Ruxsat yo'q", show_alert=True)
        return
    await callback.message.edit_text("🗄️ Botimga backup", reply_markup=user_backup_bot_menu_kb(bot_id))
    await callback.answer()

@user_router.callback_query(F.data.startswith("userbackup_create:"))
async def user_backup_create(callback: CallbackQuery):
    bot_id = int(callback.data.split(":")[1])
    if not await _get_owned_bot(callback.from_user.id, bot_id):
        await callback.answer("❌ Ruxsat yo'q", show_alert=True)
        return
    await callback.answer("📦 Backup tayyorlanmoqda...")
    backup_id = await create_bot_backup(bot_id, callback.from_user.id)
    settings = await db_get_backup_settings()
    await enforce_backup_retention("bot", bot_id, settings["retention_count"])
    row = await db_get_backup(backup_id)
    kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"userbackup_bot:{bot_id}")]])
    await callback.message.edit_text(f"✅ Tayyor:\n\n{_backup_detail_text(row)}", reply_markup=kb)

@user_router.callback_query(F.data.startswith("userbackup_list:"))
async def user_backup_list(callback: CallbackQuery):
    _, bot_id, page = callback.data.split(":")
    bot_id, page = int(bot_id), int(page)
    if not await _get_owned_bot(callback.from_user.id, bot_id):
        await callback.answer("❌ Ruxsat yo'q", show_alert=True)
        return
    rows, total = await db_list_backups("bot", bot_id, page)
    kb_rows = [[InlineKeyboardButton(text=_backup_row_label(r), callback_data=f"userbackup_view:{r['id']}:{bot_id}:{page}")] for r in rows]
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️ Oldingi", callback_data=f"userbackup_list:{bot_id}:{page - 1}"))
    if (page + 1) * 5 < total:
        nav.append(InlineKeyboardButton(text="Keyingi ➡️", callback_data=f"userbackup_list:{bot_id}:{page + 1}"))
    if nav:
        kb_rows.append(nav)
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"userbackup_bot:{bot_id}")])
    text = f"📋 Backuplaringiz ({total} ta):" if rows else "Hozircha backup yo'q."
    await callback.message.edit_text(text, reply_markup=InlineKeyboardMarkup(inline_keyboard=kb_rows))
    await callback.answer()

@user_router.callback_query(F.data.startswith("userbackup_view:"))
async def user_backup_view(callback: CallbackQuery):
    _, backup_id, bot_id, page = callback.data.split(":")
    bot_id = int(bot_id)
    if not await _get_owned_bot(callback.from_user.id, bot_id):
        await callback.answer("❌ Ruxsat yo'q", show_alert=True)
        return
    row = await db_get_backup(int(backup_id))
    if not row or row["owner_type"] != "bot" or row["owner_id"] != bot_id:
        await callback.answer("Backup topilmadi", show_alert=True)
        return
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="♻️ Tiklash", callback_data=f"userbackup_restore_ask:{backup_id}:{bot_id}:{page}")],
        [InlineKeyboardButton(text="🗑 O'chirish", callback_data=f"userbackup_delete_ask:{backup_id}:{bot_id}:{page}")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"userbackup_list:{bot_id}:{page}")],
    ])
    await callback.message.edit_text(_backup_detail_text(row), reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data.startswith("userbackup_restore_ask:"))
async def user_backup_restore_ask(callback: CallbackQuery):
    _, backup_id, bot_id, page = callback.data.split(":")
    if not await _get_owned_bot(callback.from_user.id, int(bot_id)):
        await callback.answer("❌ Ruxsat yo'q", show_alert=True)
        return
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="♻️ Ha, tiklash", callback_data=f"userbackup_restore_do:{backup_id}:{bot_id}:{page}")],
        [InlineKeyboardButton(text="❌ Bekor qilish", callback_data=f"userbackup_view:{backup_id}:{bot_id}:{page}")],
    ])
    await callback.message.edit_text(
        "⚠️ Botingizni ushbu backupdan tiklashni tasdiqlaysizmi?\n\n"
        "Joriy holatdan avtomatik xavfsizlik nusxasi olinadi, so'ng bot qayta ishga tushirilishi kerak bo'ladi.",
        reply_markup=kb,
    )
    await callback.answer()

@user_router.callback_query(F.data.startswith("userbackup_restore_do:"))
async def user_backup_restore_do(callback: CallbackQuery):
    _, backup_id, bot_id, page = callback.data.split(":")
    backup_id, bot_id, page = int(backup_id), int(bot_id), int(page)
    if not await _get_owned_bot(callback.from_user.id, bot_id):
        await callback.answer("❌ Ruxsat yo'q", show_alert=True)
        return
    ok, msg = await restore_bot_backup(backup_id, callback.from_user.id)
    row = await db_get_backup(backup_id)
    kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="🔙 Orqaga", callback_data=f"userbackup_bot:{bot_id}")]])
    await callback.message.edit_text(f"{msg}\n\n{_backup_detail_text(row)}", reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data.startswith("userbackup_delete_ask:"))
async def user_backup_delete_ask(callback: CallbackQuery):
    _, backup_id, bot_id, page = callback.data.split(":")
    if not await _get_owned_bot(callback.from_user.id, int(bot_id)):
        await callback.answer("❌ Ruxsat yo'q", show_alert=True)
        return
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🗑 Ha, o'chirish", callback_data=f"userbackup_delete_do:{backup_id}:{bot_id}:{page}")],
        [InlineKeyboardButton(text="❌ Bekor qilish", callback_data=f"userbackup_view:{backup_id}:{bot_id}:{page}")],
    ])
    await callback.message.edit_text("⚠️ Backupni o'chirish? Bu amalni orqaga qaytarib bo'lmaydi.", reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data.startswith("userbackup_delete_do:"))
async def user_backup_delete_do(callback: CallbackQuery):
    _, backup_id, bot_id, page = callback.data.split(":")
    bot_id = int(bot_id)
    if not await _get_owned_bot(callback.from_user.id, bot_id):
        await callback.answer("❌ Ruxsat yo'q", show_alert=True)
        return
    await db_delete_backup_record(int(backup_id))
    await callback.message.edit_text("🗑 O'chirildi.", reply_markup=user_backup_bot_menu_kb(bot_id))
    await callback.answer()


# ===================== 👑 ADMIN PANEL: 💳 CLICK SOZLAMALARI FSM =====================
# Qiymatlar avval FSM state'dagi "click_draft"ga yoziladi (hali DB'ga
# tegmaydi), faqat 💾 Saqlash bosilganda bitta UPDATE bilan click_settings'ga
# yoziladi — shu tufayli yarim to'ldirilgan/bekor qilingan kiritish DB'da
# noto'g'ri holatda qolmaydi. Secret Key admin interfeysida hech qachon
# to'liq ko'rsatilmaydi (faqat mask_token orqali oxirgi 4 belgi), DB'da esa
# doim encrypt_token() bilan shifrlangan holda saqlanadi.

class ClickSettingsStates(StatesGroup):
    waiting_field = State()

CLICK_FIELD_LABELS = {
    "merchant_id": "Merchant ID",
    "service_id": "Service ID",
    "secret_key": "Secret Key",
    "callback_url": "Callback URL",
}

# Whitelist — db_update_click_settings faqat shu ustunlarga yozadi
# (foydalanuvchi kiritgan matn hech qachon ustun nomiga aylanmaydi).
CLICK_UPDATABLE_COLUMNS = {"merchant_id", "service_id", "secret_key_encrypted", "callback_url"}

async def db_update_click_settings(**fields) -> None:
    cols = {k: v for k, v in fields.items() if k in CLICK_UPDATABLE_COLUMNS}
    if not cols:
        return
    set_clause = ", ".join(f"{col} = ?" for col in cols)
    async with db_connect() as db:
        await db.execute(
            f"UPDATE click_settings SET {set_clause}, updated_at = ? WHERE id = 1",
            (*cols.values(), utcnow().isoformat()),
        )
        await db.commit()

def _click_merged(db_row: dict, draft: dict) -> dict:
    """DB qiymatlarini draft (hali saqlanmagan) qiymatlar bilan birlashtiradi — faqat ko'rsatish uchun."""
    merged = dict(db_row)
    for f in ("merchant_id", "service_id", "callback_url"):
        if f in draft:
            merged[f] = draft[f]
    if "secret_key" in draft:
        merged["_draft_secret_key"] = draft["secret_key"]  # faqat mask uchun, hech qachon chop etilmaydi
    return merged

def _click_status(merged: dict) -> str:
    has_secret = bool(merged.get("secret_key_encrypted")) or bool(merged.get("_draft_secret_key"))
    configured = all([merged.get("merchant_id"), merged.get("service_id"), has_secret, merged.get("callback_url")])
    return "🟢 Sozlangan" if configured else "🔴 Sozlanmagan"

def _click_settings_text(merged: dict, draft: dict) -> str:
    secret_display = "—"
    if merged.get("_draft_secret_key"):
        secret_display = f"{mask_token(merged['_draft_secret_key'])} (hali saqlanmagan)"
    elif merged.get("secret_key_encrypted"):
        secret_display = mask_token(decrypt_token(merged["secret_key_encrypted"]))
    pending_note = "\n\n✏️ Saqlanmagan o'zgarishlar bor — 💾 Saqlash bosing." if draft else ""
    return (
        f"💳 CLICK SOZLAMALARI\n\n"
        f"Merchant ID: {merged.get('merchant_id') or '—'}\n"
        f"Service ID: {merged.get('service_id') or '—'}\n"
        f"Secret Key: {secret_display}\n"
        f"Callback URL: {merged.get('callback_url') or '—'}\n\n"
        f"Holat: {_click_status(merged)}"
        f"{pending_note}"
    )

def click_settings_kb(draft: dict) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text="✏️ Merchant ID", callback_data="click_edit:merchant_id")],
        [InlineKeyboardButton(text="✏️ Service ID", callback_data="click_edit:service_id")],
        [InlineKeyboardButton(text="🔐 Secret Key", callback_data="click_edit:secret_key")],
        [InlineKeyboardButton(text="🌐 Callback URL", callback_data="click_edit:callback_url")],
        [InlineKeyboardButton(text="🧪 Ulanishni tekshirish", callback_data="click_test")],
    ]
    if draft:
        rows.append([InlineKeyboardButton(text="💾 Saqlash", callback_data="click_save")])
    rows.append([InlineKeyboardButton(text="🗑️ Tozalash", callback_data="click_clear_ask")])
    rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="admin_panel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)

async def _render_click_menu(state: FSMContext) -> tuple[str, InlineKeyboardMarkup]:
    data = await state.get_data()
    draft = data.get("click_draft", {})
    db_row = await db_get_click_settings()
    merged = _click_merged(db_row, draft)
    return _click_settings_text(merged, draft), click_settings_kb(draft)

# --- Asosiy menyu ---
@user_router.callback_query(F.data == "click_settings")
async def show_click_settings(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.set_state(None)  # faqat aktiv FSM holatini tozalaydi, click_draft saqlanib qoladi
    text, kb = await _render_click_menu(state)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

# --- ✏️ Bitta maydonni tahrirlash ---
@user_router.callback_query(F.data.startswith("click_edit:"))
async def click_edit_field(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    field = callback.data.split(":")[1]
    if field not in CLICK_FIELD_LABELS:
        await callback.answer("Noma'lum maydon", show_alert=True)
        return
    await state.update_data(click_edit_field=field)
    await state.set_state(ClickSettingsStates.waiting_field)
    note = "\n\n🔐 Xavfsizlik uchun bu xabar chatdan avtomatik o'chiriladi." if field == "secret_key" else ""
    await callback.message.edit_text(
        f"✏️ {CLICK_FIELD_LABELS[field]}\n\nYangi qiymatni yuboring:{note}",
        reply_markup=back_kb_to("click_settings"),
    )
    await callback.answer()

@user_router.message(ClickSettingsStates.waiting_field)
async def click_receive_field(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        return
    data = await state.get_data()
    field = data.get("click_edit_field")
    value = (message.text or "").strip()
    if field == "secret_key":
        await message.delete()  # kalit chatda ochiq turib qolmasin
    if field not in CLICK_FIELD_LABELS:
        await state.set_state(None)
        return
    if not value:
        await message.answer("❌ Bo'sh qiymat qabul qilinmaydi. Qaytadan yuboring:")
        return
    if field == "callback_url" and not (value.startswith("https://") or value.startswith("http://")):
        await message.answer("❌ Callback URL http:// yoki https:// bilan boshlanishi kerak. Qaytadan yuboring:")
        return
    draft = data.get("click_draft", {})
    draft[field] = value
    await state.update_data(click_draft=draft)
    await state.set_state(None)
    await message.answer(f"✅ {CLICK_FIELD_LABELS[field]} qabul qilindi (hali saqlanmagan).")
    text, kb = await _render_click_menu(state)
    await message.answer(text, reply_markup=kb)

# --- 🧪 Ulanishni tekshirish (konfiguratsiya validatsiyasi) ---
@user_router.callback_query(F.data == "click_test")
async def click_test_connection(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    data = await state.get_data()
    draft = data.get("click_draft", {})
    db_row = await db_get_click_settings()
    merged = _click_merged(db_row, draft)

    problems = []
    if not merged.get("merchant_id"):
        problems.append("Merchant ID kiritilmagan")
    if not merged.get("service_id"):
        problems.append("Service ID kiritilmagan")
    if not (merged.get("secret_key_encrypted") or merged.get("_draft_secret_key")):
        problems.append("Secret Key kiritilmagan")
    callback_url = merged.get("callback_url")
    if not callback_url:
        problems.append("Callback URL kiritilmagan")
    elif not callback_url.startswith("https://"):
        problems.append("Callback URL https:// bilan boshlanishi kerak (Click faqat https qabul qiladi)")
    elif "/click/callback" not in callback_url:
        problems.append("Callback URL '/click/callback' yo'lini o'z ichiga olishi tavsiya etiladi")

    if problems:
        result = "🔴 Sozlamalar to'liq emas:\n" + "\n".join(f"• {p}" for p in problems)
    else:
        pay_url = _build_click_pay_url(
            {"merchant_id": merged["merchant_id"], "service_id": merged["service_id"]}, 1000, "test",
        )
        result = (
            "🟢 Konfiguratsiya to'liq va formati to'g'ri.\n"
            f"Namuna to'lov havolasi yasaldi: {pay_url}\n\n"
            "⚠️ Bu faqat sozlamalar formatini tekshiradi — haqiqiy Click "
            "sandbox/production bilan real ulanish alohida bosqichda "
            "(Prepare/Complete callback orqali) tekshiriladi."
        )
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="click_test_config",
                            result="OK" if not problems else "FAIL", target="click_settings")
    _, kb = await _render_click_menu(state)
    await callback.message.edit_text(result, reply_markup=kb)
    await callback.answer()

# --- 💾 Saqlash ---
@user_router.callback_query(F.data == "click_save")
async def click_save(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    data = await state.get_data()
    draft = data.get("click_draft", {})
    if not draft:
        await callback.answer("Saqlash uchun o'zgarish yo'q.", show_alert=True)
        return
    update_fields = {}
    for f in ("merchant_id", "service_id", "callback_url"):
        if f in draft:
            update_fields[f] = draft[f]
    if "secret_key" in draft:
        update_fields["secret_key_encrypted"] = encrypt_token(draft["secret_key"])
    await db_update_click_settings(**update_fields)
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="click_settings_save",
                            result="OK", target="click_settings")
    await state.update_data(click_draft={})
    text, kb = await _render_click_menu(state)
    await callback.message.edit_text(f"✅ Click sozlamalari saqlandi.\n\n{text}", reply_markup=kb)
    await callback.answer()

# --- 🗑️ Tozalash (xavfli amal — tasdiqlash orqali) ---
@user_router.callback_query(F.data == "click_clear_ask")
async def click_clear_ask(callback: CallbackQuery):
    if not await _require_admin(callback): return
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🗑️ Ha, tozalash", callback_data="click_clear_do")],
        [InlineKeyboardButton(text="❌ Bekor qilish", callback_data="click_settings")],
    ])
    await callback.message.edit_text(
        "⚠️ Click sozlamalari (Merchant ID, Service ID, Secret Key, Callback URL) "
        "to'liq tozalanadi. Bu amalni orqaga qaytarib bo'lmaydi. Davom etasizmi?",
        reply_markup=kb,
    )
    await callback.answer()

@user_router.callback_query(F.data == "click_clear_do")
async def click_clear_do(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    async with db_connect() as db:
        await db.execute(
            """UPDATE click_settings SET merchant_id = NULL, service_id = NULL,
               secret_key_encrypted = NULL, callback_url = NULL, updated_at = ?
               WHERE id = 1""",
            (utcnow().isoformat(),),
        )
        await db.commit()
    await state.update_data(click_draft={})
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="click_settings_clear",
                            result="OK", target="click_settings")
    text, kb = await _render_click_menu(state)
    await callback.message.edit_text(f"🗑️ Click sozlamalari tozalandi.\n\n{text}", reply_markup=kb)
    await callback.answer()


# ===================== 👑 ADMIN PANEL: ⚙️ TIZIM SOZLAMALARI (global) =====================
# FAQAT butun platformaga ta'sir qiladigan sozlamalar. Bot darajasidagi
# narsalar bot_settings'da, billing bilan bog'liq narsalar billing_settings'da,
# Click sozlamalari click_settings'da, backup sozlamalari backup_settings'da
# qoladi — bu yerga aralashmaydi.
class SystemSettingsStates(StatesGroup):
    waiting_value = State()

class BroadcastStates(StatesGroup):
    waiting_message = State()

def _bool_label(v: bool) -> str:
    return "✅ ON" if v else "❌ OFF"

SETTINGS_LABELS = {
    "registration_enabled": "🟢 Yangi ro'yxatdan o'tish",
    "telegram_login_enabled": "🔐 Telegram Login",
    "email_verification_enabled": "📧 Email tasdiqlash",
    "maintenance_mode": "🛠 Maintenance",
    "maintenance_admin_bypass": "👑 Adminlar uchun kirish",
    "default_ram_price": "RAM narxi (so'm/GB)",
    "default_disk_price": "Disk narxi (so'm/GB)",
    "default_db_overage_price": "DB overage narxi (so'm/GB)",
    "default_storage_overage_price": "Storage overage narxi (so'm/GB)",
    "default_bot_price": "Bot narxi (so'm/oy)",
    "global_notifications_enabled": "📢 Global bildirishnomalar",
    "notify_balance_warning": "⚠️ Balans tugashi",
    "notify_maintenance": "🔧 Texnik xizmat",
    "notify_payment": "💳 To'lov",
    "notify_server_issue": "🖥 Server muammosi",
    "notify_bot_error": "🤖 Bot xatosi",
    "admin_audit_log_enabled": "🔐 Admin audit log",
    "critical_action_confirmation_enabled": "🔐 Muhim amal tasdig'i",
    "api_key_masking_enabled": "🔐 API key masking",
    "session_timeout_minutes": "Session timeout (daqiqa)",
    "admin_ai_enabled": "🤖 Admin AI",
    "admin_ai_monitoring_enabled": "👁️ Monitoring",
    "admin_ai_auto_restart_enabled": "🔄 Auto-restart",
    "admin_ai_auto_diagnosis_enabled": "🧠 Auto-diagnosis",
    "admin_ai_alerts_enabled": "📢 AI alertlar",
    "website_enabled": "🌐 Website",
    "website_maintenance_banner": "📢 Maintenance banner",
}

def _toggle_btn(key: str, submenu: str, settings: dict) -> InlineKeyboardButton:
    return InlineKeyboardButton(text=f"{SETTINGS_LABELS[key]}: {_bool_label(settings[key])}",
                                 callback_data=f"sysset_toggle:{key}:{submenu}")

def _edit_btn(key: str, submenu: str, settings: dict) -> InlineKeyboardButton:
    return InlineKeyboardButton(text=f"{SETTINGS_LABELS[key]}: {settings[key]}",
                                 callback_data=f"sysset_edit:{key}:{submenu}")

def sysset_menu_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="👥 Ro'yxatdan o'tish", callback_data="sysset_reg")],
        [InlineKeyboardButton(text="🛠 Texnik xizmat", callback_data="sysset_maint")],
        [InlineKeyboardButton(text="💰 Tarif va overage", callback_data="sysset_tariff")],
        [InlineKeyboardButton(text="📢 Global bildirishnomalar", callback_data="sysset_notif")],
        [InlineKeyboardButton(text="🔐 Xavfsizlik", callback_data="sysset_sec")],
        [InlineKeyboardButton(text="🤖 AI tizimi", callback_data="sysset_ai")],
        [InlineKeyboardButton(text="🗄️ Backup", callback_data="sysset_backup")],
        [InlineKeyboardButton(text="🌐 Websayt", callback_data="sysset_site")],
        [InlineKeyboardButton(text="🔙 Orqaga", callback_data="admin_panel")],
    ])

async def _render_sysset_submenu(submenu: str, settings: dict) -> tuple[str, InlineKeyboardMarkup]:
    if submenu == "reg":
        text = "👥 Ro'yxatdan o'tish"
        rows = [
            [_toggle_btn("registration_enabled", "reg", settings)],
            [_toggle_btn("telegram_login_enabled", "reg", settings)],
            [_toggle_btn("email_verification_enabled", "reg", settings)],
        ]
    elif submenu == "maint":
        text = f"🛠 Texnik xizmat\n\n📝 Xabar: {settings['maintenance_message']}"
        rows = [
            [_toggle_btn("maintenance_mode", "maint", settings)],
            [InlineKeyboardButton(text="📝 Xabarni tahrirlash", callback_data="sysset_edit:maintenance_message:maint")],
            [_toggle_btn("maintenance_admin_bypass", "maint", settings)],
        ]
    elif submenu == "tariff":
        billing = await db_get_billing_settings()
        text = (f"💰 Tarif va overage (default/fallback qiymatlar — server/tarifda maxsus narx "
                f"belgilangan bo'lsa, o'sha ustun turadi)\n\n"
                f"ℹ️ Grace period: {billing['grace_period_hours']} soat "
                f"(billing_settings'dan, bu yerdan tahrirlanmaydi)")
        rows = [
            [_edit_btn("default_ram_price", "tariff", settings)],
            [_edit_btn("default_disk_price", "tariff", settings)],
            [_edit_btn("default_db_overage_price", "tariff", settings)],
            [_edit_btn("default_storage_overage_price", "tariff", settings)],
            [_edit_btn("default_bot_price", "tariff", settings)],
        ]
    elif submenu == "notif":
        text = "📢 Global bildirishnomalar"
        rows = [
            [InlineKeyboardButton(text="✏️ Xabar yozish va yuborish", callback_data="sysset_broadcast_start")],
            [_toggle_btn("global_notifications_enabled", "notif", settings)],
            [_toggle_btn("notify_balance_warning", "notif", settings)],
            [_toggle_btn("notify_maintenance", "notif", settings)],
            [_toggle_btn("notify_payment", "notif", settings)],
            [_toggle_btn("notify_server_issue", "notif", settings)],
            [_toggle_btn("notify_bot_error", "notif", settings)],
        ]
    elif submenu == "sec":
        text = "🔐 Xavfsizlik"
        rows = [
            [_toggle_btn("admin_audit_log_enabled", "sec", settings)],
            [_toggle_btn("critical_action_confirmation_enabled", "sec", settings)],
            [_toggle_btn("api_key_masking_enabled", "sec", settings)],
            [_edit_btn("session_timeout_minutes", "sec", settings)],
            [InlineKeyboardButton(text="📋 Loglarni ko'rish", callback_data="adminlogs_page:0:")],
        ]
    elif submenu == "ai":
        text = "🤖 AI tizimi\n\nEslatma: Admin AI'ga asosiy admin huquqi hech qachon berilmaydi — bu tizim darajasidagi o'zgarmas xavfsizlik cheklovi."
        rows = [
            [_toggle_btn("admin_ai_enabled", "ai", settings)],
            [_toggle_btn("admin_ai_monitoring_enabled", "ai", settings)],
            [_toggle_btn("admin_ai_auto_restart_enabled", "ai", settings)],
            [_toggle_btn("admin_ai_auto_diagnosis_enabled", "ai", settings)],
            [_toggle_btn("admin_ai_alerts_enabled", "ai", settings)],
        ]
    elif submenu == "site":
        banner = settings["website_maintenance_banner"] or "—"
        text = f"🌐 Websayt\n\n📢 Maintenance banner: {banner}"
        rows = [
            [_toggle_btn("website_enabled", "site", settings)],
            [_toggle_btn("telegram_login_enabled", "site", settings)],
            [InlineKeyboardButton(text="📢 Bannerni tahrirlash", callback_data="sysset_edit:website_maintenance_banner:site")],
        ]
    else:
        text, rows = "Noma'lum bo'lim", []
    rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="sysset_menu")])
    return text, InlineKeyboardMarkup(inline_keyboard=rows)

# ---- 📋 Loglar (admin_logs audit ko'rish/qidirish UI) ----
class AdminLogsStates(StatesGroup):
    waiting_search = State()

ADMIN_LOGS_PAGE_SIZE = 10

async def _render_admin_logs(page: int, filter_q: str = "") -> tuple[str, InlineKeyboardMarkup]:
    async with db_connect() as db:
        db.row_factory = aiosqlite.Row
        if filter_q:
            like = f"%{filter_q}%"
            total_row = await db.execute(
                "SELECT COUNT(*) AS c FROM admin_logs WHERE actor LIKE ? OR action LIKE ? OR target LIKE ?",
                (like, like, like))
            total = (await total_row.fetchone())["c"]
            rows_cur = await db.execute(
                "SELECT * FROM admin_logs WHERE actor LIKE ? OR action LIKE ? OR target LIKE ? "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (like, like, like, ADMIN_LOGS_PAGE_SIZE, page * ADMIN_LOGS_PAGE_SIZE))
        else:
            total_row = await db.execute("SELECT COUNT(*) AS c FROM admin_logs")
            total = (await total_row.fetchone())["c"]
            rows_cur = await db.execute(
                "SELECT * FROM admin_logs ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (ADMIN_LOGS_PAGE_SIZE, page * ADMIN_LOGS_PAGE_SIZE))
        rows = [dict(r) for r in await rows_cur.fetchall()]

    header = "📋 Loglar" + (f" (filtr: \"{filter_q}\")" if filter_q else "")
    if not rows:
        text = f"{header}\n\nHech narsa topilmadi." if total == 0 else f"{header}\n\nBoshqa sahifa yo'q."
    else:
        lines = []
        for r in rows:
            target_part = f" ({r['target']})" if r["target"] else ""
            reason_part = f" — {r['reason']}" if r["reason"] else ""
            lines.append(f"• {r['actor']} — {r['action']} — {r['result']}{target_part}{reason_part} — {r['created_at']}")
        text = f"{header} ({total} ta):\n\n" + "\n".join(lines)

    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️ Oldingi", callback_data=f"adminlogs_page:{page - 1}:{filter_q}"))
    if (page + 1) * ADMIN_LOGS_PAGE_SIZE < total:
        nav.append(InlineKeyboardButton(text="Keyingi ➡️", callback_data=f"adminlogs_page:{page + 1}:{filter_q}"))
    kb_rows = [nav] if nav else []
    kb_rows.append([InlineKeyboardButton(text="🔎 Qidirish", callback_data="adminlogs_search")])
    if filter_q:
        kb_rows.append([InlineKeyboardButton(text="✖️ Filtrni tozalash", callback_data="adminlogs_page:0:")])
    kb_rows.append([InlineKeyboardButton(text="🔙 Orqaga", callback_data="sysset_sec")])
    return text, InlineKeyboardMarkup(inline_keyboard=kb_rows)

@user_router.callback_query(F.data.startswith("adminlogs_page:"))
async def show_adminlogs_page(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    parts = callback.data.split(":", 2)
    page = int(parts[1])
    query = parts[2] if len(parts) > 2 else ""
    text, kb = await _render_admin_logs(page, query)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data == "adminlogs_search")
async def adminlogs_search_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.set_state(AdminLogsStates.waiting_search)
    await callback.message.edit_text("🔎 Actor, action yoki target bo'yicha qidiruv so'zini yuboring:",
                                      reply_markup=back_kb_to("sysset_sec"))
    await callback.answer()

@user_router.message(AdminLogsStates.waiting_search)
async def adminlogs_search_receive(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        return
    query = message.text.strip().replace(":", "")[:40]
    await state.clear()
    text, kb = await _render_admin_logs(0, query)
    await message.answer(text, reply_markup=kb)


@user_router.callback_query(F.data == "sysset_menu")
async def show_sysset_menu(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.clear()
    await callback.message.edit_text("⚙️ TIZIM SOZLAMALARI", reply_markup=sysset_menu_kb())
    await callback.answer()

@user_router.callback_query(F.data.in_({"sysset_reg", "sysset_maint", "sysset_tariff", "sysset_notif", "sysset_sec", "sysset_ai", "sysset_site"}))
async def show_sysset_submenu(callback: CallbackQuery):
    if not await _require_admin(callback): return
    submenu = callback.data.split("_", 1)[1]
    settings = await db_get_all_settings()
    text, kb = await _render_sysset_submenu(submenu, settings)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data.startswith("sysset_toggle:"))
async def sysset_toggle(callback: CallbackQuery):
    if not await _require_admin(callback): return
    _, key, submenu = callback.data.split(":")
    new_value = await db_toggle_setting(key, updated_by=callback.from_user.id)
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="system_setting_toggle",
                            result=str(new_value), target=key)
    settings = await db_get_all_settings(force_reload=True)
    text, kb = await _render_sysset_submenu(submenu, settings)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()

@user_router.callback_query(F.data.startswith("sysset_edit:"))
async def sysset_edit_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    _, key, submenu = callback.data.split(":")
    vtype = await db_get_setting_type(key)
    await state.update_data(sysset_key=key, sysset_type=vtype, sysset_submenu=submenu)
    await state.set_state(SystemSettingsStates.waiting_value)
    prompt = "🔢 Yangi qiymatni kiriting (raqam):" if vtype == "int" else "📝 Yangi matnni kiriting:"
    await callback.message.edit_text(prompt, reply_markup=back_kb_to(f"sysset_{submenu}"))
    await callback.answer()

@user_router.message(SystemSettingsStates.waiting_value)
async def sysset_edit_receive(message: Message, state: FSMContext):
    data = await state.get_data()
    key, vtype, submenu = data["sysset_key"], data["sysset_type"], data["sysset_submenu"]
    text = message.text.strip()
    if vtype == "int":
        if not text.lstrip("-").isdigit():
            await message.answer("Iltimos, faqat raqam kiriting.")
            return
        value = int(text)
    else:
        value = text
    await db_set_setting(key, value, updated_by=message.from_user.id)
    await log_admin_action(actor=f"admin:{message.from_user.id}", action="system_setting_edit",
                            result="OK", target=key, reason=str(value)[:200])
    await state.clear()
    settings = await db_get_all_settings(force_reload=True)
    text_out, kb = await _render_sysset_submenu(submenu, settings)
    await message.answer(f"✅ Yangilandi.\n\n{text_out}", reply_markup=kb)

# --- 📢 Global bildirishnoma yuborish (broadcast) ---
BROADCAST_AUDIENCE_LABELS = {"all": "Barcha", "active": "Faol foydalanuvchilar",
                              "admins": "Adminlar", "bot_owners": "Bot egalari"}

@user_router.callback_query(F.data == "sysset_broadcast_start")
async def sysset_broadcast_start(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    await state.set_state(BroadcastStates.waiting_message)
    await callback.message.edit_text("✏️ Global xabar matnini yuboring:", reply_markup=back_kb_to("sysset_notif"))
    await callback.answer()

@user_router.message(BroadcastStates.waiting_message, F.text)
async def sysset_broadcast_receive(message: Message, state: FSMContext):
    if not await is_admin(message.from_user.id):
        return
    await state.update_data(broadcast_text=message.text)
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=label, callback_data=f"sysset_broadcast_send:{key}")]
        for key, label in BROADCAST_AUDIENCE_LABELS.items()
    ] + [[InlineKeyboardButton(text="❌ Bekor qilish", callback_data="sysset_notif")]])
    await message.answer("Kimga yuborilsin?", reply_markup=kb)

async def _get_broadcast_recipients(audience: str) -> list[int]:
    async with db_connect() as db:
        if audience == "all":
            query = "SELECT telegram_id FROM users"
        elif audience == "active":
            query = "SELECT telegram_id FROM users WHERE is_active = 1"
        elif audience == "admins":
            query = "SELECT telegram_id FROM users WHERE is_admin = 1"
        elif audience == "bot_owners":
            query = "SELECT DISTINCT u.telegram_id FROM users u JOIN bots b ON b.owner_id = u.id"
        else:
            return []
        async with db.execute(query) as cur:
            return [r[0] for r in await cur.fetchall()]

@user_router.callback_query(F.data.startswith("sysset_broadcast_send:"))
async def sysset_broadcast_send(callback: CallbackQuery, state: FSMContext):
    if not await _require_admin(callback): return
    audience = callback.data.split(":")[1]
    data = await state.get_data()
    text = data.get("broadcast_text")
    await state.clear()
    if not text:
        await callback.answer("Xabar matni topilmadi, qaytadan urinib ko'ring", show_alert=True)
        return
    await callback.answer("📤 Yuborilmoqda...")
    recipients = await _get_broadcast_recipients(audience)
    sent, failed = 0, 0
    for telegram_id in recipients:
        try:
            await bot.send_message(telegram_id, f"📢 {text}")
            sent += 1
        except Exception:
            failed += 1
        await asyncio.sleep(0.05)  # Telegram rate limitiga tegmaslik uchun
    await log_admin_action(actor=f"admin:{callback.from_user.id}", action="broadcast",
                            result=f"sent={sent} failed={failed}", target=audience, reason=text[:200])
    await callback.message.edit_text(
        f"✅ Yuborildi: {sent} ta\n❌ Yetib bormadi: {failed} ta",
        reply_markup=back_kb_to("sysset_notif"),
    )


# ===================== !!! MUHIM ESLATMA — DAVOM ETTIRISH UCHUN !!! =====================
# YANGILANDI (bu sessiyada): eski eslatma "➕ Bot yaratish FSM hali yozilmagan"
# deb noto'g'ri ko'rsatib kelgan edi — bu XATO edi, FSM (BotCreateStates,
# nomi->username->token->zip->server->tasdiqlash) faylda TO'LIQ bor va
# TUGALLANGAN (2564-qatordan boshlab). Shu sessiyada ustiga BOT SUPERVISOR
# qo'shildi:
#
#   - supervisor_loop() — 30s'da bir marta 'running' botlarning jarayoni
#     haqiqatan tirikligini tekshiradi (ProcessManager.is_running orqali).
#   - Crash aniqlansa: bot 'stopped'ga o'tadi, health='error',
#     stopped_reason='crashed', consecutive_crash_count oshadi (bots jadvali,
#     migration bilan qo'shilgan ustun), va SUPERVISOR_BACKOFF_SCHEDULE
#     ([10, 30, 60] soniya, crash tartib raqami bo'yicha) asosida ALOHIDA
#     asyncio task orqali (_supervisor_delayed_restart) qayta ishga tushiriladi
#     — shu bilan bir bot uchun kutish boshqa botlarni tekshirishni bloklamaydi.
#   - Har SUPERVISOR_CRASH_ALERT_EVERY (=3) ketma-ket crashda bot egasiga VA
#     barcha adminlarga ogohlantirish yuboriladi (_supervisor_alert_crash).
#   - Bot sog'lom ekani tasdiqlansa yoki qasddan to'xtatilsa (_stop_bot_process,
#     reason != "crashed") hisoblagich db_reset_bot_crash_state() bilan 0'ga
#     qaytadi.
#   - Platforma/server qayta ishga tushishi ALOHIDA logika talab qilmaydi:
#     DB'da 'running' qolib ketgan, lekin jarayoni topilmayotgan botlar
#     birinchi supervisor tsiklida oddiy crash sifatida aniqlanib, xuddi shu
#     backoff yo'li bilan avtomatik tiklanadi.
#   - ATAYLAB admin_ai_monitor_loop'dan mustaqil yozildi (alohida loop,
#     foydalanuvchi talabi). Ular hozircha bir-biriga rasman bog'lanmagan —
#     supervisor tezroq (30s) ishlagani uchun crashni birinchi bo'lib
#     status='stopped'ga o'tkazadi, shu bilan admin_ai_monitor_loop'ning eski
#     (raw process-check) tarmog'i deyarli hech qachon ishga tushmay qoladi.
#     Ularni ongli tarzda birlashtirish (masalan: ketma-ket crashlarda AI
#     diagnostikasini so'rash) — rejadagi "User AI + Admin AI'ni Supervisor
#     bilan ulash" bosqichida qilinadi, hozircha ATAYLAB tegilmadi.
#   - main()'ga supervisor_loop() qo'shildi (asyncio.gather ichida).
#
# Hali TEKSHIRILMAGAN:
#   - .env to'liqligi (BOT_TOKEN, SESSION_SECRET, TOKEN_ENCRYPTION_KEY,
#     SUPER_ADMIN_TELEGRAM_ID) va requirements.txt (aiogram, aiosqlite,
#     aiohttp, cryptography)
#   - db_init() runtime'da xatosiz ishlashi (fayl darajasida sintaksis
#     tekshirilgan, lekin haqiqiy DB yaratish sinalmagan)
#   - supervisor_loop haqiqiy crash bilan (masalan bot processini qo'lda
#     kill qilib) sinalmagan — hozircha faqat kod/mantiq darajasida yozilgan
#
# KEYINGI NAVBAT (foydalanuvchi tasdiqlagan tartib bo'yicha):
#   3️⃣ 🤖 Botlarim — ro'yxat/boshqarish handlerlari: ▶️ Start/⏹ Stop/
#       🔄 Restart/🗑 Delete/📊 Statistika/🧠 AI sozlamalari/🗄️ Backup tugmalari,
#       barchasi supervisor bilan yozilgan _start_bot_process()/
#       _stop_bot_process() orqali ishlashi kerak (callback_data="my_bots"
#       allaqachon menyuda bor, lekin handler hali yo'q).
#   4️⃣ 💰 Billing + Click'ni real test qilish (Balans to'ldirish FSM SHART —
#       handle_click_callback() shuni kutadi)
#   5️⃣ 🧠 User AI + Admin AI'ni Supervisor bilan ulash
#   6️⃣ 🔐 Integratsiya va xavfsizlik
#   7️⃣ 📱 Mini App'ning qolgan ekranlari
#
# PROJECT_BRIEF.md'dagi "Hozirgacha YOZILGAN qismlar" ro'yxati — bu shu tartibda
# (u yerda 🤖 Botlar/Admin AI Pool/Statistika/Backup/Tizim sozlamalari kabi
# bo'limlar TUGALLANDI deb belgilangan — ular haqiqatan shu faylda bor).
#
# bot-61.py'da qo'shildi (foydalanuvchi tasdiqlagan yangi tartib, 8 bosqich):
#   1️⃣ ✅ SMS/bildirishnoma monitoring backend (MacroDroid -> Webhook -> Payment
#       Monitor): POST /payment/notify (X-Payment-Secret header bilan himoyalangan,
#       PAYMENT_WEBHOOK_SECRET .env'da), db_find_awaiting_order_by_amount(),
#       process_payment_notification() (muddati tugaganlarni tozalaydi -> aniq
#       summa moslashtiradi -> payment_transactions'ga yozadi, moslik topilmasa
#       ham -> topilsa db_confirm_payment_order orqali kredit + foydalanuvchiga
#       xabar). test_payment_monitor_standalone.py bilan 15/15 ✅ tasdiqlandi
#       (to'g'ri moslik, xato summa, takroriy transaction_id, muddati tugagan
#       buyurtma, bo'sh transaction_id uchun auto-hash ID). Bu yerda faqat
#       backend/webhook qatlami — MacroDroid profilining o'zi (telefon
#       tomoni) va Admin Panel'dagi SMS Monitoring UI keyingi bosqichda.
#   2️⃣ ✅ Admin Payment Manager — 7 bo'limli FSM UI (💳 Karta ma'lumotlari,
#       📱 SMS Monitoring, ⚙️ To'lov qoidalari, 🔍 Tekshiruv, 📜 To'lovlar
#       tarixi, 🛡️ Firibgarlik himoyasi, 🤖 AI Payment Supervisor).
#   3️⃣ ✅ To'lov qoidalari (min/max/ttl/concurrent/fractional) — 2️⃣ ichida.
#   4️⃣ ✅ Firibgarlik himoyasi — velocity + katta-summa qoidalari (fraud_events
#       jurnali, flagged_review -> admin ✅/❌) + 🔍 Tekshiruv qo'lda-moslashtirish
#       UI (unmatched/shubhali/tekshirilganlar, buyurtmaga bog'lash yoki rad
#       etish, db_manual_match_transaction yagona kredit nuqtasi orqali).
#   5️⃣ ✅ AI Payment Supervisor — heuristik xavf hisoboti (compute_fraud_risk_report).
#   6️⃣ ✅ Admin AI Engine (1-funksiya) — AI Payment Matching: compute_match_score
#       (0-100%, 💰/🕐/📦/🔁/🧾 signallar) + ai_suggest_matches top-3, "🤖 AI
#       tavsiyasi" tugmasi Tekshiruv ustida. AI hech qachon o'zi bog'lamaydi —
#       faqat tavsiya, yakuniy bog'lash admin qo'lida (xuddi shu tkr_pick oqimi).
#   7️⃣ ✅ Xavfsizlik + Logs — 📋 Loglarni ko'rish/qidirish UI (Tizim sozlamalari
#       -> Xavfsizlik ichida), admin_audit_log_enabled log_admin_action'ni
#       haqiqatan gating qiladi (fail-safe: o'qib bo'lmasa baribir yoziladi),
#       session_timeout_minutes web-sessiya TTL'siga ulandi (avval qattiq
#       kodlangan 30 kun edi), critical_action_confirmation_enabled
#       foydalanuvchi BLOKLASH amaliga (bloklash yo'nalishida) qo'shimcha
#       tasdiq bosqichi qo'shadi. api_key_masking — qat'iy xavfsizlik pol
#       sifatida har doim yoqilgan qoladi (kalit hech qachon to'liq ko'rsatilmaydi,
#       bu sozlama bilan zaiflashtirilmaydi).
#   8️⃣ ✅ Asosiy menyuni ReplyKeyboard'ga o'tkazish — main_menu_kb() allaqachon
#       doimiy pastki ReplyKeyboardMarkup panel (📱 Mini App/➕ Bot yaratish/
#       🤖 Botlarim/💰 Balans/💳 To'lovlarim/🔑 API kalitlarim/🗄️ Backup/
#       👤 Profil/👑 Admin Panel — faqat admin); bu band avvalgi bosqichda
#       allaqachon amalga oshirilgan edi.
#
# Barcha 8 bosqich TUGALLANDI. Standalone testlar: test_payment_monitor_standalone.py,
# test_payment_manager_ui_standalone.py, test_fraud_protection_standalone.py,
# test_tekshiruv_standalone.py, test_ai_matching_standalone.py,
# test_security_logs_standalone.py — barchasi ✅.
#
# .env'ga yangi qator qo'shilishi kerak: PAYMENT_WEBHOOK_SECRET=<uzun tasodifiy
# maxfiy so'z> (masalan: python3 -c "import secrets; print(secrets.token_hex(32))").
# MacroDroid HTTP so'rovida shu qiymatni "X-Payment-Secret" headerida jo'natishi
# shart, aks holda so'rov 401 bilan rad etiladi.

# ===================== ISHGA TUSHIRISH TRIGGERI =====================
# MUHIM: shu blok albatta faylning ENG OXIRIDA turishi shart — barcha
# @user_router.message/@user_router.callback_query dekoratorlari yuqorida
# import vaqtida ro'yxatdan o'tgandan KEYIN chaqirilishi kerak. Aks holda
# dp.include_router(user_router) bo'sh routerni ulaydi va /start (va boshqa
# barcha tugmalar) hech qanday handlerga mos kelmay, javobsiz qoladi —
# aynan shu sabab bilan bot avval /start'ga javob bermagan edi.
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Bot to'xtatildi")
