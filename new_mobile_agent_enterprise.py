"""
Jarvis Omni-Agent: Mobile Controller (Termux) — Enterprise Edition v2
Async rewrite with full security hardening, RBAC, and asyncio concurrency.

Security Features:
- field(default_factory=time.time) fixes stale AuthAttempt default (Audit #4)
- check_auth redesigned with unambiguous return semantics (Audit #5)
- _rate_limit reimplemented as asyncio-safe (Audit #8)
- import re at module level (Audit #9)
- Startup validation for all required secrets — no silent fallbacks (Audit #10)
- Bounds checking on vibrate() and volume() (Audit #14)
- Dead BackgroundScheduler removed entirely (Audit #13)

Concurrency:
- Full asyncio + python-telegram-bot v20+ (no threading)
- asyncio.Lock for all shared mutable state
- Blocking Termux CLI calls delegated to run_in_executor

RBAC:
- Privilege levels: SAFE, ELEVATED, DESTRUCTIVE
- Destructive actions require a time-limited confirmation token
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from functools import wraps
from pathlib import Path
from socket import AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST, socket as Socket
from typing import Any, Callable, Dict, List, Optional, Tuple

from dotenv import load_dotenv
from groq import Groq
from telegram import Update
from telegram.ext import (
    Application,
    ContextTypes,
    MessageHandler,
    filters,
)

# ── Load .env ──────────────────────────────────────────────────────────────────
load_dotenv()

# ── MAC address regex at module level (Audit fix #9) ──────────────────────────
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}([0-9A-Fa-f]{2})$")


# ── Config & validation ────────────────────────────────────────────────────────
def _require_env(key: str) -> str:
    """Return env var or raise at startup — no silent fallback secrets."""
    value = os.getenv(key, "").strip()
    if not value:
        raise ValueError(
            f"Required environment variable '{key}' is not set. "
            "Add it to your .env file and restart."
        )
    return value


TELEGRAM_TOKEN: str = _require_env("TELEGRAM_TOKEN")
CHAT_ID: str = _require_env("CHAT_ID")
GROQ_API_KEY: str = _require_env("GROQ_API_KEY")

# ── Audit fix #10: no silent default PIN ──────────────────────────────────────
_PIN_PLAINTEXT: str = _require_env("SECRET_PIN")
SECRET_PIN_HASH: str = hashlib.sha256(_PIN_PLAINTEXT.encode()).hexdigest()
del _PIN_PLAINTEXT  # Don't keep plaintext in memory after hashing

TARGET_PC_MAC: str = os.getenv("TARGET_PC_MAC", "").strip()

ALLOWED_CMDS: List[str] = ["ls", "pwd", "whoami"]
RATE_LIMIT_SECONDS: int = 10
MAX_AUTH_ATTEMPTS: int = 3
LOCKOUT_DURATION_SECONDS: int = 15 * 60
MAX_OUTPUT_LENGTH: int = 4000
COMMAND_TIMEOUT: int = 30
CONFIRM_TTL_SECONDS: int = 60


# ── Logging ────────────────────────────────────────────────────────────────────
def _setup_logger() -> logging.Logger:
    logger = logging.getLogger("JarvisMobilev2")
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler("jarvis_mobile_audit.log")
    fh.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    fmt = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s] - %(message)s"
    )
    fh.setFormatter(fmt)
    ch.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


logger: logging.Logger = _setup_logger()


# ── RBAC ───────────────────────────────────────────────────────────────────────
class Privilege(Enum):
    SAFE = auto()
    ELEVATED = auto()
    DESTRUCTIVE = auto()


@dataclass
class PendingConfirmation:
    action: str
    param: str
    expires_at: float = field(
        default_factory=lambda: time.monotonic() + CONFIRM_TTL_SECONDS
    )

    def is_expired(self) -> bool:
        return time.monotonic() > self.expires_at


ACTION_PRIVILEGES: Dict[str, Privilege] = {
    "battery": Privilege.SAFE,
    "location": Privilege.SAFE,
    "clip_get": Privilege.SAFE,
    "vibrate": Privilege.SAFE,
    "torch": Privilege.ELEVATED,
    "photo": Privilege.ELEVATED,
    "tts": Privilege.ELEVATED,
    "record": Privilege.ELEVATED,
    "cmd": Privilege.ELEVATED,
    "clip_set": Privilege.ELEVATED,
    "volume": Privilege.ELEVATED,
    "wake_pc": Privilege.ELEVATED,
    "sms_send": Privilege.DESTRUCTIVE,
}


# ── Auth state ─────────────────────────────────────────────────────────────────
@dataclass
class AuthAttempt:
    """
    Tracks brute-force attempts.

    first_attempt_time uses field(default_factory=time.time) so each
    instance captures the *current* wall-clock time, not the module-load
    time.  (Audit fix #4)
    """
    attempt_count: int = 0
    first_attempt_time: float = field(default_factory=time.time)
    locked_until: float = 0.0


# ── PIN helpers ────────────────────────────────────────────────────────────────
def _hash_pin(pin: str) -> str:
    return hashlib.sha256(pin.encode()).hexdigest()


def _verify_pin(pin: str, pin_hash: str) -> bool:
    return secrets.compare_digest(_hash_pin(pin), pin_hash)


# ── Async rate-limit decorator ─────────────────────────────────────────────────
def async_rate_limit(seconds: int) -> Callable:
    """
    Per-decorated-function async rate limiter backed by an asyncio.Lock.

    The lock prevents the TOCTOU race present in the original threading
    version (Audit fix #8).  Each decorated method gets its own lock
    instance via the closure.
    """
    _lock: asyncio.Lock = asyncio.Lock()
    _last_execution: float = 0.0

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self: "JarvisMobilev2", bot, param: str) -> Any:
            nonlocal _last_execution
            async with _lock:
                now = time.monotonic()
                elapsed = now - _last_execution
                if elapsed < seconds:
                    remaining = int(seconds - elapsed)
                    logger.warning(
                        "Rate limit hit for %s — retry in %ds", func.__name__, remaining
                    )
                    await bot.send_message(
                        self.chat_id,
                        f"⏳ Rate limited. Retry in {remaining}s.",
                    )
                    return
                _last_execution = now
            return await func(self, bot, param)

        return wrapper
    return decorator


# ── Argument sanitiser ─────────────────────────────────────────────────────────
def _sanitize_arg(arg: str, max_length: int = 256) -> Optional[str]:
    if not arg or len(arg) > max_length:
        return None
    if not all(c.isalnum() or c in "/-_.|:@" for c in arg):
        return None
    return arg


# ── Main agent ─────────────────────────────────────────────────────────────────
class JarvisMobilev2:
    """
    Async Termux controller.  All handlers are coroutines;
    blocking Termux CLI calls go through run_in_executor.
    """

    def __init__(self) -> None:
        self.ai: Groq = Groq(api_key=GROQ_API_KEY)
        self.chat_id: str = CHAT_ID

        # ── Auth state (Audit fix #4: factory-based default) ─────────────
        self._auth_lock: asyncio.Lock = asyncio.Lock()
        self._authenticated: bool = False
        self._auth_state: AuthAttempt = AuthAttempt()

        # ── Chat history ──────────────────────────────────────────────────
        self._history_lock: asyncio.Lock = asyncio.Lock()
        self._chat_history: List[Dict[str, str]] = []

        # ── Pending confirmations ─────────────────────────────────────────
        self._confirm_lock: asyncio.Lock = asyncio.Lock()
        self._pending: Dict[str, PendingConfirmation] = {}

        self.system_instruction: str = (
            "Return ONLY a JSON object with keys: action, param. "
            "Allowed actions: battery, photo, torch, location, tts, record, "
            "cmd, chat, sms_send, clip_get, clip_set, vibrate, volume, wake_pc."
        )

        self.actions: Dict[str, Callable] = {
            "battery": self.battery,
            "photo": self.photo,
            "torch": self.torch,
            "location": self.location,
            "tts": self.tts,
            "record": self.record,
            "cmd": self.cmd,
            "sms_send": self.sms_send,
            "clip_get": self.clip_get,
            "clip_set": self.clip_set,
            "vibrate": self.vibrate,
            "volume": self.volume,
            "wake_pc": self.wake_pc,
        }

        logger.info("JarvisMobilev2 initialised")

    # ── RBAC helpers ──────────────────────────────────────────────────────────

    def _make_token(self) -> str:
        return secrets.token_urlsafe(4)[:6].upper()

    async def _request_confirmation(self, bot, action: str, param: str) -> None:
        token = self._make_token()
        async with self._confirm_lock:
            self._pending = {
                t: p for t, p in self._pending.items() if not p.is_expired()
            }
            self._pending[token] = PendingConfirmation(action=action, param=param)

        await bot.send_message(
            self.chat_id,
            f"⚠️ *Destructive action requested:* `{action}`\n"
            f"Reply with the following within {CONFIRM_TTL_SECONDS}s to confirm:\n\n"
            f"`confirm {token}`",
            parse_mode="Markdown",
        )
        logger.warning("Confirmation requested for action=%s token=%s", action, token)

    async def _try_redeem_confirmation(self, bot, token: str) -> bool:
        async with self._confirm_lock:
            pending = self._pending.get(token)
            if not pending:
                return False
            if pending.is_expired():
                del self._pending[token]
                await bot.send_message(self.chat_id, "⏱️ Confirmation token expired.")
                return True
            del self._pending[token]

        handler = self.actions.get(pending.action)
        if handler:
            await bot.send_message(
                self.chat_id, f"✅ Confirmed — executing `{pending.action}`…"
            )
            await handler(bot, pending.param)
        return True

    # ── Authentication ─────────────────────────────────────────────────────────

    async def _process_pin(self, bot, message_text: str) -> bool:
        """
        Handle a 'pin <VALUE>' message.

        Returns True if the message was consumed as a PIN attempt
        (regardless of success/failure), False if it was not a PIN message
        and should be processed normally.

        This replaces the previous check_auth() whose return value
        meant different things in different branches (Audit fix #5).
        """
        if not message_text.lower().startswith("pin "):
            return False  # Not a PIN message — caller should handle it

        async with self._auth_lock:
            now = time.time()

            # Reset stale lockout window
            if now - self._auth_state.first_attempt_time > LOCKOUT_DURATION_SECONDS:
                self._auth_state = AuthAttempt()

            # Hard lockout check
            if self._auth_state.attempt_count >= MAX_AUTH_ATTEMPTS:
                remaining = max(0, int(self._auth_state.locked_until - now))
                await bot.send_message(
                    self.chat_id,
                    f"🔒 Too many failed attempts. Retry in {remaining}s.",
                )
                logger.warning(
                    "Auth blocked — attempt_count=%d", self._auth_state.attempt_count
                )
                return True  # Consumed

            parts = message_text.split(maxsplit=1)
            if len(parts) < 2:
                await bot.send_message(self.chat_id, "❌ Format: pin <YOUR_PIN>")
                return True

            provided = parts[1]
            if _verify_pin(provided, SECRET_PIN_HASH):
                self._authenticated = True
                self._auth_state = AuthAttempt()
                await bot.send_message(self.chat_id, "✅ Authenticated successfully.")
                logger.info("User authenticated")
            else:
                self._auth_state.attempt_count += 1
                self._auth_state.locked_until = now + LOCKOUT_DURATION_SECONDS
                remaining = MAX_AUTH_ATTEMPTS - self._auth_state.attempt_count
                await bot.send_message(
                    self.chat_id,
                    f"❌ Wrong PIN. {max(0, remaining)} attempt(s) remaining.",
                )
                logger.warning(
                    "Failed auth — count=%d/%d",
                    self._auth_state.attempt_count, MAX_AUTH_ATTEMPTS,
                )

        return True  # Consumed either way

    # ── Action methods ────────────────────────────────────────────────────────

    async def battery(self, bot, _: str) -> None:
        def _run() -> str:
            result = subprocess.run(
                ["termux-battery-status"],
                capture_output=True, text=True, timeout=5,
            )
            result.check_returncode()
            data = json.loads(result.stdout)
            pct = data.get("percentage", "?")
            status = data.get("status", "?")
            health = data.get("health", "?")
            return f"🔋 Battery: {pct}%  |  Status: {status}  |  Health: {health}"

        try:
            msg = await asyncio.get_event_loop().run_in_executor(None, _run)
            await bot.send_message(self.chat_id, msg)
            logger.info("Battery status retrieved")
        except Exception as exc:
            await bot.send_message(self.chat_id, "❌ Failed to get battery status.")
            logger.error("Battery error: %s", exc)

    async def photo(self, bot, param: str) -> None:
        cam_id = "1" if param.strip().lower() == "front" else "0"
        photo_file = Path.home() / ".cache" / "jarvis_photo.jpg"
        photo_file.parent.mkdir(parents=True, exist_ok=True)

        def _capture() -> bool:
            subprocess.run(
                ["termux-camera-photo", "-c", cam_id, str(photo_file)],
                timeout=10, check=True,
            )
            time.sleep(2)
            return photo_file.exists()

        try:
            ok = await asyncio.get_event_loop().run_in_executor(None, _capture)
            if ok:
                with open(photo_file, "rb") as fh:
                    await bot.send_photo(self.chat_id, fh)
                photo_file.unlink(missing_ok=True)
                logger.info("Photo captured (cam=%s)", cam_id)
            else:
                await bot.send_message(self.chat_id, "❌ Photo capture failed.")
        except Exception as exc:
            await bot.send_message(self.chat_id, f"❌ Photo error: {type(exc).__name__}")
            logger.error("Photo error: %s", exc)

    async def torch(self, bot, param: str) -> None:
        if param not in ("on", "off"):
            await bot.send_message(self.chat_id, "❌ Use 'on' or 'off'.")
            return
        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(["termux-torch", param], timeout=5, check=True),
            )
            await bot.send_message(self.chat_id, f"💡 Torch: {param}")
            logger.info("Torch turned %s", param)
        except Exception as exc:
            await bot.send_message(self.chat_id, f"❌ Torch error: {type(exc).__name__}")

    async def location(self, bot, _: str) -> None:
        def _get() -> Tuple[float, float]:
            result = subprocess.run(
                ["termux-location"],
                capture_output=True, text=True, timeout=15, check=True,
            )
            data = json.loads(result.stdout)
            return data["latitude"], data["longitude"]

        try:
            lat, lon = await asyncio.get_event_loop().run_in_executor(None, _get)
            link = f"https://maps.google.com/?q={lat},{lon}"
            await bot.send_message(self.chat_id, f"📍 Location: {link}")
            logger.info("Location retrieved: %s, %s", lat, lon)
        except Exception:
            await bot.send_message(
                self.chat_id, "❌ Location access denied or unavailable."
            )

    async def tts(self, bot, param: str) -> None:
        if not param or len(param) > 500:
            await bot.send_message(
                self.chat_id, "❌ Text must be 1–500 characters."
            )
            return
        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(
                    ["termux-tts-speak", param], timeout=30, check=True
                ),
            )
            logger.info("TTS executed")
        except Exception as exc:
            await bot.send_message(self.chat_id, f"❌ TTS error: {type(exc).__name__}")
            logger.error("TTS error: %s", exc)

    async def record(self, bot, param: str) -> None:
        try:
            duration = max(1, min(60, int(param)))
        except (ValueError, TypeError):
            duration = 5

        rec_file = Path.home() / ".cache" / "jarvis_rec.m4a"
        rec_file.parent.mkdir(parents=True, exist_ok=True)

        await bot.send_message(self.chat_id, f"🎙️ Recording for {duration}s…")

        def _record() -> bool:
            subprocess.run(
                ["termux-microphone-record", "-f", str(rec_file), "-l", str(duration)],
                timeout=duration + 5, check=True,
            )
            # Give Termux a moment to flush the file
            time.sleep(1)
            return rec_file.exists() and rec_file.stat().st_size > 0

        try:
            ok = await asyncio.get_event_loop().run_in_executor(None, _record)
            if ok:
                with open(rec_file, "rb") as fh:
                    await bot.send_voice(self.chat_id, fh)
                rec_file.unlink(missing_ok=True)
                logger.info("Audio recorded (%ds)", duration)
            else:
                await bot.send_message(self.chat_id, "❌ Recording failed or empty.")
        except Exception as exc:
            await bot.send_message(self.chat_id, f"❌ Recording error: {type(exc).__name__}")
            logger.error("Record error: %s", exc)

    @async_rate_limit(RATE_LIMIT_SECONDS)
    async def sms_send(self, bot, param: str) -> None:
        """Send an SMS. (DESTRUCTIVE — requires confirmation + rate limited)"""
        if "|" not in param:
            await bot.send_message(self.chat_id, "❌ Format: phone|message")
            return

        phone, sms_text = param.split("|", 1)
        phone = phone.strip()
        sms_text = sms_text.strip()

        if not phone or not sms_text:
            await bot.send_message(self.chat_id, "❌ Phone or message is empty.")
            return

        # Basic E.164-ish phone sanity check
        if not re.fullmatch(r"\+?\d{7,15}", phone):
            await bot.send_message(self.chat_id, "❌ Phone number format looks invalid.")
            return

        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(
                    ["termux-sms-send", "-n", phone, sms_text],
                    timeout=10, check=True,
                ),
            )
            await bot.send_message(self.chat_id, f"✅ SMS sent to {phone}.")
            logger.info("SMS sent to %s", phone)
        except Exception as exc:
            await bot.send_message(self.chat_id, f"❌ SMS error: {type(exc).__name__}")
            logger.error("SMS error: %s", exc)

    async def clip_get(self, bot, _: str) -> None:
        def _get() -> str:
            result = subprocess.run(
                ["termux-clipboard-get"],
                capture_output=True, text=True, timeout=5, check=True,
            )
            return result.stdout or "(empty clipboard)"

        try:
            content = await asyncio.get_event_loop().run_in_executor(None, _get)
            await bot.send_message(self.chat_id, content[:MAX_OUTPUT_LENGTH])
            logger.info("Clipboard retrieved")
        except subprocess.CalledProcessError:
            await bot.send_message(self.chat_id, "⚠️ Clipboard access denied by OS.")
        except Exception:
            await bot.send_message(self.chat_id, "❌ Clipboard tool not available.")

    async def clip_set(self, bot, param: str) -> None:
        if not param or len(param) > 5_000:
            await bot.send_message(
                self.chat_id, "❌ Text empty or too long (max 5 000 chars)."
            )
            return
        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(
                    ["termux-clipboard-set", param], timeout=5, check=True
                ),
            )
            await bot.send_message(self.chat_id, "✅ Clipboard updated.")
            logger.info("Clipboard set")
        except Exception as exc:
            await bot.send_message(self.chat_id, f"❌ Clipboard set error: {type(exc).__name__}")
            logger.error("clip_set error: %s", exc)

    async def vibrate(self, bot, param: str) -> None:
        """
        Vibrate for a bounded duration.
        Clamped to 100–5000 ms (Audit fix #14).
        """
        try:
            duration_ms = max(100, min(5_000, int(param)))
        except (ValueError, TypeError):
            duration_ms = 500

        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(
                    ["termux-vibrate", "-d", str(duration_ms)], timeout=6, check=True
                ),
            )
            logger.info("Vibrated %dms", duration_ms)
        except Exception as exc:
            logger.warning("Vibration error: %s", exc)

    async def volume(self, bot, param: str) -> None:
        """
        Set media volume.
        Clamped to 0–15 (standard Android range) (Audit fix #14).
        """
        try:
            level = max(0, min(15, int(param)))
        except (ValueError, TypeError):
            await bot.send_message(self.chat_id, "❌ Volume must be an integer 0–15.")
            return

        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(
                    ["termux-volume", "music", str(level)], timeout=5, check=True
                ),
            )
            await bot.send_message(self.chat_id, f"🔊 Volume set to {level}.")
            logger.info("Volume set to %d", level)
        except Exception as exc:
            await bot.send_message(self.chat_id, f"❌ Volume error: {type(exc).__name__}")
            logger.error("Volume error: %s", exc)

    async def wake_pc(self, bot, _: str) -> None:
        """Send a Wake-on-LAN magic packet to TARGET_PC_MAC."""
        if not TARGET_PC_MAC:
            await bot.send_message(
                self.chat_id, "❌ TARGET_PC_MAC is not set in .env."
            )
            return

        if not _MAC_RE.match(TARGET_PC_MAC):
            await bot.send_message(
                self.chat_id, f"❌ '{TARGET_PC_MAC}' is not a valid MAC address."
            )
            logger.error("Invalid MAC: %s", TARGET_PC_MAC)
            return

        clean = TARGET_PC_MAC.replace(":", "").replace("-", "")
        magic = b"\xff" * 6 + bytes.fromhex(clean) * 16

        def _send() -> None:
            with Socket(AF_INET, SOCK_DGRAM) as sock:
                sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
                sock.sendto(magic, ("<broadcast>", 9))

        try:
            await asyncio.get_event_loop().run_in_executor(None, _send)
            await bot.send_message(
                self.chat_id, f"📡 WoL packet sent to {TARGET_PC_MAC}."
            )
            logger.info("WoL sent to %s", TARGET_PC_MAC)
        except Exception as exc:
            await bot.send_message(self.chat_id, f"❌ WoL failed: {type(exc).__name__}")
            logger.error("WoL error: %s", exc)

    async def cmd(self, bot, param: str) -> None:
        """Execute a whitelisted Termux shell command."""
        try:
            parts = shlex.split(param)
        except ValueError as exc:
            await bot.send_message(self.chat_id, f"❌ Invalid command syntax.")
            logger.error("shlex error: %s", exc)
            return

        if not parts:
            await bot.send_message(self.chat_id, "❌ Empty command.")
            return

        cmd_name = parts[0]
        if cmd_name not in ALLOWED_CMDS:
            await bot.send_message(
                self.chat_id, f"❌ Command '{cmd_name}' is not whitelisted."
            )
            logger.warning("Blocked command: %s", cmd_name)
            return

        for arg in parts[1:]:
            if not _sanitize_arg(arg):
                await bot.send_message(self.chat_id, "❌ Invalid argument format.")
                logger.warning("Rejected argument: %s", arg)
                return

        def _run() -> str:
            result = subprocess.run(
                parts, capture_output=True, text=True,
                timeout=COMMAND_TIMEOUT, check=False,
            )
            if result.returncode != 0:
                return (
                    f"⚠️ Exit {result.returncode}:\n"
                    + (result.stderr or "No error details")
                )
            return result.stdout or "✅ Command executed (no output)."

        try:
            output = await asyncio.get_event_loop().run_in_executor(None, _run)
            await bot.send_message(self.chat_id, output[:MAX_OUTPUT_LENGTH])
            logger.info("Command executed: %s", cmd_name)
        except subprocess.TimeoutExpired:
            await bot.send_message(self.chat_id, "⏱️ Command timed out.")
            logger.error("Command timeout: %s", param)
        except Exception as exc:
            await bot.send_message(self.chat_id, f"❌ Error: {type(exc).__name__}")
            logger.error("cmd error: %s", exc)

    # ── AI processing ──────────────────────────────────────────────────────────

    async def _process_ai(self, text: str) -> Tuple[str, str]:
        if not text or len(text) > 2_000:
            return "chat", "⚠️ Message too long or empty (max 2 000 chars)."

        async with self._history_lock:
            self._chat_history.append({"role": "user", "content": text})
            self._chat_history = self._chat_history[-8:]
            snapshot = list(self._chat_history)

        try:
            completion = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.ai.chat.completions.create(
                    messages=[
                        {"role": "system", "content": self.system_instruction}
                    ] + snapshot,
                    model="llama-3.1-8b-instant",
                    response_format={"type": "json_object"},
                    timeout=15,
                ),
            )
            data = json.loads(completion.choices[0].message.content)
            action = data.get("action", "chat")
            param = str(data.get("param", ""))

            if action not in self.actions and action != "chat":
                logger.warning("Unknown AI action: %s", action)
                return "chat", "⚠️ Unknown action returned by AI."

            logger.info("AI action: %s", action)
            return action, param

        except json.JSONDecodeError as exc:
            logger.error("AI JSON parse error: %s", exc)
            return "chat", "⚠️ AI returned invalid format."
        except Exception as exc:
            logger.error("AI processing error: %s", exc)
            return "chat", "⚠️ AI service temporarily unavailable."

    # ── Telegram message handler ───────────────────────────────────────────────

    async def handle(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        message = update.message
        if not message or not message.text:
            return

        if str(message.chat.id) != self.chat_id:
            logger.debug("Unauthorized chat: %s", message.chat.id)
            return

        text = message.text.strip()
        bot = context.bot

        # ── PIN handling (must come before auth gate) ─────────────────────
        was_pin = await self._process_pin(bot, text)
        if was_pin:
            return

        # ── Auth gate ─────────────────────────────────────────────────────
        if not self._authenticated:
            await bot.send_message(
                self.chat_id, "🔒 Authentication required. Send: pin <YOUR_PIN>"
            )
            return

        # ── Confirmation redemption ───────────────────────────────────────
        confirm_match = re.fullmatch(r"confirm\s+([A-Z0-9]{6})", text, re.IGNORECASE)
        if confirm_match:
            token = confirm_match.group(1).upper()
            redeemed = await self._try_redeem_confirmation(bot, token)
            if redeemed:
                return
            await bot.send_message(self.chat_id, "❓ Unknown or expired token.")
            return

        await bot.send_chat_action(self.chat_id, "typing")
        action, param = await self._process_ai(text)

        if action == "chat":
            await bot.send_message(self.chat_id, param)
            return

        if action not in self.actions:
            await bot.send_message(self.chat_id, "❌ Unknown action.")
            logger.error("Unmapped action: %s", action)
            return

        # ── RBAC gate ─────────────────────────────────────────────────────
        privilege = ACTION_PRIVILEGES.get(action, Privilege.ELEVATED)
        if privilege == Privilege.DESTRUCTIVE:
            await self._request_confirmation(bot, action, param)
            return

        await self.actions[action](bot, param)

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def run(self) -> None:
        app = Application.builder().token(TELEGRAM_TOKEN).build()
        app.add_handler(
            MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle)
        )
        logger.info("🔥 JarvisMobilev2 running (async)…")
        app.run_polling(drop_pending_updates=True)


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        JarvisMobilev2().run()
    except ValueError as exc:
        print(f"[STARTUP ERROR] {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        logger.critical("Fatal error: %s", exc)
        sys.exit(1)
