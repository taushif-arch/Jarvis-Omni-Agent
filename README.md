# 🤖 Jarvis Omni-Agent — Enterprise Edition v2

> **Advanced Asynchronous Multi-Platform Remote Control & Automation Framework**
> 
> A production-grade, security-hardened agent system for intelligent remote device management via Telegram. Built with **asyncio**, **RBAC**, and **enterprise security patterns**.

---

## 📋 Table of Contents

- [🎯 Overview](#-overview)
- [✨ Key Features](#-key-features)
- [🏗️ Architecture](#-architecture)
  - [Async Concurrency Model](#async-concurrency-model)
  - [RBAC System](#rbac-system)
- [🔐 Security Features](#-security-features)
- [📱 Platform Agents](#-platform-agents)
- [⚙️ Installation & Setup](#-installation--setup)
- [🚀 Getting Started](#-getting-started)
- [📚 Configuration](#-configuration)
- [🔑 API Reference](#-api-reference)
- [📝 License](#-license)

---

## 🎯 Overview

**Jarvis Omni-Agent** is a next-generation remote device controller engineered for enterprise environments. It provides two specialized agents:

- **🖥️ Windows PC Agent** — Screenshot, webcam, live streaming, keylogging, file management, app launching
- **📱 Termux Mobile Agent** — Hardware controls (battery, torch, vibration, location), SMS, clipboard, Wake-on-LAN

Both agents communicate securely via **Telegram** with role-based access control, time-limited confirmation tokens, and comprehensive audit logging.

---

## ✨ Key Features

### 🖥️ Windows PC Agent (`new_pc_agent_enterprise.py`)

| Feature | Description |
|---------|-------------|
| 📸 **Screenshot** | Full desktop screenshot capture and transmission |
| 📹 **Webcam Capture** | Photo capture with auto-focus warm-up |
| 🎥 **Live Screen** | Real-time screen streaming (5s intervals) |
| 🎙️ **Screen Recording** | MP4 video recording (1–120 seconds) |
| 🔑 **Keylogger** | Background keystroke recording to encrypted file |
| 🚀 **App Launcher** | Execute whitelisted Windows applications |
| 📋 **App History** | List active windowed processes (PowerShell-backed) |
| 📥 **Download Manager** | HTTP/HTTPS file downloads with SHA-256 verification |
| 📤 **File Retrieval** | Send files from local storage to Telegram |
| 💻 **Command Execution** | Whitelisted shell commands (ipconfig, dir, whoami) |
| 📋 **Clipboard** | Get/set clipboard content |
| 🔒 **System Control** | Lock, restart, shutdown with confirmation |
| 🎛️ **AI-Powered** | Groq LLaMA natural language routing |

### 📱 Termux Mobile Agent (`new_mobile_agent_enterprise.py`)

| Feature | Description |
|---------|-------------|
| 🔋 **Battery Status** | Real-time battery health and percentage |
| 📍 **Location** | GPS coordinates with Google Maps link |
| 🔦 **Torch Control** | Flashlight on/off |
| 📱 **SMS Sending** | Send text messages (DESTRUCTIVE, requires confirmation) |
| 🎙️ **Text-to-Speech** | Speak arbitrary text via device |
| 🎤 **Audio Recording** | Record up to 60 seconds of audio |
| 📸 **Photo Capture** | Front/rear camera photo capture |
| 📋 **Clipboard** | Get/set clipboard via Termux API |
| 💫 **Vibration** | Bounded vibration (100–5000 ms) |
| 🔊 **Volume Control** | Media volume 0–15 |
| 📡 **Wake-on-LAN** | Send magic packets to wake remote PCs |
| 💻 **Shell Commands** | Whitelisted shell access (ls, pwd, whoami) |

---

## 🏗️ Architecture

### Async Concurrency Model

Both agents are built entirely on **`asyncio` + `python-telegram-bot` v20+**, eliminating thread-blocking bottlenecks:

```
┌─────────────────────────────────────────────────────┐
│         Telegram Message Received                   │
└──────────────────┬──────────────────────────────────┘
                   │
        ┌──────────▼──────────┐
        │  Auth Gate (Async)  │
        └──────────┬──────────┘
                   │
    ┌──────────────▼──────────────┐
    │  AI Routing (Groq LLaMA)    │
    │  (Executor w/ timeout)      │
    └──────────────┬──────────────┘
                   │
        ┌──────────▼──────────┐
        │  RBAC Gate          │
        │  - Check privilege  │
        │  - Destructive? →   │
        │    Request confirm  │
        └──────────┬──────────┘
                   │
    ┌──────────────▼──────────────┐
    │  Action Handler (Async)     │
    │  ├─ Blocking calls via      │
    │  │  run_in_executor()       │
    │  └─ Non-blocking I/O for    │
    │     network/Telegram        │
    └─────────────────────────────┘
```

**Key Design Principles:**

- ✅ **No threads** — Pure asyncio event loop
- ✅ **Executor delegation** — Blocking Termux/Windows CLI calls via `run_in_executor()`
- ✅ **asyncio.Lock** — All shared mutable state protected
- ✅ **Timeout management** — Every external call has a deadline
- ✅ **Graceful shutdown** — CancelledError handling in long-running tasks

### RBAC System

Actions are stratified into three privilege tiers:

```python
SAFE = 0        # Execute immediately
ELEVATED = 1    # Standard actions, requires authentication
DESTRUCTIVE = 2 # Sensitive actions, requires time-limited OTP
```

**Confirmation Flow:**

```
User: "send sms to +1234567890"
     ↓
[AI routes to: sms_send (DESTRUCTIVE)]
     ↓
[Agent generates 6-char token: K3X9M2]
     ↓
[Telegram]: "⚠️ Destructive action: sms_send
             Reply: confirm K3X9M2"
     ↓
User: "confirm K3X9M2"
     ↓
[Token validated (≤ 60s TTL)]
     ↓
✅ Action executed
```

---

## 🔐 Security Features

### 1. **Path Traversal Prevention** (Audit #1)
```python
def _safe_path(user_path: str) -> Optional[Path]:
    target = Path(user_path).resolve()
    base = BASE_DIR.resolve()
    if not target.is_relative_to(base):  # Python 3.9+
        return None  # Blocked!
    return target
```
Uses `Path.is_relative_to()` to eliminate string-prefix bypass vulnerabilities.

### 2. **Command Injection Prevention** (Audit #2)
```python
# ❌ VULNERABLE: os.system(f"cmd /c {app_name}")
# ✅ SAFE:
subprocess.run(["cmd", "/c", "start", "", app_name], check=False)
```
List-based subprocess calls prevent shell metacharacter injection.

### 3. **PIN Authentication with Constant-Time Comparison**
```python
def _verify_pin(pin: str, pin_hash: str) -> bool:
    return secrets.compare_digest(_hash_pin(pin), pin_hash)
```
Protects against timing-based brute-force attacks.

### 4. **Startup Validation** (Audit #10)
```python
TELEGRAM_TOKEN: str = _require_env("TELEGRAM_TOKEN")  # Raises if missing
GROQ_API_KEY: str = _require_env("GROQ_API_KEY")
SECRET_PIN_HASH: str = hashlib.sha256(_PIN_PLAINTEXT.encode()).hexdigest()
del _PIN_PLAINTEXT  # Never keep plaintext in memory
```
All secrets must be present at startup; no silent fallbacks.

### 5. **URL Scheme Validation** (Audit #6)
```python
parsed = urlparse(url)
if parsed.scheme not in ("http", "https"):
    return False  # Only HTTP/HTTPS allowed
```
Prevents data:// URIs, local file:// access, etc.

### 6. **Async-Safe Rate Limiting** (Audit #8)
```python
@async_rate_limit(seconds=10)
async def sms_send(self, bot, param: str) -> None:
    ...
```
Per-function asyncio.Lock eliminates TOCTOU races in the original threading version.

### 7. **Keylogger I/O Synchronization** (Audit #7)
```python
async with self._keylog_lock:
    # Atomic read-then-clear
    data = self._keylog_file.read_bytes()
    self._keylog_file.write_text("")
```
Prevents concurrent read/write races.

### 8. **Live Stream Race Prevention** (Audit #11)
```python
if param == "start":
    if self._live_event.is_set():  # Single source of truth
        return
    self._live_event.set()
    self._live_task = asyncio.create_task(self._broadcast_live(bot))
```
asyncio.Event is authoritative; eliminates check-then-act races.

### 9. **Input Validation**
- ✅ Phone numbers: E.164 format validation
- ✅ Duration bounds: Vibration (100–5000 ms), volume (0–15)
- ✅ File sizes: 500 MB limit per download
- ✅ Command arguments: Alphanumeric + safe characters only
- ✅ Clipboard: Max 5,000–10,000 characters

---

## 📱 Platform Agents

### 🖥️ Windows PC Agent

**Requirements:**
- Windows 10/11
- Python 3.9+
- OpenCV, pyautogui, pynput, pyperclip

**Key Modules:**
- `new_pc_agent_enterprise.py` — Main agent
- `requirements.txt` — Pip dependencies

**Notable Security:**
- PowerShell commands use argument lists (no shell=True)
- Keylogger runs in executor thread with asyncio.Lock for file I/O
- Live stream managed via asyncio.Event (race-free)
- Downloads verified with SHA-256 checksums

---

### 📱 Termux Mobile Agent

**Requirements:**
- Termux (F-Droid or Play Store)
- Python 3.9+
- Termux API package (for hardware controls)

**Key Modules:**
- `new_mobile_agent_enterprise.py` — Main agent
- `requirements.txt` — Pip dependencies

**Termux API Dependencies:**
```bash
pkg install termux-api termux-api-service
# Approvals for: Camera, Location, Sensors, Clipboard, Microphone, SMS
```

**Notable Security:**
- MAC address validation (regex before WoL)
- Phone number E.164 format check (before SMS)
- Vibration/volume bounds clamped (no driver abuse)
- All Termux CLI calls timeout-protected

---

## ⚙️ Installation & Setup

### Prerequisites

**Both Platforms:**
- Python 3.9 or higher
- `pip` package manager
- Telegram bot (create via [@BotFather](https://t.me/botfather))

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/jarvis-omni-agent.git
cd jarvis-omni-agent
```

### Step 2: Create Virtual Environment

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**Termux/Linux:**
```bash
python -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

**`requirements.txt`:**
```
python-telegram-bot>=20.0
groq>=0.4.0
python-dotenv>=0.19.0
pyautogui>=0.9.53      # Windows only
pyperclip>=1.8.2       # Windows only
opencv-python>=4.5.0   # Windows only
pynput>=1.7.6          # Windows only
numpy>=1.19.0          # Windows only
requests>=2.25.0
```

### Step 4: Create `.env` Configuration File

Create a `.env` file in the repository root:

```bash
# Telegram Configuration
TELEGRAM_TOKEN=123456789:ABCDefGHIjklmnoPQRstuvWXYZ
CHAT_ID=987654321

# AI Provider (Groq)
GROQ_API_KEY=gsk_abcdefghijklmnopqrstuvwxyz...

# Security
SECRET_PIN=your-secure-pin-here

# PC Agent only
TARGET_PC_MAC=AA:BB:CC:DD:EE:FF
```

**Obtain values:**

1. **TELEGRAM_TOKEN**: Message [@BotFather](https://t.me/botfather), click `/newbot`
2. **CHAT_ID**: Message your bot, then visit `https://api.telegram.org/botTOKEN/getUpdates`
3. **GROQ_API_KEY**: Sign up at [console.groq.com](https://console.groq.com)
4. **SECRET_PIN**: Choose a strong PIN (8+ alphanumeric)

---

## 🚀 Getting Started

### Windows PC Agent

```bash
# 1. Activate venv
venv\Scripts\activate

# 2. Set environment
set PYTHONUNBUFFERED=1

# 3. Run agent
python new_pc_agent_enterprise.py
```

**Expected Output:**
```
2026-04-08 14:30:15,123 - JarvisPCv2 - INFO - JarvisPCv2 initialised
2026-04-08 14:30:15,456 - JarvisPCv2 - INFO - 🔥 JarvisPCv2 running (async)…
```

### Termux Mobile Agent

```bash
# 1. Activate venv
source venv/bin/activate

# 2. Grant permissions
termux-setup-storage

# 3. Ensure termux-api service is running
termux-api-dialog

# 4. Run agent
python new_mobile_agent_enterprise.py
```

**Expected Output:**
```
2026-04-08 14:30:15,123 - JarvisMobilev2 - INFO - JarvisMobilev2 initialised
2026-04-08 14:30:15,456 - JarvisMobilev2 - INFO - 🔥 JarvisMobilev2 running (async)…
```

---

## 📚 Configuration

### Environment Variables Reference

| Variable | Required | Example | Notes |
|----------|----------|---------|-------|
| `TELEGRAM_TOKEN` | ✅ Yes | `123456789:ABC...` | From @BotFather |
| `CHAT_ID` | ✅ Yes | `987654321` | Your Telegram user ID |
| `GROQ_API_KEY` | ✅ Yes | `gsk_abc...` | From console.groq.com |
| `SECRET_PIN` | ✅ Yes | `MySecurePin123!` | Authentication PIN |
| `TARGET_PC_MAC` | ❌ No | `AA:BB:CC:DD:EE:FF` | PC Agent only (WoL) |

### Security Constants

**Hardcoded in agent code** (adjust as needed):

```python
# Rate limiting
RATE_LIMIT_SECONDS = 10

# Authentication
MAX_AUTH_ATTEMPTS = 3
LOCKOUT_DURATION_SECONDS = 15 * 60

# Confirmation tokens
CONFIRM_TTL_SECONDS = 60

# Command execution
COMMAND_TIMEOUT = 30

# File transfer
MAX_FILE_SIZE_BYTES = 500 * 1024 * 1024  # 500 MB
```

---

## 🔑 API Reference

### Command Format

All agent actions are routed via natural language. Examples:

```
User: "Take a screenshot"
→ Agent: ss action → screenshot sent

User: "What's my battery?"
→ Agent: battery action → status sent

User: "Send SMS to +1234567890: Hello"
→ Agent: sms_send (DESTRUCTIVE) → confirmation requested
User: "confirm K3X9M2"
→ Action executed
```

### Privilege Levels

```python
# Automatic (no confirmation)
SAFE:        battery, location, clip_get, webcam, ss
ELEVATED:    torch, photo, tts, record, cmd, clip_set, volume

# Requires 6-char OTP token (60s TTL)
DESTRUCTIVE: sms_send, shutdown, restart, start_keylogger
```

---

## 📝 Audit Trail & Logging

Both agents maintain comprehensive audit logs:

**Windows:** `jarvis_pc_audit.log`
```
2026-04-08 14:35:22,100 - JarvisPCv2 - WARNING - Auth blocked — attempt_count=3
2026-04-08 14:35:45,200 - JarvisPCv2 - INFO - Screenshot captured
2026-04-08 14:36:00,300 - JarvisPCv2 - WARNING - Confirmation requested for action=shutdown token=X9K3M2
```

**Mobile:** `jarvis_mobile_audit.log`
```
2026-04-08 14:35:22,100 - JarvisMobilev2 - INFO - Battery status retrieved
2026-04-08 14:35:45,200 - JarvisMobilev2 - WARNING - Rate limit hit for sms_send — retry in 3s
```

---

## 🛡️ Security Best Practices

1. **Protect `.env`** — Add to `.gitignore`; never commit secrets
2. **Use strong PINs** — Minimum 8 characters, mixed alphanumeric
3. **Monitor logs** — Review audit logs regularly for suspicious activity
4. **Limit bot access** — Only grant chat access to trusted users
5. **Update dependencies** — Run `pip install --upgrade -r requirements.txt` monthly
6. **Restrict permissions** — Use OS-level restrictions (Windows Firewall, SELinux)

---

## 🐛 Troubleshooting

### "❌ Required environment variable 'TELEGRAM_TOKEN' is not set"
→ Create `.env` file with all required variables (see [Configuration](#-configuration))

### "⏳ Rate limited. Retry in Xs."
→ Normal; destructive actions are rate-limited to prevent abuse

### "🔒 Too many failed attempts. Retry in 900s."
→ Incorrect PIN 3 times; lockout active; wait 15 minutes

### Keylogger not recording
→ Ensure `pynput` is installed; may need admin/accessibility permissions on Windows

### Termux commands not working
→ Install `termux-api` package; grant app permissions via system settings

---

## 📄 License

This project is licensed under the **MIT License**. See `LICENSE` file for details.

---

## 🙏 Acknowledgments

- **python-telegram-bot** — Async Telegram API bindings
- **Groq** — Fast LLaMA inference for natural language routing
- **Termux** — Advanced terminal emulator for Android
- Security audit team for comprehensive vulnerability assessments

---

**Built with ❤️ for enterprise security and automation.**