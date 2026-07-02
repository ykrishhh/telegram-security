# Telegram Security

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Telegram](https://img.shields.io/badge/Telegram-API-26A5E4?style=for-the-badge&logo=telegram&logoColor=white)
![Security](https://img.shields.io/badge/Security-Audit-red?style=for-the-badge)
![PRs](https://img.shields.io/badge/PRs-Welcome-brightgreen?style=for-the-badge)
![Stars](https://img.shields.io/github/stars/ykrishhh/telegram-security?style=for-the-badge&color=yellow)

Telegram security monitoring, bot detection, channel analysis, and privacy auditing tools. Analyze Telegram sessions, detect malicious bots, and audit your messaging privacy.

**Keywords**: `telegram` `security` `privacy` `bot-detection` `monitoring` `python` `telethon` `pyrogram` `session-security` `api-security`

---

## Table of Contents

- [Why This Exists](#why-this-exists)
- [Features](#features)
- [Installation](#installation)
- [Bot Detection](#bot-detection)
- [Channel Analysis](#channel-analysis)
- [Privacy Audit](#privacy-audit)
- [Session Security](#session-security)
- [API Security](#api-security)
- [Data Collection Risks](#data-collection-risks)
- [Secure Usage Guide](#secure-usage-guide)
- [Python Scripts](#python-scripts)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Why This Exists

Telegram is great for a lot of things, but privacy isn't exactly its strong suit unless you use secret chats. I kept running into the same problems: bot-spam in channels, session files sitting on disk in plaintext, privacy settings I couldn't figure out without digging through API docs. So I built tools to make this stuff easier.

---

## Features

- **Bot detection** — Identify automated accounts, spam bots, and phishing attempts
- **Channel analysis** — Audit channel metadata, posting patterns, and subscriber growth
- **Privacy audit** — Check your account exposure and settings
- **Session management** — Detect and revoke unauthorized sessions
- **API security helpers** — Secure storage for API credentials and session files
- **Data collection risk assessment** — Understand what metadata Telegram collects
- **Forward-trace detection** — Track message forwarding chains

---

## Installation

```bash
git clone https://github.com/ykrishhh/telegram-security.git
cd telegram-security
pip install -r requirements.txt
```

### Requirements

```
telethon>=1.30.0
pyrogram>=2.0.0
tgcrypto>=1.2.5
python-dotenv>=1.0.0
cryptography>=41.0.0
rich>=13.0.0
```

### Environment Setup

```bash
# Create .env file with your credentials
cat <<EOF > .env
TELEGRAM_API_ID=your_api_id
TELEGRAM_API_HASH=your_api_hash
TELEGRAM_PHONE=+1234567890
EOF
```

Obtain `API_ID` and `API_HASH` from [my.telegram.org](https://my.telegram.org).

---

## Bot Detection

### Analyze User Behavior Patterns

The scoring system here is heuristic — it's not perfect, but it catches most automated accounts. The timing regularity check is the most reliable signal. Real humans don't post at exactly 300-second intervals.

```python
#!/usr/bin/env python3
"""
Telegram bot detection via behavioral analysis
Author: ykrishhh
"""

import asyncio
from datetime import datetime, timedelta
from collections import Counter
from telethon import TelegramClient
from telethon.tl.types import User


class BotDetector:
    """Identify likely automated accounts based on activity patterns."""

    def __init__(self, client: TelegramClient):
        self.client = client

    async def analyze_user(self, user_id: int) -> dict:
        """Profile a user for bot-like characteristics."""
        user = await self.client.get_entity(user_id)
        messages = await self.client.get_messages(user, limit=200)

        if not messages:
            return {"user_id": user_id, "verdict": "insufficient_data"}

        # Extract timing patterns
        timestamps = [msg.date for msg in messages if msg.date]
        intervals = []
        for i in range(1, len(timestamps)):
            diff = (timestamps[i - 1] - timestamps[i]).total_seconds()
            intervals.append(abs(diff))

        # Calculate metrics
        avg_interval = sum(intervals) / len(intervals) if intervals else 0
        std_dev = self._std_dev(intervals) if intervals else 0
        hour_dist = Counter(t.hour for t in timestamps)

        # Scoring heuristics
        score = 0
        reasons = []

        # Regularity check: low std dev = suspicious
        if avg_interval > 0 and std_dev / avg_interval < 0.1 and len(intervals) > 10:
            score += 30
            reasons.append("Unusually regular posting intervals")

        # 24/7 activity
        active_hours = len([h for h, c in hour_dist.items() if c > 2])
        if active_hours >= 20:
            score += 25
            reasons.append(f"Active across {active_hours}/24 hours")

        # No profile photo
        if not user.photo:
            score += 10
            reasons.append("No profile photo")

        # Account age check
        if user.premium is False and user.bot is False:
            if user.id and user.id > 2000000000:
                score += 10
                reasons.append("Relatively new account ID")

        # Bot flag already set by Telegram
        if user.bot:
            score += 50
            reasons.append("Marked as bot by Telegram")

        verdict = "human"
        if score >= 60:
            verdict = "likely_bot"
        elif score >= 30:
            verdict = "suspicious"

        return {
            "user_id": user_id,
            "username": getattr(user, "username", None),
            "first_name": getattr(user, "first_name", ""),
            "score": score,
            "verdict": verdict,
            "reasons": reasons,
            "metrics": {
                "avg_post_interval_sec": round(avg_interval, 1),
                "interval_std_dev": round(std_dev, 1),
                "active_hours": active_hours,
                "total_messages": len(messages)
            }
        }

    @staticmethod
    def _std_dev(values: list) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return variance ** 0.5


async def main():
    """Scan a list of user IDs for bot behavior."""
    api_id = int(os.environ["TELEGRAM_API_ID"])
    api_hash = os.environ["TELEGRAM_API_HASH"]

    async with TelegramClient("scanner", api_id, api_hash) as client:
        detector = BotDetector(client)
        test_users = [123456789, 987654321]  # Replace with actual IDs

        for uid in test_users:
            result = await detector.analyze_user(uid)
            print(f"\nUser {uid}: {result['verdict'].upper()}")
            print(f"  Score: {result['score']}/100")
            for reason in result.get("reasons", []):
                print(f"  - {reason}")


if __name__ == "__main__":
    asyncio.run(main())
```

---

## Channel Analysis

### Metadata and Growth Auditor

This pulls channel metadata and recent messages to look for signs of fake subscribers or automated posting. If a channel has 100k followers but gets 50 views per post, something's off.

```python
#!/usr/bin/env python3
"""
Telegram channel security and metadata analysis
Author: ykrishhh
"""

import asyncio
import os
from datetime import datetime
from telethon import TelegramClient
from telethon.tl.types import ChannelParticipantsRecentlyOffline


class ChannelAuditor:
    """Analyze a Telegram channel for security and integrity."""

    def __init__(self, client: TelegramClient):
        self.client = client

    async def audit(self, channel_username: str) -> dict:
        """Run a full audit on the target channel."""
        channel = await self.client.get_entity(channel_username)
        report = {
            "name": channel.title,
            "username": channel_username,
            "id": channel.id,
            "type": "supergroup" if channel.megagroup else "channel",
            "subscribers": channel.participants_count,
            "created": str(channel.date),
            "verified": getattr(channel, "verified", False),
            "scam": getattr(channel, "scam", False),
            "fake": getattr(channel, "fake", False),
            "signatures": getattr(channel, "signatures", False),
            "restricted": getattr(channel, "restricted", False),
        }

        # Fetch recent messages for pattern analysis
        messages = []
        async for msg in self.client.iter_messages(channel, limit=100):
            messages.append(msg)

        if messages:
            report["message_count"] = len(messages)
            report["date_range"] = {
                "oldest": str(messages[-1].date),
                "newest": str(messages[0].date)
            }
            report["forwarded_count"] = sum(1 for m in messages if m.forward)
            report["media_count"] = sum(1 for m in messages if m.media)
            report["avg_views"] = (
                sum(m.views for m in messages if m.views) // len(messages)
                if any(m.views for m in messages) else 0
            )

            # Detect sudden subscriber spikes (buying subscribers)
            if channel.participants_count and channel.participants_count > 10000:
                report["subscriber_risk"] = "manual_review_recommended"
            else:
                report["subscriber_risk"] = "low"

        return report


async def run():
    api_id = int(os.environ["TELEGRAM_API_ID"])
    api_hash = os.environ["TELEGRAM_API_HASH"]

    async with TelegramClient("auditor", api_id, api_hash) as client:
        auditor = ChannelAuditor(client)
        result = await auditor.audit("durov")  # Example channel

        print(f"\nChannel: {result['name']}")
        print(f"Type: {result['type']}")
        print(f"Subscribers: {result.get('subscribers', 'N/A')}")
        print(f"Verified: {result['verified']}")
        print(f"Scam flag: {result['scam']}")
        print(f"Fake flag: {result['fake']}")
        print(f"Forwarded messages: {result.get('forwarded_count', 0)}")
        print(f"Avg views: {result.get('avg_views', 0)}")


if __name__ == "__main__":
    asyncio.run(run())
```

---

## Privacy Audit

### Account Exposure Check

Most people don't realize their phone number is visible to everyone by default. This script checks all your privacy settings and flags the risky ones.

```python
#!/usr/bin/env python3
"""
Telegram privacy settings audit
Author: ykrishhh
"""

import asyncio
import os
from telethon import TelegramClient
from telethon.tl.functions.account import GetPrivacyRequest
from telethon.tl.types import (
    PrivacyKeyStatusTimestamp,
    PrivacyKeyChatInvite,
    PrivacyKeyPhoneCall,
    PrivacyKeyPhoneP2P,
    PrivacyKeyProfilePhoto,
    PrivacyKeyPhoneNumber,
)


class PrivacyAuditor:
    """Check and report on Telegram privacy settings."""

    PRIVACY_KEYS = {
        PrivacyKeyStatusTimestamp: "Last seen",
        PrivacyKeyChatInvite: "Groups and channels",
        PrivacyKeyPhoneCall: "Phone calls",
        PrivacyKeyPhoneP2P: "Peer-to-peer calls",
        PrivacyKeyProfilePhoto: "Profile photo",
        PrivacyKeyPhoneNumber: "Phone number",
    }

    def __init__(self, client: TelegramClient):
        self.client = client

    async def audit_privacy(self) -> list:
        """Retrieve and evaluate all privacy settings."""
        results = []

        for key_cls, label in self.PRIVACY_KEYS.items():
            try:
                result = await self.client(GetPrivacyRequest(key_cls()))
                privacy_rule = result.rules[0] if result.rules else None

                if privacy_rule is None:
                    status = "unknown"
                elif hasattr(privacy_rule, "allow_users"):
                    status = "custom"
                elif hasattr(privacy_rule, "disallow_users"):
                    status = "restricted"
                else:
                    status = str(privacy_rule)

                results.append({
                    "setting": label,
                    "rule": status,
                    "allows_chat_members": getattr(result, "chats", [])
                })
            except Exception as e:
                results.append({"setting": label, "rule": f"error: {e}"})

        return results

    def evaluate_risks(self, settings: list) -> list:
        """Flag privacy settings that may expose the user."""
        risks = []
        for s in settings:
            if s["setting"] == "Phone number" and "Everybody" in str(s["rule"]):
                risks.append("Phone number visible to everyone")
            if s["setting"] == "Last seen" and "Everybody" in str(s["rule"]):
                risks.append("Online status visible to everyone")
            if s["setting"] == "Groups and channels" and "Everybody" in str(s["rule"]):
                risks.append("Anyone can add you to groups")
        return risks


async def main():
    api_id = int(os.environ["TELEGRAM_API_ID"])
    api_hash = os.environ["TELEGRAM_API_HASH"]

    async with TelegramClient("privacy-check", api_id, api_hash) as client:
        auditor = PrivacyAuditor(client)
        settings = await auditor.audit_privacy()
        risks = auditor.evaluate_risks(settings)

        print("\n=== Privacy Settings Audit ===\n")
        for s in settings:
            print(f"  {s['setting']:20s} : {s['rule']}")

        if risks:
            print("\n=== Privacy Risks Detected ===\n")
            for r in risks:
                print(f"  [!] {r}")
        else:
            print("\n[+] No obvious privacy risks found.")


if __name__ == "__main__":
    asyncio.run(main())
```

---

## Session Security

### Detect and Revoke Unauthorized Sessions

I run this monthly. It's eye-opening how many sessions pile up — old phones, web clients you forgot about, that one time you logged in from a friend's laptop. Kill the ones you don't recognize.

```python
#!/usr/bin/env python3
"""
Telegram session security manager
Author: ykrishhh
"""

import asyncio
import os
from telethon import TelegramClient
from telethon.tl.functions.account import GetAuthorizationsRequest, DeleteAuthorizationRequest


class SessionManager:
    """List, audit, and revoke Telegram sessions."""

    def __init__(self, client: TelegramClient):
        self.client = client

    async def list_sessions(self) -> list:
        """Fetch all active sessions."""
        result = await self.client(GetAuthorizationsRequest())
        sessions = []

        for auth in result.authorizations:
            sessions.append({
                "hash": auth.hash,
                "device": auth.device_model,
                "platform": auth.platform,
                "system_version": auth.system_version,
                "api_id": auth.api_id,
                "app_name": auth.app_name,
                "date_created": str(auth.date_created),
                "date_active": str(auth.date_active),
                "ip": auth.ip,
                "country": auth.country,
                "is_current": getattr(auth, "current", False),
            })

        return sessions

    async def audit_sessions(self) -> dict:
        """Identify suspicious sessions."""
        sessions = await self.list_sessions()
        current = [s for s in sessions if s["is_current"]]
        others = [s for s in sessions if not s["is_current"]]

        suspicious = []
        for s in others:
            reasons = []
            if not s["ip"]:
                reasons.append("No IP recorded")
            if "Unknown" in s["device"]:
                reasons.append("Unrecognized device")
            suspicious.append({"session": s, "reasons": reasons})

        return {
            "total_sessions": len(sessions),
            "current_session": current[0] if current else None,
            "other_sessions": others,
            "suspicious": [s for s in suspicious if s["reasons"]],
            "recommendation": "revoke_unknown" if others else "all_clear"
        }

    async def revoke(self, session_hash: int) -> bool:
        """Terminate a specific session."""
        try:
            await self.client(DeleteAuthorizationRequest(hash=session_hash))
            return True
        except Exception:
            return False

    async def revoke_all_except_current(self) -> int:
        """Kill every session except the one in use."""
        sessions = await self.list_sessions()
        revoked = 0
        for s in sessions:
            if not s["is_current"]:
                if await self.revoke(s["hash"]):
                    revoked += 1
        return revoked


async def main():
    api_id = int(os.environ["TELEGRAM_API_ID"])
    api_hash = os.environ["TELEGRAM_API_HASH"]

    async with TelegramClient("session-check", api_id, api_hash) as client:
        mgr = SessionManager(client)
        audit = await mgr.audit_sessions()

        print(f"\nActive sessions: {audit['total_sessions']}")
        for s in audit["other_sessions"]:
            print(f"  Device: {s['device']}")
            print(f"  Platform: {s['platform']}")
            print(f"  IP: {s['ip']}")
            print(f"  Last active: {s['date_active']}")
            print(f"  ---")

        if audit["suspicious"]:
            print(f"\n[!] {len(audit['suspicious'])} suspicious session(s) detected")
            confirm = input("Revoke all non-current sessions? (y/N): ")
            if confirm.lower() == "y":
                count = await mgr.revoke_all_except_current()
                print(f"[+] Revoked {count} session(s)")


if __name__ == "__main__":
    asyncio.run(main())
```

---

## API Security

### Credential Storage

Your API credentials shouldn't live in plaintext in a `.env` file on a shared server. This encrypts them with AES-256-GCM behind a master password.

```python
#!/usr/bin/env python3
"""
Secure storage for Telegram API credentials
Author: ykrishhh
"""

import os
import json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
import secrets


CREDENTIALS_FILE = Path.home() / ".config" / "tg-security" / "credentials.enc"
KEY_DERIVATION_ITERATIONS = 600_000


def store_credentials(api_id: str, api_hash: str, phone: str, master_password: str) -> None:
    """Encrypt and store Telegram credentials on disk."""
    CREDENTIALS_FILE.parent.mkdir(parents=True, exist_ok=True)

    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", master_password.encode(), salt, KEY_DERIVATION_ITERATIONS, 32)

    data = json.dumps({
        "api_id": api_id,
        "api_hash": api_hash,
        "phone": phone
    }).encode()

    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, data, None)

    with open(CREDENTIALS_FILE, "wb") as f:
        f.write(salt + nonce + ct)

    os.chmod(CREDENTIALS_FILE, 0o600)
    print(f"[+] Credentials stored at {CREDENTIALS_FILE}")


def load_credentials(master_password: str) -> dict:
    """Decrypt and return stored credentials."""
    with open(CREDENTIALS_FILE, "rb") as f:
        raw = f.read()

    salt = raw[:16]
    nonce = raw[16:28]
    ct = raw[28:]

    key = hashlib.pbkdf2_hmac("sha256", master_password.encode(), salt, KEY_DERIVATION_ITERATIONS, 32)

    pt = AESGCM(key).decrypt(nonce, ct, None)
    return json.loads(pt)
```

---

## Data Collection Risks

### What Telegram Collects

| Data Type | Collected | Retention |
|-----------|-----------|-----------|
| Phone number | Yes | Account lifetime |
| Contact list | If synced | Until removed |
| IP addresses | Per session | Up to 12 months |
| Device info | Per session | Account lifetime |
| Usage metadata | Yes | Indefinite |
| Message content | Cloud chats: Yes | Until deleted |
| Message content | Secret chats: No | End-to-end encrypted |

This is the part most people don't want to hear. Telegram stores your cloud chat content on their servers. It's encrypted in transit and at rest, but Telegram holds the keys. Secret chats are different — those are truly end-to-end encrypted and never touch Telegram's servers.

### Risk Mitigation Steps

1. **Use Secret Chats** for sensitive conversations (E2E encrypted, device-only)
2. **Disable contact syncing** in Privacy settings
3. **Use a VPN** to mask your IP from Telegram servers
4. **Set a passcode lock** on the Telegram app
5. **Enable two-step verification** with a strong password
6. **Review sessions** monthly and revoke unknown ones

---

## Secure Usage Guide

### Two-Step Verification Setup

```
Settings > Privacy and Security > Two-Step Verification > Set Password
```

Choose a password unrelated to other accounts. This prevents account takeover even if an attacker intercepts your SMS code.

### Secret Chat Activation

```
Tap a contact's profile > More (⋮) > Start Secret Chat
```

Secret chats offer:
- End-to-end encryption (no cloud storage)
- Self-destructing messages
- Screenshot notifications
- Device-only message storage

### Forwarding Protection

Enable "Disable Forwarding" in Privacy settings so others cannot attribute forwarded messages to your account.

### Passcode Lock

```
Settings > Privacy and Security > Passcode Lock > Enable
```

Adds local biometric or PIN protection to the app.

---

## Python Scripts

All scripts require API credentials from [my.telegram.org](https://my.telegram.org).

### Running Any Script

```bash
# Set environment variables
export TELEGRAM_API_ID=12345678
export TELEGRAM_API_HASH=abcdef1234567890abcdef

# Run bot detection
python scripts/bot_detector.py

# Run channel audit
python scripts/channel_auditor.py

# Run privacy audit
python scripts/privacy_auditor.py

# Run session security check
python scripts/session_manager.py
```

---

## Disclaimer

These tools are intended for auditing your own accounts and analyzing publicly available channels. Do not use them to monitor other users without their explicit consent. Unauthorized surveillance violates Telegram's Terms of Service and applicable privacy laws. The author assumes no responsibility for misuse.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
