"""Two-factor authentication: time-based one-time passwords (TOTP, RFC 6238) and recovery codes.

Works with any authenticator app (Google Authenticator, Microsoft Authenticator, Authy, 1Password,
Bitwarden...). Standard library only.
"""
import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from urllib.parse import quote

PERIOD, DIGITS, WINDOW = 30, 6, 1          # 30-second codes, 6 digits, accept one step of clock drift
RECOVERY_COUNT = 10
_B32 = "abcdefghijklmnopqrstuvwxyz234567"


def new_secret() -> str:
    """160 random bits, base32 (what authenticator apps expect)."""
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def code_at(secret: str, step: int, digits: int = DIGITS, digest=hashlib.sha1) -> str:
    """HOTP(secret, step) per RFC 4226 dynamic truncation."""
    mac = hmac.new(_key(secret), struct.pack(">Q", step), digest).digest()
    off = mac[-1] & 0x0F
    num = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(num).zfill(digits)


def current_step(now=None) -> int:
    return int((time.time() if now is None else now) // PERIOD)


def verify(secret: str, code: str, last_step: int = -1, now=None):
    """Return the matched time step, or None. Steps at or before `last_step` are refused, so a code
    can never be used twice (replay protection)."""
    code = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(code) != DIGITS or not secret:
        return None
    step = current_step(now)
    for s in range(step - WINDOW, step + WINDOW + 1):
        if s > last_step and hmac.compare_digest(code_at(secret, s), code):
            return s
    return None


def otpauth_uri(secret: str, account: str, issuer: str = "NetSentinel") -> str:
    label = quote(f"{issuer}:{account}")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}")


def pretty_secret(secret: str) -> str:
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))


# -- recovery codes ---------------------------------------------------------------------------
def _norm(code: str) -> str:
    return "".join(ch for ch in str(code or "").lower() if ch in _B32)


def hash_recovery(code: str) -> str:
    # Codes carry 50 random bits and are single-use, so a fast salted hash is enough here.
    return hashlib.sha256(b"netsentinel-recovery:" + _norm(code).encode()).hexdigest()


def new_recovery_codes(n: int = RECOVERY_COUNT):
    """Return (plain codes to show once, hashes to store)."""
    codes = []
    for _ in range(n):
        raw = "".join(secrets.choice(_B32) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes, [hash_recovery(c) for c in codes]


def looks_like_recovery(code: str) -> bool:
    return len(_norm(code)) == 10 and not str(code).strip().isdigit()
