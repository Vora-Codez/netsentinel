"""Deployment settings, read from environment variables.

NETSENTINEL_HOST            bind address            (default 127.0.0.1; Docker uses 0.0.0.0)
NETSENTINEL_PORT            port                    (default 8765)
NETSENTINEL_HOME            data folder             (default ./data)
NETSENTINEL_ALLOWED_HOSTS   comma list of Host names this server answers to, or *
NETSENTINEL_SECURE_COOKIES  1 when served over HTTPS (adds Secure + HSTS)
NETSENTINEL_TRUST_PROXY     1 when behind a reverse proxy that sets X-Forwarded-*
NETSENTINEL_SETUP_CODE      fixed first-run setup code (otherwise random, printed at start-up)
NETSENTINEL_SECRET          session signing key (otherwise generated into the data folder)
NETSENTINEL_AUTOCAPTURE     1 to start live capture automatically (sensor mode)
"""
import os
import secrets
from dataclasses import dataclass, field

LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}


def _flag(name, default="0"):
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Env:
    host: str = "127.0.0.1"
    port: int = 8765
    allowed_hosts: list = field(default_factory=lambda: ["127.0.0.1", "localhost", "[::1]"])
    secure_cookies: bool = False
    trust_proxy: bool = False
    setup_code: str = ""
    autocapture: bool = False
    host_check_disabled: bool = False

    @property
    def is_loopback(self):
        return self.host in LOOPBACK


def load() -> Env:
    e = Env()
    e.host = os.environ.get("NETSENTINEL_HOST", e.host)
    try:
        e.port = int(os.environ.get("NETSENTINEL_PORT", e.port))
    except ValueError:
        pass
    hosts = [h.strip().lower() for h in os.environ.get("NETSENTINEL_ALLOWED_HOSTS", "").split(",") if h.strip()]
    if "*" in hosts:
        e.host_check_disabled = True
    elif hosts:
        e.allowed_hosts = sorted(set(hosts) | {"127.0.0.1", "localhost"})
    elif not e.is_loopback:
        e.host_check_disabled = True     # exposed but unconfigured: login still protects; we warn at start-up
    e.secure_cookies = _flag("NETSENTINEL_SECURE_COOKIES")
    e.trust_proxy = _flag("NETSENTINEL_TRUST_PROXY")
    e.setup_code = os.environ.get("NETSENTINEL_SETUP_CODE") or secrets.token_hex(4).upper()
    e.autocapture = _flag("NETSENTINEL_AUTOCAPTURE")
    return e
