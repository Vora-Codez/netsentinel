"""Users, roles, password hashing, two-factor sign-in, server-side sessions and the audit trail."""
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone

from . import mfa

ROLES = {"viewer": 1, "analyst": 2, "admin": 3}
ROLE_HELP = {"viewer": "Can look at everything, change nothing.",
             "analyst": "Can scan, capture, run the demo and review alerts.",
             "admin": "Everything, plus settings, users and the audit log."}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD = 12
MAX_PASSWORD = 200

# scrypt cost. N=2^15, r=8 needs 32 MiB of RAM per guess, which makes GPU cracking expensive.
# Older hashes (made with N=2^14 in v3.0) still verify and are upgraded at the next sign-in.
_N, _R, _P = 2 ** 15, 8, 1
_MAXMEM = 128 * 1024 * 1024

# Passwords that pass the length rule but are still among the first things attackers try.
COMMON_PASSWORDS = {
    "123456789012", "1234567890123", "12345678901234", "000000000000", "111111111111", "123123123123",
    "qwertyuiopas", "qwerty123456", "1q2w3e4r5t6y", "1qaz2wsx3edc", "zaq12wsxcde3", "asdfghjkl123",
    "passwordpassword", "password1234", "password12345", "password123456", "passw0rd1234",
    "iloveyou1234", "letmein12345", "welcome12345", "changeme1234", "administrator", "admin1234567",
    "trustno1trustno1", "abc123456789", "abcdefghijkl", "monkey123456", "dragon123456",
    "football1234", "baseball1234", "superman1234", "sunshine1234", "princess1234",
    "correcthorsebatterystaple", "correct horse battery staple", "netsentinel123", "netsentinel1234",
}
WEAK_WORDS = {"password", "passw0rd", "qwerty", "letmein", "welcome", "admin", "administrator", "netsentinel",
              "iloveyou", "monkey", "dragon", "football", "baseball", "sunshine", "princess", "changeme",
              "master", "login", "secret", "summer", "winter", "spring", "autumn", "abc", "qwertyuiop"}


class AuthError(Exception):
    def __init__(self, message, status=400, code=""):
        super().__init__(message)
        self.status, self.code = status, code


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# -- password hashing ------------------------------------------------------------------------
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32, maxmem=_MAXMEM)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, h = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                              dklen=len(h) // 2, maxmem=_MAXMEM)
        return hmac.compare_digest(calc.hex(), h)
    except (ValueError, TypeError):
        return False


def needs_rehash(stored: str) -> bool:
    try:
        _, n, r, p, _, _ = stored.split("$")
        return (int(n), int(r), int(p)) != (_N, _R, _P)
    except ValueError:
        return True


_DUMMY = None


def _dummy_hash():
    global _DUMMY
    _DUMMY = _DUMMY or hash_password("not-a-real-password")
    return _DUMMY


def check_password_policy(password, username=""):
    """Raise AuthError with a plain-English reason if the password is too weak."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        raise AuthError(f"Use a password of at least {MIN_PASSWORD} characters. A few random words works well.")
    if len(password) > MAX_PASSWORD:
        raise AuthError(f"That password is too long (max {MAX_PASSWORD} characters).")
    low = password.lower()
    if low in COMMON_PASSWORDS or low.replace(" ", "") in COMMON_PASSWORDS:
        raise AuthError("That password is on lists of common passwords attackers try first.")
    if username and len(username) >= 3 and username.lower() in low:
        raise AuthError("Don't put your username inside your password.")
    if len(set(low)) < 5:
        raise AuthError("That password repeats too few different characters.")
    letters = re.sub(r"[^a-z]", "", low)
    if letters in WEAK_WORDS:
        raise AuthError("That's a common word with numbers or symbols added, which attackers guess easily.")


class LoginThrottle:
    """Locks a key (client + username, or a whole client address) after repeated failures."""
    def __init__(self, max_fails=5, lock_seconds=300):
        self.max_fails, self.lock_seconds = max_fails, lock_seconds
        self._state, self._lock = {}, threading.Lock()

    def wait_time(self, key) -> int:
        with self._lock:
            fails, until = self._state.get(key, (0, 0))
            return max(0, int(until - time.time()) + 1) if until > time.time() else 0

    def fail(self, key):
        with self._lock:
            fails, until = self._state.get(key, (0, 0))
            fails += 1
            if fails >= self.max_fails:
                fails, until = 0, time.time() + self.lock_seconds
            self._state[key] = (fails, until)
            if len(self._state) > 5000:
                self._state.clear()

    def ok(self, key):
        with self._lock:
            self._state.pop(key, None)


def describe_agent(ua: str) -> str:
    """'Chrome on Windows' from a User-Agent string, for the sessions list."""
    ua = ua or ""
    browser = next((name for key, name in (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"),
                                           ("Chrome/", "Chrome"), ("Safari/", "Safari")) if key in ua), "")
    system = next((name for key, name in (("Windows", "Windows"), ("Android", "Android"), ("iPhone", "iPhone"),
                                          ("iPad", "iPad"), ("Mac OS X", "macOS"), ("Linux", "Linux")) if key in ua), "")
    if browser and system:
        return f"{browser} on {system}"
    return browser or system or (ua[:40] if ua else "Unknown device")


class AuthService:
    def __init__(self, db):
        self.db = db
        self._lock = threading.Lock()

    # -- users -------------------------------------------------------------------------------
    @staticmethod
    def _public(row):
        if not row:
            return None
        out = {k: row[k] for k in ("id", "username", "role", "disabled", "created", "last_login", "last_login_ip")}
        out["totp_enabled"] = bool(row["totp_enabled"])
        out["must_change_pw"] = bool(row["must_change_pw"])
        out["recovery_left"] = len(json.loads(row["recovery_codes"] or "[]"))
        out["pw_changed"] = row["pw_changed"]
        return out

    def _row(self, uid):
        rows = self.db.query("SELECT * FROM users WHERE id = ?", (uid,))
        return rows[0] if rows else None

    def count(self) -> int:
        return self.db.query("SELECT COUNT(*) AS n FROM users")[0]["n"]

    def get(self, uid):
        return self._public(self._row(uid))

    def list(self):
        return [self._public(r) for r in self.db.query("SELECT * FROM users ORDER BY username")]

    def create(self, username, password, role="viewer", first_user=False, must_change=False):
        username = (username or "").strip()
        if not USERNAME_RE.match(username):
            raise AuthError("Usernames are 3-32 characters: letters, numbers, dot, dash, underscore.")
        if role not in ROLES:
            raise AuthError("Unknown role.")
        check_password_policy(password, username)
        pw = hash_password(password)
        with self._lock:
            if first_user and self.count() > 0:
                raise AuthError("Setup has already been completed.", 409)
            if self.db.query("SELECT 1 FROM users WHERE username = ?", (username,)):
                raise AuthError("That username is taken.", 409)
            now = _now()
            cur = self.db.execute(
                "INSERT INTO users (username, pw_hash, role, created, must_change_pw, pw_changed) VALUES (?,?,?,?,?,?)",
                (username, pw, role, now, 1 if must_change else 0, now))
        return self.get(cur.lastrowid)

    def authenticate(self, username, password):
        """Check a username and password. Returns the public user dict, or None."""
        rows = self.db.query("SELECT * FROM users WHERE username = ?", ((username or "").strip(),))
        if not rows:
            verify_password(password or "", _dummy_hash())       # same timing whether or not the user exists
            return None
        row = rows[0]
        if not verify_password(password or "", row["pw_hash"]) or row["disabled"]:
            return None
        if needs_rehash(row["pw_hash"]):                          # transparent upgrade to the current cost
            self.db.execute("UPDATE users SET pw_hash = ? WHERE id = ?", (hash_password(password), row["id"]))
        return self._public(row)

    def record_login(self, uid, ip):
        """Stamp the sign-in and return the previous one ({at, ip}) so the user can spot misuse."""
        row = self._row(uid)
        prev = {"at": row["last_login"], "ip": row["last_login_ip"]} if row and row["last_login"] else None
        self.db.execute("UPDATE users SET last_login = ?, last_login_ip = ? WHERE id = ?", (_now(), ip, uid))
        return prev

    def _admins_left(self, excluding):
        return self.db.query("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND disabled=0 AND id != ?",
                             (excluding,))[0]["n"]

    def update(self, uid, role=None, disabled=None, password=None, must_change=None, keep_session=None):
        """Admin and self-service changes. Anything that changes what a person may do signs them out
        everywhere (except `keep_session`, the session making a self-service password change)."""
        user = self.get(uid)
        if not user:
            raise AuthError("No such user.", 404)
        revoke = False
        if role is not None and role != user["role"]:
            if role not in ROLES:
                raise AuthError("Unknown role.")
            if user["role"] == "admin" and role != "admin" and not self._admins_left(uid):
                raise AuthError("There must always be at least one active administrator.")
            self.db.execute("UPDATE users SET role = ? WHERE id = ?", (role, uid))
            revoke = True
        if disabled is not None:
            if disabled and user["role"] == "admin" and not self._admins_left(uid):
                raise AuthError("There must always be at least one active administrator.")
            self.db.execute("UPDATE users SET disabled = ? WHERE id = ?", (1 if disabled else 0, uid))
            revoke = revoke or bool(disabled)
        if password is not None:
            check_password_policy(password, user["username"])
            row = self._row(uid)
            if verify_password(password, row["pw_hash"]):
                raise AuthError("Choose a password you haven't used for this account.")
            self.db.execute("UPDATE users SET pw_hash = ?, pw_changed = ? WHERE id = ?", (hash_password(password), _now(), uid))
            revoke = True
        if must_change is not None:
            self.db.execute("UPDATE users SET must_change_pw = ? WHERE id = ?", (1 if must_change else 0, uid))
        if revoke:
            self.revoke_sessions(uid, except_id=keep_session)
        return self.get(uid)

    def delete(self, uid):
        user = self.get(uid)
        if not user:
            raise AuthError("No such user.", 404)
        if user["role"] == "admin" and not self._admins_left(uid):
            raise AuthError("You can't delete the last administrator.")
        self.revoke_sessions(uid)
        self.db.execute("DELETE FROM users WHERE id = ?", (uid,))

    def check_password(self, uid, password) -> bool:
        row = self._row(uid)
        return bool(row) and verify_password(password or "", row["pw_hash"])

    def change_own_password(self, uid, current, new, keep_session=None):
        if not self.check_password(uid, current):
            raise AuthError("Your current password is incorrect.", 403)
        return self.update(uid, password=new, must_change=False, keep_session=keep_session)

    # -- two-factor --------------------------------------------------------------------------
    def enable_totp(self, uid, secret, used_step):
        """Turn on two-factor with a secret the user has proven they hold (the code for `used_step`)."""
        codes, hashes = mfa.new_recovery_codes()
        self.db.execute("UPDATE users SET totp_secret = ?, totp_enabled = 1, totp_last_step = ?, recovery_codes = ? WHERE id = ?",
                        (secret, used_step, json.dumps(hashes), uid))
        return codes

    def disable_totp(self, uid):
        self.db.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_step = -1, recovery_codes = '[]' WHERE id = ?", (uid,))

    def new_recovery_codes(self, uid):
        codes, hashes = mfa.new_recovery_codes()
        self.db.execute("UPDATE users SET recovery_codes = ? WHERE id = ?", (json.dumps(hashes), uid))
        return codes

    def verify_second_factor(self, uid, code):
        """Check a 6-digit app code or a one-time recovery code. Returns 'totp', 'recovery' or None."""
        with self._lock:
            row = self._row(uid)
            if not row or not row["totp_enabled"]:
                return None
            if mfa.looks_like_recovery(code):
                hashes = json.loads(row["recovery_codes"] or "[]")
                h = mfa.hash_recovery(code)
                match = next((x for x in hashes if hmac.compare_digest(x, h)), None)
                if match:
                    hashes.remove(match)                          # each recovery code works once
                    self.db.execute("UPDATE users SET recovery_codes = ? WHERE id = ?", (json.dumps(hashes), uid))
                    return "recovery"
                return None
            step = mfa.verify(row["totp_secret"], code, row["totp_last_step"])
            if step is None:
                return None
            self.db.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, uid))
            return "totp"

    # -- server-side sessions ----------------------------------------------------------------
    @staticmethod
    def _token_hash(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def create_session(self, uid, ip="", ua=""):
        """Returns (public session id, secret token). Only a hash of the token is stored, so a copy of
        the database can't be used to hijack sessions."""
        token, sid = secrets.token_urlsafe(32), secrets.token_hex(8)
        now = time.time()
        self.db.execute("INSERT INTO sessions (id, token_hash, user_id, created, last_seen, ip, user_agent) VALUES (?,?,?,?,?,?,?)",
                        (sid, self._token_hash(token), uid, now, now, ip, (ua or "")[:300]))
        return sid, token

    def get_session(self, token):
        if not token:
            return None
        rows = self.db.query("SELECT * FROM sessions WHERE token_hash = ?", (self._token_hash(token),))
        return rows[0] if rows else None

    def touch_session(self, sid, ip=""):
        self.db.execute("UPDATE sessions SET last_seen = ?, ip = ? WHERE id = ?", (time.time(), ip, sid))

    def end_session(self, sid):
        self.db.execute("DELETE FROM sessions WHERE id = ?", (sid,))

    def list_sessions(self, uid):
        rows = self.db.query("SELECT id, created, last_seen, ip, user_agent FROM sessions WHERE user_id = ? ORDER BY last_seen DESC", (uid,))
        for r in rows:
            r["device"] = describe_agent(r.pop("user_agent"))
        return rows

    def revoke_session(self, uid, sid):
        return self.db.execute("DELETE FROM sessions WHERE id = ? AND user_id = ?", (sid, uid)).rowcount

    def revoke_sessions(self, uid, except_id=None):
        return self.db.execute("DELETE FROM sessions WHERE user_id = ? AND id != ?", (uid, except_id or "")).rowcount

    def prune_sessions(self, idle_seconds, max_age_seconds):
        now = time.time()
        self.db.execute("DELETE FROM sessions WHERE last_seen < ? OR created < ?", (now - idle_seconds, now - max_age_seconds))

    # -- audit -------------------------------------------------------------------------------
    def audit(self, username, action, detail="", ip=""):
        self.db.execute("INSERT INTO audit (ts, username, action, detail, ip) VALUES (?,?,?,?,?)",
                        (_now(), username, action, str(detail)[:300], ip))
        self.db.execute("DELETE FROM audit WHERE id <= (SELECT MAX(id) FROM audit) - 20000")

    def audit_list(self, limit=200, username=None, actions=None):
        sql, args = "SELECT * FROM audit", []
        where = []
        if username:
            where.append("username = ? COLLATE NOCASE")
            args.append(username)
        if actions:
            where.append("action IN (%s)" % ",".join("?" * len(actions)))
            args.extend(actions)
        if where:
            sql += " WHERE " + " AND ".join(where)
        args.append(max(1, min(limit, 1000)))
        return self.db.query(sql + " ORDER BY id DESC LIMIT ?", tuple(args))
