"""Users, roles, password hashing, login throttling and the audit trail."""
import hashlib
import hmac
import os
import re
import threading
import time
from datetime import datetime, timezone

ROLES = {"viewer": 1, "analyst": 2, "admin": 3}
ROLE_HELP = {"viewer": "Can look at everything, change nothing.",
             "analyst": "Can scan, capture, run the demo and review alerts.",
             "admin": "Everything, plus settings, users and the audit log."}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD = 10
_N, _R, _P = 2 ** 14, 8, 1


class AuthError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, h = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt),
                              n=int(n), r=int(r), p=int(p), dklen=len(h) // 2)
        return hmac.compare_digest(calc.hex(), h)
    except (ValueError, TypeError):
        return False


_DUMMY = None


def _dummy_hash():
    global _DUMMY
    _DUMMY = _DUMMY or hash_password("not-a-real-password")
    return _DUMMY


def check_password_policy(password: str):
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        raise AuthError(f"Use a password of at least {MIN_PASSWORD} characters.")
    if len(password) > 200:
        raise AuthError("That password is too long (max 200 characters).")
    if password.lower() in ("password123", "1234567890", "qwertyuiop", "netsentinel"):
        raise AuthError("That password is too easy to guess.")


class LoginThrottle:
    """Locks a (client, username) pair after repeated failures."""
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


class AuthService:
    def __init__(self, db):
        self.db = db
        self._lock = threading.Lock()

    # -- users -------------------------------------------------------------
    @staticmethod
    def _public(row):
        if not row:
            return None
        return {k: row[k] for k in ("id", "username", "role", "disabled", "created", "last_login")} | \
               {"session_epoch": row["session_epoch"]}

    def count(self) -> int:
        return self.db.query("SELECT COUNT(*) AS n FROM users")[0]["n"]

    def get(self, uid):
        rows = self.db.query("SELECT * FROM users WHERE id = ?", (uid,))
        return self._public(rows[0]) if rows else None

    def list(self):
        return [self._public(r) for r in self.db.query("SELECT * FROM users ORDER BY username")]

    def create(self, username, password, role="viewer", first_user=False):
        username = (username or "").strip()
        if not USERNAME_RE.match(username):
            raise AuthError("Usernames are 3-32 characters: letters, numbers, dot, dash, underscore.")
        if role not in ROLES:
            raise AuthError("Unknown role.")
        check_password_policy(password)
        pw = hash_password(password)
        with self._lock:
            if first_user and self.count() > 0:
                raise AuthError("Setup has already been completed.", 409)
            if self.db.query("SELECT 1 FROM users WHERE username = ?", (username,)):
                raise AuthError("That username is taken.", 409)
            cur = self.db.execute(
                "INSERT INTO users (username, pw_hash, role, created) VALUES (?,?,?,?)",
                (username, pw, role, _now()))
        return self.get(cur.lastrowid)

    def authenticate(self, username, password):
        rows = self.db.query("SELECT * FROM users WHERE username = ?", ((username or "").strip(),))
        if not rows:
            verify_password(password or "", _dummy_hash())       # equalise timing
            return None
        row = rows[0]
        if not verify_password(password or "", row["pw_hash"]) or row["disabled"]:
            return None
        self.db.execute("UPDATE users SET last_login = ? WHERE id = ?", (_now(), row["id"]))
        return self._public(row)

    def _admins_left(self, excluding):
        return self.db.query("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND disabled=0 AND id != ?",
                             (excluding,))[0]["n"]

    def update(self, uid, role=None, disabled=None, password=None):
        user = self.get(uid)
        if not user:
            raise AuthError("No such user.", 404)
        bump = False
        if role is not None:
            if role not in ROLES:
                raise AuthError("Unknown role.")
            if user["role"] == "admin" and role != "admin" and not self._admins_left(uid):
                raise AuthError("There must always be at least one active administrator.")
            self.db.execute("UPDATE users SET role = ? WHERE id = ?", (role, uid))
            bump = True
        if disabled is not None:
            if disabled and user["role"] == "admin" and not self._admins_left(uid):
                raise AuthError("There must always be at least one active administrator.")
            self.db.execute("UPDATE users SET disabled = ? WHERE id = ?", (1 if disabled else 0, uid))
            bump = True
        if password is not None:
            check_password_policy(password)
            self.db.execute("UPDATE users SET pw_hash = ? WHERE id = ?", (hash_password(password), uid))
            bump = True
        if bump:                                                  # signs the user out everywhere
            self.db.execute("UPDATE users SET session_epoch = session_epoch + 1 WHERE id = ?", (uid,))
        return self.get(uid)

    def delete(self, uid):
        user = self.get(uid)
        if not user:
            raise AuthError("No such user.", 404)
        if user["role"] == "admin" and not self._admins_left(uid):
            raise AuthError("You can't delete the last administrator.")
        self.db.execute("DELETE FROM users WHERE id = ?", (uid,))

    def change_own_password(self, uid, current, new):
        rows = self.db.query("SELECT * FROM users WHERE id = ?", (uid,))
        if not rows or not verify_password(current or "", rows[0]["pw_hash"]):
            raise AuthError("Your current password is incorrect.", 403)
        return self.update(uid, password=new)

    # -- audit -------------------------------------------------------------
    def audit(self, username, action, detail="", ip=""):
        self.db.execute("INSERT INTO audit (ts, username, action, detail, ip) VALUES (?,?,?,?,?)",
                        (_now(), username, action, str(detail)[:300], ip))
        self.db.execute("DELETE FROM audit WHERE id <= (SELECT MAX(id) FROM audit) - 20000")

    def audit_list(self, limit=200):
        return self.db.query("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (max(1, min(limit, 1000)),))
