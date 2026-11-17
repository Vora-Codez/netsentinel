"""Flask app: the web UI and its JSON API, with login, two-factor sign-in, roles and an audit trail.

Roles: viewer (read-only) < analyst (scan, capture, demo, review) < admin (settings, users, audit).
Security: scrypt passwords, optional TOTP two-factor with recovery codes, server-side sessions (idle
timeout, 12-hour maximum, listable and revocable), signed HttpOnly SameSite=Strict cookie, per-session
CSRF token on every state-changing request, Origin check, login lockout per account and per address,
Host allow-list, CSP, no-store API responses, forced password change for admin-issued passwords.
"""
import base64
import functools
import hmac
import secrets
import socket
import time
from datetime import timedelta

from flask import Flask, Response, abort, g, jsonify, render_template, request, session

from . import __version__, knowledge, mfa, paths, qr, reports
from .auth import MIN_PASSWORD, ROLE_HELP, ROLES, AuthError, LoginThrottle
from .capture import CaptureError, capabilities, list_interfaces
from .env import Env
from .scanner import PRESETS, ScanError
from .simulator import SCENARIOS

SESSION_HOURS = 12            # absolute maximum session length
TOUCH_EVERY = 15              # seconds between "last active" updates for one session
PENDING_2FA_SECONDS = 300     # time allowed between the password step and the code step
# Endpoints a user may reach while they must choose a new password.
PW_CHANGE_OK = {"account_password", "account_info"}
ACCOUNT_EVENTS = ("login", "login_failed", "2fa_failed", "logout", "password_changed", "2fa_enabled",
                  "2fa_disabled", "recovery_codes_regenerated", "session_revoked", "sessions_revoked",
                  "signed_out_idle")
_subnet_cache = [0.0, None]


def _local_subnet():
    """Best-guess /24 of the server's LAN (no packets are sent)."""
    if time.time() - _subnet_cache[0] < 60:
        return _subnet_cache[1]
    result = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 80))
            ip = s.getsockname()[0]
        if ip.startswith(("10.", "192.168.")) or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31):
            result = ip.rsplit(".", 1)[0] + ".0/24"
    except OSError:
        pass
    _subnet_cache[0], _subnet_cache[1] = time.time(), result
    return result


def _bad(msg, status=400, **extra):
    return jsonify({"error": msg, **extra}), status


def create_app(core, env=None):
    env = env or Env()
    web = paths.web_dir()
    app = Flask(__name__, template_folder=str(web / "templates"), static_folder=str(web / "static"), static_url_path="/static")
    app.config.update(SECRET_KEY=core.secret, MAX_CONTENT_LENGTH=256 * 1024,
                      SESSION_COOKIE_NAME="ns_session", SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_SECURE=env.secure_cookies,
                      PERMANENT_SESSION_LIFETIME=timedelta(hours=SESSION_HOURS))
    app.json.sort_keys = False                    # keep scan presets / demo scenarios in their intended order
    if env.trust_proxy:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    throttle = LoginThrottle()                                  # per address + account: 5 tries, 5 min lock
    ip_throttle = LoginThrottle(max_fails=20, lock_seconds=600)  # per address, any account: stops password spraying
    app.config["NS_THROTTLE"] = throttle
    app.config["NS_IP_THROTTLE"] = ip_throttle
    app.config["NS_SETUP_CODE"] = env.setup_code

    def ip():
        return request.remote_addr or ""

    def audit(action, detail=""):
        u = getattr(g, "user", None)
        core.auth.audit(u["username"] if u else None, action, detail, ip())

    def idle_seconds():
        return int(core.settings.get("session_idle_minutes")) * 60

    # ------------------------------------------------------------ request guard
    @app.before_request
    def guard():
        if not env.host_check_disabled:
            host = request.host.lower()
            host = host.split("]")[0] + "]" if host.startswith("[") else host.split(":")[0]
            if host not in env.allowed_hosts:               # DNS-rebinding defence
                abort(403)
        g.user, g.sid, g.signed_out = None, None, None
        token = session.get("tok")
        if token:
            row, now = core.auth.get_session(token), time.time()
            user = core.auth.get(row["user_id"]) if row else None
            if not row or not user or user["disabled"]:
                g.signed_out = "revoked"
            elif now - row["last_seen"] > idle_seconds():
                g.signed_out = "idle"
                core.auth.audit(user["username"], "signed_out_idle", "", ip())
            elif now - row["created"] > SESSION_HOURS * 3600:
                g.signed_out = "expired"
            else:
                g.user, g.sid = user, row["id"]
                # Background polling (the dashboard refreshing itself) doesn't count as activity, so an
                # unattended browser still times out.
                if request.headers.get("X-NS-Background") != "1" and now - row["last_seen"] > TOUCH_EVERY:
                    core.auth.touch_session(row["id"], ip())
            if not g.user:
                if row:
                    core.auth.end_session(row["id"])
                session.clear()
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            origin = request.headers.get("Origin")
            if origin and origin.split("://", 1)[-1] != request.host:
                return _bad("Cross-origin request blocked.", 403)
            # Sign-in steps (and abandoning a half-finished sign-in) happen before there's a CSRF token.
            if request.endpoint in ("login", "login_2fa", "setup") or (request.endpoint == "logout" and not g.user):
                if request.headers.get("X-NS-Client") != "1":
                    return _bad("Missing client header.", 403)
            else:
                sent = request.headers.get("X-NS-Token", "")
                if not g.user or not hmac.compare_digest(sent, session.get("csrf", "")):
                    return _bad("Your session expired. Reload the page and sign in again.", 401 if not g.user else 403)

    def need(role):
        def deco(fn):
            @functools.wraps(fn)
            def inner(*a, **kw):
                if not g.user:
                    return _bad(_signed_out_message(), 401, signed_out=g.signed_out)
                if g.user["must_change_pw"] and request.endpoint not in PW_CHANGE_OK:
                    return _bad("Choose a new password before continuing.", 403, code="password_change_required")
                if ROLES[g.user["role"]] < ROLES[role]:
                    audit("denied", f"{request.method} {request.path} needs {role}")
                    return _bad(f"Your account ({g.user['role']}) can't do that. Ask an administrator.", 403)
                return fn(*a, **kw)
            return inner
        return deco

    def _signed_out_message():
        return {"idle": f"You were signed out after {core.settings.get('session_idle_minutes')} minutes without activity.",
                "expired": f"Sessions last at most {SESSION_HOURS} hours. Please sign in again.",
                "revoked": "This session was signed out. Please sign in again."}.get(g.signed_out, "Please sign in.")

    @app.after_request
    def headers(resp):
        resp.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                                       "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Resource-Policy": "same-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()"})
        if env.secure_cookies:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        if request.path.startswith("/api/") or request.path == "/":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    for code, msg in ((403, "Forbidden."), (413, "Request too large."), (405, "Method not allowed."),
                      (500, "Something went wrong inside NetSentinel. Check the server log.")):
        app.register_error_handler(code, lambda e, m=msg, c=code: _bad(m, c))
    app.register_error_handler(404, lambda e: _bad("Not found.", 404) if request.path.startswith("/api/") else ("Not found", 404))

    def body():
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}

    def intarg(name, default, lo=0, hi=10 ** 9):
        try:
            return max(lo, min(int(request.args.get(name, default)), hi))
        except (TypeError, ValueError):
            return default

    def srcarg():
        v = request.args.get("source", "all")
        return v if v in ("live", "simulation") else "all"

    def login_user(user):
        """Start a fresh server-side session (new id, so a pre-login cookie can't be fixated)."""
        session.clear()
        session.permanent = True
        sid, token = core.auth.create_session(user["id"], ip(), request.headers.get("User-Agent", ""))
        session.update(tok=token, csrf=secrets.token_urlsafe(24))
        g.user, g.sid = user, sid
        core.auth.prune_sessions(idle_seconds(), SESSION_HOURS * 3600)
        return core.auth.record_login(user["id"], ip())

    def user_payload(u):
        return {"username": u["username"], "role": u["role"], "totp_enabled": u["totp_enabled"],
                "must_change_pw": u["must_change_pw"]}

    def pending_2fa():
        p = session.get("pending")
        if p and time.time() - p.get("at", 0) <= PENDING_2FA_SECONDS:
            return p
        session.pop("pending", None)
        return None

    def check_password_or_fail(password):
        key = ("acct", g.user["id"])
        wait = throttle.wait_time(key)
        if wait:
            raise AuthError(f"Too many wrong passwords. Try again in {wait // 60 + 1} minute(s).", 429)
        if not core.auth.check_password(g.user["id"], password):
            throttle.fail(key)
            raise AuthError("Your password is incorrect.", 403)
        throttle.ok(key)

    # ------------------------------------------------------------------ pages
    @app.route("/")
    def index():
        return render_template("index.html", version=__version__)

    @app.route("/api/ping")
    def ping():
        return jsonify({"app": "netsentinel", "version": __version__})

    # ------------------------------------------------------------ session/auth
    @app.route("/api/session")
    def session_info():
        return jsonify({"version": __version__, "setup_required": core.auth.count() == 0,
                        "user": user_payload(g.user) if g.user else None,
                        "csrf": session.get("csrf") if g.user else None, "roles": ROLE_HELP,
                        "pending_2fa": bool(not g.user and pending_2fa()),
                        "signed_out": g.signed_out, "signed_out_message": _signed_out_message() if g.signed_out else "",
                        "min_password": MIN_PASSWORD, "idle_minutes": core.settings.get("session_idle_minutes")})

    @app.route("/api/setup", methods=["POST"])
    def setup():
        b = body()
        if core.auth.count() > 0:
            return _bad("Setup has already been completed.", 409)
        if not hmac.compare_digest(str(b.get("code", "")).strip().upper(), env.setup_code.upper()):
            core.auth.audit(None, "setup_failed", "wrong setup code", ip())
            return _bad("That setup code is wrong. It's printed in the server log when NetSentinel starts.", 403)
        try:
            user = core.auth.create(b.get("username"), b.get("password"), "admin", first_user=True)
        except AuthError as e:
            return _bad(str(e), e.status)
        login_user(user)
        audit("setup", f"first administrator '{user['username']}' created")
        return jsonify({"ok": True})

    @app.route("/api/login", methods=["POST"])
    def login():
        b = body()
        name = str(b.get("username", "")).strip()[:64]
        key, ipkey = (ip(), name.lower()), ("ip", ip())
        wait = max(throttle.wait_time(key), ip_throttle.wait_time(ipkey))
        if wait:
            return _bad(f"Too many failed attempts. Try again in {wait // 60 + 1} minute(s).", 429)
        user = core.auth.authenticate(name, str(b.get("password", ""))[:256])
        if not user:
            throttle.fail(key)
            ip_throttle.fail(ipkey)
            core.auth.audit(name[:32], "login_failed", "wrong username or password", ip())
            return _bad("Wrong username or password.", 401)
        throttle.ok(key)
        if user["totp_enabled"]:
            session.clear()
            session["pending"] = {"uid": user["id"], "at": time.time(), "tries": 0}
            return jsonify({"ok": True, "second_factor": True})
        prev = login_user(user)
        audit("login", "password")
        return jsonify({"ok": True, "previous": prev, "must_change_pw": user["must_change_pw"]})

    @app.route("/api/login/2fa", methods=["POST"])
    def login_2fa():
        p = pending_2fa()
        if not p:
            return _bad("Your sign-in timed out. Enter your password again.", 401, restart=True)
        user = core.auth.get(p["uid"])
        if not user or user["disabled"]:
            session.clear()
            return _bad("Wrong username or password.", 401, restart=True)
        key = ("2fa", ip(), user["id"])
        wait = throttle.wait_time(key)
        if wait:
            return _bad(f"Too many wrong codes. Try again in {wait // 60 + 1} minute(s).", 429)
        method = core.auth.verify_second_factor(user["id"], str(body().get("code", ""))[:40])
        if not method:
            throttle.fail(key)
            core.auth.audit(user["username"], "2fa_failed", "", ip())
            p["tries"] = p.get("tries", 0) + 1
            if p["tries"] >= 5:
                session.clear()
                return _bad("Too many wrong codes. Enter your password again.", 401, restart=True)
            session["pending"] = p
            return _bad("That code didn't work. Codes change every 30 seconds; check your phone's clock is right.", 401)
        throttle.ok(key)
        user = core.auth.get(user["id"])
        prev = login_user(user)
        detail = "password + authenticator app" if method == "totp" else f"password + recovery code ({user['recovery_left']} left)"
        audit("login", detail)
        return jsonify({"ok": True, "previous": prev, "used_recovery": method == "recovery",
                        "recovery_left": user["recovery_left"], "must_change_pw": user["must_change_pw"]})

    @app.route("/api/logout", methods=["POST"])
    def logout():
        audit("logout")
        if g.sid:
            core.auth.end_session(g.sid)
        session.clear()
        return jsonify({"ok": True})

    # ---------------------------------------------------------------- account
    @app.route("/api/account")
    @need("viewer")
    def account_info():
        u = g.user
        sessions = core.auth.list_sessions(u["id"])
        for s in sessions:
            s["current"] = s["id"] == g.sid
        return jsonify({"user": {k: u[k] for k in ("username", "role", "created", "last_login", "last_login_ip", "totp_enabled",
                                                   "recovery_left", "must_change_pw", "pw_changed")},
                        "sessions": sessions, "idle_minutes": core.settings.get("session_idle_minutes"),
                        "max_hours": SESSION_HOURS, "min_password": MIN_PASSWORD,
                        "activity": core.auth.audit_list(25, username=u["username"], actions=ACCOUNT_EVENTS)})

    @app.route("/api/account/password", methods=["POST"])
    @need("viewer")
    def account_password():
        b = body()
        try:
            core.auth.change_own_password(g.user["id"], b.get("current"), b.get("new"), keep_session=g.sid)
        except AuthError as e:
            return _bad(str(e), e.status)
        audit("password_changed", "other sessions signed out")
        return jsonify({"ok": True})

    @app.route("/api/account/2fa/setup", methods=["POST"])
    @need("viewer")
    def account_2fa_setup():
        if g.user["totp_enabled"]:
            return _bad("Two-factor sign-in is already on.", 409)
        secret = mfa.new_secret()
        session["totp_setup"] = {"secret": secret, "at": time.time()}
        uri = mfa.otpauth_uri(secret, g.user["username"])
        image = "data:image/svg+xml;base64," + base64.b64encode(qr.svg(uri).encode()).decode()
        return jsonify({"secret": mfa.pretty_secret(secret), "uri": uri, "qr": image})

    @app.route("/api/account/2fa/enable", methods=["POST"])
    @need("viewer")
    def account_2fa_enable():
        b, pending = body(), session.get("totp_setup")
        if not pending or time.time() - pending.get("at", 0) > 900:
            return _bad("The setup expired. Start again.", 400)
        try:
            check_password_or_fail(b.get("password"))
        except AuthError as e:
            return _bad(str(e), e.status)
        step = mfa.verify(pending["secret"], b.get("code"))
        if step is None:
            return _bad("That code didn't match. Type the 6 digits your app shows right now.", 400)
        codes = core.auth.enable_totp(g.user["id"], pending["secret"], step)
        session.pop("totp_setup", None)
        audit("2fa_enabled")
        return jsonify({"ok": True, "recovery_codes": codes})

    @app.route("/api/account/2fa/disable", methods=["POST"])
    @need("viewer")
    def account_2fa_disable():
        b = body()
        try:
            check_password_or_fail(b.get("password"))
        except AuthError as e:
            return _bad(str(e), e.status)
        if not core.auth.verify_second_factor(g.user["id"], str(b.get("code", ""))):
            return _bad("Enter a current code from your app (or a recovery code) to turn two-factor off.", 400)
        core.auth.disable_totp(g.user["id"])
        audit("2fa_disabled")
        return jsonify({"ok": True})

    @app.route("/api/account/2fa/recovery", methods=["POST"])
    @need("viewer")
    def account_2fa_recovery():
        if not g.user["totp_enabled"]:
            return _bad("Turn on two-factor sign-in first.", 400)
        try:
            check_password_or_fail(body().get("password"))
        except AuthError as e:
            return _bad(str(e), e.status)
        codes = core.auth.new_recovery_codes(g.user["id"])
        audit("recovery_codes_regenerated")
        return jsonify({"ok": True, "recovery_codes": codes})

    @app.route("/api/account/sessions/<sid>/revoke", methods=["POST"])
    @need("viewer")
    def account_session_revoke(sid):
        if sid == g.sid:
            return _bad("That's this browser. Use Sign out instead.", 400)
        if not core.auth.revoke_session(g.user["id"], sid):
            return _bad("That session has already ended.", 404)
        audit("session_revoked", sid)
        return jsonify({"ok": True})

    @app.route("/api/account/sessions/revoke-others", methods=["POST"])
    @need("viewer")
    def account_sessions_revoke_others():
        n = core.auth.revoke_sessions(g.user["id"], except_id=g.sid)
        audit("sessions_revoked", f"{n} other session(s)")
        return jsonify({"ok": True, "revoked": n})

    # ------------------------------------------------------------------ users
    @app.route("/api/users")
    @need("admin")
    def users_list():
        counts = {r["user_id"]: r["n"] for r in core.db.query("SELECT user_id, COUNT(*) AS n FROM sessions GROUP BY user_id")}
        users = [{**{k: u[k] for k in ("id", "username", "role", "disabled", "created", "last_login", "last_login_ip",
                                         "totp_enabled", "must_change_pw")}, "sessions": counts.get(u["id"], 0)}
                 for u in core.auth.list()]
        active = [u for u in users if not u["disabled"]]
        return jsonify({"users": users, "roles": ROLE_HELP,
                        "summary": {"active": len(active), "with_2fa": sum(u["totp_enabled"] for u in active),
                                    "admins_without_2fa": [u["username"] for u in active if u["role"] == "admin" and not u["totp_enabled"]]}})

    @app.route("/api/users", methods=["POST"])
    @need("admin")
    def users_create():
        b = body()
        try:
            u = core.auth.create(b.get("username"), b.get("password"), str(b.get("role", "viewer")),
                                 must_change=bool(b.get("must_change", True)))
        except AuthError as e:
            return _bad(str(e), e.status)
        audit("user_created", f"{u['username']} ({u['role']})" + (", must choose a new password" if u["must_change_pw"] else ""))
        return jsonify({"ok": True})

    @app.route("/api/users/<int:uid>", methods=["POST"])
    @need("admin")
    def users_update(uid):
        b = body()
        if uid == g.user["id"] and (b.get("role") is not None or b.get("disabled") is not None):
            return _bad("You can't change your own role or disable yourself. Ask another administrator.")
        pw = b.get("password")
        try:
            u = core.auth.update(uid, role=b.get("role"), disabled=b.get("disabled"), password=pw,
                                 must_change=True if pw is not None else None)
        except AuthError as e:
            return _bad(str(e), e.status)
        audit("user_updated", f"{u['username']}: " + ", ".join(k for k in ("role", "disabled", "password") if b.get(k) is not None))
        return jsonify({"ok": True})

    @app.route("/api/users/<int:uid>/reset-2fa", methods=["POST"])
    @need("admin")
    def users_reset_2fa(uid):
        if uid == g.user["id"]:
            return _bad("Manage your own two-factor sign-in from Account.")
        u = core.auth.get(uid)
        if not u:
            return _bad("No such user.", 404)
        core.auth.disable_totp(uid)
        core.auth.revoke_sessions(uid)
        audit("2fa_reset", u["username"])
        return jsonify({"ok": True})

    @app.route("/api/users/<int:uid>/signout", methods=["POST"])
    @need("admin")
    def users_signout(uid):
        u = core.auth.get(uid)
        if not u:
            return _bad("No such user.", 404)
        n = core.auth.revoke_sessions(uid, except_id=g.sid)
        audit("user_signed_out", f"{u['username']}: {n} session(s)")
        return jsonify({"ok": True, "revoked": n})

    @app.route("/api/users/<int:uid>/delete", methods=["POST"])
    @need("admin")
    def users_delete(uid):
        if uid == g.user["id"]:
            return _bad("You can't delete your own account while signed in.")
        victim = core.auth.get(uid)
        try:
            core.auth.delete(uid)
        except AuthError as e:
            return _bad(str(e), e.status)
        audit("user_deleted", victim["username"] if victim else uid)
        return jsonify({"ok": True})

    @app.route("/api/audit")
    @need("admin")
    def audit_log():
        return jsonify({"events": core.auth.audit_list(intarg("limit", 200, 1, 1000))})

    # ----------------------------------------------------------------- status
    @app.route("/api/status")
    @need("viewer")
    def status():
        job = core.scans.active()
        return jsonify({"version": __version__, "uptime": int(time.time() - core.started),
            "capabilities": capabilities(), "capture": core.capture.status(), "simulator": core.sim.status(),
            "scan_active": job.summary(False) if job else None, "data_dir": str(core.data_dir),
            "alerts": core.alerts.counts(), "local_subnet": _local_subnet(),
            "scenarios": {k: {"name": v[0], "desc": v[1]} for k, v in SCENARIOS.items()},
            "presets": {k: {"name": v[0], "count": len(v[1])} for k, v in PRESETS.items()}})

    @app.route("/api/overview")
    @need("viewer")
    def overview():
        src, cap = srcarg(), core.capture
        return jsonify({"health": core.health(), "alerts": core.alerts.counts(), "traffic": cap.overview(src),
            "series": cap.series(60), "talkers": cap.top_talkers(6, src), "devices": len(core.engine.device_list()),
            "latest": core.alerts.list(limit=5, status="open"),
            "last_scan": next((j.summary(False) for j in reversed(core.scans.jobs.values()) if j.status in ("done", "cancelled")), None)})

    @app.route("/api/learn")
    @need("viewer")
    def learn():
        return jsonify(knowledge.learn(core.settings.all()))

    # ----------------------------------------------------------------- alerts
    @app.route("/api/alerts")
    @need("viewer")
    def alerts():
        a = core.alerts
        return jsonify({"alerts": a.list(since_id=intarg("since_id", 0), limit=intarg("limit", 200, 1, 1000),
            severity=request.args.get("severity", "all"), source=request.args.get("source", "all"),
            status=request.args.get("status", "all")), "counts": a.counts()})

    @app.route("/api/alerts/<int:aid>/review", methods=["POST"])
    @need("analyst")
    def alert_review(aid):
        reviewed = bool(body().get("reviewed", True))
        if not core.alerts.set_reviewed(aid, reviewed):
            return _bad("No such alert.", 404)
        audit("alert_reviewed" if reviewed else "alert_reopened", f"#{aid}")
        return jsonify({"ok": True})

    @app.route("/api/alerts/review_all", methods=["POST"])
    @need("analyst")
    def alert_review_all():
        n = core.alerts.review_all()
        audit("alerts_reviewed_all", f"{n} alerts")
        return jsonify({"reviewed": n})

    @app.route("/api/alerts/clear", methods=["POST"])
    @need("admin")
    def alert_clear():
        src = body().get("source", "all")
        n = core.alerts.clear(src if src in ("live", "simulation") else "all")
        audit("alerts_cleared", f"{n} deleted ({src})")
        return jsonify({"deleted": n})

    # ---------------------------------------------------------------- traffic
    @app.route("/api/packets")
    @need("viewer")
    def packets():
        return jsonify({"packets": core.capture.packets(since_id=intarg("since_id", 0), limit=intarg("limit", 300, 1, 1000),
                                                         query=request.args.get("q", "")[:200], source=request.args.get("source", "all"))})

    @app.route("/api/packets/<int:pid>")
    @need("viewer")
    def packet(pid):
        p = core.capture.packet(pid)
        return jsonify(p) if p else _bad("That packet has already scrolled out of the buffer.", 404)

    @app.route("/api/flows")
    @need("viewer")
    def flows():
        return jsonify({"flows": core.capture.flows(limit=intarg("limit", 200, 1, 1000), sort=request.args.get("sort", "bytes"),
                                                     source=request.args.get("source", "all"))})

    @app.route("/api/devices")
    @need("viewer")
    def devices():
        return jsonify({"devices": core.engine.device_list()})

    # ---------------------------------------------------------------- capture
    @app.route("/api/interfaces")
    @need("viewer")
    def interfaces():
        return jsonify({"interfaces": list_interfaces(), "capabilities": capabilities(), "selected": core.settings.get("capture_iface")})

    @app.route("/api/capture/start", methods=["POST"])
    @need("analyst")
    def capture_start():
        iface = str(body().get("iface", ""))[:200]
        try:
            core.capture.start(iface)
        except CaptureError as e:
            return _bad(str(e), 400, capture=core.capture.status())
        core.settings.update({"capture_iface": iface})
        audit("capture_started", iface or "default interface")
        return jsonify(core.capture.status())

    @app.route("/api/capture/stop", methods=["POST"])
    @need("analyst")
    def capture_stop():
        core.capture.stop()
        audit("capture_stopped")
        return jsonify(core.capture.status())

    @app.route("/api/capture/clear", methods=["POST"])
    @need("analyst")
    def capture_clear():
        core.capture.clear("all")
        audit("capture_buffer_cleared")
        return jsonify({"ok": True})

    # -------------------------------------------------------------- simulator
    @app.route("/api/simulate", methods=["POST"])
    @need("analyst")
    def simulate():
        scenario = str(body().get("scenario", "all"))
        if scenario not in SCENARIOS:
            return _bad("Unknown scenario.")
        if not core.sim.start(scenario):
            return _bad("A demo is already running.", 409)
        audit("demo_started", scenario)
        return jsonify(core.sim.status())

    @app.route("/api/simulate/clear", methods=["POST"])
    @need("analyst")
    def simulate_clear():
        core.sim.stop()
        n = core.alerts.clear("simulation")
        core.capture.clear("simulation")
        core.engine.clear_simulated()
        audit("demo_cleared", f"{n} alerts")
        return jsonify({"deleted_alerts": n})

    # ---------------------------------------------------------------- scanning
    @app.route("/api/scan/start", methods=["POST"])
    @need("analyst")
    def scan_start():
        b = body()
        try:
            job = core.scans.start(str(b.get("targets", ""))[:2000], str(b.get("preset", "quick")), str(b.get("ports", ""))[:500],
                                   bool(b.get("confirm")), allow_public=g.user["role"] == "admin", owner=g.user["username"])
        except ScanError as e:
            audit("scan_refused", f"{str(b.get('targets', ''))[:80]}: {e.code}")
            return _bad(str(e), e.status, code=e.code)
        audit("scan_started", f"{job.label} [{job.plabel}]")
        return jsonify(job.summary(False))

    @app.route("/api/scan/history")
    @need("viewer")
    def scan_history():
        return jsonify({"runs": core.scans.history()})

    @app.route("/api/scan/history/<rid>")
    @need("viewer")
    def scan_history_item(rid):
        return jsonify({"results": core.scans.run_results(rid)})

    @app.route("/api/scan/<jid>")
    @need("viewer")
    def scan_get(jid):
        job = core.scans.get(jid)
        return jsonify(job.summary()) if job else _bad("Unknown scan.", 404)

    @app.route("/api/scan/<jid>/cancel", methods=["POST"])
    @need("analyst")
    def scan_cancel(jid):
        if not core.scans.cancel(jid):
            return _bad("Unknown scan.", 404)
        audit("scan_cancelled", jid)
        return jsonify({"ok": True})

    # --------------------------------------------------------------- settings
    @app.route("/api/settings")
    @need("viewer")
    def settings_get():
        return jsonify(core.settings.all())

    @app.route("/api/settings", methods=["POST"])
    @need("admin")
    def settings_set():
        b = body()
        result = core.settings.update(b)
        audit("settings_changed", ", ".join(sorted(k for k in b if k in result))[:250])
        return jsonify(result)

    @app.route("/api/settings/reset", methods=["POST"])
    @need("admin")
    def settings_reset():
        audit("settings_reset")
        return jsonify(core.settings.reset())

    # ---------------------------------------------------------------- exports
    def _download(text, name, mime):
        return Response(text, mimetype=mime, headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @app.route("/api/export/alerts.csv")
    @need("viewer")
    def export_alerts():
        demo = request.args.get("demo") == "1"
        return _download(reports.alerts_csv(core.alerts.list(limit=1000, source="all" if demo else "live")), "netsentinel-alerts.csv", "text/csv")

    @app.route("/api/export/packets.csv")
    @need("viewer")
    def export_packets():
        return _download(reports.packets_csv(core.capture.packets(limit=1000, query=request.args.get("q", ""))), "netsentinel-packets.csv", "text/csv")

    @app.route("/api/export/report.md")
    @need("viewer")
    def export_report():
        demo = request.args.get("demo") == "1"
        job = next((j for j in reversed(core.scans.jobs.values()) if j.status in ("done", "cancelled")), None)
        text = reports.incident_report(core.alerts.list(limit=1000, source="all" if demo else "live"), job.summary() if job else None, include_demo=demo)
        return _download(text, "netsentinel-report.md", "text/markdown")

    return app
