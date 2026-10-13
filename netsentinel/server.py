"""Flask app: the web UI and its JSON API, with login, roles and an audit trail.

Roles: viewer (read-only) < analyst (scan, capture, demo, review) < admin (settings, users, audit).
Security: scrypt passwords, signed HttpOnly SameSite=Strict session cookie, per-session CSRF token on
every state-changing request, Origin check, login lockout, Host allow-list, CSP, no-store API responses,
sessions revoked when a user's role/password/status changes.
"""
import functools
import hmac
import os
import secrets
import socket
import time
from datetime import timedelta

from flask import Flask, Response, abort, g, jsonify, render_template, request, session

from . import __version__, knowledge, paths, reports
from .auth import ROLE_HELP, ROLES, AuthError, LoginThrottle
from .capture import CaptureError, capabilities, list_interfaces
from .env import Env
from .scanner import PRESETS, ScanError
from .simulator import SCENARIOS

SESSION_HOURS = 12
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
    throttle = LoginThrottle()
    app.config["NS_THROTTLE"] = throttle
    app.config["NS_SETUP_CODE"] = env.setup_code

    def audit(action, detail=""):
        u = getattr(g, "user", None)
        core.auth.audit(u["username"] if u else None, action, detail, request.remote_addr or "")

    # ------------------------------------------------------------ request guard
    @app.before_request
    def guard():
        if not env.host_check_disabled:
            host = request.host.lower()
            host = host.split("]")[0] + "]" if host.startswith("[") else host.split(":")[0]
            if host not in env.allowed_hosts:               # DNS-rebinding defence
                abort(403)
        g.user = None
        uid = session.get("uid")
        if uid:
            u = core.auth.get(uid)
            if u and not u["disabled"] and u["session_epoch"] == session.get("epoch"):
                g.user = u
            else:
                session.clear()
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            origin = request.headers.get("Origin")
            if origin and origin.split("://", 1)[-1] != request.host:
                return _bad("Cross-origin request blocked.", 403)
            if request.endpoint in ("login", "setup"):
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
                    return _bad("Please sign in.", 401)
                if ROLES[g.user["role"]] < ROLES[role]:
                    audit("denied", f"{request.method} {request.path} needs {role}")
                    return _bad(f"Your account ({g.user['role']}) can't do that. Ask an administrator.", 403)
                return fn(*a, **kw)
            return inner
        return deco

    @app.after_request
    def headers(resp):
        resp.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                                       "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            "Cross-Origin-Opener-Policy": "same-origin", "Permissions-Policy": "camera=(), microphone=(), geolocation=()"})
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
        session.clear()
        session.permanent = True
        session.update(uid=user["id"], epoch=user["session_epoch"], csrf=secrets.token_urlsafe(24))
        g.user = user

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
                        "user": ({"username": g.user["username"], "role": g.user["role"]} if g.user else None),
                        "csrf": session.get("csrf") if g.user else None, "roles": ROLE_HELP})

    @app.route("/api/setup", methods=["POST"])
    def setup():
        b = body()
        if core.auth.count() > 0:
            return _bad("Setup has already been completed.", 409)
        if not hmac.compare_digest(str(b.get("code", "")).strip().upper(), env.setup_code.upper()):
            core.auth.audit(None, "setup_failed", "wrong setup code", request.remote_addr or "")
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
        name = str(b.get("username", "")).strip()
        key = (request.remote_addr, name.lower())
        wait = throttle.wait_time(key)
        if wait:
            return _bad(f"Too many failed attempts. Try again in {wait // 60 + 1} minute(s).", 429)
        user = core.auth.authenticate(name, str(b.get("password", "")))
        if not user:
            throttle.fail(key)
            core.auth.audit(name[:32], "login_failed", "", request.remote_addr or "")
            return _bad("Wrong username or password.", 401)
        throttle.ok(key)
        login_user(user)
        audit("login")
        return jsonify({"ok": True})

    @app.route("/api/logout", methods=["POST"])
    def logout():
        audit("logout")
        session.clear()
        return jsonify({"ok": True})

    @app.route("/api/account/password", methods=["POST"])
    @need("viewer")
    def change_password():
        b = body()
        try:
            core.auth.change_own_password(g.user["id"], b.get("current"), b.get("new"))
        except AuthError as e:
            return _bad(str(e), e.status)
        audit("password_changed")
        session.clear()                                   # all sessions revoked; sign in again
        return jsonify({"ok": True, "signed_out": True})

    # ------------------------------------------------------------------ users
    @app.route("/api/users")
    @need("admin")
    def users_list():
        return jsonify({"users": [{k: u[k] for k in ("id", "username", "role", "disabled", "created", "last_login")}
                                  for u in core.auth.list()], "roles": ROLE_HELP})

    @app.route("/api/users", methods=["POST"])
    @need("admin")
    def users_create():
        b = body()
        try:
            u = core.auth.create(b.get("username"), b.get("password"), str(b.get("role", "viewer")))
        except AuthError as e:
            return _bad(str(e), e.status)
        audit("user_created", f"{u['username']} ({u['role']})")
        return jsonify({"ok": True})

    @app.route("/api/users/<int:uid>", methods=["POST"])
    @need("admin")
    def users_update(uid):
        b = body()
        try:
            u = core.auth.update(uid, role=b.get("role"), disabled=b.get("disabled"), password=b.get("password"))
        except AuthError as e:
            return _bad(str(e), e.status)
        audit("user_updated", f"{u['username']}: " + ", ".join(k for k in ("role", "disabled", "password") if b.get(k) is not None))
        return jsonify({"ok": True})

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

    @app.route("/api/glossary")
    @need("viewer")
    def glossary():
        return jsonify({"terms": knowledge.GLOSSARY})

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
