import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from netsentinel import auth, reports
from netsentinel.db import Database
from .helpers import PASSWORD, WebCase, CoreCase

H = {"X-NS-Client": "1"}


class PasswordTests(unittest.TestCase):
    def test_hash_roundtrip_and_salting(self):
        a, b = auth.hash_password("correct horse battery"), auth.hash_password("correct horse battery")
        self.assertNotEqual(a, b)
        self.assertTrue(auth.verify_password("correct horse battery", a))
        self.assertFalse(auth.verify_password("wrong", a))
        self.assertFalse(auth.verify_password("x", "garbage"))

    def test_policy(self):
        for bad in ("short", "password123", "", None, "x" * 300):
            with self.assertRaises(auth.AuthError):
                auth.check_password_policy(bad)


class SetupAndLogin(CoreCase):
    def setUp(self):
        super().setUp()
        from netsentinel.env import Env
        from netsentinel.server import create_app
        self.app = create_app(self.core, Env(setup_code="SETUP123"))
        self.c = self.app.test_client()

    def test_everything_requires_login(self):
        for url in ("/api/status", "/api/alerts", "/api/packets", "/api/settings", "/api/export/report.md", "/api/users", "/api/audit"):
            self.assertEqual(self.c.get(url).status_code, 401, url)
        self.assertEqual(self.c.get("/").status_code, 200)         # login page itself is public
        self.assertEqual(self.c.get("/api/ping").status_code, 200)

    def test_first_run_setup_needs_code_and_only_works_once(self):
        self.assertTrue(self.c.get("/api/session").get_json()["setup_required"])
        bad = self.c.post("/api/setup", json={"code": "nope", "username": "root", "password": PASSWORD}, headers=H)
        self.assertEqual(bad.status_code, 403)
        ok = self.c.post("/api/setup", json={"code": "setup123", "username": "root", "password": PASSWORD}, headers=H)
        self.assertEqual(ok.status_code, 200)
        s = self.c.get("/api/session").get_json()
        self.assertEqual((s["setup_required"], s["user"]["role"]), (False, "admin"))
        again = self.app.test_client().post("/api/setup", json={"code": "setup123", "username": "evil", "password": PASSWORD}, headers=H)
        self.assertEqual(again.status_code, 409)

    def test_login_requires_client_header_and_same_origin(self):
        self.core.auth.create("alice", PASSWORD, "admin")
        body = {"username": "alice", "password": PASSWORD}
        self.assertEqual(self.c.post("/api/login", json=body).status_code, 403)
        self.assertEqual(self.c.post("/api/login", json=body, headers={**H, "Origin": "http://evil.com"}).status_code, 403)
        self.assertEqual(self.c.post("/api/login", json=body, headers=H).status_code, 200)

    def test_lockout_after_repeated_failures(self):
        self.core.auth.create("alice", PASSWORD, "admin")
        for _ in range(5):
            r = self.c.post("/api/login", json={"username": "alice", "password": "bad bad bad bad"}, headers=H)
            self.assertEqual(r.status_code, 401)
        r = self.c.post("/api/login", json={"username": "alice", "password": PASSWORD}, headers=H)
        self.assertEqual(r.status_code, 429)                      # even the right password is refused while locked

    def test_error_does_not_reveal_whether_user_exists(self):
        self.core.auth.create("alice", PASSWORD, "admin")
        a = self.c.post("/api/login", json={"username": "alice", "password": "wrong wrong wrong"}, headers=H).get_json()
        b = self.c.post("/api/login", json={"username": "nobody", "password": "wrong wrong wrong"}, headers=H).get_json()
        self.assertEqual(a, b)

    def test_cookie_flags(self):
        self.core.auth.create("alice", PASSWORD, "admin")
        r = self.c.post("/api/login", json={"username": "alice", "password": PASSWORD}, headers=H)
        cookie = r.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)

    def test_security_headers_and_host_allowlist(self):
        r = self.c.get("/")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(self.c.get("/api/ping", headers={"Host": "evil.example.com"}).status_code, 403)
        self.assertEqual(self.c.get("/api/ping", headers={"Host": "127.0.0.1:8765"}).status_code, 200)


class RoleTests(WebCase):
    def test_csrf_required_even_when_signed_in(self):
        c = self.as_("bob")
        self.assertEqual(c.post("/api/simulate", json={"scenario": "baseline"}).status_code, 403)
        self.assertEqual(c.post("/api/simulate", json={"scenario": "baseline"}, headers={"X-NS-Token": "wrong"}).status_code, 403)
        r = c.post("/api/alerts/review_all", data="{}", content_type="text/plain", headers={"X-NS-Token": "x"})
        self.assertEqual(r.status_code, 403)

    def test_viewer_is_read_only(self):
        for url in ("/api/alerts/review_all", "/api/capture/start", "/api/capture/clear", "/api/simulate", "/api/simulate/clear",
                    "/api/scan/start", "/api/settings", "/api/settings/reset", "/api/alerts/clear", "/api/users"):
            self.assertEqual(self.post("carol", url, {"scenario": "baseline"}).status_code, 403, url)
        for url in ("/api/status", "/api/alerts", "/api/overview", "/api/packets", "/api/settings", "/api/export/alerts.csv"):
            self.assertEqual(self.as_("carol").get(url).status_code, 200, url)
        self.assertEqual(self.as_("carol").get("/api/users").status_code, 403)
        self.assertEqual(self.as_("carol").get("/api/audit").status_code, 403)

    def test_analyst_can_operate_but_not_administer(self):
        self.assertEqual(self.post("bob", "/api/simulate", {"scenario": "baseline"}).status_code, 200)
        self.assertEqual(self.post("bob", "/api/settings", {"exfil_mb": 7}).status_code, 403)
        self.assertEqual(self.post("bob", "/api/alerts/clear").status_code, 403)
        self.assertEqual(self.as_("bob").get("/api/users").status_code, 403)
        r = self.post("bob", "/api/scan/start", {"targets": "8.8.8.8", "confirm": True})
        self.assertEqual((r.status_code, r.get_json()["code"]), (403, "forbidden"))     # analysts can't scan the internet
        r = self.post("bob", "/api/scan/start", {"targets": "127.0.0.1", "preset": "custom", "ports": "1"})
        self.assertEqual(r.status_code, 200)

    def test_admin_can_do_everything(self):
        self.assertEqual(self.post("alice", "/api/settings", {"exfil_mb": 7}).get_json()["exfil_mb"], 7)
        self.assertEqual(self.as_("alice").get("/api/users").status_code, 200)

    def test_changing_role_or_password_revokes_sessions(self):
        self.as_("bob")
        bob = next(u for u in self.core.auth.list() if u["username"] == "bob")
        self.assertEqual(self.as_("bob").get("/api/status").status_code, 200)
        self.assertEqual(self.post("alice", f"/api/users/{bob['id']}", {"role": "viewer"}).status_code, 200)
        self.assertEqual(self.as_("bob").get("/api/status").status_code, 401)       # old session is dead

    def test_disabled_user_is_signed_out_and_cannot_log_in(self):
        self.as_("bob")
        bob = next(u for u in self.core.auth.list() if u["username"] == "bob")
        self.post("alice", f"/api/users/{bob['id']}", {"disabled": True})
        self.assertEqual(self.as_("bob").get("/api/status").status_code, 401)
        r = self.app.test_client().post("/api/login", json={"username": "bob", "password": PASSWORD}, headers=H)
        self.assertEqual(r.status_code, 401)

    def test_cannot_remove_last_admin(self):
        alice = next(u for u in self.core.auth.list() if u["username"] == "alice")
        self.assertEqual(self.post("alice", f"/api/users/{alice['id']}", {"role": "viewer"}).status_code, 400)
        self.assertEqual(self.post("alice", f"/api/users/{alice['id']}", {"disabled": True}).status_code, 400)
        self.assertEqual(self.post("alice", f"/api/users/{alice['id']}/delete").status_code, 400)

    def test_user_management_validation(self):
        self.assertEqual(self.post("alice", "/api/users", {"username": "bob", "password": PASSWORD}).status_code, 409)
        self.assertEqual(self.post("alice", "/api/users", {"username": "x", "password": PASSWORD}).status_code, 400)
        self.assertEqual(self.post("alice", "/api/users", {"username": "dave", "password": "short"}).status_code, 400)
        self.assertEqual(self.post("alice", "/api/users", {"username": "dave", "password": PASSWORD, "role": "root"}).status_code, 400)
        self.assertEqual(self.post("alice", "/api/users", {"username": "dave", "password": PASSWORD, "role": "analyst"}).status_code, 200)
        self.assertNotIn("pw_hash", self.as_("alice").get("/api/users").get_data(as_text=True))

    def test_change_own_password(self):
        other = self.app.test_client()                              # carol is also signed in elsewhere
        other.post("/api/login", json={"username": "carol", "password": PASSWORD}, headers=H)
        r = self.post("carol", "/api/account/password", {"current": "wrong wrong wrong", "new": "another long password"})
        self.assertEqual(r.status_code, 403)
        r = self.post("carol", "/api/account/password", {"current": PASSWORD, "new": "another long password"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.as_("carol").get("/api/status").status_code, 200)   # this browser stays signed in
        self.assertEqual(other.get("/api/status").status_code, 401)               # every other session is ended
        ok = self.app.test_client().post("/api/login", json={"username": "carol", "password": "another long password"}, headers=H)
        self.assertEqual(ok.status_code, 200)

    def test_audit_trail_records_actions_and_denials(self):
        self.post("bob", "/api/simulate", {"scenario": "baseline"})
        self.post("carol", "/api/settings", {"exfil_mb": 9})                          # denied
        self.app.test_client().post("/api/login", json={"username": "bob", "password": "nope nope nope nope"}, headers=H)
        events = self.as_("alice").get("/api/audit").get_json()["events"]
        actions = {(e["username"], e["action"]) for e in events}
        for want in (("bob", "demo_started"), ("carol", "denied"), ("bob", "login_failed"), ("alice", "login")):
            self.assertIn(want, actions)

    def test_logout_ends_session(self):
        c = self.as_("bob")
        self.assertEqual(self.post("bob", "/api/logout").status_code, 200)
        self.assertEqual(c.get("/api/status").status_code, 401)


class ApiBehaviour(WebCase):
    def test_settings_are_validated(self):
        s = self.post("alice", "/api/settings", {"port_scan_threshold": 99999, "exfil_mb": "abc",
                      "blacklist": {"1.2.3.4": "bad", "not-an-ip": "x"}, "malicious_ports": {"9999": "t", "x": "y", "70000": "z"}, "bogus": 1}).get_json()
        self.assertEqual(s["port_scan_threshold"], 1000)
        self.assertEqual(s["exfil_mb"], 50)
        self.assertEqual(s["blacklist"], {"1.2.3.4": "bad"})
        self.assertEqual(s["malicious_ports"], {"9999": "t"})
        self.assertNotIn("bogus", s)
        self.assertEqual(self.post("alice", "/api/settings/reset").get_json()["port_scan_threshold"], 15)

    def test_simulation_end_to_end(self):
        self.assertEqual(self.post("bob", "/api/simulate", {"scenario": "port_scan"}).status_code, 200)
        end = time.time() + 15
        while self.core.sim.running and time.time() < end:
            time.sleep(0.1)
        c = self.as_("carol")
        data = c.get("/api/alerts").get_json()
        self.assertIn("port_scan", [a["rule_id"] for a in data["alerts"]])
        a = data["alerts"][0]
        self.assertEqual(a["source"], "simulation")
        self.assertTrue(a["meaning"] and a["action"])
        self.assertEqual(c.get("/api/alerts?source=live").get_json()["alerts"], [])
        ov = c.get("/api/overview").get_json()
        self.assertEqual(ov["health"]["level"], "demo")
        pk = c.get("/api/packets?q=port:80").get_json()["packets"]
        self.assertTrue(all(80 in (p["sport"], p["dport"]) for p in pk))
        first = c.get("/api/packets").get_json()["packets"][0]["id"]
        self.assertEqual(c.get(f"/api/packets/{first}").status_code, 200)
        self.post("bob", "/api/simulate/clear")
        self.assertEqual(c.get("/api/alerts").get_json()["alerts"], [])
        self.assertEqual(c.get("/api/overview").get_json()["traffic"]["packets"], 0)

    def test_all_rules_fire_in_the_full_demo(self):
        self.post("bob", "/api/simulate", {"scenario": "all"})
        end = time.time() + 40
        while self.core.sim.running and time.time() < end:
            time.sleep(0.2)
        got = {a["rule_id"] for a in self.as_("carol").get("/api/alerts?limit=1000").get_json()["alerts"]}
        for rule in ("port_scan", "sweep", "beaconing", "syn_flood", "exfil", "arp_spoof"):
            self.assertIn(rule, got)
        self.assertNotIn("cleartext", got)

    def test_review_and_exports(self):
        self.eng.process_arp("192.168.1.1", "aa:aa:aa:aa:aa:01", 1, "simulation")
        self.eng.process_arp("192.168.1.1", "bb:bb:bb:bb:bb:02", 2, "simulation")
        aid = self.as_("carol").get("/api/alerts").get_json()["alerts"][0]["id"]
        self.assertEqual(self.post("bob", f"/api/alerts/{aid}/review", {"reviewed": True}).status_code, 200)
        self.assertEqual(self.post("bob", "/api/alerts/99999/review").status_code, 404)
        self.assertIn("ARP Spoofing Suspected", self.as_("carol").get("/api/export/alerts.csv?demo=1").get_data(as_text=True))
        self.assertIn("What it means", self.as_("carol").get("/api/export/report.md?demo=1").get_data(as_text=True))
        self.assertIn("No alerts", self.as_("carol").get("/api/export/report.md").get_data(as_text=True))

    def test_scan_api(self):
        r = self.post("alice", "/api/scan/start", {"targets": "8.8.8.8"})
        self.assertEqual((r.status_code, r.get_json()["code"]), (403, "confirm_required"))
        r = self.post("bob", "/api/scan/start", {"targets": "169.254.169.254", "confirm": True})
        self.assertEqual(r.get_json()["code"], "blocked")
        r = self.post("bob", "/api/scan/start", {"targets": "127.0.0.1", "preset": "custom", "ports": "1"})
        jid = r.get_json()["id"]
        self.assertEqual(r.get_json()["owner"], "bob")
        c = self.as_("carol")
        end = time.time() + 10
        while c.get(f"/api/scan/{jid}").get_json()["status"] == "running" and time.time() < end:
            time.sleep(0.05)
        self.assertEqual(c.get(f"/api/scan/{jid}").get_json()["status"], "done")
        self.assertEqual(self.post("bob", "/api/scan/start", {"targets": ""}).status_code, 400)

    def test_scan_presets_default_to_quick_first(self):
        presets = self.as_("carol").get("/api/status").get_json()["presets"]
        self.assertEqual(list(presets)[0], "quick")

    def test_capture_without_scapy_gives_friendly_error(self):
        import importlib.util
        if importlib.util.find_spec("scapy"):
            self.skipTest("scapy installed")
        r = self.post("bob", "/api/capture/start", {"iface": ""})
        self.assertEqual(r.status_code, 400)
        self.assertIn("Scapy", r.get_json()["error"])
        self.assertEqual(self.as_("carol").get("/api/interfaces").get_json()["interfaces"], [])


class SafetyTests(unittest.TestCase):
    def test_csv_formula_injection_neutralised(self):
        out = reports.alerts_csv([{"id": 1, "timestamp": "t", "severity": "low", "rule_name": "=cmd|' /c calc'!A0", "mitre_id": "-",
                                   "src_ip": "@x", "dst_ip": "+1", "count": 1, "reviewed": 0, "source": "live", "description": "-2+3"}])
        for cell in ("'=cmd", "'@x", "'+1", "'-2+3"):
            self.assertIn(cell, out)

    def test_v2_database_is_upgraded_in_place(self):
        d = Path(tempfile.mkdtemp())
        conn = sqlite3.connect(d / "old.db")
        conn.execute("""CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, rule_name TEXT NOT NULL, severity TEXT NOT NULL,
            mitre_id TEXT, src_ip TEXT, dst_ip TEXT, description TEXT NOT NULL, timestamp TEXT NOT NULL, reviewed INTEGER DEFAULT 0)""")
        conn.execute("""CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, port INTEGER NOT NULL,
            state TEXT NOT NULL, banner TEXT, timestamp TEXT NOT NULL)""")
        conn.execute("INSERT INTO alerts (rule_name,severity,mitre_id,src_ip,dst_ip,description,timestamp) VALUES "
                     "('Port Scan Detected','medium','T1046','1.1.1.1','2.2.2.2','old','2026-09-23T01:58:19')")
        conn.commit(); conn.close()
        db = Database(d / "old.db")
        self.addCleanup(db.close)
        row = db.query("SELECT * FROM alerts")[0]
        self.assertEqual((row["description"], row["count"], row["source"]), ("old", 1, "live"))
        from netsentinel.alerts import AlertManager
        from netsentinel.config import Settings
        old = AlertManager(db, Settings(d / "s.json"), d).list()[0]
        self.assertEqual(old["rule_id"], "port_scan")
        self.assertTrue(old["meaning"])


if __name__ == "__main__":
    unittest.main()


class FrozenPathsTests(unittest.TestCase):
    def test_exe_paths(self):
        import sys, os
        from unittest import mock
        from pathlib import Path
        from netsentinel import paths
        import tempfile
        exe_dir = tempfile.mkdtemp()
        with mock.patch.object(sys, "frozen", True, create=True), \
             mock.patch.object(sys, "_MEIPASS", "/tmp/_MEI123", create=True), \
             mock.patch.object(sys, "executable", os.path.join(exe_dir, "NetSentinel.exe")), \
             mock.patch.dict(os.environ, {"NETSENTINEL_HOME": ""}):
            self.assertEqual(paths.web_dir(), Path("/tmp/_MEI123/netsentinel/web"))
            self.assertEqual(paths.data_dir().name, "NetSentinel-data")
            self.assertNotIn("_MEI", str(paths.data_dir()))
