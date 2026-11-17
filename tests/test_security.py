"""v3.1 account security: two-factor sign-in, server-side sessions, password policy, lockouts."""
import hashlib
import time
import unittest
from unittest import mock

from netsentinel import auth, knowledge, mfa, qr
from .helpers import PASSWORD, WebCase

H = {"X-NS-Client": "1"}
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"     # base32 of the RFC 6238 test key "12345678901234567890"


class TotpTests(unittest.TestCase):
    def test_rfc6238_vectors(self):
        for t, want in ((59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"), (2000000000, "69279037")):
            self.assertEqual(mfa.code_at(RFC_SECRET, t // 30, digits=8), want)

    def test_window_and_replay(self):
        now = 1_700_000_000
        step = now // 30
        code = mfa.code_at(RFC_SECRET, step)
        self.assertEqual(mfa.verify(RFC_SECRET, code, now=now), step)
        self.assertEqual(mfa.verify(RFC_SECRET, mfa.code_at(RFC_SECRET, step - 1), now=now), step - 1)   # 30 s clock drift
        self.assertIsNone(mfa.verify(RFC_SECRET, mfa.code_at(RFC_SECRET, step - 3), now=now))            # too old
        self.assertIsNone(mfa.verify(RFC_SECRET, code, last_step=step, now=now))                         # already used
        self.assertIsNone(mfa.verify(RFC_SECRET, "12345", now=now))
        self.assertEqual(mfa.verify(RFC_SECRET, code[:3] + " " + code[3:], now=now), step)               # "123 456" is fine

    def test_secret_and_uri(self):
        s = mfa.new_secret()
        self.assertEqual(len(s), 32)
        uri = mfa.otpauth_uri(s, "alice")
        self.assertTrue(uri.startswith("otpauth://totp/NetSentinel%3Aalice?secret=" + s))

    def test_recovery_codes(self):
        codes, hashes = mfa.new_recovery_codes()
        self.assertEqual(len(set(codes)), 10)
        self.assertTrue(all(mfa.looks_like_recovery(c) for c in codes))
        self.assertEqual(mfa.hash_recovery(codes[0].upper().replace("-", " ")), hashes[0])
        self.assertNotIn(codes[0], "".join(hashes))

    def test_qr_code_decodes(self):
        try:
            import cv2
            import numpy as np
        except ImportError:
            self.skipTest("opencv not installed")
        uri = mfa.otpauth_uri(mfa.new_secret(), "a.long-user_name")
        m = np.array(qr.encode(uri).mod, dtype=np.uint8)
        img = cv2.resize((np.pad(1 - m, 4, constant_values=1) * 255).astype(np.uint8), None, fx=8, fy=8,
                         interpolation=cv2.INTER_NEAREST)
        decoded = cv2.QRCodeDetectorAruco().detectAndDecode(img)[0] or cv2.QRCodeDetector().detectAndDecode(img)[0]
        self.assertEqual(decoded, uri)
        self.assertIn("<svg", qr.svg(uri))


class PasswordPolicyTests(unittest.TestCase):
    def test_rejects_weak_passwords(self):
        for pw, user in (("short pass", ""), ("password1234", ""), ("Password2024!", ""), ("aaaaabbbbbbb", ""),
                         ("alice-is-great-2024", "alice"), ("correcthorsebatterystaple", "")):
            with self.assertRaises(auth.AuthError, msg=pw):
                auth.check_password_policy(pw, user)

    def test_accepts_good_passwords(self):
        for pw in (PASSWORD, "purple tractor singing", "N3t-S3nt!nel-x9"):
            auth.check_password_policy(pw, "bob")

    def test_old_hashes_are_upgraded_on_sign_in(self):
        from netsentinel.db import Database
        import tempfile
        db = Database(tempfile.mkdtemp() + "/t.db")
        self.addCleanup(db.close)
        svc = auth.AuthService(db)
        svc.create("olduser", PASSWORD, "viewer")
        salt = b"0123456789abcdef"
        old = hashlib.scrypt(PASSWORD.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
        db.execute("UPDATE users SET pw_hash = ? WHERE username = 'olduser'", (f"scrypt${2**14}$8$1${salt.hex()}${old.hex()}",))
        self.assertTrue(svc.authenticate("olduser", PASSWORD))
        stored = db.query("SELECT pw_hash FROM users WHERE username = 'olduser'")[0]["pw_hash"]
        self.assertTrue(stored.startswith(f"scrypt${2**15}$"))
        self.assertTrue(svc.authenticate("olduser", PASSWORD))


class TwoFactorFlow(WebCase):
    def enroll(self, who="alice"):
        c = self.as_(who)
        setup = self.post(who, "/api/account/2fa/setup").get_json()
        self.assertTrue(setup["qr"].startswith("data:image/svg+xml;base64,"))
        secret = setup["secret"].replace(" ", "")
        self.assertEqual(self.post(who, "/api/account/2fa/enable", {"password": "wrong wrong wrong", "code": "000000"}).status_code, 403)
        self.assertEqual(self.post(who, "/api/account/2fa/enable", {"password": PASSWORD, "code": "000000"}).status_code, 400)
        step = mfa.current_step()
        r = self.post(who, "/api/account/2fa/enable", {"password": PASSWORD, "code": mfa.code_at(secret, step)})
        self.assertEqual(r.status_code, 200, r.get_json())
        return c, secret, step, r.get_json()["recovery_codes"]

    def start_login(self, who="alice"):
        c = self.app.test_client()
        r = c.post("/api/login", json={"username": who, "password": PASSWORD}, headers=H).get_json()
        self.assertTrue(r["second_factor"])
        return c

    def test_enrol_then_sign_in_with_app_code(self):
        _, secret, step, codes = self.enroll()
        self.assertEqual(len(codes), 10)
        c = self.start_login()
        self.assertEqual(c.get("/api/status").status_code, 401)                      # password alone isn't enough
        self.assertTrue(c.get("/api/session").get_json()["pending_2fa"])
        self.assertEqual(c.post("/api/login/2fa", json={"code": "123456"}, headers=H).status_code, 401)
        replay = c.post("/api/login/2fa", json={"code": mfa.code_at(secret, step)}, headers=H)
        self.assertEqual(replay.status_code, 401)                                     # the enrolment code can't be reused
        # 30 seconds later the app shows a new code. (The clock is faked, so check the session inside the block:
        # the signed cookie would otherwise look like it came from the future.)
        with mock.patch("netsentinel.mfa.time.time", return_value=(step + 1) * 30 + 1):
            ok = c.post("/api/login/2fa", json={"code": mfa.code_at(secret, step + 1)}, headers=H)
            self.assertEqual(ok.status_code, 200, ok.get_json())
            self.assertEqual(c.get("/api/status").status_code, 200)
        events = [(e["action"], e["detail"]) for e in self.as_("alice").get("/api/audit").get_json()["events"]]
        self.assertIn(("login", "password + authenticator app"), events)
        self.assertIn("2fa_failed", [a for a, _ in events])

    def test_recovery_code_works_once(self):
        _, _, _, codes = self.enroll()
        c = self.start_login()
        r = c.post("/api/login/2fa", json={"code": codes[0]}, headers=H).get_json()
        self.assertTrue(r["used_recovery"])
        self.assertEqual(r["recovery_left"], 9)
        c2 = self.start_login()
        self.assertEqual(c2.post("/api/login/2fa", json={"code": codes[0]}, headers=H).status_code, 401)

    def test_too_many_wrong_codes_restarts_sign_in(self):
        self.enroll()
        c = self.start_login()
        for _ in range(4):
            self.assertEqual(c.post("/api/login/2fa", json={"code": "000000"}, headers=H).status_code, 401)
        r = c.post("/api/login/2fa", json={"code": "000000"}, headers=H)
        self.assertTrue(r.get_json().get("restart"))
        self.assertFalse(c.get("/api/session").get_json()["pending_2fa"])

    def test_start_over_cancels_a_half_finished_sign_in(self):
        self.enroll()
        c = self.start_login()
        self.assertEqual(c.post("/api/logout", json={}, headers=H).status_code, 200)
        self.assertFalse(c.get("/api/session").get_json()["pending_2fa"])

    def test_pending_sign_in_expires(self):
        self.enroll()
        c = self.start_login()
        with c.session_transaction() as s:
            s["pending"] = {**s["pending"], "at": time.time() - 600}
        r = c.post("/api/login/2fa", json={"code": "000000"}, headers=H)
        self.assertEqual((r.status_code, r.get_json().get("restart")), (401, True))

    def test_turning_off_needs_password_and_code(self):
        _, secret, step, codes = self.enroll()
        self.assertEqual(self.post("alice", "/api/account/2fa/disable", {"password": PASSWORD, "code": "000000"}).status_code, 400)
        self.assertEqual(self.post("alice", "/api/account/2fa/disable", {"password": "nope nope nope", "code": codes[1]}).status_code, 403)
        self.assertEqual(self.post("alice", "/api/account/2fa/disable", {"password": PASSWORD, "code": codes[1]}).status_code, 200)
        r = self.app.test_client().post("/api/login", json={"username": "alice", "password": PASSWORD}, headers=H).get_json()
        self.assertNotIn("second_factor", r)

    def test_new_recovery_codes_replace_old_ones(self):
        _, _, _, codes = self.enroll()
        fresh = self.post("alice", "/api/account/2fa/recovery", {"password": PASSWORD}).get_json()["recovery_codes"]
        self.assertEqual(len(fresh), 10)
        c = self.start_login()
        self.assertEqual(c.post("/api/login/2fa", json={"code": codes[0]}, headers=H).status_code, 401)
        self.assertEqual(c.post("/api/login/2fa", json={"code": fresh[0]}, headers=H).status_code, 200)

    def test_admin_can_reset_someone_elses_two_factor(self):
        self.enroll("bob")
        bob = next(u for u in self.as_("alice").get("/api/users").get_json()["users"] if u["username"] == "bob")
        self.assertTrue(bob["totp_enabled"])
        self.assertEqual(self.post("alice", f"/api/users/{bob['id']}/reset-2fa").status_code, 200)
        self.assertEqual(self.as_("bob").get("/api/status").status_code, 401)        # signed out everywhere
        r = self.app.test_client().post("/api/login", json={"username": "bob", "password": PASSWORD}, headers=H).get_json()
        self.assertNotIn("second_factor", r)
        me = next(u for u in self.as_("alice").get("/api/users").get_json()["users"] if u["username"] == "alice")
        self.assertEqual(self.post("alice", f"/api/users/{me['id']}/reset-2fa").status_code, 400)


class SessionTests(WebCase):
    def test_token_is_only_stored_hashed(self):
        c = self.as_("alice")
        with c.session_transaction() as s:
            token = s["tok"]
        rows = self.core.db.query("SELECT token_hash FROM sessions")
        self.assertIn(hashlib.sha256(token.encode()).hexdigest(), [r["token_hash"] for r in rows])
        self.assertNotIn(token, str(rows))

    def test_list_and_revoke_sessions(self):
        self.as_("alice")
        other = self.app.test_client()
        other.post("/api/login", json={"username": "alice", "password": PASSWORD}, headers={**H, "User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/130.0 Safari/537"})
        info = self.as_("alice").get("/api/account").get_json()
        self.assertEqual(len(info["sessions"]), 2)
        mine = next(s for s in info["sessions"] if s["current"])
        theirs = next(s for s in info["sessions"] if not s["current"])
        self.assertEqual(theirs["device"], "Chrome on Windows")
        self.assertEqual(self.post("alice", f"/api/account/sessions/{mine['id']}/revoke").status_code, 400)
        self.assertEqual(self.post("alice", f"/api/account/sessions/{theirs['id']}/revoke").status_code, 200)
        self.assertEqual(other.get("/api/status").status_code, 401)
        self.assertEqual(self.as_("alice").get("/api/status").status_code, 200)

    def test_sign_out_everywhere_else(self):
        others = [self.app.test_client() for _ in range(2)]
        for o in others:
            o.post("/api/login", json={"username": "bob", "password": PASSWORD}, headers=H)
        self.assertEqual(self.post("bob", "/api/account/sessions/revoke-others").get_json()["revoked"], 2)
        self.assertTrue(all(o.get("/api/status").status_code == 401 for o in others))
        self.assertEqual(self.as_("bob").get("/api/status").status_code, 200)

    def test_idle_timeout(self):
        self.core.settings.update({"session_idle_minutes": 5})
        c = self.as_("bob")
        self.core.db.execute("UPDATE sessions SET last_seen = ?", (time.time() - 400,))
        r = c.get("/api/status")
        self.assertEqual((r.status_code, r.get_json()["signed_out"]), (401, "idle"))
        self.assertIn("5 minutes", r.get_json()["error"])
        self.assertEqual(self.core.db.query("SELECT COUNT(*) AS n FROM sessions WHERE user_id = (SELECT id FROM users WHERE username='bob')")[0]["n"], 0)

    def test_background_polling_does_not_keep_session_alive(self):
        c = self.as_("bob")
        old = time.time() - 100
        self.core.db.execute("UPDATE sessions SET last_seen = ?", (old,))
        c.get("/api/status", headers={"X-NS-Background": "1"})
        self.assertAlmostEqual(self.core.db.query("SELECT last_seen FROM sessions")[0]["last_seen"], old, places=3)
        c.get("/api/status")
        self.assertGreater(self.core.db.query("SELECT last_seen FROM sessions")[0]["last_seen"], old + 50)

    def test_absolute_session_limit(self):
        c = self.as_("bob")
        self.core.db.execute("UPDATE sessions SET created = ?", (time.time() - 13 * 3600,))
        self.assertEqual(c.get("/api/status").get_json()["signed_out"], "expired")

    def test_previous_sign_in_is_reported(self):
        first = self.app.test_client().post("/api/login", json={"username": "carol", "password": PASSWORD}, headers=H).get_json()
        self.assertIsNone(first["previous"])
        second = self.app.test_client().post("/api/login", json={"username": "carol", "password": PASSWORD}, headers=H).get_json()
        self.assertEqual(second["previous"]["ip"], "127.0.0.1")
        activity = self.as_("carol").get("/api/account").get_json()["activity"]
        self.assertGreaterEqual(sum(e["action"] == "login" for e in activity), 2)

    def test_old_v30_cookie_is_ignored(self):
        c = self.app.test_client()
        with c.session_transaction() as s:
            s.update(uid=1, epoch=0, csrf="x")
        self.assertEqual(c.get("/api/status").status_code, 401)


class AccountRules(WebCase):
    def test_admin_issued_password_must_be_changed(self):
        self.assertEqual(self.post("alice", "/api/users", {"username": "dave", "password": PASSWORD, "role": "analyst"}).status_code, 200)
        c = self.app.test_client()
        r = c.post("/api/login", json={"username": "dave", "password": PASSWORD}, headers=H).get_json()
        self.assertTrue(r["must_change_pw"])
        token = c.get("/api/session").get_json()["csrf"]
        blocked = c.get("/api/status")
        self.assertEqual((blocked.status_code, blocked.get_json()["code"]), (403, "password_change_required"))
        self.assertEqual(c.get("/api/account").status_code, 200)
        same = c.post("/api/account/password", json={"current": PASSWORD, "new": PASSWORD}, headers={"X-NS-Token": token})
        self.assertEqual(same.status_code, 400)                                        # must actually change it
        ok = c.post("/api/account/password", json={"current": PASSWORD, "new": "my own new passphrase"}, headers={"X-NS-Token": token})
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(c.get("/api/status").status_code, 200)

    def test_admin_password_reset_signs_user_out_and_forces_change(self):
        self.as_("carol")
        carol = next(u for u in self.core.auth.list() if u["username"] == "carol")
        self.assertEqual(self.post("alice", f"/api/users/{carol['id']}", {"password": "temporary pass 77"}).status_code, 200)
        self.assertEqual(self.as_("carol").get("/api/status").status_code, 401)
        self.assertTrue(self.core.auth.get(carol["id"])["must_change_pw"])

    def test_admin_can_sign_a_user_out(self):
        c = self.as_("bob")
        bob = next(u for u in self.core.auth.list() if u["username"] == "bob")
        self.assertEqual(self.post("alice", f"/api/users/{bob['id']}/signout").get_json()["revoked"], 1)
        self.assertEqual(c.get("/api/status").status_code, 401)

    def test_admin_cannot_change_own_role(self):
        alice = next(u for u in self.core.auth.list() if u["username"] == "alice")
        self.post("alice", "/api/users", {"username": "zoe", "password": PASSWORD, "role": "admin"})
        self.assertEqual(self.post("alice", f"/api/users/{alice['id']}", {"role": "viewer"}).status_code, 400)

    def test_password_spraying_locks_the_address(self):
        c = self.app.test_client()
        for i in range(20):
            c.post("/api/login", json={"username": f"user{i}", "password": "Spring2026!x"}, headers=H)
        r = c.post("/api/login", json={"username": "alice", "password": PASSWORD}, headers=H)
        self.assertEqual(r.status_code, 429)

    def test_users_summary_flags_admins_without_two_factor(self):
        s = self.as_("alice").get("/api/users").get_json()["summary"]
        self.assertEqual(s["admins_without_2fa"], ["alice"])
        self.assertEqual(s["with_2fa"], 0)


class LearnTests(WebCase):
    def test_learn_content_follows_settings(self):
        d = self.as_("carol").get("/api/learn").get_json()
        self.assertEqual(len(d["attack"]["tactics"]), 14)
        ids = {t["id"] for t in d["techniques"]}
        for rule in knowledge.RULES.values():                                  # every mapped rule has a page
            if rule["mitre"] != "-":
                self.assertIn(rule["mitre"], ids)
        self.post("alice", "/api/settings", {"port_scan_threshold": 42})
        d = self.as_("carol").get("/api/learn").get_json()
        self.assertIn("42 or more", next(r for r in d["rules"] if r["id"] == "port_scan")["trigger"])
        self.assertTrue(all(g["cat"] in d["categories"] for g in d["glossary"]))


if __name__ == "__main__":
    unittest.main()
