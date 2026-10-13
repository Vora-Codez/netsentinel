import shutil
import tempfile
import unittest

from netsentinel.core import Core
from netsentinel.env import Env
from netsentinel.server import create_app

PASSWORD = "correct horse battery"


class CoreCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.core = Core(self.tmp)
        self.eng = self.core.engine

    def tearDown(self):
        self.core.shutdown()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def ev(self, t, src, dst, dport, flags="S", length=64, proto="TCP"):
        self.eng.process({"ts": t, "src_ip": src, "dst_ip": dst, "protocol": proto, "src_port": 40000,
                          "dst_port": dport, "length": length, "flags": flags, "source": "live"})

    def rules(self):
        return [a["rule_id"] for a in self.core.alerts.list()]


class WebCase(CoreCase):
    """A running app with an admin, analyst and viewer account; helpers to act as each."""
    def setUp(self):
        super().setUp()
        self.env = Env(setup_code="SETUP123")
        self.app = create_app(self.core, self.env)
        for name, role in (("alice", "admin"), ("bob", "analyst"), ("carol", "viewer")):
            self.core.auth.create(name, PASSWORD, role)
        self.clients = {}

    def as_(self, name):
        if name not in self.clients:
            c = self.app.test_client()
            r = c.post("/api/login", json={"username": name, "password": PASSWORD}, headers={"X-NS-Client": "1"})
            assert r.status_code == 200, r.get_json()
            c.csrf = c.get("/api/session").get_json()["csrf"]
            self.clients[name] = c
        return self.clients[name]

    def post(self, who, url, data=None):
        c = self.as_(who)
        return c.post(url, json=data or {}, headers={"X-NS-Token": c.csrf})
