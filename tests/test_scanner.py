import socket
import threading
import time
import unittest

from netsentinel import scanner
from netsentinel.scanner import ScanError, parse_ports, parse_targets
from .helpers import CoreCase


class Listener:
    def __init__(self, banner=b"SSH-2.0-TestServer\r\n"):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(20)
        self.port, self.banner, self.alive = self.sock.getsockname()[1], banner, True
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while self.alive:
            try:
                c, _ = self.sock.accept()
                c.sendall(self.banner)
                c.close()
            except OSError:
                return

    def close(self):
        self.alive = False
        self.sock.close()


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class ParseTests(unittest.TestCase):
    def test_ports(self):
        self.assertEqual(parse_ports("22, 80,8000-8002"), [22, 80, 8000, 8001, 8002])
        self.assertEqual(parse_ports("10-8"), [8, 9, 10])

    def test_bad_ports(self):
        for bad in ("", "abc", "0", "70000", "1-99999"):
            with self.assertRaises(ScanError):
                parse_ports(bad)

    def test_targets(self):
        self.assertEqual(parse_targets("127.0.0.1"), ["127.0.0.1"])
        self.assertEqual(len(parse_targets("192.168.1.0/24")), 254)
        self.assertEqual(parse_targets("192.168.1.10-12"), ["192.168.1.10", "192.168.1.11", "192.168.1.12"])
        self.assertEqual(parse_targets("10.0.0.1-10.0.0.2, 10.0.0.2"), ["10.0.0.1", "10.0.0.2"])

    def test_bad_targets(self):
        for bad in ("", "10.0.0.0/8", "999.1.1.1/24", "10.0.0.5-2000", "no-such-host.invalid"):
            with self.assertRaises(ScanError):
                parse_targets(bad)


class ScanTests(CoreCase):
    def wait(self, job, timeout=15):
        end = time.time() + timeout
        while job.status in ("queued", "running") and time.time() < end:
            time.sleep(0.05)
        self.assertEqual(job.status, "done", job.error)

    def test_finds_open_port_with_banner_and_skips_closed(self):
        srv = Listener()
        try:
            job = self.core.scans.start("127.0.0.1", "custom", f"{srv.port},{closed_port()}")
            self.wait(job)
        finally:
            srv.close()
        res = job.summary()["results"]
        self.assertEqual([r["port"] for r in res], [srv.port])
        self.assertIn("SSH-2.0-TestServer", res[0]["banner"])
        self.assertEqual(res[0]["service"], "ssh")
        self.assertEqual(self.core.scans.history()[0]["open_count"], 1)

    def test_risk_classification(self):
        info = scanner.knowledge.classify_port(3389)
        self.assertEqual(info["risk"], "high")
        self.assertTrue(info["advice"])

    def test_public_target_needs_confirmation_and_admin(self):
        with self.assertRaises(ScanError) as cm:
            self.core.scans.start("8.8.8.8", "quick")
        self.assertEqual(cm.exception.code, "confirm_required")
        with self.assertRaises(ScanError) as cm:
            self.core.scans.start("8.8.8.8", "quick", confirm=True, allow_public=False)
        self.assertEqual(cm.exception.code, "forbidden")

    def test_never_scans_metadata_or_reserved_ranges(self):
        for t in ("169.254.169.254", "224.0.0.1", "0.0.0.0"):
            with self.assertRaises(ScanError) as cm:
                self.core.scans.start(t, "quick", confirm=True)
            self.assertEqual(cm.exception.code, "blocked")

    def test_probe_cap(self):
        with self.assertRaises(ScanError):
            self.core.scans.start("10.0.0.0/22", "all", confirm=True)

    def test_discovery_for_multiple_hosts(self):
        srv = Listener()
        try:
            job = self.core.scans.start("127.0.0.1-127.0.0.2", "custom", str(srv.port))
            self.wait(job)
        finally:
            srv.close()
        s = job.summary()
        self.assertEqual(s["hosts_up"], 2)
        self.assertGreaterEqual(s["open_count"], 1)
        self.assertTrue(any(d["ip"] == "127.0.0.1" for d in self.eng.device_list()))

    def test_one_scan_at_a_time_and_cancel(self):
        orig = scanner.probe
        scanner.probe = lambda *a, **k: (time.sleep(0.05), {"state": "filtered", "banner": ""})[1]
        try:
            self.core.settings.update({"scan_workers": 2})
            job = self.core.scans.start("127.0.0.1", "top1024")
            with self.assertRaises(ScanError) as cm:
                self.core.scans.start("127.0.0.1", "quick")
            self.assertEqual(cm.exception.status, 409)
            self.core.scans.cancel(job.id)
            end = time.time() + 10
            while job.status == "running" and time.time() < end:
                time.sleep(0.05)
            self.assertEqual(job.status, "cancelled")
            self.assertLess(job.done, job.total)
        finally:
            scanner.probe = orig


if __name__ == "__main__":
    unittest.main()
