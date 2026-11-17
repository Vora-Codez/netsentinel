import unittest
from .helpers import CoreCase


class DetectionTests(CoreCase):
    def test_port_scan_fires(self):
        for i in range(15):
            self.ev(100 + i * 0.1, "10.0.0.66", "192.168.1.50", 1000 + i)
        self.assertIn("port_scan", self.rules())

    def test_port_scan_not_fired_below_threshold(self):
        for i in range(10):
            self.ev(100 + i * 0.1, "10.0.0.66", "192.168.1.50", 1000 + i)
        self.assertNotIn("port_scan", self.rules())

    def test_normal_browsing_is_not_a_sweep(self):
        for i in range(30):
            self.ev(100 + i * 0.1, "192.168.1.10", f"151.101.{i}.1", 443)
        self.assertNotIn("sweep", self.rules())

    def test_real_sweep_fires(self):
        for i in range(25):
            self.ev(100 + i * 0.1, "192.168.1.99", f"192.168.1.{i + 2}", 445)
        self.assertIn("sweep", self.rules())

    def test_multicast_and_broadcast_ignored(self):
        for i in range(40):
            self.ev(100 + i * 0.1, "192.168.1.9", "255.255.255.255", 445 + i, proto="UDP")
        self.assertEqual(self.rules(), [])

    def test_established_traffic_is_not_a_scan(self):
        for i in range(50):
            self.ev(100 + i * 0.1, "192.168.1.10", "192.168.1.20", 2000 + i, flags="A")
        self.assertEqual(self.rules(), [])

    def test_beaconing_fires_on_regular_public_traffic(self):
        for t in (0, 5.1, 9.9, 15.2, 20.0):
            self.ev(100 + t, "192.168.1.50", "185.220.101.7", 8443)
        self.assertIn("beaconing", self.rules())

    def test_beaconing_ignores_bursts(self):
        for i in range(10):
            self.ev(100 + i * 0.1, "192.168.1.50", "185.220.101.7", 8443)
        self.assertNotIn("beaconing", self.rules())

    def test_beaconing_ignores_private_dst_and_ntp(self):
        for t in (0, 5, 10, 15, 20):
            self.ev(100 + t, "192.168.1.50", "192.168.1.1", 8443)
            self.ev(100 + t, "192.168.1.50", "185.220.101.7", 123, proto="UDP")
        self.assertNotIn("beaconing", self.rules())

    def test_beaconing_ignores_irregular(self):
        for t in (0, 3, 11, 12, 40):
            self.ev(100 + t, "192.168.1.50", "185.220.101.7", 8443)
        self.assertNotIn("beaconing", self.rules())

    def test_malicious_port_beacon_is_high(self):
        for t in (0, 5, 10, 15, 20):
            self.ev(100 + t, "192.168.1.50", "185.220.101.7", 4444)
        sev = {a["rule_id"]: a["severity"] for a in self.core.alerts.list()}
        self.assertEqual((sev["malicious_port"], sev["beaconing"]), ("high", "high"))

    def test_exfil_and_internal_transfer(self):
        for i in range(12):
            self.ev(100 + i, "192.168.1.23", "93.184.216.34", 443, "PA", 6_000_000)
        self.assertIn("exfil", self.rules())

    def test_big_internal_transfer_is_not_exfil(self):
        for i in range(30):
            self.ev(100 + i, "192.168.1.23", "192.168.1.30", 445, "PA", 6_000_000)
        self.assertNotIn("exfil", self.rules())

    def test_syn_flood(self):
        for i in range(250):
            self.ev(100 + i * 0.01, "10.0.0.77", "192.168.1.10", 80)
        self.assertIn("syn_flood", self.rules())

    def test_cleartext_and_blacklist(self):
        self.core.settings.update({"blacklist": {"203.0.113.66": "test"}})
        self.ev(1, "192.168.1.5", "192.168.1.9", 23, "PA")
        self.ev(2, "192.168.1.5", "203.0.113.66", 80, "A")
        self.assertTrue({"cleartext", "blacklist"} <= set(self.rules()))

    def test_scan_touching_telnet_port_is_not_cleartext_use(self):
        for i in range(30):
            self.ev(100 + i * 0.1, "10.0.0.66", "192.168.1.50", 15 + i)
        self.assertNotIn("cleartext", self.rules())

    def test_cooldown_merges_duplicates(self):
        for rnd in range(3):
            for i in range(15):
                self.ev(100 + rnd * 12 + i * 0.1, "10.0.0.66", "192.168.1.50", 1000 + i)
        alerts = [a for a in self.core.alerts.list() if a["rule_id"] == "port_scan"]
        self.assertEqual(len(alerts), 1)
        self.assertGreaterEqual(alerts[0]["count"], 2)

    def test_arp_spoof_and_new_device(self):
        self.eng.process_arp("192.168.1.1", "aa:aa:aa:aa:aa:01", 1, "simulation")
        self.eng.process_arp("192.168.1.1", "bb:bb:bb:bb:bb:66", 6, "simulation")
        got = [a["rule_id"] for a in self.core.alerts.list()]
        self.assertTrue({"arp_spoof", "new_device"} <= set(got))

    def test_no_new_device_alert_during_warmup(self):
        self.eng.process_arp("192.168.1.7", "aa:aa:aa:aa:aa:07", None, "live")
        self.assertNotIn("new_device", self.rules())
        self.assertEqual(len(self.eng.device_list()), 1)

    def test_demo_alerts_not_written_to_siem_log(self):
        for i in range(15):
            self.eng.process({"ts": 100 + i * .1, "src_ip": "10.0.0.66", "dst_ip": "192.168.1.50", "protocol": "TCP",
                              "dst_port": 1000 + i, "flags": "S", "length": 64, "source": "simulation"})
        self.assertFalse(self.core.alerts.log_path.exists())
        for i in range(15):
            self.ev(100 + i * .1, "10.0.0.67", "192.168.1.50", 1000 + i)
        self.assertTrue(self.core.alerts.log_path.exists())

    def test_tracking_tables_stay_bounded_under_address_spray(self):
        self.eng.MAX_WINDOWS = 500
        for i in range(10_000):   # every packet goes to a new address
            self.eng.process({"ts": 100 + i * .001, "src_ip": "192.168.1.9", "dst_ip": f"151.101.{i // 250}.{i % 250 + 1}",
                              "protocol": "TCP", "dst_port": 443, "flags": "S", "length": 64, "source": "live"})
        eng = self.eng
        for table in (eng._scan, eng._sweep, eng._beacon, eng._exfil, eng._syn):
            self.assertLessEqual(len(table), 500)
        for i in range(15):       # a real scan is still caught after the flood
            self.ev(200 + i * 0.1, "10.0.0.66", "192.168.1.50", 1000 + i)
        self.assertIn("port_scan", self.rules())


if __name__ == "__main__":
    unittest.main()
