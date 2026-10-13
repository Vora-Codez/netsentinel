"""Demo-mode traffic generator. Everything is tagged source="simulation": shown with a DEMO badge,
never written to the SIEM log, wipeable in one click. Each scenario has its own synthetic clock."""
import random
import threading
import time

SCENARIOS = {
    "baseline": ("Everyday traffic", "Normal browsing and DNS - should raise nothing."),
    "port_scan": ("Port scan", "One device probes 25 ports on another."),
    "sweep": ("Network sweep", "One device checks for SMB (445) across 30 machines."),
    "beaconing": ("C2 beaconing", "A PC phones home to an outside server every ~5 seconds."),
    "syn_flood": ("SYN flood", "A burst of 260 connection requests in 3 seconds."),
    "exfil": ("Data exfiltration", "A PC uploads ~70 MB to one outside server."),
    "arp_spoof": ("ARP spoofing", "A new device claims the router's address."),
    "attack_chain": ("Full attack chain", "Scan, then compromise, then beaconing - like a real incident."),
    "all": ("Everything", "Normal traffic plus every attack above."),
}
PUBLIC_POOL = ["142.250.80.46", "151.101.1.69", "104.18.32.7", "13.107.42.14", "172.217.14.206",
               "52.96.108.2", "157.240.22.35", "23.45.67.89"]
C2 = "185.220.101.7"          # illustrative only - nothing ever connects to it
ATTACKER, VICTIM = "10.0.0.66", "192.168.1.50"


def _ev(t, src, dst, dport, flags="S", length=64, proto="TCP"):
    return {"ts": t, "src_ip": src, "dst_ip": dst, "protocol": proto, "src_port": random.randint(1025, 65000),
            "dst_port": dport, "length": length, "flags": flags, "source": "simulation"}


def _baseline(t0, n=70):
    out, t = [], t0
    for _ in range(n):
        t += random.uniform(0.2, 1.0)
        client = f"192.168.1.{random.randint(10, 40)}"
        if random.random() < 0.25:
            name = random.choice(["example.com", "update.microsoft.com", "news.ycombinator.com"])
            out.append((0.03, _ev(t, client, "192.168.1.1", 53, "", 80, "UDP"), f"Query: {name}", "DNS"))
        else:
            out.append((0.03, _ev(t, client, random.choice(PUBLIC_POOL), random.choice([443, 443, 443, 80]),
                                  random.choice(["S", "A", "PA", "PA", "A"]), random.randint(60, 1500)),
                        "", "TLS" if random.random() < .6 else ""))
    return out


def _port_scan(t0, src=ATTACKER, dst=VICTIM):
    return [(0.05, _ev(t0 + i * 0.1, src, dst, p), "", "") for i, p in enumerate(random.sample(range(1, 1024), 25))]


def _sweep(t0):
    return [(0.04, _ev(t0 + i * 0.1, "192.168.1.99", f"192.168.1.{i + 2}", 445), "", "") for i in range(30)]


def _beacon(t0, port=8443):
    return [(0.25, _ev(t0 + o, VICTIM, C2, port, "S", 128), "", "") for o in (0, 5.1, 9.9, 15.2, 20.0, 25.1)]


def _syn_flood(t0):
    return [(0.004, _ev(t0 + i * 0.012, "10.0.0.77", "192.168.1.10", 80), "", "") for i in range(260)]


def _exfil(t0):
    return [(0.15, _ev(t0 + i * 2, "192.168.1.23", "93.184.216.34", 443, "PA", 6_000_000),
             "Bulk upload (aggregated, simulated)", "TLS") for i in range(12)]


def _chain(t0):
    return _port_scan(t0) + _beacon(t0 + 90, port=4444)


def build(name):
    t0 = time.time()
    if name == "all":
        out, t = _baseline(t0, 40), t0 + 60
        for fn in (_port_scan, _sweep, _beacon, _syn_flood, _exfil):
            out += fn(t)
            t += 200
        return out
    fns = {"baseline": _baseline, "port_scan": _port_scan, "sweep": _sweep, "beaconing": _beacon,
           "syn_flood": _syn_flood, "exfil": _exfil, "attack_chain": _chain}
    return fns[name](t0) if name in fns else []


class Simulator:
    def __init__(self, capture, engine):
        self.capture, self.engine = capture, engine
        self._thread, self._stop = None, threading.Event()
        self.scenario, self.done, self.total = "", 0, 0

    @property
    def running(self):
        return bool(self._thread and self._thread.is_alive())

    def status(self):
        return {"running": self.running, "scenario": self.scenario,
                "progress": (self.done / self.total) if self.total else 0.0}

    def start(self, scenario):
        if scenario not in SCENARIOS or self.running:
            return False
        self._stop.clear()
        self.scenario, self.done = scenario, 0
        self._thread = threading.Thread(target=self._run, args=(scenario,), daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._stop.set()

    def _run(self, scenario):
        try:
            events = build(scenario)
            if scenario in ("arp_spoof", "all"):
                events += self._arp_events(events[-1][1]["ts"] + 1 if events else time.time())
            self.total = len(events)
            for delay, ev, info, label in events:
                if self._stop.is_set():
                    break
                if ev.get("protocol") == "ARP":
                    self.engine.process_arp(ev["_ip"], ev["_mac"], ev["ts"], "simulation")
                self.capture.ingest(ev, info=info, label=label)
                self.done += 1
                time.sleep(delay)
        finally:
            self.done = self.total

    @staticmethod
    def _arp_events(t0):
        def arp(t, ip, mac, who):
            return (0.4, {"ts": t, "src_ip": ip, "dst_ip": "192.168.1.255", "protocol": "ARP", "length": 42,
                          "source": "simulation", "_ip": ip, "_mac": mac}, f"ARP: {ip} is-at {mac} {who}", "ARP")
        return [arp(t0, "192.168.1.1", "a4:2b:b0:11:22:33", "(router)"),
                arp(t0 + 5, "192.168.1.1", "de:ad:be:ef:66:66", "(NEW owner!)")]
