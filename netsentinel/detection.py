"""Rule-based detection engine. Feed it events with process(event).

Event: ts, src_ip, dst_ip, src_port, dst_port, protocol, length, flags, source.
Rules count NEW CONNECTIONS (SYN without ACK, or UDP), not every packet; scans are tracked per
(source, target), sweeps per (source, port); beaconing needs public, non-DNS/NTP destinations;
windows are incremental so a busy network can't stall capture. Events may carry their own clock.
"""
import heapq
import ipaddress
import threading
import time
from collections import Counter, deque
from functools import lru_cache

WEB_PORTS = {53, 80, 123, 137, 138, 443, 1900, 5353, 5355, 8080, 8443}
CLEARTEXT = {23: "Telnet", 21: "FTP", 110: "POP3", 143: "IMAP"}


@lru_cache(maxsize=8192)
def _ip(addr):
    try:
        return ipaddress.ip_address(addr)
    except (ValueError, TypeError):
        return None


def is_private(addr):
    ip = _ip(addr)
    return bool(ip and (ip.is_private or ip.is_loopback or ip.is_link_local))


def is_special(addr):
    ip = _ip(addr)
    return bool(ip is None or ip.is_multicast or ip.is_unspecified or addr == "255.255.255.255")


def is_public(addr):
    ip = _ip(addr)
    return bool(ip and not is_special(addr) and not is_private(addr))


class SlidingDistinct:
    __slots__ = ("q", "c", "touched")

    def __init__(self):
        self.q, self.c, self.touched = deque(), Counter(), time.time()

    def add(self, ts, item, window):
        self.touched = time.time()
        self.q.append((ts, item)); self.c[item] += 1
        cutoff = ts - window
        while self.q and self.q[0][0] < cutoff:
            _, old = self.q.popleft()
            self.c[old] -= 1
            if self.c[old] <= 0:
                del self.c[old]
        return len(self.c)

    def clear(self):
        self.q.clear(); self.c.clear()


class SlidingSum:
    __slots__ = ("q", "total", "touched")

    def __init__(self):
        self.q, self.total, self.touched = deque(), 0, time.time()

    def add(self, ts, weight, window):
        self.touched = time.time()
        self.q.append((ts, weight)); self.total += weight
        cutoff = ts - window
        while self.q and self.q[0][0] < cutoff:
            self.total -= self.q.popleft()[1]
        return self.total

    def clear(self):
        self.q.clear(); self.total = 0


class Stamps:
    __slots__ = ("q", "touched")

    def __init__(self, maxlen):
        self.q, self.touched = deque(maxlen=maxlen), time.time()


class DetectionEngine:
    def __init__(self, settings, alerts):
        self.s, self.alerts = settings, alerts
        self._lock = threading.RLock()
        self.devices = {}
        self._born = time.time()
        self._reset_windows()

    def _reset_windows(self):
        self._scan, self._sweep, self._beacon, self._exfil, self._syn = {}, {}, {}, {}, {}
        self._n = 0

    def clear_simulated(self):
        with self._lock:
            self._reset_windows()
            self.devices = {k: v for k, v in self.devices.items() if v.get("source") != "simulation"}

    @staticmethod
    def is_conn_start(proto, flags):
        if proto == "TCP":
            return True if not flags else ("S" in flags and "A" not in flags)
        return proto in ("UDP", "ICMP", "OTHER")

    def process(self, ev):
        src, dst = ev.get("src_ip"), ev.get("dst_ip")
        if not src or not dst:
            return
        with self._lock:
            now = ev.get("ts") or time.time()
            source = ev.get("source", "live")
            proto, flags, dport = ev.get("protocol"), ev.get("flags") or "", ev.get("dst_port")
            self._check_blacklist(src, dst, now, source)
            if self.is_conn_start(proto, flags):
                self._check_malicious_port(src, dst, dport, now, source)
                if dport is not None:
                    self._check_port_scan(src, dst, dport, now, source)
                    self._check_sweep(src, dst, dport, now, source)
                if proto == "TCP":
                    self._check_beacon(src, dst, dport, now, source)
                if proto == "TCP" and "S" in flags:
                    self._check_syn_flood(src, dst, now, source)
            # Cleartext needs real DATA (PSH): a bare SYN from a port scan is not "use".
            if proto == "TCP" and "P" in flags and dport is not None:
                self._check_cleartext(src, dst, dport, now, source)
            self._check_exfil(src, dst, ev.get("length") or 0, now, source)
            self._n += 1
            if self._n % 2000 == 0:
                self._gc()

    def _alert(self, rule, src, dst, desc, now, source, **kw):
        self.alerts.raise_alert(rule, src, dst, desc, now=now, source=source, **kw)

    def _check_blacklist(self, src, dst, now, source):
        bl = self.s.get("blacklist")
        for ip in (src, dst):
            if ip in bl:
                self._alert("blacklist", src, dst, f"{ip} is on your blocked list ({bl[ip] or 'no reason given'}).", now, source)

    def _check_malicious_port(self, src, dst, dport, now, source):
        why = self.s.get("malicious_ports").get(str(dport)) if dport is not None else None
        if why:
            self._alert("malicious_port", src, dst, f"{src} connected to {dst} on port {dport} ({why}).", now, source)

    def _check_port_scan(self, src, dst, dport, now, source):
        if is_special(dst):
            return
        win = self.s.get("port_scan_window")
        w = self._scan.setdefault((src, dst), SlidingDistinct())
        n = w.add(now, dport, win)
        if n >= self.s.get("port_scan_threshold"):
            self._alert("port_scan", src, dst, f"{src} tried {n} different ports on {dst} within {win} seconds "
                        f"(threshold {self.s.get('port_scan_threshold')}).", now, source)
            w.clear()

    def _check_sweep(self, src, dst, dport, now, source):
        if is_special(dst):
            return
        thr = self.s.get("sweep_threshold_web" if dport in WEB_PORTS else "sweep_threshold")
        win = self.s.get("sweep_window")
        w = self._sweep.setdefault((src, dport), SlidingDistinct())
        n = w.add(now, dst, win)
        if n >= thr:
            self._alert("sweep", src, f"port {dport} (many hosts)", f"{src} probed port {dport} on {n} different "
                        f"hosts within {win} seconds (threshold {thr}).", now, source)
            w.clear()

    def _check_beacon(self, src, dst, dport, now, source):
        if not is_public(dst) or dport is None or dport in self.s.get("beacon_ignore_ports"):
            return
        hits = self.s.get("beacon_min_hits")
        w = self._beacon.get((src, dst, dport))
        if w is None or w.q.maxlen != hits:
            w = self._beacon[(src, dst, dport)] = Stamps(hits)
        w.touched = time.time()
        w.q.append(now)
        if len(w.q) < hits:
            return
        ts = list(w.q)
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        mean = sum(gaps) / len(gaps)
        if not (2.0 <= mean <= 900.0):
            return
        tol = max(0.5, mean * self.s.get("beacon_jitter_pct") / 100.0)
        if all(abs(g - mean) <= tol for g in gaps):
            sev = "high" if str(dport) in self.s.get("malicious_ports") else "medium"
            self._alert("beaconing", src, dst, f"{src} connected to {dst}:{dport} {hits} times, once every "
                        f"~{mean:.0f}s with very little variation.", now, source, severity=sev)
            w.q.clear()

    def _check_exfil(self, src, dst, length, now, source):
        if not length or not is_private(src) or not is_public(dst):
            return
        win, limit = self.s.get("exfil_window"), self.s.get("exfil_mb") * 1_000_000
        w = self._exfil.setdefault((src, dst), SlidingSum())
        total = w.add(now, length, win)
        if total >= limit:
            self._alert("exfil", src, dst, f"{total / 1e6:.0f} MB was sent from {src} to {dst} within {win} "
                        f"seconds (limit {self.s.get('exfil_mb')} MB).", now, source,
                        severity="high" if total >= limit * 5 else "medium")
            w.clear()

    def _check_syn_flood(self, src, dst, now, source):
        if is_special(dst):
            return
        w = self._syn.setdefault((src, dst), SlidingSum())
        n = w.add(now, 1, 5)
        if n >= self.s.get("syn_flood_threshold"):
            self._alert("syn_flood", src, dst, f"{src} sent {n} connection requests to {dst} in 5 seconds.", now, source)
            w.clear()

    def _check_cleartext(self, src, dst, dport, now, source):
        name = CLEARTEXT.get(dport)
        if name and self.s.get("cleartext_alerts") and not is_special(dst):
            self._alert("cleartext", src, dst, f"{src} used {name} (port {dport}) to talk to {dst}. Passwords and "
                        "data on this connection are not encrypted.", now, source, cooldown=600)

    def process_arp(self, ip, mac, ts=None, source="live"):
        if not ip or not mac or ip == "0.0.0.0" or mac.lower() in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return
        with self._lock:
            now, wall = ts or time.time(), time.time()
            dev = self.devices.get(ip)
            if dev is None:
                self.devices[ip] = {"ip": ip, "mac": mac, "first_seen": wall, "last_seen": wall,
                                    "source": source, "via": "arp", "previous_macs": []}
                if ((wall - self._born) > 30 or source == "simulation") and self.s.get("new_device_alerts"):
                    self._alert("new_device", ip, "-", f"New device {ip} ({mac}) appeared on the network.", now, source)
                return
            dev["last_seen"] = wall
            if dev["mac"].lower() != mac.lower():
                prev = dev["mac"]
                dev["previous_macs"].append(prev)
                dev["mac"] = mac
                self._alert("arp_spoof", ip, "-", f"{ip} changed its hardware address from {prev} to {mac}. "
                            "Possible ARP cache poisoning / man-in-the-middle attempt.", now, source)

    def note_host(self, ip, via="scan", source="live"):
        with self._lock:
            wall = time.time()
            dev = self.devices.get(ip)
            if dev:
                dev["last_seen"] = wall
            else:
                self.devices[ip] = {"ip": ip, "mac": "", "first_seen": wall, "last_seen": wall,
                                    "source": source, "via": via, "previous_macs": []}

    def device_list(self):
        with self._lock:
            return sorted((dict(d) for d in self.devices.values()),
                          key=lambda d: [int(x) if x.isdigit() else 0 for x in d["ip"].split(".")])

    MAX_WINDOWS = 20_000    # per table; bounds memory when traffic hits many distinct addresses

    def _gc(self):
        cutoff = time.time() - 600
        for table in (self._scan, self._sweep, self._beacon, self._exfil, self._syn):
            for k in [k for k, v in table.items() if v.touched < cutoff]:
                del table[k]
            extra = len(table) - self.MAX_WINDOWS
            if extra > 0:   # evict the least recently used windows; active attackers keep theirs
                for k, _ in heapq.nsmallest(extra, table.items(), key=lambda kv: kv[1].touched):
                    del table[k]
