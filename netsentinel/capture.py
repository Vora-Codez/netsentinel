"""Traffic intake: live packet capture (Scapy) and the in-memory views of it.

Everything that produces traffic (live capture or the demo simulator) calls CaptureManager.ingest(),
which feeds the packet list, conversation table, rate graph and the detection engine.
Packets live in bounded in-memory buffers, not SQLite.
"""
import importlib.util
import json
import os
import sys
import threading
import time
from collections import Counter, OrderedDict, deque
from types import SimpleNamespace

from . import paths

RING_SIZE, MAX_FLOWS, PAYLOAD_KEEP = 3000, 5000, 128


class CaptureError(Exception):
    pass


def friendly_error(exc):
    text = str(exc) if exc else ""
    low = text.lower()
    if isinstance(exc, PermissionError) or "permission" in low or "operation not permitted" in low:
        if os.name == "nt":
            return "Windows needs Administrator rights to capture packets."
        return ("Packet capture needs root or the NET_RAW capability "
                "(Docker: cap_add NET_RAW and NET_ADMIN, network_mode host).")
    if any(k in low for k in ("winpcap", "npcap", "libpcap", "layer 2", "wpcap")):
        return "Npcap isn't installed. Get it free from https://npcap.com, then try again."
    if "no such device" in low or "interface" in low:
        return f"That network interface isn't available. ({text})"
    return text or "Capture could not be started."


def capabilities():
    scapy_ok = importlib.util.find_spec("scapy") is not None
    npcap = None
    if os.name == "nt":
        root = os.environ.get("SystemRoot", r"C:\Windows")
        npcap = any(os.path.exists(os.path.join(root, "System32", p)) for p in ("Npcap", "wpcap.dll")) \
            or os.path.exists(os.path.join(root, "SysWOW64", "Npcap"))
    return {"scapy": scapy_ok, "npcap": npcap, "admin": paths.can_capture(), "platform": sys.platform}


def list_interfaces():
    if importlib.util.find_spec("scapy") is None:
        return []
    try:
        from scapy.all import conf, get_if_list
        out = []
        if os.name == "nt":
            for ifc in conf.ifaces.values():
                ip = getattr(ifc, "ip", "") or ""
                if not ip or ip.startswith("169.254") or ip == "0.0.0.0":
                    continue
                out.append({"id": getattr(ifc, "network_name", None) or ifc.name,
                            "name": getattr(ifc, "description", None) or ifc.name, "ip": ip})
        else:
            from scapy.all import get_if_addr
            for name in get_if_list():
                try:
                    ip = get_if_addr(name)
                except Exception:
                    ip = ""
                out.append({"id": name, "name": name, "ip": ip if ip != "0.0.0.0" else ""})
        return out
    except Exception:
        return []


class CaptureManager:
    def __init__(self, settings, engine, log_dir=None):
        self.settings, self.engine, self.log_dir = settings, engine, log_dir
        self._lock = threading.RLock()
        self._ring = deque(maxlen=RING_SIZE)
        self._flows = OrderedDict()
        self._buckets = OrderedDict()
        self._protos, self._totals = Counter(), Counter()
        self._pid = 0
        self._sniffer, self._L = None, None
        self.state, self.iface, self.error, self.started, self.decode_errors = "stopped", "", "", None, 0

    def ingest(self, ev, info="", payload=b"", label=""):
        source = ev.get("source", "live")
        now, wall = ev.get("ts") or time.time(), time.time()
        length = ev.get("length") or 0
        src, dst = ev.get("src_ip"), ev.get("dst_ip")
        proto = label or ev.get("protocol") or "OTHER"
        with self._lock:
            self._pid += 1
            rec = {"id": self._pid, "ts": now, "src": src, "dst": dst, "sport": ev.get("src_port"),
                   "dport": ev.get("dst_port"), "proto": proto, "transport": ev.get("protocol"),
                   "length": length, "flags": ev.get("flags") or "", "info": info or self._default_info(ev),
                   "source": source, "payload": bytes(payload[:PAYLOAD_KEEP])}
            self._ring.append(rec)
            key = (src, dst, ev.get("dst_port"), ev.get("protocol"), source)
            flow = self._flows.get(key)
            if flow is None:
                flow = self._flows[key] = {"src": src, "dst": dst, "dport": ev.get("dst_port"),
                                           "proto": ev.get("protocol"), "source": source,
                                           "packets": 0, "bytes": 0, "first": wall, "last": wall}
                if len(self._flows) > MAX_FLOWS:
                    self._flows.popitem(last=False)
            flow["packets"] += 1; flow["bytes"] += length; flow["last"] = wall
            self._flows.move_to_end(key)
            b = self._buckets.get(int(wall))
            if b is None:
                b = self._buckets[int(wall)] = [0, 0]
                while len(self._buckets) > 180:
                    self._buckets.popitem(last=False)
            b[0] += 1; b[1] += length
            self._protos[(source, proto)] += 1
            self._totals[(source, "packets")] += 1
            self._totals[(source, "bytes")] += length
        if self.settings.get("log_packets_jsonl") and source == "live":
            self._log_packet(rec)
        self.engine.process(ev)
        return rec["id"]

    @staticmethod
    def _default_info(ev):
        sp, dp, fl = ev.get("src_port"), ev.get("dst_port"), ev.get("flags")
        base = f"{sp} → {dp}" if sp is not None and dp is not None else ""
        return f"{base} [{fl}]" if fl else base

    def _log_packet(self, rec):
        try:
            with open(os.path.join(self.log_dir, "packets.jsonl"), "a", encoding="utf-8") as f:
                f.write(json.dumps({k: v for k, v in rec.items() if k != "payload"}) + "\n")
        except (OSError, TypeError):
            pass

    def packets(self, since_id=0, limit=300, query="", source="all"):
        tests, out = _parse_filter(query), []
        with self._lock:
            for rec in reversed(self._ring):
                if rec["id"] <= since_id or len(out) >= limit:
                    break
                if source != "all" and rec["source"] != source:
                    continue
                if tests and not all(t(rec) for t in tests):
                    continue
                out.append(_public(rec))
        out.reverse()
        return out

    def packet(self, pid):
        with self._lock:
            for rec in reversed(self._ring):
                if rec["id"] == pid:
                    d = _public(rec)
                    d["hex"] = _hexdump(rec["payload"])
                    return d
        return None

    def flows(self, limit=200, sort="bytes", source="all"):
        key = sort if sort in ("bytes", "packets", "last") else "bytes"
        with self._lock:
            rows = [dict(f) for f in self._flows.values() if source == "all" or f["source"] == source]
        rows.sort(key=lambda f: f[key], reverse=True)
        return rows[:limit]

    def top_talkers(self, n=6, source="all"):
        agg = {}
        with self._lock:
            for f in self._flows.values():
                if source != "all" and f["source"] != source:
                    continue
                a = agg.setdefault(f["src"], [0, 0])
                a[0] += f["packets"]; a[1] += f["bytes"]
        rows = sorted(({"ip": ip, "packets": p, "bytes": b} for ip, (p, b) in agg.items()),
                      key=lambda r: r["bytes"], reverse=True)
        return rows[:n]

    def series(self, seconds=60):
        now = int(time.time())
        with self._lock:
            return [{"t": s, "packets": (self._buckets.get(s) or [0, 0])[0], "bytes": (self._buckets.get(s) or [0, 0])[1]}
                    for s in range(now - seconds + 1, now + 1)]

    def overview(self, source="all"):
        with self._lock:
            tot = lambda kind: sum(v for (s, k), v in self._totals.items() if k == kind and (source == "all" or s == source))
            protos = Counter()
            for (s, p), v in self._protos.items():
                if source == "all" or s == source:
                    protos[p] += v
            return {"packets": tot("packets"), "bytes": tot("bytes"),
                    "protocols": [{"proto": p, "packets": v} for p, v in protos.most_common(8)]}

    def clear(self, source="all"):
        with self._lock:
            if source == "all":
                self._ring.clear(); self._flows.clear(); self._protos.clear(); self._totals.clear()
                return
            keep = [r for r in self._ring if r["source"] != source]
            self._ring.clear(); self._ring.extend(keep)
            for table, idx in ((self._flows, 4), (self._protos, 0), (self._totals, 0)):
                for k in [k for k in table if k[idx] == source]:
                    del table[k]

    def status(self):
        with self._lock:
            if self.state == "running" and self._sniffer is not None:
                th = getattr(self._sniffer, "thread", None)
                if th is not None and not th.is_alive():
                    self.state, self.error = "error", self.error or "Capture stopped unexpectedly."
            return {"state": self.state, "iface": self.iface, "error": self.error, "started": self.started,
                    "decode_errors": self.decode_errors, "live_packets": self._totals[("live", "packets")]}

    def start(self, iface=""):
        with self._lock:
            if self.state == "running":
                raise CaptureError("Capture is already running.")
            if importlib.util.find_spec("scapy") is None:
                self.state, self.error = "error", "The packet-capture engine (Scapy) isn't installed on this server."
                raise CaptureError(self.error)
            try:
                from scapy.all import AsyncSniffer, ARP, DNS, DNSQR, ICMP, IP, IPv6, Raw, TCP, UDP
                self._L = SimpleNamespace(ARP=ARP, DNS=DNS, DNSQR=DNSQR, ICMP=ICMP, IP=IP, IPv6=IPv6, Raw=Raw, TCP=TCP, UDP=UDP)
                sniffer = AsyncSniffer(iface=iface or None, prn=self._on_packet, store=False)
                sniffer.start()
                time.sleep(0.7)
                th = getattr(sniffer, "thread", None)
                if th is not None and not th.is_alive():
                    raise CaptureError(friendly_error(getattr(sniffer, "exception", None)))
            except CaptureError as e:
                self.state, self.error = "error", str(e)
                raise
            except Exception as e:
                self.state, self.error = "error", friendly_error(e)
                raise CaptureError(self.error) from e
            self._sniffer, self.iface, self.state = sniffer, iface, "running"
            self.error, self.started = "", time.time()

    def stop(self):
        with self._lock:
            sn, self._sniffer = self._sniffer, None
            self.state = "stopped"
        if sn is not None:
            try:
                sn.stop()
            except Exception:
                pass

    def _on_packet(self, pkt):
        try:
            L = self._L
            if pkt.haslayer(L.ARP):
                a = pkt[L.ARP]
                self.engine.process_arp(a.psrc, a.hwsrc)
                self.ingest({"src_ip": a.psrc, "dst_ip": a.pdst, "protocol": "ARP", "length": len(pkt)},
                            info=f"ARP {'who-has' if a.op == 1 else 'is-at'} {a.pdst} (from {a.hwsrc})", label="ARP")
                return
            ip = pkt[L.IP] if pkt.haslayer(L.IP) else pkt[L.IPv6] if pkt.haslayer(L.IPv6) else None
            if ip is None:
                return
            ev = {"src_ip": ip.src, "dst_ip": ip.dst, "protocol": "OTHER", "length": len(pkt),
                  "src_port": None, "dst_port": None, "flags": ""}
            payload, label, info = b"", "", ""
            if pkt.haslayer(L.TCP):
                t = pkt[L.TCP]
                ev.update(protocol="TCP", src_port=t.sport, dst_port=t.dport, flags=str(t.flags))
                payload = bytes(t.payload)
                label = _tcp_label(payload)
                info = f"{t.sport} → {t.dport} [{ev['flags']}] len={len(payload)}"
                if label == "HTTP" and payload:
                    info = payload.split(b"\r\n", 1)[0][:90].decode("latin-1", "replace")
            elif pkt.haslayer(L.UDP):
                u = pkt[L.UDP]
                ev.update(protocol="UDP", src_port=u.sport, dst_port=u.dport)
                payload = bytes(u.payload)
                info = f"{u.sport} → {u.dport} len={len(payload)}"
                if pkt.haslayer(L.DNSQR):
                    q = pkt[L.DNSQR].qname
                    name = q.decode("latin-1", "replace").rstrip(".") if isinstance(q, bytes) else str(q)
                    label, info = "DNS", f"{'Response' if pkt[L.DNS].qr == 1 else 'Query'}: {name}"
            elif pkt.haslayer(L.ICMP):
                ic = pkt[L.ICMP]
                ev["protocol"], label, info = "ICMP", "ICMP", f"type={ic.type} code={ic.code}"
            self.ingest(ev, info=info, payload=payload, label=label)
        except Exception:
            self.decode_errors += 1


def _tcp_label(payload):
    if payload[:3] in (b"GET", b"POS", b"HEA", b"PUT", b"DEL", b"OPT") or payload[:5] == b"HTTP/":
        return "HTTP"
    if len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03:
        return "TLS"
    return "TCP"


def _public(rec):
    return {k: v for k, v in rec.items() if k != "payload"}


def _hexdump(data):
    return [{"offset": f"{i:04x}", "hex": " ".join(f"{b:02x}" for b in data[i:i + 16]),
             "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data[i:i + 16])}
            for i in range(0, len(data), 16)]


def _parse_filter(query):
    """Wireshark-lite filter: tcp, dns, port:443, ip:1.2.3.4, src:, dst:, or free text (ANDed)."""
    tests = []
    for tok in (query or "").lower().split():
        if tok.startswith("port:"):
            try:
                n = int(tok[5:])
            except ValueError:
                continue
            tests.append(lambda r, n=n: n in (r["sport"], r["dport"]))
        elif tok.startswith("ip:"):
            v = tok[3:]; tests.append(lambda r, v=v: v in (r["src"] or "") or v in (r["dst"] or ""))
        elif tok.startswith("src:"):
            v = tok[4:]; tests.append(lambda r, v=v: v in (r["src"] or ""))
        elif tok.startswith("dst:"):
            v = tok[4:]; tests.append(lambda r, v=v: v in (r["dst"] or ""))
        elif tok in ("tcp", "udp", "icmp", "arp", "dns", "http", "tls"):
            tests.append(lambda r, v=tok: v in (r["proto"].lower(), (r["transport"] or "").lower()))
        else:
            tests.append(lambda r, v=tok: v in (r["info"] or "").lower() or v in (r["src"] or "").lower() or v in (r["dst"] or "").lower())
    return tests
