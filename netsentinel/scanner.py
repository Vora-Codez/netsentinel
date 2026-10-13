"""TCP connect scanner (nmap-style, no raw sockets needed).

Targets: IP/hostname, CIDR, ranges (192.168.1.10-50), or a mix. Ports: presets or custom.
Multiple targets get a host-discovery pass first. Runs as a background job with progress + cancel.
Every open port is labelled with service, risk and plain-English advice.
"""
import errno
import ipaddress
import queue
import socket
import ssl
import threading
import uuid
from collections import OrderedDict

from . import knowledge
from .alerts import utcnow
from .detection import is_private

MAX_HOSTS, MAX_PROBES = 1024, 300_000
DISCOVERY_PORTS = [80, 443, 22, 445, 135, 139, 3389, 53, 8080]
REFUSED = {errno.ECONNREFUSED, 10061, 61, 111}
HTTP_PORTS, TLS_PORTS = {80, 8000, 8008, 8080, 8888}, {443, 8443, 993, 995, 465}
PRESETS = {
    "quick": ("Quick - ~40 common ports", knowledge.QUICK_PORTS),
    "top1024": ("Standard - ports 1-1024", list(range(1, 1025))),
    "all": ("Everything - ports 1-65535 (slow)", list(range(1, 65536))),
}


class ScanError(Exception):
    def __init__(self, message, code="bad_request", status=400):
        super().__init__(message)
        self.code, self.status = code, status


def parse_ports(spec):
    ports = set()
    for tok in (spec or "").replace(" ", "").split(","):
        if not tok:
            continue
        try:
            if "-" in tok:
                lo, hi = (int(x) for x in tok.split("-", 1))
                rng = range(min(lo, hi), max(lo, hi) + 1)
            else:
                rng = [int(tok)]
        except ValueError:
            raise ScanError(f"'{tok}' isn't a valid port or range.")
        for p in rng:
            if not 1 <= p <= 65535:
                raise ScanError(f"Port {p} is out of range (1-65535).")
            ports.add(p)
    if not ports:
        raise ScanError("Enter at least one port (for example 22,80,443 or 1-1024).")
    return sorted(ports)


def parse_targets(text):
    hosts = OrderedDict()
    for tok in (text or "").replace(",", " ").split():
        try:
            if "/" in tok:
                net = ipaddress.ip_network(tok, strict=False)
                if net.version != 4:
                    raise ScanError("Only IPv4 targets are supported for scanning.")
                if net.num_addresses > MAX_HOSTS * 4:
                    raise ScanError(f"{tok} is too large. Use /22 or smaller (max {MAX_HOSTS} hosts).")
                for h in (list(net.hosts()) if net.prefixlen < 31 else list(net)):
                    hosts[str(h)] = None
            elif "-" in tok and tok.split("-", 1)[0].count(".") == 3:
                start_s, end_s = tok.split("-", 1)
                start = ipaddress.IPv4Address(start_s)
                end = ipaddress.IPv4Address(end_s) if "." in end_s else ipaddress.IPv4Address(start_s.rsplit(".", 1)[0] + "." + end_s)
                if int(end) < int(start):
                    start, end = end, start
                if int(end) - int(start) + 1 > MAX_HOSTS:
                    raise ScanError(f"Range too large (max {MAX_HOSTS} hosts).")
                for n in range(int(start), int(end) + 1):
                    hosts[str(ipaddress.IPv4Address(n))] = None
            else:
                try:
                    hosts[str(ipaddress.IPv4Address(tok))] = None
                except ipaddress.AddressValueError:
                    try:
                        hosts[socket.getaddrinfo(tok, None, socket.AF_INET)[0][4][0]] = None
                    except socket.gaierror:
                        raise ScanError(f"Couldn't find a host called '{tok}'.")
        except ScanError:
            raise
        except ValueError:
            raise ScanError(f"'{tok}' isn't a valid IP, range or network.")
        if len(hosts) > MAX_HOSTS:
            raise ScanError(f"Too many targets (max {MAX_HOSTS}). Try a smaller network.")
    if not hosts:
        raise ScanError("Enter a target - for example 127.0.0.1 or 192.168.1.0/24.")
    return list(hosts)


def _printable(raw, limit=120):
    text = "".join(c if c.isprintable() else " " for c in raw.decode("latin-1", "replace"))
    return " ".join(text.split())[:limit]


def _server_line(raw):
    lines = raw.decode("latin-1", "replace").split("\r\n")
    status = lines[0][:40] if lines else ""
    server = next((l[7:].strip() for l in lines if l.lower().startswith("server:")), "")
    return _printable(f"{status} {('Server: ' + server) if server else ''}".encode())


def _grab_banner(sock, host, port, timeout):
    try:
        sock.settimeout(max(timeout, 1.0))
        if port in TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            with ctx.wrap_socket(sock, server_hostname=host if not host[0].isdigit() else None) as ss:
                out = ss.version() or "TLS"
                if port in (443, 8443):
                    ss.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                    out += " | " + _server_line(ss.recv(1024))
                return out.rstrip(" |")
        if port in HTTP_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            return _server_line(sock.recv(1024))
        return _printable(sock.recv(256))
    except (OSError, ssl.SSLError):
        return ""


def probe(host, port, timeout, banner=True):
    """Returns {state: open|closed|filtered, banner}."""
    res = {"state": "filtered", "banner": ""}
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        code = s.connect_ex((host, port))
        if code == 0:
            res["state"] = "open"
            if banner:
                res["banner"] = _grab_banner(s, host, port, timeout)
        elif code in REFUSED:
            res["state"] = "closed"
    except OSError:
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass
    return res


class ScanJob:
    def __init__(self, targets, ports, label, owner=""):
        self.id = uuid.uuid4().hex[:10]
        self.targets, self.ports, self.label, self.owner, self.plabel = targets, ports, label, owner, ""
        self.status, self.phase, self.done, self.total = "queued", "", 0, 0
        self.hosts_up, self.results, self.error = [], [], ""
        self.started, self.finished = utcnow(), None
        self.cancel, self.lock = threading.Event(), threading.Lock()

    def summary(self, with_results=True):
        with self.lock:
            risk = {"high": 0, "medium": 0, "low": 0}
            for r in self.results:
                if r["risk"] in risk:
                    risk[r["risk"]] += 1
            d = {"id": self.id, "status": self.status, "phase": self.phase, "done": self.done, "total": self.total,
                 "progress": (self.done / self.total) if self.total else 0.0, "targets": len(self.targets),
                 "target_label": self.label, "ports": len(self.ports), "hosts_up": len(self.hosts_up),
                 "open_count": len(self.results), "risk": risk, "error": self.error, "owner": self.owner,
                 "started": self.started, "finished": self.finished}
            if with_results:
                key = lambda h: [int(x) for x in h.split(".")]
                d["results"] = sorted(self.results, key=lambda r: (key(r["host"]), r["port"]))
                d["hosts"] = sorted(self.hosts_up, key=key)
            return d


class ScanManager:
    def __init__(self, db, settings, engine):
        self.db, self.settings, self.engine = db, settings, engine
        self.jobs, self._lock = OrderedDict(), threading.Lock()

    def active(self):
        return next((j for j in self.jobs.values() if j.status in ("queued", "running")), None)

    def start(self, targets_text, preset="quick", ports_spec="", confirm=False, allow_public=True, owner=""):
        targets = parse_targets(targets_text)
        for t in targets:        # never probe link-local (cloud metadata!), multicast or reserved space
            ip = ipaddress.ip_address(t)
            if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
                raise ScanError(f"{t} is in a range NetSentinel never scans (link-local, multicast or reserved).", "blocked", 403)
        if preset == "custom" or (ports_spec and preset not in PRESETS):
            ports, plabel = parse_ports(ports_spec), "custom"
        elif preset in PRESETS:
            ports, plabel = PRESETS[preset][1], preset
        else:
            raise ScanError("Unknown scan type.")
        if len(targets) * len(ports) > MAX_PROBES:
            raise ScanError(f"That's {len(targets) * len(ports):,} probes - too many. Scan fewer ports or a smaller network.")
        external = [t for t in targets if not is_private(t)]
        if external and not allow_public:
            raise ScanError("Only administrators can scan addresses outside your private network.", "forbidden", 403)
        if external and not confirm:
            raise ScanError("This target is outside your private network. Confirm you own it or have written "
                            "permission to scan it.", "confirm_required", 403)
        label = targets[0] if len(targets) == 1 else f"{targets[0]} ... {targets[-1]} ({len(targets)} hosts)"
        with self._lock:
            if self.active():
                raise ScanError("A scan is already running. Cancel it or wait for it to finish.", "busy", 409)
            job = ScanJob(targets, ports, label, owner)
            job.plabel = plabel
            self.jobs[job.id] = job
            while len(self.jobs) > 20:
                self.jobs.popitem(last=False)
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job

    def get(self, job_id):
        return self.jobs.get(job_id)

    def cancel(self, job_id):
        job = self.jobs.get(job_id)
        if job:
            job.cancel.set()
        return bool(job)

    def _pool(self, job, work, fn):
        q = queue.Queue()
        for item in work:
            q.put(item)

        def worker():
            while not job.cancel.is_set():
                try:
                    item = q.get_nowait()
                except queue.Empty:
                    return
                try:
                    fn(item)
                finally:
                    with job.lock:
                        job.done += 1
        threads = [threading.Thread(target=worker, daemon=True)
                   for _ in range(max(1, min(int(self.settings.get("scan_workers")), len(work))))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def _run(self, job):
        timeout = float(self.settings.get("scan_timeout"))
        try:
            job.status = "running"
            if len(job.targets) > 1:
                job.phase, job.total, job.done = "Finding live hosts", len(job.targets), 0

                def disc(host):
                    for p in DISCOVERY_PORTS:
                        if job.cancel.is_set():
                            return
                        if probe(host, p, min(timeout, 0.5), banner=False)["state"] in ("open", "closed"):
                            with job.lock:
                                job.hosts_up.append(host)
                            return
                self._pool(job, job.targets, disc)
            else:
                job.hosts_up = list(job.targets)
            if not job.cancel.is_set() and job.hosts_up:
                job.phase = "Scanning ports"
                work = [(h, p) for h in job.hosts_up for p in job.ports]
                job.total, job.done = len(work), 0

                def scan(item):
                    host, port = item
                    r = probe(host, port, timeout)
                    if r["state"] == "open":
                        info = knowledge.classify_port(port, r["banner"])
                        with job.lock:
                            job.results.append({"host": host, "port": port, "state": "open", "banner": r["banner"], **info})
                self._pool(job, work, scan)
            job.status = "cancelled" if job.cancel.is_set() else "done"
        except Exception as e:
            job.status, job.error = "error", str(e)
        finally:
            job.phase, job.finished = "", utcnow()
            self._persist(job)

    def _persist(self, job):
        try:
            for h in job.hosts_up:
                self.engine.note_host(h, via="scan")
            ts = utcnow()
            self.db.executemany(
                "INSERT INTO scans (run_id, target, port, state, service, risk, banner, timestamp) VALUES (?,?,?,?,?,?,?,?)",
                [(job.id, r["host"], r["port"], "open", r["service"], r["risk"], r["banner"], ts) for r in job.results])
            self.db.execute(
                """INSERT OR REPLACE INTO scan_runs (id, targets, ports, started, finished, status, hosts_scanned,
                   hosts_up, open_count) VALUES (?,?,?,?,?,?,?,?,?)""",
                (job.id, job.label, job.plabel, job.started, job.finished, job.status,
                 len(job.targets), len(job.hosts_up), len(job.results)))
        except Exception:
            pass

    def history(self, limit=15):
        return self.db.query("SELECT * FROM scan_runs ORDER BY started DESC LIMIT ?", (limit,))

    def run_results(self, run_id):
        rows = self.db.query("SELECT * FROM scans WHERE run_id = ? ORDER BY target, port", (run_id,))
        for r in rows:
            r["host"] = r["target"]
            r["advice"] = knowledge.classify_port(r["port"], r.get("banner") or "")["advice"]
        return rows
