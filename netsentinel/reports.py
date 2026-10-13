"""CSV and Markdown exports."""
import csv
import io
from collections import Counter, OrderedDict
from datetime import datetime, timezone

from . import __version__


def _safe_cell(v):
    """Neutralise spreadsheet formula injection (=, +, -, @ at the start of a cell)."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _csv(header, rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for r in rows:
        w.writerow([_safe_cell(x) for x in r])
    return buf.getvalue()


def alerts_csv(alerts):
    return _csv(["id", "time_utc", "severity", "rule", "mitre", "source_ip", "destination", "count", "status", "origin", "description"],
                [[a["id"], a["timestamp"], a["severity"], a["rule_name"], a["mitre_id"], a["src_ip"], a["dst_ip"],
                  a["count"], "reviewed" if a["reviewed"] else "open", a["source"], a["description"]] for a in alerts])


def packets_csv(packets):
    return _csv(["id", "time", "source", "destination", "src_port", "dst_port", "protocol", "length", "info", "origin"],
                [[p["id"], datetime.fromtimestamp(p["ts"], timezone.utc).isoformat(timespec="milliseconds"), p["src"], p["dst"],
                  p["sport"], p["dport"], p["proto"], p["length"], p["info"], p["source"]] for p in packets])


def _md(s):
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")


def incident_report(alerts, scan=None, include_demo=False):
    """Plain-English Markdown report an analyst could hand off."""
    alerts = [a for a in alerts if include_demo or a["source"] == "live"]
    sev = Counter(a["severity"] for a in alerts)
    out = ["# NetSentinel Report", "", f"*Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} by NetSentinel v{__version__}*", "",
           "## Summary", "", f"- **{len(alerts)}** alert(s): {sev['high']} high, {sev['medium']} medium, {sev['low']} low",
           f"- **{sum(1 for a in alerts if not a['reviewed'])}** not yet reviewed"]
    if scan:
        out.append(f"- Latest scan of **{_md(scan['target_label'])}**: {scan['hosts_up']} host(s) up, {scan['open_count']} open port(s)")
    out.append("")
    if not alerts:
        out += ["No alerts were recorded.", ""]
    else:
        out += ["## Timeline", "", "| Time (UTC) | Severity | Alert | Source | Destination | Count |", "|---|---|---|---|---|---|"]
        for a in sorted(alerts, key=lambda a: a["id"]):
            out.append(f"| {_md(a['timestamp'])} | {a['severity']} | {_md(a['rule_name'])} | `{_md(a['src_ip'])}` | `{_md(a['dst_ip'])}` | {a['count']} |")
        out += ["", "## Findings", ""]
        groups = OrderedDict()
        for a in sorted(alerts, key=lambda a: ({"high": 0, "medium": 1, "low": 2}[a["severity"]], a["id"])):
            groups.setdefault(a["rule_id"] or a["rule_name"], []).append(a)
        for items in groups.values():
            first = items[0]
            mitre = f" (MITRE ATT&CK {first['mitre_id']})" if first["mitre_id"] not in ("", "-", None) else ""
            out += [f"### {_md(first['rule_name'])}{mitre}", "", f"**What happened:** {_md(first['title'])}. Seen {len(items)} time(s).", ""]
            out += [f"- {_md(a['description'])}" for a in items[:5]]
            if len(items) > 5:
                out.append(f"- ... and {len(items) - 5} more")
            if first["meaning"]:
                out += ["", f"**What it means:** {first['meaning']}", "", f"**What to do:** {first['action']}"]
            out.append("")
    if scan and scan.get("results"):
        out += ["## Open ports (latest scan)", "", "| Host | Port | Service | Risk | Advice |", "|---|---|---|---|---|"]
        out += [f"| `{r['host']}` | {r['port']} | {_md(r['service'])} | {r['risk']} | {_md(r['advice'])} |" for r in scan["results"]]
        out.append("")
    out += ["---", "*Only scan and monitor networks you own or have permission to test.*", ""]
    return "\n".join(out)
