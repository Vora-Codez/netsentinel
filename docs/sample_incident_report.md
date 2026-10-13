# Incident Report — INC-2026-0001

**Analyst:** Jayzon Ray
**Date:** 2026-09-23
**Tool:** NetSentinel
**Severity:** Medium → escalated to High

## Summary
NetSentinel's detection engine flagged a rapid multi-port connection pattern
from host `10.0.0.66` against `192.168.1.50`, consistent with a TCP port scan
(MITRE ATT&CK T1046 — Network Service Discovery). Approximately 90 seconds
later, the same victim host began periodic outbound connections to an
external IP on port 4444, a default Metasploit handler port, at a highly
regular ~5 second interval — consistent with C2 beaconing (T1071).

## Timeline
| Time (UTC) | Event |
|---|---|
| 01:58:12 | `10.0.0.66` begins connecting to sequential ports on `192.168.1.50` |
| 01:58:19 | Port Scan Detected alert fires — 15 distinct ports touched in 10s |
| 01:59:41 | `192.168.1.50` begins outbound connections to `185.220.101.7:4444` |
| 01:59:42 | Known-Malicious Port Contacted alert fires |
| 01:59:47 | Possible C2 Beaconing alert fires — 5 connections at ~5s intervals |

## Analysis
The sequencing strongly suggests the scan was reconnaissance that
succeeded — `192.168.1.50` responded to something delivered during or
shortly after the scan window and is now exhibiting classic post-exploitation
beaconing behavior to an external host on a well-known backdoor/handler port.

## Recommended Response
1. Isolate `192.168.1.50` from the network pending investigation
2. Capture memory/disk image for forensic review
3. Block outbound traffic to `185.220.101.7` at the perimeter firewall
4. Review `10.0.0.66` for signs of compromise or unauthorized scanning activity
5. Search logs for any successful authentication or process execution on
   `192.168.1.50` in the window between the scan and the first beacon

## MITRE ATT&CK Mapping
- **T1046** — Network Service Discovery
- **T1071** — Application Layer Protocol (C2)

---
*This report was generated from a controlled lab simulation
(`sniffer.simulate_traffic()`) for portfolio/demonstration purposes.*
