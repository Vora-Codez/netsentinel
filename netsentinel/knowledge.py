"""Plain-English explanations: what each alert means and what a port is."""

RULES = {
    "port_scan": {"name": "Port Scan Detected", "severity": "medium", "mitre": "T1046",
        "title": "Someone is knocking on many doors of one device",
        "meaning": "One device tried many different ports on another device in a short time. Attackers do this to find out which services are running (and which might be weak) before choosing an attack. It can also be a harmless vulnerability scanner or an admin tool.",
        "action": "Check whether the source is a device or tool you own (like an inventory scanner). If not, find the device and investigate it, and make sure the target only exposes services it needs."},
    "sweep": {"name": "Network Sweep Detected", "severity": "medium", "mitre": "T1046",
        "title": "Someone is checking many devices for the same service",
        "meaning": "One device probed the same port on lots of different machines. This is how attackers and worms hunt for vulnerable systems (for example 'which machines have Remote Desktop open?').",
        "action": "Identify the source. If it's inside your network, that device may be infected or misused - isolate it and scan it for malware."},
    "malicious_port": {"name": "Known-Malicious Port Contacted", "severity": "high", "mitre": "T1571",
        "title": "A connection to a port commonly used by malware",
        "meaning": "A device connected to a port that is a well-known default for hacking tools or old backdoors. Legitimate software almost never uses these ports.",
        "action": "Find out which program on the source device made the connection. If you don't recognise it, disconnect the device and run a malware scan."},
    "blacklist": {"name": "Blacklisted IP Contacted", "severity": "high", "mitre": "-",
        "title": "Traffic involving an address you flagged as bad",
        "meaning": "Traffic was seen to or from an IP address on your blocked list (Settings).",
        "action": "Look at what the device was doing with that address and decide whether to block it at your router or firewall."},
    "beaconing": {"name": "Possible C2 Beaconing", "severity": "medium", "mitre": "T1071",
        "title": "A device is 'phoning home' on a regular schedule",
        "meaning": "A device is connecting to the same outside address at very regular intervals. Malware often does this to ask its operator for instructions ('command and control'). Some legitimate software (updaters, sync clients, telemetry) behaves similarly.",
        "action": "Look up the destination address. If the source runs software you recognise and the destination matches its vendor, it's probably fine. If not, investigate the source device."},
    "exfil": {"name": "Possible Data Exfiltration", "severity": "medium", "mitre": "T1041",
        "title": "A large amount of data is leaving your network",
        "meaning": "A device on your network sent an unusually large amount of data to a single outside address. This can mean stolen data is being uploaded - or simply a big backup, video upload or cloud sync.",
        "action": "Ask whether someone was uploading something big on purpose. If not, check what the source device is doing and where the data went."},
    "syn_flood": {"name": "SYN Flood / Connection Burst", "severity": "high", "mitre": "T1498",
        "title": "A flood of new connection requests",
        "meaning": "A huge number of connection attempts arrived in a few seconds. This is the signature of a denial-of-service attack, an aggressive scanner, or a misbehaving program.",
        "action": "Identify the source. If it's external, consider rate-limiting or blocking it at your router. If internal, check the device for malware."},
    "cleartext": {"name": "Unencrypted Protocol in Use", "severity": "low", "mitre": "-",
        "title": "A service that sends passwords and data in plain text",
        "meaning": "A device used Telnet, FTP, POP3 or IMAP without encryption. Anyone on the same network can read what's sent, including passwords.",
        "action": "Switch to the encrypted version: SSH instead of Telnet, SFTP/FTPS instead of FTP, and POP3S/IMAPS."},
    "arp_spoof": {"name": "ARP Spoofing Suspected", "severity": "high", "mitre": "T1557",
        "title": "Two devices are claiming to be the same address",
        "meaning": "An IP address suddenly changed which hardware (MAC) address owns it. Attackers do this to sit 'in the middle' of traffic and read or alter it. It can also be harmless (a device replaced or a reused DHCP lease).",
        "action": "Check whether you recently changed a router or device. If not, find the new MAC address on your network and investigate it. Avoid logging into anything sensitive until resolved."},
    "new_device": {"name": "New Device on Network", "severity": "low", "mitre": "-",
        "title": "A device we haven't seen before just appeared",
        "meaning": "A new IP/MAC combination showed up on your network.",
        "action": "If you recognise it (a new phone, guest laptop), no action needed. If not, check your router's device list and consider changing your Wi-Fi password."},
}

GLOSSARY = [
    ("Port", "A numbered 'door' on a device. Each service (web, email, remote login) listens on its own port."),
    ("Port scan", "Trying lots of ports on a device to see which are open. Attackers use it to find a way in; admins use it to audit."),
    ("Open / Closed / Filtered", "Open: a service is listening. Closed: nothing is listening. Filtered: a firewall silently dropped the probe."),
    ("Banner", "A short greeting some services send when you connect, often revealing the software and version."),
    ("Beaconing", "Software checking in with a remote server at regular intervals - normal for updaters, suspicious for malware."),
    ("C2 (command and control)", "The server an attacker uses to give instructions to infected machines."),
    ("Exfiltration", "Sneaking data out of a network."),
    ("ARP", "The protocol that maps IP addresses to hardware (MAC) addresses on a local network."),
    ("SYN", "The first packet in a TCP connection ('hello, can we talk?'). Lots of SYNs without follow-up is a scan or flood."),
    ("MITRE ATT&CK", "A public catalogue of attacker techniques. IDs like T1046 let you look up exactly what the behaviour is."),
    ("Conversation (flow)", "All the packets between one pair of devices on one port, grouped together."),
]

PORTS = {
    21: ("ftp", "medium", "FTP sends passwords in plain text. Use SFTP/FTPS, or close it."),
    22: ("ssh", "low", "Encrypted remote login. Fine if you use it - use keys, not weak passwords."),
    23: ("telnet", "high", "Telnet is unencrypted and ancient. Disable it and use SSH."),
    25: ("smtp", "low", "Mail server. Make sure it isn't an open relay."),
    53: ("dns", "info", "Name resolution. Expected on routers and DNS servers."),
    67: ("dhcp", "info", "Hands out IP addresses. Expected on routers."),
    69: ("tftp", "medium", "TFTP has no authentication. Disable it unless you need it."),
    80: ("http", "info", "Unencrypted website. Fine for a router page, but prefer HTTPS."),
    110: ("pop3", "medium", "Plain-text email retrieval. Use POP3S (995) instead."),
    111: ("rpcbind", "medium", "Can expose internal services. Close it unless required."),
    123: ("ntp", "info", "Time sync."),
    135: ("msrpc", "medium", "Windows RPC. Should not be reachable from outside your PC."),
    137: ("netbios-ns", "medium", "Legacy Windows name service - often abused for recon."),
    139: ("netbios-ssn", "medium", "Legacy Windows file sharing. Prefer disabling it."),
    143: ("imap", "low", "Email access. Prefer IMAPS (993)."),
    161: ("snmp", "medium", "SNMP with default 'public' community leaks device info."),
    389: ("ldap", "medium", "Directory service. Shouldn't be exposed beyond your servers."),
    443: ("https", "info", "Encrypted website. Expected."),
    445: ("smb", "high", "Windows file sharing - a top ransomware target. Never expose it to the internet."),
    465: ("smtps", "info", "Encrypted mail submission."),
    514: ("syslog", "low", "Log collection."),
    587: ("submission", "info", "Mail submission."),
    631: ("ipp", "low", "Network printing."),
    993: ("imaps", "info", "Encrypted IMAP."),
    995: ("pop3s", "info", "Encrypted POP3."),
    1433: ("mssql", "medium", "SQL Server. Databases should not be reachable from untrusted networks."),
    1521: ("oracle", "medium", "Oracle database. Restrict to application servers."),
    1723: ("pptp", "medium", "Old VPN protocol with known weaknesses."),
    1883: ("mqtt", "medium", "IoT messaging, often unauthenticated."),
    2049: ("nfs", "medium", "Network file sharing. Restrict it."),
    3306: ("mysql", "medium", "MySQL database. Restrict to application servers."),
    3389: ("rdp", "high", "Remote Desktop - heavily attacked. Use a VPN and strong passwords/MFA."),
    5060: ("sip", "low", "VoIP signalling."),
    5432: ("postgresql", "medium", "PostgreSQL database. Restrict access."),
    5555: ("adb/freeciv", "medium", "Often Android Debug Bridge - grants device control."),
    5900: ("vnc", "high", "Remote screen control, often weakly protected. Use a VPN."),
    5985: ("winrm", "medium", "Windows remote management."),
    6379: ("redis", "high", "Redis often runs with no password. Never expose it."),
    8000: ("http-alt", "info", "Alternate web port (dev servers, admin panels)."),
    8080: ("http-proxy", "info", "Alternate web port or proxy."),
    8443: ("https-alt", "info", "Alternate HTTPS port."),
    9200: ("elasticsearch", "high", "Elasticsearch has leaked millions of records when exposed."),
    27017: ("mongodb", "high", "MongoDB is frequently found open without a password."),
}
QUICK_PORTS = sorted(PORTS)


def classify_port(port, banner=""):
    """Return {service, risk, advice} for an open port."""
    service, risk, advice = PORTS.get(port, (None, "unknown", ""))
    b = (banner or "").lower()
    if b.startswith("ssh-"):
        service = "ssh"
    elif b.startswith("http/") or "server:" in b:
        service = service if service and service.startswith("http") else "http"
    elif b.startswith("220") and "ftp" in b:
        service = "ftp"
    elif b.startswith("220") and "smtp" in b:
        service = "smtp"
    if service is None:
        try:
            import socket
            service = socket.getservbyport(port, "tcp")
        except OSError:
            service = "unknown"
    if risk == "unknown" and not advice:
        advice = "Not a well-known port. Make sure you know which program opened it."
    return {"service": service, "risk": risk, "advice": advice}


def rule_info(rule_id):
    return RULES.get(rule_id, {"name": rule_id, "severity": "low", "mitre": "-",
                               "title": rule_id, "meaning": "", "action": ""})
