"""Plain-English explanations: what each alert means, the MITRE ATT&CK techniques behind them,
a glossary of networking and security terms, and what a port is."""

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
    "syn_flood": {"name": "SYN Flood / Connection Burst", "severity": "high", "mitre": "T1499",
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

# --------------------------------------------------------------------------------------------
# MITRE ATT&CK
# --------------------------------------------------------------------------------------------
ATTACK_URL = "https://attack.mitre.org/"

ATTACK_INTRO = [
    "MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a free, public knowledge base of how "
    "real attackers behave, built from reports of real intrusions. It is maintained by MITRE, a US not-for-profit, "
    "and security teams around the world use it as a shared vocabulary.",
    "It is organised like a map. Tactics are the attacker's goals at each stage of an attack, the \"why\". "
    "Techniques are the ways they reach those goals, the \"how\". Many techniques are split further into "
    "sub-techniques for specific methods.",
    "Every technique has an ID. T1046 is a technique; T1557.002 is sub-technique 002 of T1557. Tactics have IDs "
    "starting with TA, such as TA0007 for Discovery. Each technique's page on attack.mitre.org lists real attacker "
    "groups that used it, ways to detect it, and mitigations.",
]
ATTACK_HOW_TO_USE = [
    ("Triage faster", "An ID tells you instantly what kind of behaviour you're looking at and where it sits in an attack, so you know what usually comes before and after it."),
    ("Speak a common language", "Writing 'T1046 seen from 192.168.1.40' in a report means the same thing to every analyst, tool and vendor."),
    ("Find your blind spots", "Comparing the techniques your tools can see with the full matrix shows what you're not watching yet."),
    ("Plan defences", "Each technique lists mitigations, such as network segmentation or egress filtering, that make it harder."),
]
ATTACK_IN_NETSENTINEL = (
    "When a detection rule matches behaviour described by an ATT&CK technique, the alert carries that technique's ID. "
    "Click the ID on any alert to read about it here, or open the official page. A match means the network "
    "traffic looks like the technique, not that an attack is proven: always check the context.")

# The 14 tactics of the Enterprise matrix, in attack order.
TACTICS = [
    ("TA0043", "Reconnaissance", "Gathering information to plan an attack, before getting in."),
    ("TA0042", "Resource Development", "Setting up servers, accounts and tools to use in the attack."),
    ("TA0001", "Initial Access", "Getting a first foothold, for example phishing or exploiting a public service."),
    ("TA0002", "Execution", "Running the attacker's code on a system."),
    ("TA0003", "Persistence", "Keeping access through restarts and password changes."),
    ("TA0004", "Privilege Escalation", "Gaining higher permissions, such as administrator."),
    ("TA0005", "Defense Evasion", "Avoiding detection by security tools."),
    ("TA0006", "Credential Access", "Stealing passwords, keys and session tokens."),
    ("TA0007", "Discovery", "Learning about the network and its systems once inside."),
    ("TA0008", "Lateral Movement", "Moving from one compromised machine to others."),
    ("TA0009", "Collection", "Gathering the data the attacker is after."),
    ("TA0011", "Command and Control", "Talking to compromised systems to control them remotely."),
    ("TA0010", "Exfiltration", "Getting stolen data out of the network."),
    ("TA0040", "Impact", "Disrupting, destroying or holding systems and data hostage."),
]

TECHNIQUES = {
    "T1046": {"name": "Network Service Discovery", "tactics": ["Discovery"],
        "summary": "Attackers list the services running on other machines, often with port scans, to find software they can exploit or log in to.",
        "looks_like": "One device knocking on many ports of another, or on the same port across many devices, in a short time.",
        "defend": ["Close or firewall services that don't need to be reachable.",
                   "Separate the network into segments so one device can't reach everything.",
                   "Know which devices legitimately scan (inventory tools) so real scans stand out."],
        "rules": ["port_scan", "sweep"]},
    "T1571": {"name": "Non-Standard Port", "tactics": ["Command and Control"],
        "summary": "Malware talks to its operator over an unusual port, either to slip past filters that only watch common ports or because a hacking tool uses that port by default.",
        "looks_like": "Connections to ports that ordinary software rarely uses, such as 4444 (Metasploit's default) or 31337.",
        "defend": ["Block outbound traffic except the ports your network actually needs (egress filtering).",
                   "Send web traffic through a proxy so unusual connections are visible.",
                   "Investigate any program that opens connections on unexpected ports."],
        "rules": ["malicious_port"]},
    "T1071": {"name": "Application Layer Protocol", "tactics": ["Command and Control"],
        "summary": "Malware hides its check-ins inside everyday protocols such as web (HTTP/HTTPS) or DNS, so the traffic blends in with normal browsing.",
        "looks_like": "A device contacting the same outside address at very regular intervals, like a timer, even when nobody is using it.",
        "defend": ["Know what normal outbound traffic looks like and question unfamiliar destinations.",
                   "Use DNS and web filtering that blocks known-bad domains.",
                   "Investigate machines that 'phone home' on a schedule you can't explain."],
        "rules": ["beaconing"], "subs": [("T1071.001", "Web Protocols"), ("T1071.004", "DNS")]},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactics": ["Exfiltration"],
        "summary": "Attackers send stolen data out over the same connection they already use to control the compromised machine.",
        "looks_like": "A device on your network uploading an unusually large amount of data to one outside address.",
        "defend": ["Limit which devices can reach the internet and how much they can send.",
                   "Watch for large uploads to unfamiliar destinations.",
                   "Encrypt and restrict access to sensitive data so stolen copies are less useful."],
        "rules": ["exfil"]},
    "T1499": {"name": "Endpoint Denial of Service", "tactics": ["Impact"],
        "summary": "Attackers overwhelm a server so it can't serve real users. A SYN flood sends huge numbers of half-opened connections until the target's connection table is full (sub-technique T1499.001, OS Exhaustion Flood).",
        "looks_like": "One source sending hundreds of connection requests to one device within seconds.",
        "defend": ["Turn on SYN cookies and connection rate limits on servers and firewalls.",
                   "Use your provider's DDoS protection for internet-facing services.",
                   "If the source is inside your network, check that device for malware."],
        "rules": ["syn_flood"], "subs": [("T1499.001", "OS Exhaustion Flood")]},
    "T1498": {"name": "Network Denial of Service", "tactics": ["Impact"],
        "summary": "A related technique: flooding a network link with so much traffic that legitimate traffic can't get through. Alerts made by NetSentinel 3.0 used this ID for SYN floods; 3.1 uses the more precise T1499.",
        "looks_like": "Very high traffic volume aimed at one network or device, often from many sources at once.",
        "defend": ["Ask your internet provider about upstream filtering.", "Use a DDoS protection service for public sites."],
        "rules": []},
    "T1557": {"name": "Adversary-in-the-Middle", "tactics": ["Credential Access", "Collection"],
        "summary": "An attacker positions their device between two others so traffic passes through it, letting them read or change it, for example to steal passwords. On a local network the classic method is ARP cache poisoning (T1557.002).",
        "looks_like": "An IP address, often the router's, suddenly answering from a different hardware (MAC) address.",
        "defend": ["Use encrypted protocols (HTTPS, SSH) so intercepted traffic can't be read.",
                   "Enable Dynamic ARP Inspection on managed switches.",
                   "Set static ARP entries for critical devices like the router."],
        "rules": ["arp_spoof"], "subs": [("T1557.002", "ARP Cache Poisoning")]},
    "T1040": {"name": "Network Sniffing", "tactics": ["Credential Access", "Discovery"],
        "summary": "Attackers capture traffic on a network to collect passwords and other information sent without encryption.",
        "looks_like": "Hard to see from the network itself. What NetSentinel can show is the risk: services that send passwords in plain text, which sniffing would expose.",
        "defend": ["Replace Telnet, FTP, POP3 and IMAP with their encrypted versions.",
                   "Use switched networks and WPA2/WPA3 Wi-Fi encryption."],
        "rules": [], "related_rule": "cleartext"},
}


def technique_url(tid):
    return ATTACK_URL + "techniques/" + str(tid).replace(".", "/") + "/"


def rule_trigger(rule_id, s):
    """What exactly makes a rule fire, using the live settings."""
    t = {
        "port_scan": f"One device tries {s['port_scan_threshold']} or more different ports on another device within {s['port_scan_window']} seconds.",
        "sweep": f"One device contacts the same port on {s['sweep_threshold']} or more devices within {s['sweep_window']} seconds "
                 f"({s['sweep_threshold_web']} for busy web and DNS ports).",
        "malicious_port": f"Any new connection to one of the {len(s['malicious_ports'])} suspicious ports listed in Settings.",
        "blacklist": f"Any traffic to or from one of the {len(s['blacklist'])} addresses on your blocked list.",
        "beaconing": f"{s['beacon_min_hits']} connections to the same outside address and port, 2 seconds to 15 minutes apart, "
                     f"with every gap within {s['beacon_jitter_pct']}% of the average. DNS and time-sync ports are ignored.",
        "exfil": f"A private device sends {s['exfil_mb']} MB or more to one public address within {s['exfil_window']} seconds.",
        "syn_flood": f"{s['syn_flood_threshold']} or more connection requests from one device to another within 5 seconds.",
        "cleartext": "A device sends data over Telnet, FTP, POP3 or IMAP." + ("" if s["cleartext_alerts"] else " (Turned off in Settings.)"),
        "arp_spoof": "An IP address starts answering from a different hardware (MAC) address than before.",
        "new_device": "A new IP and hardware address pair appears in ARP traffic, after the first 30 seconds of capture."
                      + ("" if s["new_device_alerts"] else " (Turned off in Settings.)"),
    }
    return t.get(rule_id, "")


RULE_METHOD = {
    "port_scan": "Sliding-window counter of distinct ports per (source, target) pair.",
    "sweep": "Sliding-window counter of distinct targets per (source, port) pair.",
    "malicious_port": "Lookup of the destination port in your suspicious-ports list.",
    "blacklist": "Lookup of both addresses in your blocked list.",
    "beaconing": "The last few connection times per (source, destination, port); fires when the gaps are nearly equal.",
    "exfil": "Running total of bytes per (inside device, outside address) over a sliding window.",
    "syn_flood": "Running count of connection requests per (source, target) over 5 seconds.",
    "cleartext": "Checks data-carrying TCP packets (PSH flag) for plain-text service ports.",
    "arp_spoof": "Table of IP-to-MAC pairs learned from ARP; fires when a known IP changes MAC.",
    "new_device": "Same table; fires when an IP is seen for the first time.",
}

GLOSSARY_CATEGORIES = ["Networking basics", "Attacks and threats", "Detection and response", "Tools", "Account and web security"]
GLOSSARY = [
    # Networking basics
    ("IP address", "Networking basics", "A device's address on a network, like 192.168.1.20. Every packet carries a source and destination IP."),
    ("Private vs public address", "Networking basics", "Private ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x) are used inside homes and offices and can't be reached directly from the internet. Everything else is public. NetSentinel uses this to tell inside devices from outside ones."),
    ("Port", "Networking basics", "A numbered 'door' on a device, from 1 to 65535. Each service listens on its own port: web on 443, SSH on 22, Remote Desktop on 3389."),
    ("Open / closed / filtered", "Networking basics", "Open: a service answered. Closed: the device answered that nothing is listening. Filtered: no answer at all, usually because a firewall dropped the probe."),
    ("TCP", "Networking basics", "The protocol most services use. It sets up a connection first and guarantees data arrives in order, which is why scanners can tell an open port from a closed one."),
    ("UDP", "Networking basics", "A lighter protocol that sends packets without setting up a connection. Used by DNS, video calls and games. Harder to scan reliably because closed ports often stay silent."),
    ("Three-way handshake", "Networking basics", "How TCP connections start: SYN ('can we talk?'), SYN-ACK ('yes'), ACK ('great'). A SYN with no follow-up is typical of scans and floods."),
    ("TCP flags", "Networking basics", "Single-letter markers on TCP packets: S (SYN, start), A (ACK, acknowledge), P (PSH, carrying data), F (FIN, finish), R (RST, reset). NetSentinel reads them to count new connections and to tell real data from probes."),
    ("Packet", "Networking basics", "One small chunk of network traffic, with headers (addresses, ports, flags) and usually a payload of data."),
    ("Conversation (flow)", "Networking basics", "All the packets between one pair of devices on one port and protocol, grouped together. The Live traffic page's Conversations tab shows them."),
    ("CIDR notation", "Networking basics", "A compact way to write a range of addresses. 192.168.1.0/24 means the 256 addresses from 192.168.1.0 to 192.168.1.255; a smaller number after the slash means a bigger range."),
    ("MAC address", "Networking basics", "A hardware address burned into each network card, like a4:2b:b0:11:22:33. Used to deliver packets on the local network."),
    ("ARP", "Networking basics", "Address Resolution Protocol: how a device asks 'who has 192.168.1.1?' and learns the MAC address to send to. It has no authentication, which is what ARP spoofing abuses."),
    ("DNS", "Networking basics", "The internet's phone book: it turns names like example.com into IP addresses. Runs on port 53."),
    ("ICMP", "Networking basics", "Control messages such as 'ping' and 'destination unreachable'."),
    ("TLS / HTTPS", "Networking basics", "Encryption for traffic. HTTPS is web traffic inside TLS. Someone watching the network sees who you talk to, but not what you say."),
    ("Banner", "Networking basics", "A greeting some services send when you connect, often naming the software and version, for example 'SSH-2.0-OpenSSH_9.6'. The scanner shows banners because old versions may have known flaws."),
    # Attacks and threats
    ("Port scan", "Attacks and threats", "Trying many ports on a device to see which are open. Attackers use it to find a way in; administrators use it to audit their own machines."),
    ("Network sweep", "Attacks and threats", "Checking the same port across many devices, for example 'which machines have Remote Desktop open?'. Typical of worms and attackers hunting for one weakness."),
    ("Beaconing", "Attacks and threats", "Software checking in with a remote server at regular intervals. Normal for updaters; suspicious for malware waiting for instructions."),
    ("C2 (command and control)", "Attacks and threats", "The server an attacker uses to send instructions to infected machines and receive stolen data."),
    ("Exfiltration", "Attacks and threats", "Moving stolen data out of a network."),
    ("Denial of service (DoS)", "Attacks and threats", "Overloading a system so real users can't use it. A distributed attack (DDoS) uses many sources at once."),
    ("SYN flood", "Attacks and threats", "A denial-of-service attack that sends floods of SYN packets and never finishes the handshake, filling the target's table of half-open connections."),
    ("ARP spoofing", "Attacks and threats", "Sending fake ARP replies so other devices send their traffic to the attacker's machine, which then sits in the middle of the conversation."),
    ("Man-in-the-middle", "Attacks and threats", "Any attack where the attacker secretly relays traffic between two parties so they can read or change it. ATT&CK calls it Adversary-in-the-Middle (T1557)."),
    ("Cleartext protocol", "Attacks and threats", "A service that sends data, including passwords, without encryption: Telnet, FTP, POP3, IMAP. Anyone on the same network path can read it."),
    ("Backdoor", "Attacks and threats", "A hidden way into a system that skips normal sign-in. Many old backdoors listen on well-known ports, which is why NetSentinel keeps a suspicious-ports list."),
    ("Malware", "Attacks and threats", "Software made to harm or take control of a device: viruses, worms, trojans, ransomware and spyware."),
    ("Brute force", "Attacks and threats", "Guessing a password by trying many possibilities. Slow password hashing and lockouts make it impractical."),
    ("Password spraying", "Attacks and threats", "Trying one or two common passwords against many accounts to avoid per-account lockouts. NetSentinel also locks out a single address that fails too often across accounts."),
    ("Credential stuffing", "Attacks and threats", "Trying usernames and passwords leaked from another website, betting people reuse them. Two-factor sign-in stops it."),
    # Detection and response
    ("MITRE ATT&CK", "Detection and response", "A public catalogue of attacker tactics and techniques. IDs like T1046 let you look up exactly what a behaviour is. See the MITRE ATT&CK tab."),
    ("TTPs", "Detection and response", "Tactics, Techniques and Procedures: how an attacker operates. ATT&CK is a catalogue of TTPs."),
    ("IDS / IPS", "Detection and response", "An Intrusion Detection System watches traffic and raises alerts; an Intrusion Prevention System can also block it. NetSentinel is a small IDS: it alerts but doesn't block."),
    ("SIEM", "Detection and response", "Security Information and Event Management: a central system that collects logs and alerts from many tools. NetSentinel writes live alerts to logs/alerts.jsonl so a SIEM can read them."),
    ("IOC (indicator of compromise)", "Detection and response", "A clue that a system may be compromised, such as a known-bad IP address or file hash. The blocked-addresses list is a simple IOC list."),
    ("False positive / false negative", "Detection and response", "A false positive is an alert about something harmless; a false negative is a real attack that raised no alert. Tuning thresholds trades one against the other."),
    ("Threshold", "Detection and response", "The number that has to be reached before a rule fires, such as 15 ports in 10 seconds. Raise it for fewer alerts; lower it to be more sensitive."),
    ("Sliding window", "Detection and response", "Counting only events from the last N seconds, with old events dropping out as time moves on. NetSentinel's rules use sliding windows so each packet costs the same small amount of work."),
    ("Severity", "Detection and response", "How urgent an alert is. High: likely harmful, look now. Medium: suspicious, look soon. Low: worth knowing about."),
    ("Triage", "Detection and response", "Deciding quickly which alerts matter, which are harmless, and what to do first."),
    ("Egress filtering", "Detection and response", "Limiting which outbound connections a network allows. It blocks many command-and-control and exfiltration methods."),
    ("Network segmentation", "Detection and response", "Splitting a network into zones with firewalls between them, so a compromised device can't reach everything."),
    # Tools
    ("Nmap", "Tools", "The best-known free port scanner. NetSentinel's scanner does a simpler TCP connect scan and explains each result in plain words."),
    ("Wireshark", "Tools", "The best-known free packet analyser. NetSentinel's Live traffic page is a lighter, friendlier viewer that adds automatic detection."),
    ("Npcap / libpcap", "Tools", "The packet-capture drivers that let programs read network traffic. Windows needs Npcap installed; Linux and macOS include libpcap."),
    ("Scapy", "Tools", "A Python library for capturing and building packets. NetSentinel uses it for live capture."),
    ("TCP connect scan", "Tools", "Scanning by completing a normal TCP connection to each port. Needs no special permissions, but the target can log it."),
    # Account and web security
    ("Two-factor authentication (2FA)", "Account and web security", "Signing in with something you know (your password) plus something you have (your phone). A stolen password alone isn't enough."),
    ("TOTP", "Account and web security", "Time-based One-Time Password (RFC 6238): your authenticator app and the server both compute a 6-digit code from a shared secret and the current time. Codes change every 30 seconds."),
    ("Recovery codes", "Account and web security", "One-time backup codes for when you lose your phone. Each works once. Store them somewhere safe, offline."),
    ("Password hashing", "Account and web security", "Storing a one-way fingerprint of a password instead of the password. NetSentinel uses scrypt, which is deliberately slow and memory-hungry so stolen hashes are very expensive to crack."),
    ("Salt", "Account and web security", "Random data mixed into each password before hashing, so two people with the same password get different hashes and precomputed tables don't work."),
    ("Session", "Account and web security", "What keeps you signed in between page loads. NetSentinel stores sessions on the server, so you can see and end them from Account, and they end after a period of inactivity."),
    ("CSRF", "Account and web security", "Cross-Site Request Forgery: a malicious site tricking your browser into sending a request to an app you're signed in to. NetSentinel requires a secret per-session token on every change, which other sites can't read."),
    ("XSS", "Account and web security", "Cross-Site Scripting: getting a site to run an attacker's script. NetSentinel escapes every piece of untrusted text and uses a strict Content Security Policy."),
    ("Content Security Policy (CSP)", "Account and web security", "A browser rule set by the server that says which scripts and styles may run. NetSentinel allows only its own files, so injected code is refused."),
    ("SQL injection", "Account and web security", "Smuggling database commands inside user input. NetSentinel only passes input to the database as parameters, never as part of the command text."),
    ("Least privilege", "Account and web security", "Giving each person only the access they need. That's why most people should be viewers or analysts, not administrators."),
]


def learn(settings):
    """Everything the Learn page shows, with rule thresholds filled in from the live settings."""
    covered = sorted({tac for t in TECHNIQUES.values() if t["rules"] for tac in t["tactics"]})
    techniques = [{"id": tid, **{k: v for k, v in t.items()}, "url": technique_url(tid),
                   "subs": [{"id": s, "name": n, "url": technique_url(s)} for s, n in t.get("subs", [])],
                   "rule_names": [RULES[r]["name"] for r in t["rules"]]} for tid, t in TECHNIQUES.items()]
    rules = [{"id": rid, "name": r["name"], "severity": r["severity"], "mitre": r["mitre"], "title": r["title"],
              "meaning": r["meaning"], "action": r["action"], "trigger": rule_trigger(rid, settings),
              "method": RULE_METHOD.get(rid, "")} for rid, r in RULES.items()]
    return {"attack": {"intro": ATTACK_INTRO, "how_to_use": [{"title": a, "text": b} for a, b in ATTACK_HOW_TO_USE],
                       "in_netsentinel": ATTACK_IN_NETSENTINEL, "url": ATTACK_URL,
                       "tactics": [{"id": i, "name": n, "text": d, "covered": n in covered} for i, n, d in TACTICS]},
            "techniques": techniques, "rules": rules, "cooldown": settings["alert_cooldown"],
            "glossary": [{"term": a, "cat": b, "text": c} for a, b, c in GLOSSARY], "categories": GLOSSARY_CATEGORIES}


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
