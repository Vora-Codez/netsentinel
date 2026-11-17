# Changelog

## 3.1.0
**New look**
- Redesigned interface: navy sidebar with grouped navigation, top bar with live status and user menu, status-coloured overview, stat cards, cleaner tables and dialogs.
- Light and dark themes (follows your system; the toggle remembers your choice).
- New sign-in screen with a password-strength meter.

**Learn section**
- What MITRE ATT&CK is, how to read technique IDs, and the 14 tactics with the ones NetSentinel can see highlighted.
- A page for each technique NetSentinel recognises: what it looks like on the network, how to defend, links to attack.mitre.org.
- Every detection rule's exact trigger, filled in from your current settings.
- Searchable glossary of 60 terms across networking, attacks, detection, tools and account security.
- ATT&CK tags on alerts open the matching Learn page; expanded alerts explain their technique.
- SYN floods now map to T1499 Endpoint Denial of Service (more precise than T1498).

**Account security**
- Two-factor sign-in with any authenticator app (QR code setup) and 10 one-time recovery codes.
- Server-side sessions: see where you're signed in, sign out other devices, idle sign-out (configurable), 12-hour maximum.
- Last sign-in time and address shown when you sign in, plus a recent-activity list on your account page.
- Stronger passwords: 12-character minimum, common-password and username checks, scrypt cost doubled (old hashes upgrade automatically).
- Admin-created and admin-reset passwords must be changed at first sign-in.
- Lockout per address across accounts to stop password spraying.
- Admins see who uses two-factor, can reset someone's two-factor, and can sign a user out.
- Changing your own password keeps you signed in and signs out your other sessions.

**Upgrading:** existing databases are upgraded in place. Everyone is signed out once, because sessions moved to the server.

## 3.0.0
- Self-hosted web app: port scanner, live traffic, detection engine, plain-English alerts, demo mode, roles, audit log, Docker, CI, single-file Windows exe.
