# Security

## Reporting a vulnerability
Please open a private security advisory on GitHub (Security tab → "Report a vulnerability") rather than a public issue. Include steps to reproduce and the affected version.

## Hardening checklist for deployments
1. Put NetSentinel behind HTTPS (see `docs/DEPLOYMENT.md`) and set `NETSENTINEL_SECURE_COOKIES=1`.
2. Set `NETSENTINEL_ALLOWED_HOSTS` to the hostname(s) people use to reach it.
3. Don't expose it directly to the internet. Prefer a VPN, SSH tunnel or an authenticating proxy in front.
4. Create named accounts per person; give most people `viewer` or `analyst`.
5. Turn on two-factor sign-in for every administrator (Users shows who hasn't).
6. Lower the idle sign-out time in Settings if the dashboard is used on shared screens.
7. Back up the data folder (`/data` in Docker). `secret.key` signs sessions: keep it private.
8. Review the Audit log periodically.

## Threat model notes
- The scanner can reach whatever the server can reach. That's why non-admins are limited to private ranges and link-local/metadata addresses are always refused.
- Banners, DNS names and packet contents come from untrusted hosts. They're rendered as text only, never as HTML.
- Detection state and the packet buffer are in memory; the SIEM feed (`logs/alerts.jsonl`) contains live alerts only, never demo data.
- Login throttling is per process: per client address + username (5 tries) and per address across all usernames (20 tries). Use a reverse proxy rate limit if you expose it more widely.

## Account security (v3.1)
- **Passwords:** scrypt, N=2^15, r=8, p=1, 16-byte random salt. Hashes made by 3.0 (N=2^14) are upgraded transparently at the next sign-in. Minimum 12 characters; common passwords, passwords containing the username and "common word + digits" patterns are refused. Admin-issued passwords must be changed at first sign-in.
- **Two-factor:** TOTP per RFC 6238 (SHA-1, 6 digits, 30 s, ±1 step for clock drift). A code's time step is recorded so the same code can't be used twice. Ten 50-bit recovery codes are shown once and stored as SHA-256 hashes; each works once. Turning 2FA off needs the password and a current code. Admins can reset another user's 2FA (audited, signs them out). The TOTP secret itself is stored in the database unencrypted, so protect the data folder.
- **Sessions:** a random 256-bit token lives in the signed cookie; the database keeps only its SHA-256, plus device, address and timestamps. Sessions end after the idle limit (Settings, default 30 minutes; requests marked as background polling don't extend it), after 12 hours regardless, on sign-out, or when revoked by the user or an admin. A new session id is issued at every sign-in (no fixation).
- **Pending sign-in:** after a correct password with 2FA on, the browser has 5 minutes and 5 attempts to enter a code before it must start again.
