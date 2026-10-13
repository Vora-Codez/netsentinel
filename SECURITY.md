# Security

## Reporting a vulnerability
Please open a private security advisory on GitHub (Security tab → "Report a vulnerability") rather than a public issue. Include steps to reproduce and the affected version.

## Hardening checklist for deployments
1. Put NetSentinel behind HTTPS (see `docs/DEPLOYMENT.md`) and set `NETSENTINEL_SECURE_COOKIES=1`.
2. Set `NETSENTINEL_ALLOWED_HOSTS` to the hostname(s) people use to reach it.
3. Don't expose it directly to the internet. Prefer a VPN, SSH tunnel or an authenticating proxy in front.
4. Create named accounts per person; give most people `viewer` or `analyst`.
5. Back up the data folder (`/data` in Docker). `secret.key` signs sessions: keep it private.
6. Review the Audit log periodically.

## Threat model notes
- The scanner can reach whatever the server can reach. That's why non-admins are limited to private ranges and link-local/metadata addresses are always refused.
- Banners, DNS names and packet contents come from untrusted hosts. They're rendered as text only, never as HTML.
- Detection state and the packet buffer are in memory; the SIEM feed (`logs/alerts.jsonl`) contains live alerts only, never demo data.
- Login throttling is per process and per client address + username; use a reverse proxy rate limit if you expose it more widely.
