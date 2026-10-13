# Deployment

## Choose a mode
| Goal | How |
|---|---|
| Try it on your laptop | `python -m netsentinel serve` |
| Always-on dashboard + scanner | `docker compose up -d` |
| Live packet capture sensor (Linux) | add `-f docker-compose.sensor.yml` |

## Environment variables
| Variable | Default | Meaning |
|---|---|---|
| `NETSENTINEL_HOST` / `PORT` | `127.0.0.1` / `8765` | bind address and port |
| `NETSENTINEL_HOME` | `./data` (`/data` in Docker) | database, settings, logs, session key |
| `NETSENTINEL_ALLOWED_HOSTS` | loopback names | comma list of hostnames the server answers to (`*` disables the check) |
| `NETSENTINEL_SECURE_COOKIES` | off | set to `1` over HTTPS (also enables HSTS) |
| `NETSENTINEL_TRUST_PROXY` | off | set to `1` behind a reverse proxy that sets `X-Forwarded-*` |
| `NETSENTINEL_SETUP_CODE` | random | first-run code; printed at start-up if not set |
| `NETSENTINEL_SECRET` | generated | session signing key (otherwise stored in `secret.key`) |
| `NETSENTINEL_AUTOCAPTURE` | off | start live capture on boot |

## HTTPS with Caddy (simplest)
```
netsentinel.example.com {
    reverse_proxy 127.0.0.1:8765
}
```
Then run NetSentinel with `NETSENTINEL_ALLOWED_HOSTS=netsentinel.example.com NETSENTINEL_SECURE_COOKIES=1 NETSENTINEL_TRUST_PROXY=1`.

## HTTPS with nginx
```
location / {
    proxy_pass http://127.0.0.1:8765;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

## Packet capture permissions
- **Linux (bare metal):** run as root, or `sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))`.
- **Docker:** `docker-compose.sensor.yml` uses host networking plus `NET_RAW`/`NET_ADMIN`. Host networking isn't available on Docker Desktop for macOS/Windows.
- **Windows:** install [Npcap](https://npcap.com) and run from an Administrator terminal.
- To see other devices' traffic on a switched network, plug the sensor into a **mirror (SPAN) port**.

## Backups and upgrades
Stop the container, copy the data volume, start again. Databases from earlier NetSentinel versions are upgraded in place on first start.
