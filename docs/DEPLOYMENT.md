# Controlled VPS deployment

**Do not deploy directly from GitHub Actions to the live server.** This project intentionally ships no SSH keys, production host address or automatic deployment credentials.

## Prerequisites

- Ubuntu/Linux VPS with Python 3.10+, systemd and the existing DEVIL data directory.
- Working service `devil-intel-dashboard` executing `/opt/devil-intel/dashboard.py`.
- A reverse proxy that authenticates users, routes to `127.0.0.1:8765`, and offers TLS (e.g. a configured HTTPS gateway).
- Existing `intelligence.db`, optionally `events.db` and `geo_enrichment.csv`, remain **only on the VPS**.
- For real external users, prefer MFA and private network ACLs where possible; Basic Auth by itself is not enterprise-grade.

## Recommended controlled upgrade (run manually on the VPS)

1. Transfer `dashboard.py` from a reviewed release to a temporary path on the VPS, e.g. `/tmp/devil-dashboard-release.py`.
2. Run as an authorized administrator (root required for systemd and `/opt/devil-intel`):

```bash
sudo bash scripts/deploy.sh /tmp/devil-dashboard-release.py
```

The script checks syntax, creates a timestamped backup of the existing dashboard in `/opt/devil-intel/`, restarts **only** the dashboard service, verifies the `/healthz` response and requested version, and restores the backup if validation fails. **It does not restart Nginx, sing-box, Tailscale, Uptime Kuma, or router services.** Review the script before execution. It expects to run on the VPS where DEVIL is already installed.

## Development-only systemd example

See `deploy/devil-intel-dashboard.service.example`. For the production service, preserve the existing tested unit unless performing a separate controlled change. The app binds loopback internally and has **no own login mechanism**.

## Reverse proxy example

See `deploy/nginx-site.conf.example`. It is not applied automatically. The sample listens on `127.0.0.1:8080` and points to an **absolute path outside the repo** for the htpasswd file; use existing secure ownership/permissions. Never commit live password hashes.

## Smoke checks on the VPS

```bash
curl --noproxy '*' -fsS http://127.0.0.1:8765/healthz
curl --noproxy '*' -fsS http://127.0.0.1:8765/api/status
curl --noproxy '*' -fsS http://127.0.0.1:8765/api/atlas
```

Be aware that local backend requests bypass the authenticating reverse proxy: they are safe only from authorized localhost processes. For public access, test through the real HTTPS gateway, **including** unauthorized `401` and authorized `200` behavior.

## Rollback

The deployment script automatically rolls back if its health checks fail. To revert manually, copy the last known-good backup over `dashboard.py` and restart `devil-intel-dashboard` only.
