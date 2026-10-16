# External components inventory (not present in this source drop)

The running DEVIL deployment had other components, according to its operator's deployment history:

| Existing component | Function | Source in this GitHub archive? |
| --- | --- | --- |
| `/opt/devil-intel/collector.py` | Fetch URLhaus indicators into SQLite | **No — export and review separately** |
| `/opt/devil-intel/risk_engine.py` | Local intel risk report | **No** |
| `/opt/devil-intel/lookup.py` | Local exact indicator lookup | **No** |
| `/opt/devil-intel/correlator.py` | Compare supplied IPs to local intel and record correlations | **No** |
| `/opt/devil-intel/telegram_alert.py` | Telegram notification transport | **No** |
| `/opt/devil-intel/telegram.env` | Production Telegram secrets | **NEVER include** |
| `/root/devil-threat-watch.sh` (router) | Collect router connection samples and forward via SSH | **No** |
| `/etc/cron.d/...`, root crontab, SSH tunnel keys | Deployment-specific automation | **NEVER include production secrets/config verbatim** |
| Nginx/Tailscale/VLESS | Access and networking infrastructure | **Examples only** |

This is **not a replacement for any of these running components**. Only the operator-supplied v3.1 dashboard source was present for direct import. Do not reconstruct or overwrite production collectors from guesses, or add secrets to Git history.

## Safe migration into the repository

1. Export **only source `.py` / `.sh` files** to a local review folder; do not include `.env`, DB, SSH keys or htpasswd.
2. Review each source for hard-coded tokens, chat IDs, external IPs, URLs, credentials or customer identifying values. Replace with environment variables or config templates.
3. Validate scripts against a fresh **synthetic** SQLite database and add tests in `tests/`.
4. Only after review, add the sanitized integration sources as separate commits under `integrations/`.
5. Keep a separate deployment runbook documenting cron jobs and systemd units, without production secrets.

A sensible next milestone is to add the original correlator and URLhaus collector as independently tested modules and add notifications through secret injection in production only.
