# Checklist before clicking Public

- [x] No production SQLite databases, source-of-truth threat feed records, exported incident logs or GeoIP bulk dumps are bundled.
- [x] No real server IP, Tailscale hostname, passwords, SSH keys, Telegram tokens or auth files included in the supplied package.
- [x] Source still binds dashboard to `127.0.0.1` by default, behind separate reverse-proxy auth.
- [x] Public GitHub instructions use PUBLIC visibility.
- [ ] Confirm you have rights to publicly distribute *all* code and any embedded coastline/world shapes before publishing.
- [ ] Decide license strategy: source-available (default), commercial license, or open source.
- [ ] Confirm no secrets or customer data are added when uploading your own files.
- [ ] Enable GitHub 2FA, secret scanning, vulnerability reporting and branch protection where available.

This is a prototype dashboard, not a completed SIEM/EDR or certified enterprise security product.
