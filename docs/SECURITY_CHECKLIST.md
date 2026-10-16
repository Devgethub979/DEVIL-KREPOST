# Pre-release security checklist

- [ ] Repository created **Private**; no secrets or runtime DBs in any commit history.
- [ ] Authentication and authorization enforced **before** Python backend: loopback + reverse proxy + optional MFA.
- [ ] HTTPS enforced end-to-end at the public access gateway; verify `401` without credentials.
- [ ] Rate limit login attempts; be careful with proxy-forwarded addresses (never blindly ban `127.0.0.1`).
- [ ] Dashboard service runs with least permissions feasible and read-only access to data.
- [ ] API endpoints contain no customer-identifying information; review public diagnostic details.
- [ ] Offline GeoIP dataset licensed for intended use, attribution visible and current.
- [ ] No public write endpoints, network blocking logic or direct production packet capture.
- [ ] Review bundled coastline/third-party data attribution before distribution.
- [ ] Backups and retention policy exist outside GitHub; incident-response plan tested.
- [ ] For commercial multi-tenant use: implement per-user/tenant access control, MFA, audit trails, tenant data separation and independent security testing.

## Baseline confidentiality

`.gitignore` is a **preventive guard, not an audit**. It cannot undo a previously committed secret. Before the first push, review `git status`, `git diff --cached`, and scan tracked files for API keys, private IPs, chat IDs and domain names. If a secret has ever been committed, rotate it and purge it from history.
