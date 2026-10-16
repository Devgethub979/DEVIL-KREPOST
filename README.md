# DEVIL Cyber Intelligence — Command Center

**Local-first threat-intelligence dashboard · GeoINT Atlas · lightweight Linux observability**
**Current release: v3.1 · Python 3.10+ · SQLite · HTML/CSS/JavaScript · no pip dependencies**

> [!IMPORTANT]
> This project is a **defensive intelligence and observability prototype**, not a validated SIEM, EDR, real-time attack feed, or multi-tenant commercial service. It does not intercept packet contents or block traffic. Feed records and approximate GeoIP locations do **not** prove attacks on your network.

## Highlights

| Workspace | What it actually does |
| --- | --- |
| Command Overview | Counts locally stored indicators, database health, collection dates, recorded correlations |
| Live System Pulse | Linux `/proc` CPU, RAM, TCP and network-interface telemetry, updated when dashboard is visited |
| Threat Intelligence | Search, exact lookup, paginated records, CSV export from SQLite |
| Threat Atlas v3.1 | Offline country rankings, world map, IP points / heatmap / clusters, zoom and analyst drill-down |
| Detection Timeline | Read-only view of stored exact-match correlation events |
| Event Review Desk | Read-only review UI; does **not** create persistent incident tickets |
| Operations / System Health | Pipeline and integration diagnostics, explicit coverage limitations |

**Privacy by design:** The app listens on `127.0.0.1:8765` only. It contains no user accounts or public TLS server. An **external authenticated reverse proxy** is required for remote use.

## Repository layout

```text
.
├── dashboard.py                 # Full v3.1 UI + JSON API (original single-file release)
├── tools/
│   ├── geo_enrich.py             # Optional offline GeoIP CSV generator for local feed IPs
│   └── make_demo_data.py         # Creates synthetic/demo SQLite data in an isolated folder
├── tests/                       # Standard-library unittest suite, no production DB
├── scripts/
│   ├── deploy.sh                 # Opt-in backup + health-check + rollback deployment
│   └── verify.sh                 # Local service health check
├── deploy/
│   ├── devil-intel-dashboard.service.example
│   └── nginx-site.conf.example
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DEPLOYMENT.md
│   ├── GEOIP.md
│   ├── API.md
│   ├── OPERATIONS.md
│   ├── INTEGRATIONS.md
│   ├── GITHUB_PUBLISH.md
│   ├── SECURITY_CHECKLIST.md
│   └── README_AR.md
├── .github/workflows/test.yml
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
└── .gitignore                  # Excludes DBs, secrets, server backups and GeoIP archives
```

## Quick start — offline demo

Run locally on Linux or any OS supported by Python (live system metrics require Linux):

```bash
python3 -m unittest discover -s tests -v
python3 tools/make_demo_data.py --output /tmp/devil-demo-data
DEVIL_DATA_DIR=/tmp/devil-demo-data DEVIL_PORT=8765 python3 dashboard.py
```

Visit `http://127.0.0.1:8765/` **on the same machine**. Demo records are **synthetic** (documentation-only IP ranges), not real cyber incidents. For production, see [Deployment](docs/DEPLOYMENT.md).

## Integrate existing installation

The repository preserves compatibility with the pre-existing `/opt/devil-intel/data/intelligence.db`, `events.db` and `geo_enrichment.csv`. It is intended to replace only `dashboard.py` on a controlled deployment. Do not remove existing collectors, correlators, alerting, Nginx, Tailscale, or VPN services.

**Important scope note:** The operator's running VPS also has `collector.py`, `risk_engine.py`, `correlator.py`, a Telegram notifier, cron and OpenWrt-side scripts. Their full production source code was **not supplied** with this repository build, so those scripts are **not falsely presented here as included**. Instructions to export, review and add them safely are in [Integrations](docs/INTEGRATIONS.md).

## Threat Atlas and data provenance

The dashboard accepts `data/geo_enrichment.csv` with `ip,latitude,longitude,country`. `tools/geo_enrich.py` can build it offline from an authorized DB-IP City Lite CSV/GZ and IPs in your local database (no remote GeoIP calls). The source dataset is **not redistributed** in this repository. Credit the provider according to its license; see [GeoIP](docs/GEOIP.md).

The release embeds an offline illustrative world-outline backdrop inherited from v3.1, with coastline attribution documented. Atlas aggregates examine all valid exact matches; map payloads sample at most 1,000 IPs to reduce browser load. GeoIP is approximate and may refer to hosting, VPN or anycast locations.

## Security and commercial readiness

- The backend has **no built-in authentication**. Deploy only on loopback behind a properly configured HTTPS reverse proxy with access control, MFA where appropriate, and rate limiting; see [Security checklist](docs/SECURITY_CHECKLIST.md).
- Avoid publishing client data, `.db` files, raw events, public infrastructure addresses, API keys or operational backups.
- No audit trail, persistent case management, RBAC, tenant isolation or enterprise-scale event pipeline is provided yet.
- Public repository visibility is supported for a **source-available prototype**, but verify you have publishing rights for all included source and artwork, and do not publish any production data or infrastructure secrets.
- **Licensing:** No open-source license is granted by default. Public viewing is not permission to reuse or resell the software; see [LICENSE_POLICY.md](LICENSE_POLICY.md) and decide whether to add commercial or open-source terms.

## Status and tests

Source imported from the operator-provided DEVIL v3.1 release, with documentation and helper scripts added for GitHub. Run `python3 -m unittest discover -s tests -v` and verify locally before deployment. CI runs against **synthetic data only**. The GitHub project itself is not connected to a live VPS.

## Roadmap

- [ ] Import and separately review original collector/correlator/alerting scripts
- [ ] Separate backend, frontend and job workers into maintainable modules
- [ ] Per-user RBAC, optional MFA, robust audit logging and tenant isolation
- [ ] Ingestion connectors, signed feeds, telemetry coverage and retention controls
- [ ] Safe performance testing on constrained VPS before commercial workloads

Publishing guide: [GitHub setup](docs/GITHUB_PUBLISH.md) · Arabic: [README_AR.md](docs/README_AR.md).

For security reports: [SECURITY.md](SECURITY.md).
