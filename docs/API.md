# Read-only HTTP API

This API has **no built-in auth**, so it must be reachable only through the authenticated reverse proxy. Its bind address is fixed at `127.0.0.1`; the port is set with `DEVIL_PORT`.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/` | Single-page dashboard HTML |
| GET | `/healthz` | Health and release version |
| GET | `/api/status` | Intelligence counts and local database state |
| GET | `/api/telemetry` | Linux host statistics and recent in-memory samples |
| GET | `/api/atlas` | GeoIP exact matches, country summaries, sampled points; filters `country`, `source`, `q` |
| GET | `/api/atlas/records` | Paginated enriched IPs, with filters and `page` |
| GET | `/api/atlas/ip?ip=...` | Inspect one exact enriched IP |
| GET | `/api/indicators` | Filtered/paginated intel list (`q`, `kind`, `source`, `page`, `limit`) |
| GET | `/api/lookup?value=...` | Exact indicator lookup |
| GET | `/api/events` | Existing correlations, read-only |
| GET | `/api/cases` | Non-persistent analyst preview of correlation rows |
| GET | `/api/system` | Limited backend diagnostics |
| GET | `/api/export.csv` | Bounded, formula-escaped CSV export |

Returned collections are **observations and investigative leads**, not confirmed attacks. Input filters are bounded by the application; any integration should still enforce its own rate limits and authorization.
