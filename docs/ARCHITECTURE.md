# Architecture

```text
                          Internet user
                               |
                      HTTPS access gateway
                     (MFA / Basic Auth / ACL)
                               |
                    Reverse proxy (Nginx)
                        127.0.0.1:8080
                               |
                     DEVIL dashboard.py
                        127.0.0.1:8765
                      /      |        \
           intelligence.db  events.db  geo_enrichment.csv
                     |         |           |
              external IOC   external     offline DB-IP
              collector      correlator   enrichment
                  [the last two are NOT included in this repo]
```

**Untrusted clients must never reach 8765 directly**; security relies on the reverse proxy. The app is read-only towards SQLite. `/api/atlas` aggregates exact IP matches from locally produced CSV and database. Data does not certify a compromise. Linux telemetry reads `/proc` from the machine hosting Python, not the router or endpoints.

### Database expectations

`intelligence.db`: table `indicators(kind, value, source, example_url, first_seen, last_seen)`.

`events.db`: optional `detections(ip,source,first_seen,last_seen,observations)` and `pending_alerts` table with `sent_at` if alert statistics are desired. Existing deployment retains ownership of writing these records.

### Performance

- 5-second sampling of Linux `/proc`, retained in a bounded in-process deque.
- GeoIP cache invalidated by CSV and DB modification stamps; CSV size capped at 6 MB, maximum 60,000 rows parsed.
- At most 1,000 map points per response; country totals computed over all available exact matches.
- No packet payload collection, EDR, or background ML processing included.
- On a 1 vCPU / ~1 GB RAM VPS, monitor memory and service availability; test in staging when adding sources.
