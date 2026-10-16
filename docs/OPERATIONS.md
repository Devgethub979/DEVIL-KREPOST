# Running the dashboard

- **Resource-sensitive**: benchmark every new integration on the target VPS before enabling it. The previously observed server was ~1 vCPU/~1 GB RAM; measurements cannot guarantee future performance.
- Observe `systemctl status devil-intel-dashboard` and `journalctl -u devil-intel-dashboard -n 50 --no-pager` for application errors.
- Health endpoint: `http://127.0.0.1:8765/healthz` (local only).
- The UI's CPU/RAM/throughput graphs are samples of **that VPS**, not flow attribution or proof of a DDoS.
- `pending_alerts` and `detections` depend on independently running external collectors/correlators.
- Threat Atlas works only after valid local GeoIP enrichment; absence of positions must not be replaced with fake locations.
- Plan for log rotation, DB backups stored securely outside Git, credential rotation, TLS certificate lifecycle, and legal review of data retention.
