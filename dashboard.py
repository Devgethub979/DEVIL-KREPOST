#!/usr/bin/env python3
"""DEVIL Cyber Command Center v3.1 — local-only, read-only SOC dashboard.

Deployment: replace /opt/devil-intel/dashboard.py, keep Nginx Basic Auth +
Tailscale Funnel as the authenticated/public entrypoint. Do NOT bind publicly.
No pip dependencies; Python >= 3.10. Does not make network requests.
Real measurements only; decorative visuals are explicitly marked illustrative.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import os
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

DATA = Path(os.getenv('DEVIL_DATA_DIR', '/opt/devil-intel/data'))
HOST = '127.0.0.1'  # SECURITY: never expose the unauthenticated Python backend
PORT = int(os.getenv('DEVIL_PORT', '8765'))
VERSION = '3.1.0'
LOG = logging.getLogger('devil.command')
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
MAX_QUERY = 160
PAGE_SIZE = 40
MAX_PAGE = 125  # bound both work and response size


def connect(dbname: str):
    path = DATA / dbname
    if not path.is_file():
        return None
    # sqlite ro mode; no writes, schema changes, or network calls.
    db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=3)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA query_only=ON')
    db.execute('PRAGMA busy_timeout=3000')
    return db


def query(dbname: str, sql: str, params=()):
    db = connect(dbname)
    if db is None:
        return []
    try:
        return [dict(r) for r in db.execute(sql, params).fetchall()]
    except sqlite3.OperationalError as e:
        if any(x in str(e).lower() for x in ('no such table', 'no such column')):
            LOG.warning('Expected optional DB structure not found in %s', dbname)
            return []
        raise
    finally:
        db.close()


def one(dbname: str, sql: str, params=(), field='n', default=0):
    records = query(dbname, sql, params)
    return records[0].get(field, default) if records else default


def table_columns(dbname: str, table: str):
    # Fixed, developer-controlled names; not interpolated from user input.
    return {r['name'] for r in query(dbname, f'PRAGMA table_info({table})')}


def iso_now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def clean(v):
    if v is None:
        return ''
    return str(v)


def days_since(s):
    if not s:
        return None
    try:
        d = datetime.fromisoformat(str(s).replace('Z', '+00:00'))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return max(0, round((datetime.now(timezone.utc) - d).total_seconds() / 3600, 1))
    except (ValueError, TypeError):
        return None


def get_events(limit=50):
    c = table_columns('events.db', 'detections')
    needed = ('ip', 'source', 'first_seen', 'last_seen', 'observations')
    if not set(needed).issubset(c):
        return []
    limit = max(1, min(int(limit), 100))
    return query('events.db',
                 'SELECT ip, source, first_seen, last_seen, observations '
                 'FROM detections ORDER BY last_seen DESC LIMIT ?', (limit,))


def counts():
    by_kind = query('intelligence.db',
                    'SELECT kind, COUNT(*) AS n FROM indicators GROUP BY kind ORDER BY n DESC')
    source_rows = query('intelligence.db',
                        'SELECT source, COUNT(*) AS n FROM indicators GROUP BY source ORDER BY n DESC LIMIT 12')
    total = one('intelligence.db', 'SELECT COUNT(*) AS n FROM indicators')
    days = query('intelligence.db',
                 'SELECT substr(last_seen,1,10) AS day, COUNT(*) AS n FROM indicators '
                 "WHERE last_seen IS NOT NULL AND last_seen <> '' "
                 'GROUP BY substr(last_seen,1,10) ORDER BY day DESC LIMIT 21')
    days.reverse()
    ip_octets = query('intelligence.db',
                      'SELECT substr(value,1,instr(value,".")-1) AS octet, COUNT(*) AS n '
                      'FROM indicators WHERE kind = ? AND instr(value,".") > 0 '
                      'GROUP BY octet ORDER BY n DESC LIMIT 12', ('ip',))
    top_domains = query('intelligence.db',
                        'SELECT value FROM indicators WHERE kind = ? LIMIT 10000', ('domain',))
    suffixes = Counter()
    for row in top_domains:
        domain = clean(row['value']).strip('.').lower()
        if '.' in domain:
            suffixes['.' + domain.rsplit('.', 1)[-1]] += 1
        else:
            suffixes['(other)'] += 1
    kinds = {r['kind']: r['n'] for r in by_kind}
    # These are recorded events, not proof of malicious traffic.
    detection_count = one('events.db', 'SELECT COUNT(*) AS n FROM detections')
    alert_cols = table_columns('events.db', 'pending_alerts')
    if 'sent_at' in alert_cols:
        pending = one('events.db', 'SELECT COUNT(*) AS n FROM pending_alerts WHERE sent_at IS NULL')
        sent = one('events.db', 'SELECT COUNT(*) AS n FROM pending_alerts WHERE sent_at IS NOT NULL')
    else:
        pending = sent = 0
    recent_feed = one('intelligence.db', 'SELECT MAX(last_seen) AS v FROM indicators', field='v', default=None)
    first_feed = one('intelligence.db', 'SELECT MIN(first_seen) AS v FROM indicators', field='v', default=None)
    recent_indicators = query('intelligence.db',
                              'SELECT kind,value,source,first_seen,last_seen '
                              'FROM indicators ORDER BY last_seen DESC LIMIT 10')
    hours = days_since(recent_feed)
    return {
        'version': VERSION, 'timestamp': iso_now(), 'total': total,
        'ip': kinds.get('ip', 0), 'domain': kinds.get('domain', 0),
        'other': max(0, total - kinds.get('ip', 0) - kinds.get('domain', 0)),
        'kinds': by_kind, 'sources': source_rows,
        'detections': detection_count, 'pending': pending, 'sent': sent,
        'last_collection': recent_feed, 'first_collection': first_feed,
        'feed_age_hours': hours, 'collection_days': days,
        'ip_octets': ip_octets,
        'suffixes': [{'suffix': k, 'n': v} for k, v in suffixes.most_common(8)],
        'recent': get_events(12), 'recent_indicators': recent_indicators,
        'health': {
            'intel_db': (DATA / 'intelligence.db').is_file(),
            'events_db': (DATA / 'events.db').is_file(),
            'backend': True,
            'feeds_status': 'NO DATA' if recent_feed is None else
                           'STALE >24H' if hours is not None and hours > 24 else 'DATA PRESENT',
            'ingestion_mode': 'Database snapshots · not live packet inspection',
            'public_ip_geolocation': ('LOCAL GEOIP CSV' if (DATA / 'geo_enrichment.csv').is_file() else 'NOT CONFIGURED'),
            'endpoint_telemetry': 'NOT CONFIGURED',
            'auto_blocking': 'DISABLED',
        },
        'disclaimer': 'Intel entries are investigative leads. Counts are stored records, not live attacks.'
    }


def literal_like(q):
    return '%' + q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'


def search_indicators(q='', kind='', source='', page=1, limit=PAGE_SIZE):
    q = clean(q).strip()[:MAX_QUERY]
    kind = clean(kind).strip()[:36]
    source = clean(source).strip()[:80]
    page = max(1, min(int(page), MAX_PAGE))
    limit = max(1, min(int(limit), 100))
    clauses = []
    params = []
    if q:
        clauses.append("(value LIKE ? ESCAPE '\\' OR source LIKE ? ESCAPE '\\')")
        params.extend((literal_like(q), literal_like(q)))
    if kind:
        clauses.append('kind = ?')
        params.append(kind)
    if source:
        clauses.append('source = ?')
        params.append(source)
    where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
    total = one('intelligence.db', f'SELECT COUNT(*) AS n FROM indicators{where}', tuple(params))
    offset = (page - 1) * limit
    # Exact match first, then the most recently observed record; SQL is parameterized.
    rows = query('intelligence.db',
                 'SELECT kind, value, source, example_url, first_seen, last_seen '
                 f'FROM indicators{where} '
                 'ORDER BY CASE WHEN value = ? THEN 0 ELSE 1 END, last_seen DESC, value ASC '
                 'LIMIT ? OFFSET ?', tuple(params) + (q, limit, offset))
    return {'total': total, 'page': page, 'limit': limit, 'items': rows, 'query': q,
            'filter': {'kind': kind, 'source': source}}


def exact_lookup(indicator):
    indicator = clean(indicator).strip()[:MAX_QUERY]
    if not indicator:
        return {'indicator': '', 'matches': [], 'verdict': 'NO_INPUT'}
    rows = query('intelligence.db',
                 'SELECT kind,value,source,example_url,first_seen,last_seen '
                 'FROM indicators WHERE lower(value) = lower(?) LIMIT 30', (indicator,))
    return {'indicator': indicator, 'matches': rows,
            'verdict': 'INTEL_MATCH' if rows else 'NOT_IN_LOCAL_FEED',
            'note': ('Match is a lead, not proof of compromise.' if rows else
                     'No local match does not imply the target is safe.')}


def diagnostic():
    items = []
    for filename in ('intelligence.db', 'events.db'):
        p = DATA / filename
        items.append({'component': filename, 'available': p.is_file(),
                      'size_bytes': p.stat().st_size if p.is_file() else None})
    return {'timestamp': iso_now(), 'version': VERSION, 'components': items,
            'listen': f'{HOST}:{PORT}', 'auth': 'REQUIRED AT REVERSE PROXY',
            'mode': 'READ_ONLY', 'collector': 'EXTERNAL JOB',
            'not_integrated': ['EDR/endpoint telemetry', 'SIEM ingest', 'RBAC', 'Audit log']}


def export_csv(q, kind, source, limit=1000):
    # An analyst-triggered, bounded export of existing indicators. Prevent CSV formula execution.
    d = search_indicators(q, kind, source, page=1, limit=100)
    # Get up to 1000 rows through fixed, bounded pages.
    items = []
    for pg in range(1, min(10, (min(d['total'], limit) + 99) // 100) + 1):
        items += search_indicators(q, kind, source, page=pg, limit=100)['items']
    output = io.StringIO()
    writer = csv.writer(output)
    fields = ('kind', 'value', 'source', 'first_seen', 'last_seen', 'example_url')
    writer.writerow(fields)
    for item in items:
        safe = []
        for field in fields:
            val = clean(item.get(field))
            # Spreadsheet formula injection protection.
            if val.lstrip().startswith(('=', '+', '-', '@', '\t', '\r')):
                val = "'" + val
            safe.append(val)
        writer.writerow(safe)
    return output.getvalue()


# DEVIL v3 observation functions. Read-only: never capture payloads or change firewall rules.
import threading
import time
import hashlib
import ipaddress
from collections import deque

_METRIC_LOCK = threading.Lock()
_METRIC_HISTORY = deque(maxlen=120)
_METRIC_PREVIOUS = None
_METRIC_LAST = 0.0


def _read_text(path, max_bytes=65536):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read(max_bytes)
    except (OSError, ValueError):
        return ''


def _memory():
    fields = {}
    for line in _read_text('/proc/meminfo').splitlines():
        name, sep, value = line.partition(':')
        if sep:
            try:
                fields[name] = int(value.strip().split()[0]) * 1024
            except (IndexError, ValueError):
                pass
    return fields


def _net_primary():
    # On Linux, the host interface from the default IPv4 route; excludes Docker/Tailscale tunnels.
    for line in _read_text('/proc/net/route').splitlines()[1:]:
        parts = line.split()
        if len(parts) > 3 and parts[1] == '00000000':
            try:
                if int(parts[3], 16) & 1:
                    return parts[0]
            except ValueError:
                pass
    return None


def _net_bytes(interface):
    if not interface:
        return None
    for line in _read_text('/proc/net/dev').splitlines():
        if ':' not in line:
            continue
        key, _, values = line.partition(':')
        if key.strip() == interface:
            parts = values.split()
            if len(parts) >= 16:
                try:
                    return int(parts[0]), int(parts[8])
                except ValueError:
                    return None
    return None


def _cpu_jiffies():
    first = _read_text('/proc/stat', max_bytes=2000).splitlines()
    if not first or not first[0].startswith('cpu '):
        return None
    try:
        nums = [int(x) for x in first[0].split()[1:]]
        total = sum(nums)
        idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
        return total, idle
    except (ValueError, IndexError):
        return None


def _socket_counts():
    counts = {'established': 0, 'listening': 0, 'time_wait': 0}
    # Count the kernel's TCP sockets, not the number of remote attacks or clients.
    for name in ('/proc/net/tcp', '/proc/net/tcp6'):
        for line in _read_text(name, max_bytes=2_000_000).splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            state = parts[3]
            if state == '01':
                counts['established'] += 1
            elif state == '0A':
                counts['listening'] += 1
            elif state == '06':
                counts['time_wait'] += 1
    return counts


def _disk_stats():
    try:
        stat = os.statvfs('/')
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bavail * stat.f_frsize
        return {'total_bytes': total, 'available_bytes': free,
                'used_percent': round(100 * (1 - free / total), 1) if total else None}
    except OSError:
        return {'total_bytes': None, 'available_bytes': None, 'used_percent': None}


def live_metrics():
    """Lightweight VPS host sampling when queried, at most once per 5 seconds."""
    global _METRIC_PREVIOUS, _METRIC_LAST
    now = time.monotonic()
    with _METRIC_LOCK:
        if _METRIC_HISTORY and now - _METRIC_LAST < 5:
            return {'version': VERSION, 'timestamp': iso_now(), 'interval_seconds': 5,
                    'latest': dict(_METRIC_HISTORY[-1]), 'history': list(_METRIC_HISTORY),
                    'source': 'Linux /proc + statvfs · host-level only · no packet capture'}
        cpu = _cpu_jiffies()
        nic = _net_primary()
        network = _net_bytes(nic)
        previous = _METRIC_PREVIOUS
        dt = now - previous['at'] if previous else 0
        cpupct = None
        rx, tx = None, None
        if previous and dt > 0:
            if cpu and previous['cpu']:
                delta_total = cpu[0] - previous['cpu'][0]
                delta_idle = cpu[1] - previous['cpu'][1]
                if delta_total > 0:
                    cpupct = round(max(0, min(100, (1 - delta_idle / delta_total) * 100)), 1)
            if network and previous['network'] and nic == previous['nic']:
                rx = max(0, int((network[0] - previous['network'][0]) / dt))
                tx = max(0, int((network[1] - previous['network'][1]) / dt))
        mem = _memory()
        total = mem.get('MemTotal')
        avail = mem.get('MemAvailable')
        swap_total = mem.get('SwapTotal')
        swap_free = mem.get('SwapFree')
        try:
            uptime = float((_read_text('/proc/uptime').split() or ['0'])[0])
        except ValueError:
            uptime = None
        sample = {'at': iso_now(), 'cpu_percent': cpupct,
                  'ram_percent': round(100 * (1 - avail / total), 1) if total and avail is not None else None,
                  'ram_available_bytes': avail, 'ram_total_bytes': total,
                  'swap_used_bytes': swap_total - swap_free if swap_total is not None and swap_free is not None else None,
                  'swap_total_bytes': swap_total,
                  'rx_bytes_per_sec': rx, 'tx_bytes_per_sec': tx,
                  'network_interface': nic, 'tcp': _socket_counts(),
                  'disk': _disk_stats(), 'uptime_seconds': uptime}
        _METRIC_HISTORY.append(sample)
        _METRIC_PREVIOUS = {'at': now, 'cpu': cpu, 'network': network, 'nic': nic}
        _METRIC_LAST = now
        return {'version': VERSION, 'timestamp': iso_now(), 'interval_seconds': 5,
                'latest': sample, 'history': list(_METRIC_HISTORY),
                'source': 'Linux /proc + statvfs · host-level only · no packet capture'}


def triage_queue():
    """Read-only view of detections; IDs are display-only and NOT stored cases."""
    rows = get_events(100)
    items = []
    for row in rows:
        ip = str(row.get('ip') or '')
        source = str(row.get('source') or '')
        try:
            observed = max(0, int(row.get('observations') or 0))
        except (ValueError, TypeError):
            observed = 0
        identity = hashlib.sha256((ip + '\0' + source).encode()).hexdigest()[:10].upper()
        items.append({'id': 'EV-' + identity, 'ip': ip, 'source': source,
                      'first_seen': row.get('first_seen'), 'last_seen': row.get('last_seen'),
                      'observations': observed,
                      'activity': 'REPEATED MATCH' if observed >= 2 else 'SINGLE MATCH',
                      'status': 'NOT REVIEWED',
                      'note': 'Heuristic based on observation count, not validated severity.'})
    return {'timestamp': iso_now(), 'total': one('events.db', 'SELECT COUNT(*) AS n FROM detections'),
            'items': items, 'read_only': True,
            'disclaimer': 'These are correlation rows, not confirmed security incidents or persisted case tickets.'}


# v3.1 GeoINT: all exact-matched local CSV records, bounded output and cached read-only aggregation.
_GEO_LOCK = threading.Lock()
_GEO_CACHE = {'key': None, 'records': (), 'sources': (), 'countries': ()}
_GEO_ATTRIBUTION = 'Geolocation: DB-IP City Lite (October 2026), CC BY 4.0 · https://db-ip.com/db/lite.php'


def _geo_inventory():
    path = DATA / 'geo_enrichment.csv'
    db_path = DATA / 'intelligence.db'
    try:
        gs, ds = path.stat(), db_path.stat()
        fingerprint = (gs.st_mtime_ns, gs.st_size, ds.st_mtime_ns, ds.st_size)
    except OSError:
        return {'enabled': False, 'records': (), 'sources': (), 'countries': (),
                'reason': 'Missing local GeoIP CSV or threat database.'}
    if gs.st_size > 6_000_000:
        return {'enabled': False, 'records': (), 'sources': (), 'countries': (),
                'reason': 'GeoIP CSV exceeds safe 6 MB file limit.'}
    with _GEO_LOCK:
        if _GEO_CACHE['key'] == fingerprint:
            return _GEO_CACHE['data']
        entries = {}
        try:
            with path.open('r', encoding='utf-8-sig', newline='') as stream:
                for idx, row in enumerate(csv.DictReader(stream)):
                    if idx >= 60000:
                        break
                    value = str(row.get('ip') or '').strip()
                    try:
                        ip = ipaddress.ip_address(value)
                        if not ip.is_global:
                            continue
                        latitude = float(row.get('latitude'))
                        longitude = float(row.get('longitude'))
                        if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
                            continue
                    except (ValueError, TypeError):
                        continue
                    country = str(row.get('country') or 'ZZ').upper().strip()[:2]
                    if len(country) != 2 or not country.isalpha() or country == 'ZZ':
                        country = 'UN'
                    entries[value] = {'ip': value, 'lat': round(latitude, 4),
                                      'lon': round(longitude, 4), 'country': country}
        except (OSError, UnicodeError, csv.Error) as exc:
            LOG.warning('Geo enrichment unreadable: %s', type(exc).__name__)
            return {'enabled': False, 'records': (), 'sources': (), 'countries': (),
                    'reason': 'Invalid GeoIP enrichment file.'}
        found = {}
        ips = sorted(entries)
        for offset in range(0, len(ips), 350):
            batch = ips[offset:offset + 350]
            placeholders = ','.join('?' for _ in batch)
            rows = query('intelligence.db',
                         'SELECT value, source FROM indicators WHERE kind = ? AND value IN (' + placeholders + ')',
                         ('ip', *batch))
            for row in rows:
                found.setdefault(row['value'], set()).add(str(row.get('source') or 'UNKNOWN')[:80])
        matches = []
        for ip in ips:
            if ip in found:
                item = entries[ip].copy()
                item['sources'] = sorted(found[ip])
                matches.append(item)
        by_country = Counter(item['country'] for item in matches)
        by_source = Counter(src for item in matches for src in item['sources'])
        result = {'enabled': True, 'records': tuple(matches),
                  'countries': tuple({'code': c, 'count': n} for c, n in by_country.most_common()),
                  'sources': tuple({'name': s, 'count': n} for s, n in by_source.most_common()),
                  'reason': ''}
        _GEO_CACHE.update(key=fingerprint, data=result)
        LOG.info('DEVIL GEOINT cache ready: %d exact IP matches from local CSV', len(matches))
        return result


def _geo_filtered(country='', source='', q=''):
    info = _geo_inventory()
    country = str(country or '').upper().strip()[:2]
    source = str(source or '').strip()[:80]
    q = str(q or '').strip()[:90]
    rows = info['records']
    if country and country != 'ALL':
        rows = (r for r in rows if r['country'] == country)
    if source and source != 'ALL':
        rows = (r for r in rows if source in r['sources'])
    if q:
        rows = (r for r in rows if q.lower() in r['ip'].lower())
    return info, list(rows)


def _geo_sample(items, maximum=1000):
    """Stable evenly distributed sample; aggregation always uses all matching rows."""
    if len(items) <= maximum:
        return items
    # Sorted by a stable deterministic digest to avoid input-order and country bias.
    return sorted(items, key=lambda r: hashlib.blake2s(r['ip'].encode(), digest_size=8).digest())[:maximum]


def geo_atlas(country='', source='', q=''):
    info, matches = _geo_filtered(country, source, q)
    if not info['enabled']:
        return {'enabled': False, 'total_geocoded': 0, 'total_filtered': 0,
                'points': [], 'countries': [], 'sources': [], 'country_count': 0,
                'mode': 'NO GEO DATASET', 'note': info['reason'], 'attribution': _GEO_ATTRIBUTION,
                'display_limit': 1000, 'truncated': False}
    sample = _geo_sample(matches)
    return {'enabled': True, 'total_geocoded': len(info['records']),
            'total_filtered': len(matches), 'points': sample,
            'countries': list(info['countries']), 'sources': list(info['sources']),
            'country_count': len(info['countries']), 'truncated': len(sample) < len(matches),
            'display_limit': 1000, 'mode': 'OFFLINE GEOINT · EXACT IOC MATCHES',
            'note': 'Approximate IP registration/hosting geolocation; not attack origins. Map points are sampled for performance.',
            'attribution': _GEO_ATTRIBUTION, 'sample_strategy': 'stable uniform IP sampling'}


def geo_records(country='', source='', q='', page=1):
    info, matched = _geo_filtered(country, source, q)
    page = max(1, min(int(page), 5000))
    limit = 25
    offset = (page - 1) * limit
    return {'total': len(matched), 'page': page, 'limit': limit,
            'items': matched[offset:offset + limit], 'enabled': info['enabled']}


def geo_inspect(ip=''):
    value = str(ip or '').strip()[:64]
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return {'found': False, 'error': 'Invalid IP address'}
    info = _geo_inventory()
    record = next((r for r in info['records'] if r['ip'] == value), None)
    if not record:
        return {'found': False, 'ip': value,
                'note': 'No exact locally enriched IOC for this address.'}
    return {'found': True, 'record': record, 'intelligence': exact_lookup(value),
            'note': 'Geographic registration does not establish attack origin or malicious intent.'}


# Standalone HTML; no CDN, tracking scripts, external fonts, or API keys.
HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#070b12">
<title>DEVIL // Cyber Intelligence Platform</title>
<style>
:root{color-scheme:dark;--bg:#060a11;--panel:#0c1420;--panel2:#0e1928;--line:#223246;--line2:#1b2b3d;--txt:#dce8f2;--muted:#738ca1;--dim:#4a6478;--cyan:#53e1ff;--violet:#a98aff;--lime:#b8ff74;--red:#ff647f;--amber:#ffc47c;--mono:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;--sans:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;color:var(--txt);font:13px/1.5 var(--sans);background:radial-gradient(ellipse 45% 40% at 72% 0%,#14304966,transparent 86%),radial-gradient(ellipse 30% 25% at 0% 95%,#271c4b28,transparent 95%),var(--bg);overflow-x:hidden;min-height:100vh}
body::after{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;background-image:linear-gradient(#a7cfe509 1px,transparent 1px),linear-gradient(90deg,#a7cfe509 1px,transparent 1px);background-size:36px 36px;mask-image:linear-gradient(90deg,transparent 2%,black 90%);opacity:.38}
a{color:var(--cyan)}button,input,select{font:inherit}button{cursor:pointer}button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}::selection{background:#37d7ef55;color:#fff}
.layout{display:grid;grid-template-columns:240px minmax(0,1fr);min-height:100vh}.sidebar{background:linear-gradient(180deg,#0c1522,#080e19 80%);border-right:1px solid var(--line);position:sticky;top:0;align-self:start;height:100vh;display:flex;flex-direction:column;z-index:10}
.brand{padding:32px 23px 25px;display:flex;align-items:center;gap:13px;border-bottom:1px solid #1c2937}.brand-symbol{position:relative;width:39px;height:39px;border:1px solid #38d5e990;clip-path:polygon(25% 0,75% 0,100% 25%,100% 75%,75% 100%,25% 100%,0 75%,0 25%);display:grid;place-items:center;color:var(--cyan);font:900 25px var(--mono);background:#0a2931;box-shadow:inset 0 0 22px #36d7e429}.brand-name{font-size:21px;font-weight:900;letter-spacing:4px;line-height:1}.brand-name i{color:var(--cyan);font-style:normal}.brand-sub{color:#627c91;letter-spacing:1.4px;font:9px var(--mono);margin-top:7px}
.nav-title{margin:28px 24px 10px;color:var(--dim);font:10px var(--mono);letter-spacing:2px}.nav{padding:0 11px;display:grid;gap:4px}.nav-btn{height:43px;background:transparent;border:1px solid transparent;border-radius:7px;color:#89a2b6;text-align:left;padding:0 13px;display:flex;align-items:center;gap:13px;letter-spacing:.25px;font-size:12px;transition:.18s ease}.nav-btn:hover{color:var(--txt);background:#132336}.nav-btn.active{color:var(--cyan);background:linear-gradient(90deg,#153a45bb,#11223522);border-color:#23647a75;box-shadow:inset 3px 0 0 var(--cyan)}.nav-glyph{font:17px var(--mono);width:22px;text-align:center}.nav-num{font:9px var(--mono);color:#546d82;margin-left:auto}.side-bottom{margin-top:auto;padding:16px}.side-indicator{padding:15px;background:#0f1c2a;border:1px solid var(--line);border-radius:9px}.side-indicator .tiny{letter-spacing:1.1px}.side-green{display:flex;align-items:center;gap:9px;margin:10px 0 4px;color:var(--lime);font:11px var(--mono)}.pulse{display:inline-block;background:var(--lime);width:7px;height:7px;box-shadow:0 0 0 4px #baff7617,0 0 13px #baff7688;border-radius:50%;animation:pulse 2.6s infinite}.side-note{font:10px/1.5 var(--mono);color:var(--dim)}.side-version{padding-top:12px;color:#455d71;font:10px var(--mono);letter-spacing:1px}
.content{min-width:0}.topbar{min-height:75px;display:flex;align-items:center;justify-content:space-between;gap:15px;border-bottom:1px solid var(--line);padding:14px 32px;background:#0a111bcc;backdrop-filter:blur(12px);position:sticky;top:0;z-index:9}.crumb{color:#7790a4;font:11px var(--mono);letter-spacing:1px}.crumb strong{color:#dce8f2;font-weight:650}.slash{color:var(--cyan);padding:0 12px}.top-actions{display:flex;align-items:center;justify-content:flex-end;gap:17px}.meta{font:10px var(--mono);color:var(--muted)}.top-live{display:flex;align-items:center;gap:8px;color:var(--lime);font:10px var(--mono);letter-spacing:1px}.top-button{background:#132333;border:1px solid #294256;border-radius:6px;color:#bdd6e6;padding:9px 12px;display:flex;align-items:center;gap:9px;font:11px var(--mono)}.top-button:hover{border-color:var(--cyan);color:var(--cyan)}
.page{display:none;padding:26px 31px 34px;max-width:1750px;margin:0 auto;animation:in .25s ease}.page.active{display:block}@keyframes in{from{opacity:.5;transform:translateY(4px)}to{opacity:1;transform:none}}
.eyebrow{font:10px var(--mono);letter-spacing:2.4px;color:var(--cyan);margin-bottom:7px}.headline-row{display:flex;justify-content:space-between;gap:20px;align-items:center;margin-bottom:23px}.headline{font-size:clamp(23px,2vw,31px);letter-spacing:-.7px;font-weight:750;line-height:1.15;margin:0}.headline span{color:var(--cyan)}.desc{font:11px/1.65 var(--mono);color:var(--muted);margin:9px 0 0;max-width:720px}.protocol{font:10px var(--mono);border:1px solid #244658;padding:8px 11px;background:#0b1c29;border-radius:5px;color:#7fd7ec;white-space:nowrap}
.kpis{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px;margin-bottom:17px}.surface{background:linear-gradient(148deg,#111d2dcc,#0b1420f5 76%);border:1px solid var(--line);border-radius:10px;position:relative;min-width:0;box-shadow:0 10px 30px #00000021;overflow:hidden}.surface:before{content:"";position:absolute;left:0;top:0;width:48px;height:1px;background:#53e1ff80}.kpi{padding:18px 16px 14px;min-height:111px}.kpi-label{font:10px var(--mono);letter-spacing:1.2px;color:#809baf;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.kpi-value{font:700 clamp(20px,2vw,32px) var(--mono);letter-spacing:-1px;color:#edf9ff;margin-top:12px}.kpi-value.cyan{color:var(--cyan)}.kpi-value.lime{color:var(--lime)}.kpi-value.violet{color:var(--violet)}.kpi-foot{font:9px var(--mono);letter-spacing:.4px;color:#627d91;margin-top:8px}.kpi-accent{position:absolute;right:16px;top:16px;color:#466377;font:14px var(--mono)}
.dashboard-grid{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(295px,1fr) minmax(270px,.93fr);gap:15px}.pad{padding:19px 20px}.panel-head{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:17px}.panel-name{font:650 11px var(--mono);color:#d2e7f4;letter-spacing:1.3px}.panel-icon{color:var(--cyan);margin-right:7px}.panel-pill{font:9px var(--mono);letter-spacing:.7px;color:#8dadbf;border:1px solid #31485b;border-radius:3px;padding:5px 7px;white-space:nowrap}.panel-pill.teal{color:var(--lime);border-color:#456643}.panel-pill.red{color:var(--red);border-color:#694055}.large{grid-column:span 2}.span3{grid-column:1/-1}.globe-box{min-height:408px;position:relative;overflow:hidden;background:radial-gradient(ellipse at 49% 40%,#114b5c46 0%,transparent 49%)}#globe{position:absolute;inset:0;width:100%;height:100%;filter:drop-shadow(0 0 26px #3ce0f222)}.globe-overlay{pointer-events:none;position:absolute;inset:0}.globe-corner{position:absolute;z-index:1;font:10px var(--mono);color:#66899e;letter-spacing:1px}.globe-corner.tl{left:18px;top:15px}.globe-corner.tr{right:18px;top:15px}.globe-corner.bl{left:18px;bottom:16px}.globe-corner.br{right:18px;bottom:16px}.globe-mid{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);text-align:center;font:9px var(--mono);letter-spacing:1px;color:#62b6c8;text-shadow:0 0 20px #0af;pointer-events:none}.globe-mid div{font:700 14px var(--mono);color:#e0fcff;letter-spacing:2px}.scan-legend{display:flex;gap:12px;flex-wrap:wrap;border-top:1px solid #213347;margin-top:2px;padding-top:12px;font:9px var(--mono);color:#65879d}.scan-legend b{color:var(--lime);font-weight:500}.globe-flag{position:absolute;right:18px;bottom:16px;color:#6c95ad;font:9px var(--mono);background:#081520bd;padding:4px 7px;z-index:2}
.source-list{display:grid;gap:12px;margin-top:4px}.source-row{display:grid;grid-template-columns:minmax(0,1fr) 58px;gap:10px;align-items:center}.source-title{font:11px var(--mono);color:#bdd7e6;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.source-val{text-align:right;font:11px var(--mono);color:var(--cyan)}.track{background:#192a38;height:4px;border-radius:7px;overflow:hidden;margin-top:7px}.track>div{height:100%;background:linear-gradient(90deg,#315a8e,var(--cyan));border-radius:7px;box-shadow:0 0 7px #54d7f855}.hint{margin-top:13px;padding-top:11px;border-top:1px solid var(--line2);font:10px/1.6 var(--mono);color:#68859a}.signal{display:flex;align-items:center;gap:10px;margin:0 0 13px}.signal-dot{width:8px;height:8px;flex:none;border-radius:50%;background:var(--cyan);box-shadow:0 0 12px #53e1ff77}.signal-dot.good{background:var(--lime);box-shadow:0 0 12px #b8ff7477}.signal-dot.warn{background:var(--amber);box-shadow:0 0 12px #ffc47c77}.signal-dot.off{background:#587183;box-shadow:none}.signal-ttl{font:11px var(--mono);color:#c0d9e8}.signal-sub{font:9px var(--mono);color:#627d92;margin-top:3px}.signal-val{margin-left:auto;font:10px var(--mono);color:#9cc1d4;text-align:right;white-space:nowrap}
.chartwrap{height:208px;position:relative;padding:8px 0 24px}.bars{height:100%;display:flex;align-items:end;gap:5px;padding:0 6px 0 0;border-bottom:1px solid #314659;background:repeating-linear-gradient(to top,transparent 0,transparent calc(25% - 1px),#29405345 25%)}.barcell{height:100%;flex:1;display:flex;flex-direction:column;justify-content:flex-end;min-width:0;position:relative}.barcell .b{background:linear-gradient(0deg,#17788c,#46dff4);border-radius:3px 3px 0 0;width:100%;max-width:30px;align-self:center;min-height:2px;box-shadow:0 0 15px #46ddfa2a}.barcell:hover .b{background:linear-gradient(0deg,#258b9a,#c0fbff)}.xlabels{display:flex;gap:5px;margin-top:7px;color:#647d91;font:8px var(--mono)}.xlabels span{flex:1;text-align:center;overflow:hidden}.collection-note{font:9px/1.5 var(--mono);color:var(--dim);margin-top:12px}
.donutbox{display:flex;align-items:center;justify-content:center;gap:24px;min-height:210px}.donut{height:152px;width:152px;border-radius:50%;background:conic-gradient(var(--cyan) 0 var(--mix),var(--violet) var(--mix) 100%);display:grid;place-items:center;box-shadow:0 0 32px #53e1ff23;flex:none}.donut-inner{height:119px;width:119px;border-radius:50%;background:#0c1724;display:grid;place-content:center;text-align:center}.donut-inner strong{font:700 28px var(--mono);color:#e4f8ff}.donut-inner small{font:9px var(--mono);color:#688ca2;letter-spacing:1.2px}.mix-legend{display:grid;gap:14px;min-width:92px}.mix-entry{font:10px var(--mono);color:#8aa8bd}.mix-entry b{display:block;font:17px var(--mono);color:#e9f5fb;margin-top:5px}.sq{display:inline-block;width:9px;height:9px;margin-right:8px;background:var(--cyan)}.sq.violet{background:var(--violet)}.sq.dim{background:#547588}
.event-list{max-height:243px;overflow:auto}.event{display:flex;gap:10px;align-items:flex-start;padding:11px 0;border-bottom:1px solid #203044}.event:first-child{padding-top:0}.event-point{background:#193241;color:var(--cyan);padding:5px 7px;font:10px var(--mono);border-radius:4px}.event-main{min-width:0;flex:1}.event-ip{font:11px var(--mono);color:#d1eaf6;overflow-wrap:anywhere}.event-extra{font:9px var(--mono);color:#6f92a7;margin-top:4px}.event-time{font:9px var(--mono);color:#6a8395;text-align:right;white-space:nowrap}.empty{color:#7190a4;font:11px/1.65 var(--mono);padding:22px 5px}.empty.center{text-align:center}
.footer-note{display:flex;justify-content:space-between;flex-wrap:wrap;gap:15px;margin:17px 0 0;color:#5e7b90;font:10px/1.8 var(--mono)}
.toolbar{display:flex;gap:9px;margin:0 0 15px;align-items:center;flex-wrap:wrap}.field{background:#091525;border:1px solid #294257;border-radius:6px;padding:11px 13px;color:#d7f0f8;font:11px var(--mono);min-width:0;outline:none}.field:focus{border-color:var(--cyan)}.field.search{flex:1;min-width:240px}.field.small{max-width:170px}.btn{border:1px solid #285c6b;background:#123542;color:var(--cyan);padding:11px 16px;border-radius:6px;font:11px var(--mono);letter-spacing:.5px;white-space:nowrap}.btn.primary{background:var(--cyan);border-color:var(--cyan);color:#03121a;font-weight:800}.btn:hover{filter:brightness(1.15)}.btn.secondary{background:#142333;color:#c7dbe7;border-color:#385064}.btn:disabled{opacity:.45;cursor:not-allowed}
.table-scroll{overflow:auto}.datatable{border-collapse:collapse;width:100%;min-width:660px;table-layout:auto;text-align:left}.datatable th{padding:12px 14px;color:#7395aa;border-bottom:1px solid #2b4053;background:#0c1928;font:10px var(--mono);letter-spacing:1px;white-space:nowrap}.datatable td{padding:13px 14px;color:#bdd1df;border-bottom:1px solid #1c2e41;font:11px var(--mono);max-width:300px;overflow-wrap:anywhere}.datatable tr:hover td{background:#10223480}.datatable td.value{color:#e5f2ff}.datatable .muted{color:#6b879b}.datatable .date{white-space:nowrap}.type-chip{font:9px var(--mono);display:inline-flex;border:1px solid #2d5e6d;border-radius:4px;padding:4px 6px;color:var(--cyan);letter-spacing:.6px}.type-chip.domain{color:var(--violet);border-color:#574780}.type-chip.other{color:#a7b4c2;border-color:#384b5c}.copyrow{background:transparent;color:#81a8bd;border:0;margin-left:6px}.copyrow:hover{color:var(--cyan)}.pages{display:flex;justify-content:flex-end;align-items:center;gap:13px;margin-top:16px;font:10px var(--mono);color:#7798ad}.pages button{padding:8px 10px;border:1px solid #29475d;border-radius:4px;background:#112638;color:#b7d4e3}.pages button:disabled{opacity:.3;cursor:not-allowed}
.two-col{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(260px,.8fr);gap:16px}.three-col{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}.sec-title{font:700 12px var(--mono);letter-spacing:1.2px;color:#dbecf7;margin-bottom:13px}.kicker{color:var(--cyan);font:10px var(--mono);letter-spacing:1.6px}.section-text{color:#7f9bad;font:11px/1.8 var(--mono)}.metric-xl{font:700 33px var(--mono);color:var(--cyan);margin:10px 0}.stat-pair{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--line2);font:11px var(--mono)}.stat-pair span:first-child{color:#7592a6}.stat-pair span:last-child{color:#d0e4f0;overflow-wrap:anywhere;text-align:right}.inspector{padding:20px}.inspector-status{margin-top:15px;border:1px solid #2c5460;border-radius:6px;padding:16px;background:#0b263044}.inspector-status b{font:12px var(--mono);color:var(--lime)}.inspector-status.not-found b{color:var(--amber)}.inspector-status p{font:10px/1.8 var(--mono);color:#9ab5c5;margin:9px 0 0}.inspector-hidden{display:none}
.pipeline{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:13px 0 18px}.pipe{padding:18px;background:linear-gradient(135deg,#122737cc,#0a1826);border:1px solid #294257;border-radius:9px;position:relative;min-height:165px}.pipe-top{font:10px var(--mono);color:var(--cyan);letter-spacing:1.5px}.pipe-icon{font:32px var(--mono);color:#66cfe5;margin:18px 0 8px}.pipe h3{font:600 13px var(--sans);margin:0 0 5px}.pipe p{font:10px/1.5 var(--mono);color:#7592a4;margin:0}.pipe .arrow{position:absolute;right:-13px;top:38%;z-index:2;color:var(--cyan);font:18px var(--mono)}.pipe:last-child .arrow{display:none}
.capability{display:flex;align-items:flex-start;gap:12px;padding:13px 0;border-bottom:1px solid #1f3042}.cap-icon{font:13px var(--mono);color:var(--cyan);background:#112d3b;border:1px solid #2d5467;border-radius:5px;padding:6px 8px}.cap-title{font:11px var(--mono);color:#d5e7f3}.cap-info{font:10px/1.6 var(--mono);color:#7190a4;margin-top:4px}.cap-badge{margin-left:auto;flex:none;font:9px var(--mono);border:1px solid #344f60;border-radius:3px;padding:5px;color:#87a9bb}.cap-badge.lime{color:var(--lime);border-color:#45663a}.cap-badge.amber{color:var(--amber);border-color:#715537}
.banner{background:linear-gradient(100deg,#193c45,#182642 65%,#251b46);border:1px solid #366273;border-radius:8px;padding:15px 19px;display:flex;align-items:center;justify-content:space-between;gap:18px;margin:16px 0}.banner p{margin:0;font:11px/1.7 var(--mono);color:#a7c3d5}.banner strong{color:#e5f7ff}.logline{font:11px/1.8 var(--mono);color:#8fbbca;background:#07121e;border-left:2px solid #268da4;padding:9px 12px;margin:7px 0;overflow-wrap:anywhere}.oplist{margin:0;padding:0;list-style:none}.oplist li{padding:12px 0 12px 20px;border-bottom:1px solid #223346;position:relative;font:11px/1.7 var(--mono);color:#abc2d0}.oplist li:before{content:"◈";position:absolute;left:0;color:var(--cyan)}.faint{color:#6c889d}.lowline{font:10px/1.7 var(--mono);color:#638196;margin-top:14px}.compact{margin-top:0}
.toast-container{position:fixed;bottom:24px;right:25px;z-index:50;display:grid;gap:10px}.toast{background:#102c3a;border:1px solid #3c6f7e;border-radius:7px;padding:11px 16px;color:#e0f9ff;box-shadow:0 15px 40px #0008;font:11px var(--mono);max-width:350px}.toast.error{background:#3b1927;border-color:#a84465}.kbd{font:10px var(--mono);color:#86a9bd;border:1px solid #395267;border-radius:4px;padding:4px 6px}.helptext{border-left:2px solid #2c6575;padding:10px 13px;margin-top:10px;font:10px/1.7 var(--mono);color:#94b2c1;background:#0c233055}
@media(max-width:1480px){.dashboard-grid{grid-template-columns:minmax(0,1.4fr) minmax(280px,1fr)}.dashboard-grid>.surface:nth-child(3){grid-column:span 2}.kpis{grid-template-columns:repeat(3,minmax(0,1fr))}.donutbox{justify-content:space-evenly}}@media(max-width:1070px){.layout{grid-template-columns:67px minmax(0,1fr)}.sidebar .brand{padding:24px 13px}.brand-name,.brand-sub,.sidebar .nav-title,.nav-btn span:not(.nav-glyph),.nav-num,.side-indicator,.side-version{display:none}.nav{padding:0 8px}.nav-btn{justify-content:center;padding:0}.nav-glyph{font-size:20px}.side-bottom{padding:5px}.topbar{padding:14px 20px}.page{padding:22px 20px}.three-col{grid-template-columns:1fr 1fr}.pipeline{grid-template-columns:repeat(2,1fr)}.pipe .arrow{display:none}}
@media(max-width:760px){.layout{display:block}.sidebar{position:sticky;top:0;width:100%;height:auto;border-right:0;border-bottom:1px solid var(--line);flex-direction:row;align-items:center;justify-content:space-between;padding:4px 9px;overflow:auto}.sidebar .brand{padding:8px 5px;border:0}.brand-symbol{width:32px;height:32px;font-size:20px}.sidebar .nav{display:flex;gap:3px;padding:0}.nav-btn{width:38px;height:36px}.sidebar .nav-btn span:not(.nav-glyph){display:none}.side-bottom{display:none}.topbar{position:static;min-height:53px;padding:11px 14px;gap:5px}.topbar .meta,.topbar .kbd{display:none}.top-actions{gap:8px}.top-button{padding:7px}.page{padding:19px 13px}.headline-row{align-items:flex-start}.headline{font-size:24px}.protocol{display:none}.kpis{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.kpi{padding:13px 12px;min-height:100px}.kpi-value{font-size:24px}.dashboard-grid,.two-col,.three-col{grid-template-columns:minmax(0,1fr)}.dashboard-grid>.surface:nth-child(3),.large,.span3{grid-column:span 1}.globe-box{min-height:340px}.pad{padding:17px 15px}.pipeline{grid-template-columns:1fr 1fr;gap:7px}.pipe{padding:12px;min-height:140px}.pipe-icon{font-size:23px;margin:12px 0 5px}.toolbar .field.search{min-width:100%;flex-basis:100%}.donutbox{gap:20px}.donut{width:128px;height:128px}.donut-inner{width:100px;height:100px}}
@media(max-width:380px){.sidebar .nav-btn{width:33px}.kpi-label{font-size:9px}.donut{width:112px;height:112px}.donut-inner{width:86px;height:86px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;transition:none!important}html{scroll-behavior:auto}}

/* DEVIL v3 — addon visual system. The hero effects are presentation, not traffic. */
:root{--v3cyan:#4de8ff;--v3green:#a2ff88;--v3purple:#b79aff;--v3orange:#ffbb78}
.v3tag{display:inline-flex;align-items:center;gap:8px;letter-spacing:1.2px;text-transform:uppercase;font:10px var(--mono);color:var(--cyan);padding:7px 10px;border:1px solid #2a6172;background:#0e303b70;border-radius:5px}
.v3tag .v3dot{width:6px;height:6px;background:var(--lime);border-radius:50%;box-shadow:0 0 12px var(--lime)}
.v3block{padding:20px;min-width:0}
.v3wide{display:grid;grid-template-columns:1.65fr 1fr;gap:15px;margin:0 0 17px}
.v3-mini-strips{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:0 0 17px}
.v3-mini{background:linear-gradient(110deg,#0d1c2c,#0b1522);border:1px solid #2a4253;padding:12px 15px;border-radius:9px;position:relative;overflow:hidden}
.v3-mini:before{content:"";position:absolute;width:120px;height:120px;right:-65px;top:-65px;border:1px solid #4de8ff29;border-radius:100%}
.v3-mini label{display:block;color:#7899ae;font:9px var(--mono);letter-spacing:1.5px}.v3-mini strong{display:block;font:700 23px var(--mono);margin-top:8px;color:#daf4ff}.v3-mini small{display:block;color:#6d8ba1;margin-top:6px;font:9px/1.5 var(--mono)}
.v3-mini strong.v3mint{color:var(--lime)}.v3-mini strong.v3turq{color:var(--cyan)}
.v3layout{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(270px,.9fr);gap:15px}
.v3panel{background:linear-gradient(145deg,#102032,#0a1320 70%);border:1px solid #253e53;border-radius:12px;padding:20px;min-width:0;position:relative;overflow:hidden;box-shadow:0 12px 28px #0002}
.v3panel:before{content:"";width:52px;height:2px;position:absolute;left:0;top:0;background:#4de8ff8a}
.v3pane-title{display:flex;align-items:center;gap:10px;justify-content:space-between;margin:0 0 17px;color:#ddf3ff;font:700 11px var(--mono);letter-spacing:1px}
.v3pane-title span{font:9px var(--mono);color:#6ea9bc}
.v3feature{min-height:385px;display:grid;grid-template-rows:auto 1fr auto;background:radial-gradient(ellipse at 70% 52%,#0e657530,transparent 55%),linear-gradient(135deg,#111e31,#070e18)}
.v3osc{width:100%;display:block;height:205px;margin:4px auto;border-radius:6px}
.v3faint{color:#7292a7;font:10px/1.8 var(--mono)}.v3legend{color:#a5c1d3;font:10px var(--mono)}.v3legend em{font-style:normal;color:var(--cyan)}
.v3statgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.v3number{font:700 clamp(24px,2vw,38px) var(--mono);color:var(--cyan);line-height:1.2;letter-spacing:-1px;margin:13px 0}
.v3number.green{color:var(--lime)}.v3number.purple{color:var(--violet)}.v3small{font:10px/1.75 var(--mono);color:#7797ae}
.v3progress{height:6px;background:#203248;border-radius:6px;overflow:hidden;margin-top:10px}.v3progress i{display:block;height:100%;width:0;background:linear-gradient(90deg,#0f91bc,#50f1ff);border-radius:6px;transition:width .55s}.v3progress.green i{background:linear-gradient(90deg,#438e66,#aaff99)}
.v3tabletable{width:100%;border-collapse:collapse}.v3tabletable th,.v3tabletable td{text-align:left;border-bottom:1px solid #203348;padding:13px 11px;font:11px var(--mono)}.v3tabletable th{font-size:9px;color:#7392a8;letter-spacing:1px}.v3tabletable td{color:#b5d0de;overflow-wrap:anywhere}
.v3monopill{display:inline-flex;border:1px solid #335669;padding:5px 8px;border-radius:4px;color:var(--cyan);background:#0c2535;font:9px var(--mono);white-space:nowrap}
.v3monopill.warn{color:#ffbf7f;border-color:#6b533e;background:#2e201c}.v3monopill.good{color:#a5f99b;border-color:#3b6653;background:#14251f}
.v3glow{position:absolute;right:-100px;top:-90px;width:260px;height:260px;border:1px solid #56dcff18;border-radius:50%;pointer-events:none;box-shadow:0 0 0 40px #56dcff07,0 0 0 85px #56dcff04}
.v3callout{border-left:2px solid #30cde5;padding:13px 15px;background:#10283a;color:#95bed0;font:11px/1.75 var(--mono);margin:17px 0 0}
.v3detail{border:1px solid #2b445c;background:#0c1828;padding:18px;border-radius:8px;min-height:220px}
.v3detail .v3key{color:var(--cyan);font:800 19px var(--mono);word-break:break-word;margin:6px 0 15px}.v3detail .v3row{display:flex;justify-content:space-between;gap:12px;border-top:1px solid #263b4f;padding:10px 0;color:#85a4ba;font:10px var(--mono)}.v3detail .v3row b{color:#d8eaf7;font-weight:500;text-align:right;word-break:break-all}
.v3attackmap{height:420px;position:relative;overflow:hidden;background:radial-gradient(ellipse at center,#103148,#081321 64%);border:1px solid #274356;border-radius:11px}
.v3attackmap canvas{display:block;width:100%;height:100%}.v3map-badge{position:absolute;left:18px;top:17px;font:10px var(--mono);color:#83c5da;background:#091b2acc;padding:7px 10px;border:1px solid #245064;border-radius:4px;pointer-events:none}
.v3map-foot{position:absolute;left:18px;bottom:17px;right:18px;display:flex;justify-content:space-between;gap:10px;color:#688ba1;font:9px var(--mono);pointer-events:none}
.v3map-data{padding:16px;border:1px solid #274356;border-radius:8px;background:#0c1b2a;margin-top:15px}
.v3orb{display:inline-block;width:7px;height:7px;border-radius:50%;background:#50ffb1;box-shadow:0 0 12px #52ffba}
.v3timeline{position:relative;padding-left:22px;margin-left:7px}.v3timeline:before{content:"";position:absolute;left:6px;top:3px;bottom:10px;width:1px;background:#275366}.v3timelineitem{position:relative;padding:0 0 18px;color:#accede;font:11px var(--mono)}.v3timelineitem:before{content:"";position:absolute;left:-21px;top:5px;width:10px;height:10px;border-radius:50%;background:#2cd4e9;box-shadow:0 0 14px #2cd4e955}.v3timelineitem small{display:block;color:#6d90a8;margin-top:5px;font:10px var(--mono)}
.v3hero-title{font-size:clamp(25px,2.2vw,35px);font-weight:780;margin:0;letter-spacing:-.8px}.v3hero-title span{color:var(--cyan)}
@media(max-width:1400px){.v3mini-strips{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:880px){.v3layout,.v3wide{grid-template-columns:1fr}.v3statgrid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:570px){.v3mini-strips,.v3statgrid{grid-template-columns:repeat(2,minmax(0,1fr))}.v3mini{padding:11px}.v3mini strong{font-size:19px}.v3panel{padding:15px}.v3attackmap{height:320px}}

/* DEVIL GeoINT v3.1: offline world atlas, analyst filtering, bounded canvas. */
.geo-beta{display:inline-flex;vertical-align:middle;font:700 10px var(--mono);letter-spacing:1.7px;padding:6px 9px;margin-left:13px;border:1px solid #346775;border-radius:4px;color:#8cffb9;background:#0b312a}
.geo-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:16px}.geo-kpis .v3-mini{min-height:110px}
.geo-toolbar{display:flex;align-items:end;flex-wrap:wrap;gap:9px;margin-bottom:16px;background:#0e1b2b;padding:13px;border:1px solid #284258;border-radius:9px}
.geo-field{display:flex;flex-direction:column;gap:6px;min-width:135px;flex:1}.geo-field.geo-query{flex:1.35;min-width:185px}.geo-field span{font:9px var(--mono);letter-spacing:1.3px;color:#7799ab}.geo-field input,.geo-field select{background:#071524;border:1px solid #33526a;color:#cceef8;padding:10px 11px;border-radius:5px;min-width:0;width:100%;height:39px;font:11px var(--mono)}.geo-field input:focus,.geo-field select:focus{outline:1px solid var(--cyan)}.geo-toolbar .btn{height:39px;padding:8px 12px}
.geo-layout{display:grid;grid-template-columns:minmax(0,1.8fr) minmax(280px,.75fr);gap:15px;align-items:start}.geo-main,.geo-aside{display:grid;gap:15px;min-width:0}.geo-panel{padding:17px}.geo-panel .v3pane-title{margin-bottom:13px}
.geo-map-controls{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:10px}.geo-modes,.geo-zoom{display:flex;align-items:center;gap:5px}.geo-toggle,.geo-zoom button{border:1px solid #2a4759;background:#0d2030;color:#91b4c6;border-radius:5px;font:10px var(--mono);padding:8px 10px}.geo-toggle:hover,.geo-zoom button:hover{border-color:#4de8ff;color:#d8faff}.geo-toggle.active{background:#104051;border-color:#49d4ed;color:#8df8ff}.geo-zoom button{width:32px;font-size:17px;padding:3px;height:32px}
.geo-map{height:490px;background:radial-gradient(ellipse at center,#102b43,#060f1c 70%);cursor:grab;touch-action:none}.geo-map:active{cursor:grabbing}.geo-map canvas{width:100%;height:100%}.geo-map-hud{position:absolute;left:14px;top:14px;pointer-events:none;color:#b6faff;font:700 13px var(--mono);letter-spacing:1px;background:#061420bb;border:1px solid #2a5668;padding:10px 11px;border-radius:5px}.geo-map-hud span{color:#4de8ff}.geo-map-hud small{font:9px var(--mono);color:#78a1b4;letter-spacing:1.1px}
.geo-map-footer{position:absolute;bottom:12px;left:14px;right:14px;display:flex;justify-content:space-between;gap:8px;font:9px var(--mono);letter-spacing:.5px;color:#76a0b4;pointer-events:none}
.geo-tooltip{position:absolute;pointer-events:none;z-index:4;min-width:180px;max-width:245px;background:#071626f5;border:1px solid #4dbbd1;border-radius:7px;box-shadow:0 12px 30px #0009;padding:12px 14px;color:#e2faff;font:11px/1.6 var(--mono);overflow-wrap:anywhere}.geo-tooltip strong{display:block;font-size:13px;color:#a8ff9a}.geo-tooltip span{color:#8cbbce}
.geo-map-meta{margin-top:12px;display:flex;gap:9px;align-items:flex-start;flex-wrap:wrap;background:#102b3b;border-left:2px solid var(--cyan);padding:10px 13px;font:10px/1.6 var(--mono);color:#9bbdcd}.geo-led{margin-top:4px;width:7px;height:7px;background:#8cff9d;box-shadow:0 0 10px #68fc98;border-radius:50%;flex:none}.geo-sample{margin-left:auto;color:#63bde0}
.geo-license{margin-top:13px;font:10px/1.7 var(--mono);color:#7e9eb0}.geo-license a{color:#78cce4}
.geo-ranking{display:grid;gap:8px}.geo-country{width:100%;display:block;text-align:left;border:1px solid transparent;border-radius:5px;background:transparent;padding:8px 7px;color:#b6d6e6}.geo-country:hover,.geo-country.selected{background:#122e3d;border-color:#29556b}.geo-country-top{display:flex;justify-content:space-between;gap:8px;font:10px var(--mono);color:#a7cadc}.geo-country-top b{color:#a2ff88}.geo-country-bar{height:4px;margin-top:8px;background:#1c3445;border-radius:5px;overflow:hidden}.geo-country-bar i{display:block;height:100%;background:linear-gradient(90deg,#167989,#6ef6cc);border-radius:5px}.geo-mini-note{color:#718fa4;font:10px/1.7 var(--mono);padding-top:12px;margin-top:12px;border-top:1px solid #274155}
.geo-inspector{min-height:155px;font:11px/1.7 var(--mono);color:#a6c3d5}.geo-inspector strong{color:#afffde;font:700 19px var(--mono);display:block;margin:7px 0 11px;word-break:break-all}.geo-inspector-line{display:flex;justify-content:space-between;gap:8px;border-top:1px solid #264157;padding:8px 0;font:10px var(--mono)}.geo-inspector-line span{color:#739ab0}.geo-inspector-line b{color:#dbf3ff;max-width:70%;text-align:right;overflow-wrap:anywhere}.geo-inspector .btn{margin-top:12px}
.geo-table{min-width:620px}.geo-pagination{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:14px;font:10px var(--mono);color:#7897ab}.geo-pagination div{display:flex;gap:8px}.geo-pagination .btn{padding:9px 11px}.geo-integrity .signal{margin:0 0 14px}
@media(max-width:1270px){.geo-layout{grid-template-columns:1fr}.geo-aside{grid-template-columns:repeat(2,minmax(0,1fr))}.geo-aside>.v3panel:last-child{grid-column:span 2}}
@media(max-width:760px){.geo-kpis{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.geo-toolbar{gap:8px}.geo-field{min-width:42%}.geo-toolbar .btn{flex:1}.geo-map{height:340px}.geo-toggle{font-size:9px;padding:8px 7px}.geo-zoom button{width:29px}.geo-aside{grid-template-columns:1fr}.geo-aside>.v3panel:last-child{grid-column:auto}.geo-sample{margin-left:0}}
@media(max-width:450px){.geo-field,.geo-field.geo-query{min-width:100%}.geo-toolbar .btn{min-width:100%}.geo-map{height:285px}.geo-map-controls{align-items:start;flex-direction:column}.geo-map-footer{font-size:8px}.geo-map-hud{font-size:11px}}

</style>
</head>
<body>
<div class="layout">
  <aside class="sidebar" aria-label="Main navigation">
    <div class="brand"><div class="brand-symbol" aria-hidden="true">◇</div><div><div class="brand-name">DEV<i>I</i>L</div><div class="brand-sub">INTELLIGENCE / 03.1</div></div></div>
    <div class="nav-title">WORKSPACE</div>
    <nav class="nav" id="nav">
      <button class="nav-btn active" data-page="overview" title="Command overview"><span class="nav-glyph">◈</span><span>Command overview</span><span class="nav-num">01</span></button>
      <button class="nav-btn" data-page="pulse" title="Live host telemetry"><span class="nav-glyph">⌁</span><span>Live system pulse</span><span class="nav-num">06</span></button>
      <button class="nav-btn" data-page="intelligence" title="Threat intelligence"><span class="nav-glyph">⌕</span><span>Threat intelligence</span><span class="nav-num">02</span></button>
      <button class="nav-btn" data-page="atlas" title="Threat atlas"><span class="nav-glyph">◉</span><span>Threat atlas</span><span class="nav-num">07</span></button>
      <button class="nav-btn" data-page="detections" title="Detections"><span class="nav-glyph">◎</span><span>Detection timeline</span><span class="nav-num">03</span></button>
      <button class="nav-btn" data-page="caseboard" title="Event review desk"><span class="nav-glyph">▣</span><span>Event review desk</span><span class="nav-num">08</span></button>
      <button class="nav-btn" data-page="operations" title="Operations"><span class="nav-glyph">⌘</span><span>Operations</span><span class="nav-num">04</span></button>
      <button class="nav-btn" data-page="system" title="System status"><span class="nav-glyph">▦</span><span>System & health</span><span class="nav-num">05</span></button>
    </nav>
    <div class="side-bottom"><div class="side-indicator"><div class="tiny">INTELLIGENCE ENGINE</div><div class="side-green"><span class="pulse"></span><span id="sideHealth">INITIALIZING</span></div><div class="side-note">Read-only analytics<br>Protected at reverse proxy</div></div><div class="side-version">DEVIL / COMMAND CENTER v3.1</div></div>
  </aside>
  <div class="content">
    <header class="topbar"><div class="crumb">DEVIL <span class="slash">/</span> <strong id="breadcrumb">COMMAND OVERVIEW</strong></div><div class="top-actions"><span class="top-live"><span class="pulse"></span><span id="connection">CONNECTING</span></span><span class="meta" id="clock">--:--:-- UTC</span><button class="top-button" id="refresh" title="Refresh data now">↻ <span>SYNC</span></button><span class="kbd" title="Global search keyboard shortcut">CTRL K</span></div></header>
    <main>
      <section id="page-overview" class="page active" aria-label="Command overview">
        <div class="headline-row"><div><div class="eyebrow">/// OPERATIONAL PICTURE / 001</div><h1 class="headline">Cyber Intelligence <span>Command Center</span></h1><p class="desc">Unified intelligence telemetry · verified local records · defensive investigation workspace</p></div><div class="protocol">◉ DATA MODE / READ ONLY</div></div>
        <div class="kpis">
          <div class="surface kpi"><span class="kpi-accent">◈</span><div class="kpi-label">TOTAL INDICATORS</div><div class="kpi-value cyan" id="kTotal">—</div><div class="kpi-foot">LOCAL INTELLIGENCE DB</div></div>
          <div class="surface kpi"><span class="kpi-accent">▦</span><div class="kpi-label">IP INDICATORS</div><div class="kpi-value" id="kIp">—</div><div class="kpi-foot">RECORDS · NOT ATTACKS</div></div>
          <div class="surface kpi"><span class="kpi-accent">◇</span><div class="kpi-label">DOMAINS</div><div class="kpi-value violet" id="kDomain">—</div><div class="kpi-foot">TRACKED HOSTNAMES</div></div>
          <div class="surface kpi"><span class="kpi-accent">◎</span><div class="kpi-label">MATCHED EVENTS</div><div class="kpi-value lime" id="kDetections">—</div><div class="kpi-foot">CORRELATOR RECORDS</div></div>
          <div class="surface kpi"><span class="kpi-accent">↥</span><div class="kpi-label">ALERTS QUEUED</div><div class="kpi-value" id="kPending">—</div><div class="kpi-foot">TELEGRAM PENDING</div></div>
          <div class="surface kpi"><span class="kpi-accent">✓</span><div class="kpi-label">ALERTS SENT</div><div class="kpi-value" id="kSent">—</div><div class="kpi-foot">RECORDED DELIVERY STATE</div></div>
        </div>
        <div class="v3-mini-strips" aria-label="Live host resource preview">
          <div class="v3-mini"><label>VPS CPU UTILIZATION</label><strong class="v3turq" id="oCpu">—</strong><small>Kernel counters / realtime</small></div>
          <div class="v3-mini"><label>AVAILABLE RAM</label><strong id="oMem">—</strong><small>Linux MemAvailable</small></div>
          <div class="v3-mini"><label>NETWORK INBOUND</label><strong class="v3mint" id="oRx">—</strong><small>Default-route interface</small></div>
          <div class="v3-mini"><label>TCP ESTABLISHED</label><strong id="oTcp">—</strong><small>Local VPS socket counters</small></div>
        </div>
        <div class="dashboard-grid">
          <article class="surface pad large"><div class="panel-head"><div class="panel-name"><span class="panel-icon">◉</span>GLOBAL INTELLIGENCE VISUALIZATION</div><span class="panel-pill">ANIMATED / ILLUSTRATIVE</span></div><div class="globe-box" id="globeBox"><canvas id="globe" aria-label="Decorative rotating wireframe globe; not geolocated attacks"></canvas><div class="globe-overlay"><div class="globe-corner tl">COORDINATE GRID / WGS84 STYLE</div><div class="globe-corner tr">360° VISUAL SCAN</div><div class="globe-corner bl">INTELLIGENCE GRAPHICS<br>NOT LIVE TRAFFIC</div><div class="globe-mid"><div>DEVIL NETWORK</div>ANALYSIS / ONLINE</div></div><div class="globe-flag">GEO ATTRIBUTION NOT CONNECTED</div></div><div class="scan-legend"><span><b>●</b> STATIC SIGNAL NODES / ARTWORK</span><span>◈ INDICATOR COUNTS FROM SQLITE</span><span>↻ ROTATION IS PRESENTATIONAL</span></div></article>
          <article class="surface pad"><div class="panel-head"><div class="panel-name"><span class="panel-icon">◫</span>INTELLIGENCE SOURCES</div><span class="panel-pill teal">LOCAL DATABASE</span></div><div class="source-list" id="sourceList"><div class="empty">Waiting for feed data...</div></div><div class="hint">Source shares reflect stored indicators. No external threat feed is queried by this page.</div></article>
          <article class="surface pad"><div class="panel-head"><div class="panel-name"><span class="panel-icon">▥</span>COLLECTION TIMELINE</div><span class="panel-pill">LAST-SEEN DAY</span></div><div class="chartwrap"><div class="bars" id="collectionBars"></div><div class="xlabels" id="collectionLabels"></div></div><p class="collection-note">Grouped by each indicator's last_seen date. NOT a chart of real-time attacks or ingest volume.</p></article>
          <article class="surface pad"><div class="panel-head"><div class="panel-name"><span class="panel-icon">◉</span>INDICATOR COMPOSITION</div><span class="panel-pill">DATABASE DISTRIBUTION</span></div><div class="donutbox"><div class="donut" id="composition" style="--mix:50%"><div class="donut-inner"><strong id="percentIp">—</strong><small>IP SHARE</small></div></div><div class="mix-legend"><div class="mix-entry"><span class="sq"></span>IP RECORDS <b id="mixIp">—</b></div><div class="mix-entry"><span class="sq violet"></span>DOMAIN RECORDS <b id="mixDomains">—</b></div><div class="mix-entry"><span class="sq dim"></span>OTHER <b id="mixOther">—</b></div></div></div></article>
          <article class="surface pad"><div class="panel-head"><div class="panel-name"><span class="panel-icon">◈</span>PLATFORM STATUS</div><span class="panel-pill teal">LOCAL CHECK</span></div><div id="statusSignals"><div class="empty">Loading...</div></div></article>
          <article class="surface pad"><div class="panel-head"><div class="panel-name"><span class="panel-icon">◎</span>LATEST DETECTION RECORDS</div><span class="panel-pill">EVENTS DATABASE</span></div><div class="event-list" id="eventMini"><div class="empty">Loading...</div></div><div class="hint">Matches are triage leads, not validated intrusions. No inferred severity ranking.</div></article>
        </div><div class="footer-note"><span id="updated">AWAITING FIRST SYNC</span><span>DATA ≠ EXPLOITATION · NO AUTOMATED BLOCKING · SOC ANALYST MODE</span></div>
      </section>
<section id="page-pulse" class="page" aria-label="Live host telemetry">
  <div class="headline-row"><div><div class="eyebrow">/// LIVE OPERATIONS / 006</div><h1 class="v3hero-title">System <span>Pulse</span> <small style="font:10px var(--mono);color:#9effa7;vertical-align:middle">● LIVE HOST</small></h1><p class="desc">Live Linux host counters, not attacks. Samples refresh every 5s while the page is visible.</p></div><div class="v3tag"><span class="v3dot"></span> PROC / TELEMETRY</div></div>
  <div class="v3-mini-strips">
    <div class="v3-mini"><label>CPU UTILIZATION</label><strong class="v3turq" id="pCpu">—</strong><small>Delta of /proc/stat · 1 vCPU</small><div class="v3progress"><i id="barCpu"></i></div></div>
    <div class="v3-mini"><label>RAM UTILIZATION</label><strong id="pRam">—</strong><small id="pMemDetail">MemAvailable / MemTotal</small><div class="v3progress green"><i id="barRam"></i></div></div>
    <div class="v3-mini"><label>DOWNLOAD RATE</label><strong class="v3mint" id="pRx">—</strong><small id="pNic">Host default-route interface</small></div>
    <div class="v3-mini"><label>UPLOAD RATE</label><strong id="pTx">—</strong><small>Interface byte-counter delta</small></div>
  </div>
  <div class="v3layout">
    <article class="v3panel v3feature"><div class="v3pane-title">◈ HOST CPU AND MEMORY / RECENT SAMPLES <span>REAL COUNTERS · 5s</span></div><canvas class="v3osc" id="cpuChart" role="img" aria-label="CPU and RAM time series"></canvas><div class="v3legend"><em>━</em> CPU UTILIZATION&nbsp;&nbsp; <span style="color:var(--v3purple)">━</span> RAM UTILIZATION <span class="v3faint"> · sampled only when queried</span></div><div class="v3glow"></div></article>
    <article class="v3panel"><div class="v3pane-title">▦ RESOURCE GUARD <span id="pCheck">CHECKING</span></div><div class="v3statgrid"><div><div class="v3small">DISK USAGE</div><div class="v3number" id="pDisk">—</div></div><div><div class="v3small">SWAP CONSUMED</div><div class="v3number purple" id="pSwap">—</div></div><div><div class="v3small">TCP ESTABLISHED</div><div class="v3number green" id="pTcp">—</div></div><div><div class="v3small">HOST UPTIME</div><div class="v3number" id="pUptime">—</div></div></div><div class="v3callout" id="pHealthNote">Measurements are from this VPS only. Network traffic counters do not identify applications or remote malicious actors.</div></article>
    <article class="v3panel"><div class="v3pane-title">⌁ NETWORK THROUGHPUT <span>BYTES PER SECOND · HOST</span></div><canvas class="v3osc" id="netChart" role="img" aria-label="Network upload and download throughput"></canvas><div class="v3legend"><em>━</em> INBOUND&nbsp;&nbsp;<span style="color:var(--v3green)">━</span> OUTBOUND <span class="v3faint"> · interface only · no packet inspection</span></div></article>
    <article class="v3panel"><div class="v3pane-title">◎ OBSERVABILITY COVERAGE <span>HONEST INVENTORY</span></div><div id="pulseCoverage"><div class="empty">Loading...</div></div></article>
  </div>
  <div class="v3callout">Network rates are measured from the host's default-route interface and might include VPN, monitoring, and user traffic. They are not packet captures, DDoS alerts, or evidence of intrusions. Historical series exists in process memory only.</div>
</section>
<section id="page-atlas" class="page" aria-label="Threat Atlas GeoINT">
  <div class="headline-row"><div><div class="eyebrow">/// GEOSPATIAL INTELLIGENCE / 007 · MODULE 3.1</div><h1 class="v3hero-title">Threat <span>Atlas</span><small class="geo-beta">GEOINT</small></h1><p class="desc">Worldwide spatial intelligence for locally verified IOCs. Exact feed matches · approximate geolocation · no simulated attacks.</p></div><div class="v3tag"><span class="v3dot"></span> OFFLINE GEOINT / READ ONLY</div></div>
  <div class="geo-kpis">
    <div class="v3-mini"><label>GEO-ENRICHED IOCS</label><strong class="v3mint" id="geoTotal">—</strong><small>Exact IPs in intelligence.db</small></div>
    <div class="v3-mini"><label>COUNTRIES COVERED</label><strong id="geoCountries">—</strong><small>Approximate registration country</small></div>
    <div class="v3-mini"><label>FILTERED IOCS</label><strong class="v3turq" id="geoFiltered">—</strong><small>Matches current analyst filters</small></div>
    <div class="v3-mini"><label>RENDERED MAP POINTS</label><strong id="geoRendered">—</strong><small>Bounded client visualization</small></div>
  </div>
  <div class="geo-toolbar" role="search">
    <label class="geo-field geo-query"><span>IP / SUBSTRING</span><input id="geoSearch" type="search" maxlength="90" placeholder="Find address e.g. 185.12" autocomplete="off"></label>
    <label class="geo-field"><span>COUNTRY</span><select id="geoCountry"><option value="">ALL COUNTRIES</option></select></label>
    <label class="geo-field"><span>INTEL FEED</span><select id="geoSource"><option value="">ALL SOURCES</option></select></label>
    <button id="geoApply" class="btn primary" type="button">⌕ SEARCH INTEL</button>
    <button id="geoClear" class="btn secondary" type="button">RESET</button>
  </div>
  <div class="geo-layout">
    <div class="geo-main">
      <article class="v3panel geo-panel">
        <div class="v3pane-title">◉ GLOBAL THREAT INTELLIGENCE MAP <span id="atlasMode">LOADING</span></div>
        <div class="geo-map-controls">
          <div class="geo-modes" role="group" aria-label="Map visualization mode"><button class="geo-toggle active" id="geoModePoints" type="button">◉ IOC POINTS</button><button class="geo-toggle" id="geoModeHeat" type="button">▦ HEATMAP</button><button class="geo-toggle" id="geoModeClusters" type="button">⬡ CLUSTERS</button></div>
          <div class="geo-zoom" role="group" aria-label="Map zoom"><button type="button" id="geoZoomIn" title="Zoom in">+</button><button type="button" id="geoZoomOut" title="Zoom out">−</button><button type="button" id="geoZoomReset" title="Reset map">⌖</button></div>
        </div>
        <div class="v3attackmap geo-map" id="atlasBox">
          <canvas id="atlasCanvas" role="img" aria-label="Geographic map of approximate locations of stored threat indicators; selectable points"></canvas>
          <div class="geo-map-hud">DEVIL<span> // </span>GEOINT<br><small>GLOBAL INDEX · WGS84</small></div>
          <div id="geoTooltip" class="geo-tooltip" aria-live="polite" hidden></div>
          <div class="geo-map-footer"><span>◎ REPRESENTATIVE IOC LOCATIONS</span><span id="geoZoomLabel">100% SCALE</span></div>
        </div>
        <div class="geo-map-meta"><span class="geo-led"></span><span id="atlasNote">Loading local GeoIP enrichment...</span><span id="geoSampleNote" class="geo-sample"></span></div>
        <div class="geo-license">GEOGRAPHY: <a href="https://db-ip.com/db/lite.php" target="_blank" rel="noopener noreferrer">DB-IP City Lite</a> (Oct 2026) · <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer">CC BY 4.0</a>. Coastline backdrop: GSHHG / NOAA via Basemap. GeoIP is approximate, not the physical origin of an attack.</div>
      </article>
      <article class="v3panel"><div class="v3pane-title">▦ GEOINT INDICATOR EXPLORER <span id="geoTableTitle">READ-ONLY RECORDS</span></div>
        <div class="table-scroll"><table class="v3tabletable geo-table"><thead><tr><th>IP INDICATOR</th><th>COUNTRY</th><th>COORDINATES</th><th>SOURCE</th><th>ANALYZE</th></tr></thead><tbody id="geoRows"><tr><td colspan="5">Loading geolocation inventory...</td></tr></tbody></table></div>
        <div class="geo-pagination"><span id="geoPageInfo">—</span><div><button class="btn secondary" id="geoPrev" type="button">← PREV</button><button class="btn secondary" id="geoNext" type="button">NEXT →</button></div></div>
      </article>
    </div>
    <div class="geo-aside">
      <article class="v3panel"><div class="v3pane-title">▧ GLOBAL COUNTRY RANKING <span>EXACT MATCHED IOCS</span></div><div id="geoRanking" class="geo-ranking"><div class="empty">Loading country distribution...</div></div><div class="geo-mini-note">Percentages use all geocoded IPs, not only the mapped sample. A high count is not a count of cyberattacks.</div></article>
      <article class="v3panel"><div class="v3pane-title">⌕ SELECTED IOC INSPECTOR <span>SQLITE EVIDENCE</span></div><div id="geoInspector" class="geo-inspector"><div class="v3small">Select a plotted point or an IOC in the table for exact-match threat intelligence details.</div></div></article>
      <article class="v3panel"><div class="v3pane-title">◇ DATA INTEGRITY <span>PROVENANCE</span></div><div class="geo-integrity"><div class="signal"><span class="signal-dot good"></span><div><div class="signal-ttl">Verified local IOC matches</div><div class="signal-sub">Matching IP address exists in intelligence.db</div></div></div><div class="signal"><span class="signal-dot good"></span><div><div class="signal-ttl">Offline geolocation enrichment</div><div class="signal-sub">DB-IP CSV, no live third-party lookup</div></div></div><div class="signal"><span class="signal-dot off"></span><div><div class="signal-ttl">Attack attribution</div><div class="signal-sub">Not established by geolocation alone</div></div></div></div></article>
    </div>
  </div>
</section>
<section id="page-caseboard" class="page" aria-label="Detection review desk">
  <div class="headline-row"><div><div class="eyebrow">/// ANALYST REVIEW / 008</div><h1 class="v3hero-title">Event <span>Review Desk</span></h1><p class="desc">Review-only investigation workspace based on stored correlator detections. Case IDs are display references, not a persistent ticketing system.</p></div><div class="v3tag">READ ONLY / NO REMEDIATION</div></div>
  <div class="v3-mini-strips"><div class="v3-mini"><label>REVIEW ROWS</label><strong id="cTotal">—</strong><small>Matching events in events.db</small></div><div class="v3-mini"><label>REPEATED MATCHES</label><strong class="v3mint" id="cRepeat">—</strong><small>Observations ≥ 2 · not severity</small></div><div class="v3-mini"><label>UNREVIEWED IN UI</label><strong id="cUnreviewed">—</strong><small>No case workflow connected</small></div><div class="v3-mini"><label>DATA SOURCE</label><strong style="font-size:19px">EVENTS.DB</strong><small>Local SQLite correlation records</small></div></div>
  <div class="v3layout"><article class="v3panel"><div class="v3pane-title">◎ DETECTION REVIEW QUEUE <span>MAX 100 LATEST</span></div><div class="toolbar"><input class="field search" placeholder="Filter by IP or source..." id="caseSearch" autocomplete="off" maxlength="140" aria-label="Filter event review queue"><button class="btn secondary" type="button" id="caseRefresh">↻ REFRESH</button></div><div class="table-scroll"><table class="v3tabletable" aria-label="Read only detection review queue"><thead><tr><th>REFERENCE</th><th>INDICATOR</th><th>OBSERVATIONS</th><th>ACTIVITY</th><th>DETAILS</th></tr></thead><tbody id="caseRows"><tr><td colspan="5" class="empty">Loading correlation rows...</td></tr></tbody></table></div></article>
  <article class="v3panel"><div class="v3pane-title">⌕ EVENT INSPECTOR <span>LOCAL SQLITE</span></div><div class="v3detail" id="caseDetail"><div class="v3small">Select a row to inspect evidence fields. No automated blocking or attribution.</div></div><div class="v3callout">A database match is an investigative lead, not proof of exploitation. No EDR/packet capture, confirmed incident severity, or customer case workflow is configured.</div></article></div>
</section>

      <section id="page-intelligence" class="page" aria-label="Threat intelligence">
        <div class="headline-row"><div><div class="eyebrow">/// INVESTIGATIONS / 002</div><h1 class="headline">Indicator <span>Explorer</span></h1><p class="desc">Search and inspect locally stored indicators. Filter by category or feed and export a bounded CSV.</p></div><div class="protocol">SAFE QUERY / PARAMETERIZED SQL</div></div>
        <div class="surface pad"><div class="panel-head"><span class="panel-name"><span class="panel-icon">⌕</span>SEARCH THREAT INTELLIGENCE</span><span class="panel-pill" id="resultCount">— RECORDS</span></div>
          <form id="intelForm" class="toolbar"><input class="field search" id="intelQuery" maxlength="160" autocomplete="off" spellcheck="false" placeholder="Search IP, hostname, or source..." aria-label="Search indicators"><select class="field small" id="intelKind" aria-label="Indicator kind"><option value="">ALL TYPES</option><option value="ip">IP ADDRESS</option><option value="domain">DOMAIN</option></select><select class="field small" id="intelSource" aria-label="Indicator source"><option value="">ALL SOURCES</option></select><button type="submit" class="btn primary">⌕ SCAN</button><button type="button" id="exportBtn" class="btn secondary">↓ EXPORT CSV</button></form>
          <div class="table-scroll"><table class="datatable" aria-label="Threat indicator results"><thead><tr><th>TYPE</th><th>INDICATOR / HOST</th><th>INTEL SOURCE</th><th>FIRST OBSERVED</th><th>LAST OBSERVED</th><th>ACTION</th></tr></thead><tbody id="intelRows"><tr><td colspan="6" class="empty center">Loading records...</td></tr></tbody></table></div>
          <div class="pages"><span id="paging">—</span><button id="pagePrev" type="button">← PREVIOUS</button><button id="pageNext" type="button">NEXT →</button></div><p class="lowline">Threat intelligence alone cannot prove an endpoint was compromised. Source URLs are displayed as inert data, never executed.</p>
        </div><div class="two-col" style="margin-top:16px"><article class="surface inspector"><div class="panel-head"><span class="panel-name">◈ EXACT IOC LOOKUP</span><span class="panel-pill">NO WILDCARDS</span></div><form id="lookupForm" class="toolbar"><input class="field search" id="lookupValue" maxlength="160" placeholder="Exact IP address or hostname" aria-label="Exact indicator lookup"><button class="btn primary" type="submit">LOOK UP</button></form><div class="inspector-status inspector-hidden" id="lookupAnswer" aria-live="polite"></div><p class="section-text">An exact match flags an investigative lead. Absence from the current local feed never certifies safety.</p></article><article class="surface pad"><div class="panel-head"><span class="panel-name">▤ DOMAIN SUFFIX SNAPSHOT</span><span class="panel-pill">DATA-DRIVEN</span></div><div class="source-list" id="suffixList"><div class="empty">Loading...</div></div></article></div>
      </section>
      <section id="page-detections" class="page" aria-label="Detection timeline">
        <div class="headline-row"><div><div class="eyebrow">/// CORRELATION / 003</div><h1 class="headline">Detection <span>Timeline</span></h1><p class="desc">Recorded exact indicator matches produced by your correlator. These are not packet captures or confirmed incidents.</p></div><div class="protocol">EVENTS.DB / READ ONLY</div></div>
        <div class="three-col" style="margin-bottom:16px"><div class="surface pad"><div class="kicker">RECORDED MATCHES</div><div class="metric-xl" id="detTotal">—</div><div class="section-text">Unique detection rows in the events database.</div></div><div class="surface pad"><div class="kicker">PENDING ALERTS</div><div class="metric-xl" id="detPending">—</div><div class="section-text">Telegram delivery queue records awaiting sent_at.</div></div><div class="surface pad"><div class="kicker">SENT ALERTS</div><div class="metric-xl" id="detSent">—</div><div class="section-text">Delivery state recorded in the local alert database.</div></div></div>
        <div class="surface pad"><div class="panel-head"><span class="panel-name"><span class="panel-icon">◎</span>RECENT CORRELATION EVENTS</span><span class="panel-pill">UP TO 100 ROWS</span></div><div class="table-scroll"><table class="datatable"><thead><tr><th>OBSERVED IP</th><th>SOURCE</th><th>OBSERVATIONS</th><th>FIRST RECORDED</th><th>LAST RECORDED</th><th>LOOK UP</th></tr></thead><tbody id="detRows"><tr><td colspan="6" class="empty center">Loading...</td></tr></tbody></table></div><p class="lowline">Caution: router conntrack sampling may not cover all traffic; zero matches cannot demonstrate a secure network.</p></div>
      </section>
      <section id="page-operations" class="page" aria-label="Operations">
        <div class="headline-row"><div><div class="eyebrow">/// ANALYST WORKSPACE / 004</div><h1 class="headline">Security <span>Operations</span></h1><p class="desc">The collection-to-alert pipeline, investigation entry points, and integration readiness. No fabricated AI decisions.</p></div><div class="protocol">PIPELINE STATUS / DESCRIPTIVE</div></div>
        <div class="surface pad"><div class="panel-head"><span class="panel-name"><span class="panel-icon">⌘</span>DEFENSIVE INTELLIGENCE PIPELINE</span><span class="panel-pill">ARCHITECTURE VIEW</span></div><div class="pipeline"><div class="pipe"><div class="pipe-top">STAGE 01</div><div class="pipe-icon">⌁</div><h3>Threat feed collection</h3><p>External collector populates SQLite indicator records.</p><div class="arrow">→</div></div><div class="pipe"><div class="pipe-top">STAGE 02</div><div class="pipe-icon">▦</div><h3>IOC normalization</h3><p>IP / hostname records indexed for exact investigations.</p><div class="arrow">→</div></div><div class="pipe"><div class="pipe-top">STAGE 03</div><div class="pipe-icon">◇</div><h3>Correlation</h3><p>Separate router script compares sampled destination IPs.</p><div class="arrow">→</div></div><div class="pipe"><div class="pipe-top">STAGE 04</div><div class="pipe-icon">↗</div><h3>Alerts & review</h3><p>Matches stored; Telegram sender is separate backend logic.</p></div></div><div class="helptext">This diagram describes the configured software architecture, not proof that every stage ran recently. Collector scheduling and router reachability need independent checks.</div></div>
        <div class="two-col" style="margin-top:16px"><article class="surface pad"><div class="panel-head"><span class="panel-name">◉ FEED OPERATIONS</span><span class="panel-pill">DB STATUS</span></div><div class="stat-pair"><span>Stored indicators</span><span id="opIndicators">—</span></div><div class="stat-pair"><span>Last indicator timestamp</span><span id="opLast">—</span></div><div class="stat-pair"><span>Age of newest indicator</span><span id="opAge">—</span></div><div class="stat-pair"><span>Distinct feed sources</span><span id="opSources">—</span></div><div class="stat-pair"><span>Automatic IP blocking</span><span>NOT ENABLED</span></div><div class="lowline">A timestamp on an indicator is not direct proof of the collector schedule or network sensor health.</div></article><article class="surface pad"><div class="panel-head"><span class="panel-name">◫ IP /8 DISTRIBUTION</span><span class="panel-pill">NOT GEOLOCATION</span></div><div class="source-list" id="prefixList"><div class="empty">Loading...</div></div><div class="hint">Groups IPv4 indicators by first octet. IP prefixes do not establish location, ownership, or attack origin.</div></article></div>
      </section>
      <section id="page-system" class="page" aria-label="System and health">
        <div class="headline-row"><div><div class="eyebrow">/// PLATFORM HEALTH / 005</div><h1 class="headline">System <span>Observability</span></h1><p class="desc">Transparent integration coverage, backend diagnostics, and deployment readiness for future commercial work.</p></div><div class="protocol">DIAGNOSTICS / NO SECRETS</div></div>
        <div class="two-col"><article class="surface pad"><div class="panel-head"><span class="panel-name">▦ BACKEND COMPONENTS</span><span class="panel-pill teal">READ-ONLY PROBE</span></div><div id="components"><div class="empty">Connecting...</div></div><div class="stat-pair"><span>Dashboard build</span><span id="sysVersion">—</span></div><div class="stat-pair"><span>API binding</span><span>127.0.0.1:8765*</span></div><div class="stat-pair"><span>Data access</span><span>SQLITE READ ONLY</span></div><div class="stat-pair"><span>Refresh cadence</span><span>30 SECONDS</span></div><div class="lowline">* Unless the local DEVIL_PORT override is configured. Public authentication is enforced by Nginx, not this Python process.</div></article><article class="surface pad"><div class="panel-head"><span class="panel-name">◇ INTEGRATION MATURITY</span><span class="panel-pill">HONEST COVERAGE</span></div><div id="integrations"><div class="empty">Loading...</div></div></article></div>
        <div class="banner"><p><strong>Commercial readiness / engineering note</strong><br>This release is a polished analyst dashboard prototype, not a certified enterprise SIEM. Selling to organizations responsibly requires tenant isolation, RBAC, audit trails, privacy controls, hardened deployment, backup and incident procedures, and security testing.</p></div>
        <div class="surface pad"><div class="panel-head"><span class="panel-name">⌘ OPERATOR SHORTCUTS</span><span class="panel-pill">KEYBOARD</span></div><div class="three-col"><div class="logline">CTRL / CMD + K → Search intelligence</div><div class="logline">CTRL / CMD + R → Browser refresh</div><div class="logline">SYNC button → Fetch latest database snapshot</div></div><div class="lowline">Security boundaries: no public Python listener · no external JavaScript dependencies · no automated containment · authentication at reverse proxy.</div></div>
      </section>
    </main>
  </div>
</div>
<div id="toasts" class="toast-container" role="status" aria-live="polite"></div>
<script>
'use strict';
const $=id=>document.getElementById(id),fmt=n=>Number(n||0).toLocaleString('en-US');
const state={current:'overview',page:1,query:'',kind:'',source:'',status:null,events:[],lastFetch:0,busy:false};
const text=(id,val)=>{const e=$(id);if(e)e.textContent=val??'—'};
const elt=(tag,cls='',str)=>{const e=document.createElement(tag);if(cls)e.className=cls;if(str!==undefined)e.textContent=String(str);return e};
const nfmt=t=>t==null||t===''?'—':String(t).replace('T',' ').replace('+00:00','Z');
const esc=(v)=>String(v??''); // All variable content is inserted via textContent, never innerHTML.
const aTime=v=>{if(!v)return 'N/A';const d=new Date(String(v).replace(' ','T'));return Number.isNaN(d.getTime())?String(v):d.toLocaleString('en-GB',{month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit',timeZone:'UTC'})+' UTC'};
function toast(msg,error=false){const e=elt('div',error?'toast error':'toast',msg);$('toasts').append(e);setTimeout(()=>e.remove(),4000)}
function emptyBody(id,col,msg){const target=$(id);target.replaceChildren();const row=elt('tr'),td=elt('td','empty center',msg);td.colSpan=col;row.append(td);target.append(row)}
function nav(page){if(!['overview','intelligence','detections','operations','system','pulse','atlas','caseboard'].includes(page))return;state.current=page;document.querySelectorAll('.nav-btn').forEach(b=>{const active=b.dataset.page===page;b.classList.toggle('active',active);b.setAttribute('aria-current',active?'page':'false')});document.querySelectorAll('.page').forEach(s=>s.classList.toggle('active',s.id==='page-'+page));text('breadcrumb',({overview:'COMMAND OVERVIEW',intelligence:'THREAT INTELLIGENCE',detections:'DETECTION TIMELINE',operations:'OPERATIONS',system:'SYSTEM & HEALTH',pulse:'LIVE SYSTEM PULSE',atlas:'THREAT ATLAS',caseboard:'EVENT REVIEW DESK'})[page]);window.scrollTo({top:0,behavior:'auto'});if(page==='intelligence')loadIntelligence();if(page==='detections')loadEvents();if(page==='system')loadSystem();if(page==='pulse')v3FetchPulse();if(page==='atlas')v3LoadAtlas();if(page==='caseboard')v3LoadCases();if(page==='overview')setTimeout(drawGlobe,100)}
document.querySelectorAll('.nav-btn').forEach(b=>b.addEventListener('click',()=>nav(b.dataset.page)));
document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();nav('intelligence');$('intelQuery').focus()}});
async function api(path){const ac=new AbortController();const timer=setTimeout(()=>ac.abort(),11000);try{const r=await fetch(path,{cache:'no-store',signal:ac.signal,credentials:'same-origin'});if(!r.ok)throw Error('HTTP '+r.status);return await r.json()}finally{clearTimeout(timer)}}
function barList(id,arr,labelFn,nameFn){const box=$(id);box.replaceChildren();if(!arr||!arr.length){box.append(elt('div','empty','No records available'));return}const m=Math.max(1,...arr.map(x=>Number(x.n||0)));for(const item of arr){const wrap=elt('div','source-row'),left=elt('div'),ttl=elt('div','source-title',nameFn(item)),track=elt('div','track'),fill=elt('div'),right=elt('div','source-val',fmt(item.n));fill.style.width=Math.max(1,Math.round(Number(item.n||0)/m*100))+'%';track.append(fill);left.append(ttl,track);wrap.append(left,right);box.append(wrap)}}
function renderBars(days){const c=$('collectionBars'),x=$('collectionLabels');c.replaceChildren();x.replaceChildren();if(!days?.length){c.append(elt('div','empty','No dated indicator records'));return}const max=Math.max(1,...days.map(r=>Number(r.n)));const length=days.length;days.forEach((row,i)=>{const e=elt('div','barcell'),bar=elt('div','b');bar.style.height=Math.max(2,Math.round((row.n/max)*165))+'px';bar.title=row.day+': '+fmt(row.n)+' indicator records';e.append(bar);c.append(e);const l=elt('span','',((i===0||i===length-1||i%Math.max(1,Math.floor(length/5))===0)?(row.day||'').slice(5):''));x.append(l)})}
function eventCards(rows){const target=$('eventMini');target.replaceChildren();if(!rows?.length){target.append(elt('div','empty','No correlations recorded. This does not establish network safety.'));return}for(const row of rows.slice(0,6)){const e=elt('div','event');const ico=elt('div','event-point','◎');const body=elt('div','event-main');body.append(elt('div','event-ip',row.ip||'Unknown IP'),elt('div','event-extra',`${row.source||'Source unknown'} / ${row.observations??0} observations`));e.append(ico,body,elt('div','event-time',aTime(row.last_seen)));target.append(e)}}
function signal(title,detail,flag,value){const e=elt('div','signal'),dot=elt('div','signal-dot '+flag),middle=elt('div'),ttl=elt('div','signal-ttl',title),sub=elt('div','signal-sub',detail),v=elt('div','signal-val',value);middle.append(ttl,sub);e.append(dot,middle,v);return e}
function showStatus(s){state.status=s;state.lastFetch=Date.now();text('connection','DB POLLING / 30s');text('sideHealth',s.health?.intel_db?'DATABASE ONLINE':'DATABASE MISSING');const maps={kTotal:s.total,kIp:s.ip,kDomain:s.domain,kDetections:s.detections,kPending:s.pending,kSent:s.sent,mixIp:s.ip,mixDomains:s.domain,mixOther:s.other,detTotal:s.detections,detPending:s.pending,detSent:s.sent,opIndicators:s.total};for(const [k,v] of Object.entries(maps))text(k,fmt(v));const ipshare=s.total?Math.round((s.ip/s.total)*100):0;text('percentIp',ipshare+'%');$('composition').style.setProperty('--mix',(s.total?(s.ip/s.total)*100:0)+'%');barList('sourceList',s.sources,r=>r.n,r=>(r.source??'(unspecified)'));barList('suffixList',s.suffixes,r=>r.n,r=>r.suffix);barList('prefixList',s.ip_octets,r=>r.n,r=>(r.octet||'?')+'.0.0.0/8');renderBars(s.collection_days);eventCards(s.recent);const sig=$('statusSignals');sig.replaceChildren();sig.append(signal('Threat indicators database','SQLite indexed records',s.health?.intel_db?'good':'off',s.health?.intel_db?'AVAILABLE':'MISSING'));sig.append(signal('Correlation event store','Stored matches only',s.health?.events_db?'good':'off',s.health?.events_db?'AVAILABLE':'MISSING'));sig.append(signal('Data recency','Newest indicator last_seen',s.health?.feeds_status==='STALE >24H'?'warn':'good',s.health?.feeds_status||'UNKNOWN'));sig.append(signal('Geolocation service','No location enrichment','off','NOT LINKED'));text('updated','LAST SYNC '+aTime(s.timestamp)+' · NEWEST FEED '+aTime(s.last_collection));text('opLast',nfmt(s.last_collection));text('opAge',s.feed_age_hours==null?'UNKNOWN':s.feed_age_hours+' HOURS');text('opSources',fmt(s.sources?.length));populateSources(s.sources||[])}
function populateSources(sources){const sel=$('intelSource'),old=sel.value;sel.replaceChildren(new Option('ALL SOURCES',''));for(const s of sources){sel.append(new Option((s.source||'(unspecified)').slice(0,75),s.source||''))}sel.value=old}
async function refresh(){if(state.busy)return;state.busy=true;text('connection','SYNCING...');try{const s=await api('/api/status');showStatus(s);if(state.current==='detections')loadEvents();if(state.current==='system')loadSystem()}catch(e){text('connection','DATA UNAVAILABLE');text('sideHealth','API ERROR');toast('Unable to refresh: '+e.message,true)}finally{state.busy=false}}
$('refresh').addEventListener('click',()=>{refresh();toast('Database snapshot requested')});
function td(value,cls=''){return elt('td',cls,value==null?'—':String(value))}
async function loadIntelligence(){const qs=new URLSearchParams({q:state.query,kind:state.kind,source:state.source,page:state.page,limit:40});emptyBody('intelRows',6,'Querying local indicators...');try{const data=await api('/api/indicators?'+qs.toString());const b=$('intelRows');b.replaceChildren();text('resultCount',fmt(data.total)+' RECORDS');text('paging',`PAGE ${data.page} / ${Math.max(1,Math.ceil(data.total/40))} · ${fmt(data.total)} RECORDS`);$('pagePrev').disabled=state.page<=1;$('pageNext').disabled=state.page*40>=data.total||state.page>=125;if(!data.items.length){emptyBody('intelRows',6,'No matching indicators. This does not imply safety.');return}for(const row of data.items){const tr=elt('tr');const kind=elt('td'),chip=elt('span','type-chip '+(row.kind==='domain'?'domain':row.kind==='ip'?'':'other'),String(row.kind||'OTHER').toUpperCase());kind.append(chip);const val=elt('td','value');val.append(document.createTextNode(row.value||''));const copy=elt('button','copyrow','⧉');copy.title='Copy indicator';copy.setAttribute('aria-label','Copy indicator');copy.addEventListener('click',()=>copyText(row.value||''));val.append(copy);tr.append(kind,val,td(row.source||'—'),td(nfmt(row.first_seen),'date'),td(nfmt(row.last_seen),'date'));const action=elt('td'),inspect=elt('button','copyrow','INSPECT →');inspect.addEventListener('click',()=>{$('lookupValue').value=row.value;lookup();$('lookupValue').scrollIntoView({behavior:'smooth',block:'center'})});action.append(inspect);tr.append(action);b.append(tr)}}catch(e){emptyBody('intelRows',6,'Search unavailable: '+e.message);toast('Search request failed',true)}}
async function copyText(val){try{await navigator.clipboard.writeText(String(val));toast('Indicator copied')}catch(e){toast('Clipboard unavailable in this context',true)}}
$('intelForm').addEventListener('submit',e=>{e.preventDefault();state.query=$('intelQuery').value.trim();state.kind=$('intelKind').value;state.source=$('intelSource').value;state.page=1;loadIntelligence()});$('pagePrev').addEventListener('click',()=>{if(state.page>1){state.page--;loadIntelligence()}});$('pageNext').addEventListener('click',()=>{if(state.page<125){state.page++;loadIntelligence()}});
$('exportBtn').addEventListener('click',()=>{const query=new URLSearchParams({q:state.query,kind:state.kind,source:state.source});const a=document.createElement('a');a.href='/api/export.csv?'+query.toString();a.download='devil-indicators.csv';document.body.append(a);a.click();a.remove();toast('CSV export requested (max 1,000 rows)')});
$('lookupForm').addEventListener('submit',e=>{e.preventDefault();lookup()});async function lookup(){const value=$('lookupValue').value.trim(),box=$('lookupAnswer');if(!value){toast('Enter an exact IP address or hostname',true);return}box.classList.remove('inspector-hidden');box.replaceChildren(elt('p','','Checking local database...'));try{const d=await api('/api/lookup?value='+encodeURIComponent(value));box.classList.toggle('not-found',!d.matches?.length);box.replaceChildren(elt('b','',d.verdict==='INTEL_MATCH'?'◈ LOCAL INTELLIGENCE MATCH':'◇ NOT IN LOCAL FEED'),elt('p','',d.note||''));for(const r of (d.matches||[]).slice(0,8))box.append(elt('p','',`${r.kind||'IOC'} · ${r.value} · ${r.source||'unspecified'}`))}catch(e){box.replaceChildren(elt('p','','Lookup error: '+e.message))}}
async function loadEvents(){try{const d=await api('/api/events'),b=$('detRows');state.events=d.items||[];b.replaceChildren();if(!state.events.length){emptyBody('detRows',6,'No detections recorded. Zero events is not a proof of a clean network.');return}for(const r of state.events){const tr=elt('tr');tr.append(td(r.ip,'value'),td(r.source),td(fmt(r.observations)),td(nfmt(r.first_seen)),td(nfmt(r.last_seen)));const last=elt('td'),btn=elt('button','copyrow','EXACT IOC →');btn.addEventListener('click',()=>{nav('intelligence');$('lookupValue').value=r.ip;lookup()});last.append(btn);tr.append(last);b.append(tr)}}catch(e){emptyBody('detRows',6,'Events unavailable: '+e.message)}}
function cap(title,details,enabled){const e=elt('div','capability');e.append(elt('div','cap-icon',enabled?'✓':'·'));const txt=elt('div');txt.append(elt('div','cap-title',title),elt('div','cap-info',details));e.append(txt,elt('span','cap-badge '+(enabled?'lime':'amber'),enabled?'AVAILABLE':'NOT CONNECTED'));return e}
async function loadSystem(){try{const d=await api('/api/system');text('sysVersion',d.version);const box=$('components');box.replaceChildren();for(const c of d.components){box.append(signal(c.component,c.size_bytes==null?'No database file':fmt(c.size_bytes)+' bytes',c.available?'good':'off',c.available?'PRESENT':'MISSING'))}const x=$('integrations');x.replaceChildren();x.append(cap('Read-only SQLite exploration','Local indicators, correlations, filters and CSV',true));x.append(cap('Authentication gateway','Reverse proxy access is configured separately; not verified by this API',false));x.append(cap('Geolocation enrichment','Requires licensed GeoIP and additional verified processing',false));x.append(cap('Enterprise account roles','SSO, RBAC, MFA, multi-user audit logging required',false));x.append(cap('Endpoint telemetry','No EDR, sysmon agent, or full packet capture integration',false));x.append(cap('Case management','Incident workflows, approvals, SLAs not implemented',false))}catch(e){toast('System diagnostics unavailable',true)}}
function tick(){text('clock',new Date().toLocaleTimeString('en-GB',{timeZone:'UTC',hour12:false})+' UTC')};tick();setInterval(tick,1000);refresh();setInterval(refresh,30000);
// VISUALIZATION ONLY: stylized sphere, orbit paths and pulsing objects are not geolocated incidents.
const canvas=$('globe');let gw=0,gh=0,dpr=1,globeStart=performance.now(),mouse={x:0,y:0},frame=0;
function sizeGlobe(){const box=$('globeBox'),r=box.getBoundingClientRect();if(!r.width||!r.height)return;dpr=Math.min(window.devicePixelRatio||1,2);gw=r.width;gh=r.height;canvas.width=Math.round(gw*dpr);canvas.height=Math.round(gh*dpr);canvas.style.width=gw+'px';canvas.style.height=gh+'px'}
function project(lat,lon,spin,cx,cy,R){let p=lat*Math.PI/180,l=lon*Math.PI/180+spin;let X=Math.cos(p)*Math.sin(l),Y=Math.sin(p),Z=Math.cos(p)*Math.cos(l);return {x:cx+X*R,y:cy-Y*R,z:Z}}
function drawGlobe(){if(state.current!=='overview')return;const r=$('globeBox').getBoundingClientRect();if(!r.width)return;if(Math.abs(r.width-gw)>2||Math.abs(r.height-gh)>2)sizeGlobe();const c=canvas.getContext('2d');if(!c)return;c.setTransform(dpr,0,0,dpr,0,0);c.clearRect(0,0,gw,gh);const t=(performance.now()-globeStart)/1000,reduce=window.matchMedia('(prefers-reduced-motion: reduce)').matches;let spin=reduce?0.26:(t*0.09+.25);const cx=gw*.50,cy=gh*.50,R=Math.min(gw*.35,gh*.42,178);if(R<20)return;
 // Back glow + filled sphere.
 const halo=c.createRadialGradient(cx,cy,20,cx,cy,R*1.35);halo.addColorStop(0,'rgba(12,71,89,.43)');halo.addColorStop(.55,'rgba(4,46,65,.19)');halo.addColorStop(1,'rgba(0,0,0,0)');c.fillStyle=halo;c.beginPath();c.arc(cx,cy,R*1.35,0,Math.PI*2);c.fill();
 const core=c.createRadialGradient(cx-R*.32,cy-R*.32,R*.04,cx,cy,R);core.addColorStop(0,'rgba(19,67,88,.30)');core.addColorStop(.72,'rgba(4,28,44,.42)');core.addColorStop(1,'rgba(6,17,27,.72)');c.fillStyle=core;c.beginPath();c.arc(cx,cy,R,0,Math.PI*2);c.fill();
 c.save();c.beginPath();c.arc(cx,cy,R,0,Math.PI*2);c.clip();
 function path(points,front,color,alpha){c.beginPath();let started=false;for(const p of points){if(front&&p.z<-.025){started=false;continue}if(!started){c.moveTo(p.x,p.y);started=true}else c.lineTo(p.x,p.y)}c.strokeStyle=color;c.globalAlpha=alpha;c.stroke();c.globalAlpha=1}
 c.lineWidth=.85;
 for(let lat=-75;lat<=75;lat+=15){const arr=[];for(let lon=-180;lon<=180;lon+=2.5)arr.push(project(lat,lon,spin,cx,cy,R));path(arr,true,'#3295b2',lat===0?.60:.25)}
 for(let lon=-180;lon<180;lon+=15){const arr=[];for(let lat=-90;lat<=90;lat+=2)arr.push(project(lat,lon,spin,cx,cy,R));path(arr,true,'#2f8eab',lon%45===0?.46:.23)}
 // Stylized vector routes deliberately not attributed to geographic origins.
 const points=[[-20,-122],[39,-70],[16,82],[-28,25],[42,125],[57,-8],[-13,148],[5,-42]];
 for(let i=0;i<points.length;i++){const a=project(points[i][0],points[i][1],spin,cx,cy,R),b=project(points[(i+3)%points.length][0],points[(i+3)%points.length][1],spin,cx,cy,R);if(a.z<0||b.z<0)continue;c.beginPath();c.moveTo(a.x,a.y);c.quadraticCurveTo((a.x+b.x)/2,Math.min(a.y,b.y)-24,(b.x),(b.y));c.strokeStyle='rgba(89,223,248,.25)';c.lineWidth=1;c.stroke();c.beginPath();c.arc(a.x,a.y,2.1,0,Math.PI*2);c.fillStyle='#6de9ff';c.shadowBlur=13;c.shadowColor='#5ce7fb';c.fill();c.shadowBlur=0}
 c.restore();c.beginPath();c.arc(cx,cy,R,0,Math.PI*2);c.lineWidth=1.6;c.strokeStyle='#4cb5d166';c.stroke();
 // Outer orbital rings & dynamic scanner: decorative instrumentation.
 for(let j=0;j<3;j++){c.beginPath();c.ellipse(cx,cy,R*(1.10+j*.15),R*(.37+j*.07),(j%2?-.19:.23),0,Math.PI*2);c.strokeStyle=`rgba(67,167,207,${.18-j*.04})`;c.lineWidth=1;c.stroke()}
 c.beginPath();c.arc(cx,cy,R*1.10,spin,spin+.46);c.lineWidth=2;c.strokeStyle='#66e6ff';c.shadowBlur=19;c.shadowColor='#53e1ff';c.stroke();c.shadowBlur=0;
 // Side tick marks for instrumentation.
 c.fillStyle='#517e93';c.font='9px ui-monospace,monospace';c.fillText('LAT 00.00',Math.max(12,cx-R-76),cy-10);c.fillText('LON 00.00',Math.min(gw-72,cx+R+19),cy+8);
 }
function loop(){if(document.visibilityState==='visible'&&state.current==='overview'){drawGlobe()}if(!window.matchMedia('(prefers-reduced-motion: reduce)').matches)requestAnimationFrame(loop)}
window.addEventListener('resize',()=>{sizeGlobe();drawGlobe()});document.addEventListener('visibilitychange',()=>{if(!document.hidden)drawGlobe()});sizeGlobe();drawGlobe();if(!window.matchMedia('(prefers-reduced-motion: reduce)').matches)requestAnimationFrame(loop);

/* DEVIL v3 instrumentation. Browser draws only server-observed measurements. */
let v3Metrics=null,v3Atlas=null,v3Cases=[],v3Running=false;
const v3Value=(v,fallback='—')=>(v===null||v===undefined||!Number.isFinite(Number(v)))?fallback:Number(v);
const v3Percent=(v)=>typeof v==='number'&&Number.isFinite(v)?v.toFixed(1)+'%':'—';
const v3Byte=(v)=>{if(v==null||!Number.isFinite(Number(v)))return '—';const units=['B','KB','MB','GB','TB'];let n=Number(v),i=0;while(n>=1024&&i<units.length-1){n/=1024;i++}return n.toFixed(i===0?0:n<10?1:0)+' '+units[i]};
const v3SetWidth=(id,val)=>{const e=$(id);if(e)e.style.width=(Number.isFinite(val)?Math.max(0,Math.min(100,val)):0)+'%'};
function v3CanvasPrep(canvas,height){if(!canvas)return null;const box=canvas.getBoundingClientRect();const w=Math.max(100,box.width||600),h=height||box.height||200,d=Math.min(window.devicePixelRatio||1,2);canvas.width=Math.round(w*d);canvas.height=Math.round(h*d);const c=canvas.getContext('2d');if(!c)return null;c.setTransform(d,0,0,d,0,0);return {c,w,h};}
function v3Graph(id,series,maxValue,labels){const el=$(id);const setup=v3CanvasPrep(el,205);if(!setup)return;const {c,w,h}=setup;const l=35,r=w-15,t=22,b=h-31;c.clearRect(0,0,w,h);for(let i=0;i<=4;i++){let y=t+(b-t)*i/4;c.beginPath();c.moveTo(l,y);c.lineTo(r,y);c.strokeStyle='#2e506270';c.lineWidth=1;c.stroke();c.fillStyle='#718fa6';c.font='9px monospace';c.fillText(String(Math.round(maxValue*(4-i)/4)),5,y+3)}for(let i=0;i<=5;i++){let x=l+(r-l)*i/5;c.beginPath();c.moveTo(x,t);c.lineTo(x,b);c.strokeStyle='#23405548';c.stroke();}
for(const s of series){const rows=s.values||[];let started=false;c.beginPath();rows.forEach((v,i)=>{if(v==null||!Number.isFinite(v)){started=false;return}let x=l+(r-l)*(rows.length===1?1:i/(rows.length-1)),y=b-Math.max(0,Math.min(maxValue,v))/maxValue*(b-t);if(!started){c.moveTo(x,y);started=true}else{c.lineTo(x,y)}});c.strokeStyle=s.color;c.lineWidth=2.1;c.shadowBlur=11;c.shadowColor=s.color;c.stroke();c.shadowBlur=0;if(rows.length){let last=rows[rows.length-1];if(last!=null&&Number.isFinite(last)){let x=r,y=b-Math.min(maxValue,last)/maxValue*(b-t);c.fillStyle=s.color;c.beginPath();c.arc(x,y,3.1,0,Math.PI*2);c.fill()}}}
c.fillStyle='#6d899d';c.font='9px monospace';c.fillText('OLDER',l,b+18);c.textAlign='right';c.fillText('NOW',r,b+18);c.textAlign='left';if(!series.some(s=>s.values.some(x=>Number.isFinite(x)))){c.fillStyle='#819db1';c.font='12px monospace';c.textAlign='center';c.fillText('WAITING FOR FIRST RATE SAMPLE',w/2,h/2);c.textAlign='left'}}
function v3RenderPulse(d){v3Metrics=d;const p=d.latest||{},tcp=p.tcp||{},disk=p.disk||{};text('pCpu',v3Percent(p.cpu_percent));text('pRam',v3Percent(p.ram_percent));text('pRx',p.rx_bytes_per_sec===null?'—':v3Byte(p.rx_bytes_per_sec)+'/s');text('pTx',p.tx_bytes_per_sec===null?'—':v3Byte(p.tx_bytes_per_sec)+'/s');text('pMemDetail',p.ram_total_bytes?v3Byte(p.ram_available_bytes)+' available of '+v3Byte(p.ram_total_bytes):'RAM metrics unavailable');text('pNic',p.network_interface?'Interface '+p.network_interface:'No default-route interface');text('pDisk',v3Percent(disk.used_percent));text('pSwap',v3Byte(p.swap_used_bytes));text('pTcp',fmt(tcp.established));text('pUptime',p.uptime_seconds!=null?Math.floor(p.uptime_seconds/86400)+'d '+Math.floor(p.uptime_seconds%86400/3600)+'h':'—');v3SetWidth('barCpu',p.cpu_percent);v3SetWidth('barRam',p.ram_percent);text('pCheck',p.ram_percent!=null&&p.ram_percent>90?'HIGH MEMORY USAGE':'LINUX PROC / ACTIVE');text('oCpu',v3Percent(p.cpu_percent));text('oMem',v3Byte(p.ram_available_bytes));text('oRx',p.rx_bytes_per_sec===null?'—':v3Byte(p.rx_bytes_per_sec)+'/s');text('oTcp',fmt(tcp.established));if(state.current!=='pulse')return;
const h=d.history||[];v3Graph('cpuChart',[{values:h.map(x=>x.cpu_percent),color:'#4de8ff'},{values:h.map(x=>x.ram_percent),color:'#b79aff'}],100);let max=Math.max(1024,...h.flatMap(x=>[x.rx_bytes_per_sec||0,x.tx_bytes_per_sec||0]));max=Math.max(1024,Math.ceil(max/1024)*1024);v3Graph('netChart',[{values:h.map(x=>x.rx_bytes_per_sec),color:'#4de8ff'},{values:h.map(x=>x.tx_bytes_per_sec),color:'#a2ff88'}],max);
const box=$('pulseCoverage');box.replaceChildren();box.append(signal('Host CPU / RAM / disk','Linux /proc and statvfs','good','CONNECTED'));box.append(signal('Host interface throughput','Default-route interface counters',p.network_interface?'good':'warn',p.network_interface||'UNAVAILABLE'));box.append(signal('Exact-match IOC correlation','Separate router job; not full coverage',state.status?.health?.events_db?'good':'off',state.status?.health?.events_db?'DB AVAILABLE':'NO DB'));box.append(signal('Deep packet inspection','No packet sensor or stored payloads','off','NOT ENABLED'));box.append(signal('Endpoint detection agents','No Sysmon or EDR connector','off','NOT CONFIGURED'));}
async function v3FetchPulse(){if(document.hidden||v3Running)return;v3Running=true;try{v3RenderPulse(await api('/api/telemetry'))}catch(e){if(state.current==='pulse')text('pCheck','TELEMETRY UNAVAILABLE')}finally{v3Running=false}}
const GEO_COASTS=[[[-180.0,69.0],[-175.3,67.7],[-173.9,66.1],[-174.6,67.1],[-173.6,67.1],[-171.7,66.9],[-169.7,66.1],[-170.6,65.6],[-171.4,65.8],[-171.1,65.5],[-173.0,65.7],[-172.1,65.5],[-172.1,65.0],[-173.2,64.8],[-172.2,64.4],[-173.2,64.2],[-173.3,64.6],[-173.7,64.3],[-175.4,64.8],[-176.5,65.5],[-178.4,65.5],[-178.5,66.4],[-179.4,66.3],[-179.3,65.5],[-180.0,65.1]],[[180.0,65.1],[179.5,64.8],[175.1,64.7],[176.2,64.7],[176.1,64.4],[177.5,64.7],[178.2,64.2],[178.2,64.4],[179.6,62.7],[179.1,62.3],[177.1,62.5],[173.5,61.8],[170.5,60.4],[170.3,59.9],[169.3,60.6],[167.0,60.4],[166.3,59.8],[166.3,60.5],[164.8,59.8],[164.5,60.1],[163.6,60.0],[161.9,58.0],[163.3,57.7],[162.7,57.3],[163.4,56.2],[162.1,56.1],[162.1,54.7],[160.0,54.2],[160.0,53.1],[158.4,53.0],[158.5,52.3],[156.7,50.9],[155.6,55.2],[156.0,56.7],[156.9,57.8],[158.3,58.0],[161.9,60.4],[163.8,60.8],[164.1,62.3],[165.3,62.5],[164.6,62.7],[163.3,62.5],[163.3,61.7],[162.4,61.7],[160.2,60.6],[160.4,61.0],[159.8,60.9],[159.8,61.2],[160.4,62.0],[156.7,61.5],[154.2,59.9],[154.1,59.5],[155.0,59.5],[155.2,59.2],[151.3,58.8],[151.1,59.1],[152.3,59.2],[149.4,59.8],[148.9,59.2],[146.5,59.5],[146.0,59.1],[145.7,59.4],[142.5,59.2],[138.2,56.4],[135.2,54.9],[135.7,54.6],[136.8,54.6],[136.8,53.8],[137.7,54.3],[137.3,53.5],[138.6,54.0],[138.7,54.3],[139.7,54.3],[141.4,53.3],[141.2,53.0],[140.6,53.1],[141.5,52.2],[140.4,50.7],[140.4,49.0],[138.1,46.2],[135.1,43.5],[133.0,42.7],[131.8,43.3],[131.2,42.6],[130.7,42.7],[130.7,42.3],[129.8,41.8],[129.7,40.8],[127.5,39.7],[127.4,39.2],[128.4,38.7],[129.4,37.1],[129.6,36.0],[129.1,35.1],[128.6,35.2],[128.4,34.8],[127.7,35.0],[127.8,34.6],[127.5,34.9],[127.3,34.4],[127.2,34.8],[126.5,34.3],[126.3,34.6],[126.6,34.6],[126.2,35.1],[126.9,36.1],[126.5,36.1],[126.5,36.7],[126.4,36.4],[126.1,36.8],[126.5,37.1],[126.9,36.8],[126.5,37.8],[125.6,38.0],[125.5,37.9],[125.0,37.9],[125.3,38.1],[124.7,38.1],[125.0,38.6],[125.6,38.6],[125.1,38.9],[125.6,39.7],[123.6,39.9],[121.1,38.7],[121.9,39.4],[121.2,39.4],[122.3,40.5],[121.9,41.0],[121.0,40.8],[119.0,39.2],[117.7,39.1],[117.7,38.4],[118.8,38.2],[119.2,37.1],[120.7,37.8],[122.7,37.4],[122.5,36.9],[122.0,37.0],[120.8,36.6],[120.7,36.1],[120.1,36.2],[120.3,36.0],[119.2,35.0],[119.2,34.7],[120.3,34.3],[120.9,32.6],[121.9,31.7],[120.1,32.0],[120.8,31.9],[121.9,30.9],[120.1,30.2],[121.3,30.3],[122.1,29.9],[121.4,29.5],[122.0,29.6],[122.0,29.2],[121.4,29.2],[121.7,28.9],[121.3,28.7],[121.6,28.3],[120.6,28.1],[120.9,27.9],[120.1,26.6],[119.5,26.8],[119.8,26.4],[119.6,26.4],[120.0,26.4],[119.5,26.1],[119.7,25.4],[119.3,25.6],[119.3,25.2],[118.9,25.2],[119.0,24.9],[118.6,24.9],[118.7,24.6],[117.8,24.5],[118.1,24.3],[117.6,23.7],[117.4,23.9],[117.2,23.6],[116.5,23.4],[116.7,23.2],[116.5,22.9],[115.6,22.7],[115.3,22.9],[114.9,22.5],[114.8,22.8],[114.2,22.5],[114.3,22.3],[113.4,23.1],[113.5,22.2],[113.3,22.4],[113.1,22.1],[112.9,22.5],[112.9,21.9],[112.4,22.0],[112.3,21.7],[111.7,21.8],[111.6,21.5],[110.4,21.2],[110.4,21.4],[110.3,20.2],[109.9,20.2],[109.7,20.9],[110.0,21.5],[109.6,21.8],[109.2,21.4],[108.6,21.9],[108.5,21.6],[107.8,21.5],[107.3,21.0],[106.6,21.0],[106.8,20.7],[106.6,20.8],[106.6,20.3],[105.9,19.9],[105.6,18.9],[107.1,16.9],[108.3,16.1],[108.9,15.2],[109.5,12.6],[109.2,12.6],[109.0,11.4],[107.3,10.4],[106.7,10.6],[106.8,10.3],[106.4,10.3],[106.8,10.1],[106.4,10.2],[106.6,9.8],[106.2,10.2],[106.5,9.6],[105.8,10.0],[106.2,9.4],[105.3,8.8],[104.8,8.8],[105.1,10.0],[103.9,10.7],[103.6,10.5],[103.6,11.2],[103.1,10.9],[102.6,12.2],[101.8,12.7],[100.9,12.6],[101.0,13.5],[100.0,13.3],[100.0,12.2],[99.2,10.3],[99.2,9.3],[99.8,9.3],[100.4,7.2],[101.6,6.8],[103.2,5.3],[103.5,4.5],[103.5,2.8],[104.3,1.4],[103.9,1.7],[103.5,1.3],[101.3,2.8],[100.6,4.3],[100.1,6.6],[98.7,8.4],[98.3,8.2],[98.8,10.3],[98.6,10.0],[98.5,10.7],[98.9,11.7],[98.5,11.9],[98.7,12.8],[98.2,14.0],[98.1,13.6],[97.8,14.9],[97.7,16.6],[97.4,16.5],[96.9,17.5],[96.9,16.8],[96.5,16.5],[96.1,16.8],[96.3,16.4],[95.7,16.2],[95.5,15.7],[95.1,16.1],[95.0,15.7],[94.6,16.1],[94.4,15.8],[94.6,16.3],[94.2,16.0],[94.6,17.6],[94.1,19.4],[93.9,18.8],[93.5,19.4],[94.0,19.4],[93.8,19.9],[93.0,20.1],[93.1,20.6],[92.8,20.2],[91.4,22.8],[90.7,22.8],[90.8,22.2],[90.6,22.0],[90.5,22.6],[90.2,21.8],[89.9,22.4],[89.8,21.8],[89.5,22.1],[89.2,21.7],[89.0,22.1],[89.0,21.6],[88.6,22.1],[88.2,21.6],[88.0,22.2],[87.8,21.7],[86.9,21.3],[87.1,20.7],[86.4,20.0],[85.0,19.4],[84.1,18.3],[82.3,17.0],[82.3,16.6],[81.3,16.3],[80.9,15.7],[80.3,15.7],[80.0,15.1],[80.3,13.3],[79.8,11.7],[79.9,10.3],[79.3,10.3],[78.9,9.5],[79.2,9.3],[78.3,9.0],[78.1,8.4],[77.5,8.1],[76.5,8.9],[75.9,11.1],[73.5,16.1],[72.7,19.8],[72.9,20.8],[72.6,21.3],[72.9,21.7],[72.5,21.7],[72.5,22.0],[72.9,22.3],[72.3,22.3],[72.1,21.2],[70.8,20.7],[68.9,22.3],[70.2,22.5],[70.4,23.0],[69.2,22.8],[68.4,23.5],[68.8,23.9],[68.3,23.6],[68.3,24.0],[67.5,23.9],[67.3,24.8],[66.7,24.8],[66.5,25.6],[61.8,25.0],[57.3,25.8],[56.7,27.2],[54.8,26.5],[53.7,26.7],[52.4,27.6],[51.4,27.9],[50.1,30.2],[49.6,30.0],[48.9,30.4],[48.9,30.0],[48.0,30.1],[48.2,29.5],[47.7,29.4],[48.1,29.4],[48.8,27.6],[50.2,26.6],[50.0,26.0],[50.8,24.7],[51.0,26.0],[51.6,25.9],[51.3,24.3],[52.1,23.9],[52.6,24.2],[54.1,24.1],[56.5,26.4],[56.3,25.6],[56.6,24.5],[57.2,23.9],[58.8,23.5],[59.8,22.2],[58.5,20.4],[58.2,20.6],[57.8,20.2],[57.8,19.0],[56.8,18.7],[56.4,17.9],[55.4,17.8],[55.0,17.0],[52.5,16.4],[52.2,15.6],[49.3,14.6],[48.7,14.0],[45.7,13.3],[45.0,12.8],[43.5,12.7],[42.6,15.2],[42.7,16.7],[40.8,19.7],[39.2,21.1],[39.1,22.4],[38.5,23.8],[37.4,24.4],[37.2,25.2],[35.2,28.0],[34.6,28.1],[35.0,29.5],[34.2,27.7],[32.6,29.9],[32.3,31.2],[34.2,31.3],[36.0,34.5],[35.7,35.6],[36.2,36.8],[35.4,36.5],[34.6,36.8],[34.0,36.2],[32.8,36.0],[31.2,36.9],[30.6,36.9],[30.4,36.2],[29.7,36.1],[28.5,36.9],[27.4,36.7],[28.3,37.1],[27.3,37.0],[27.6,37.2],[27.0,37.7],[27.3,38.0],[26.2,38.3],[26.4,38.7],[26.7,38.3],[27.2,38.4],[26.7,38.6],[26.9,39.6],[26.1,39.5],[26.1,39.9],[26.7,40.4],[29.0,40.4],[29.0,40.6],[29.9,40.7],[29.3,40.8],[29.2,41.2],[31.2,41.1],[33.3,42.0],[35.0,42.1],[36.4,41.2],[38.4,40.9],[40.2,40.9],[41.4,41.4],[41.8,41.8],[41.4,42.7],[36.6,45.2],[37.5,45.4],[38.3,46.3],[38.6,46.0],[37.7,46.7],[38.6,46.7],[39.3,47.3],[35.9,46.7],[35.0,46.1],[35.2,46.5],[34.5,45.9],[35.0,45.4],[35.5,45.3],[34.8,46.1],[35.5,45.3],[36.6,45.4],[34.0,44.4],[33.4,44.6],[33.2,45.4],[32.5,45.4],[33.7,45.8],[33.6,46.2],[31.8,46.3],[32.0,46.4],[31.5,46.6],[32.4,46.5],[32.0,46.9],[30.8,46.5],[30.5,46.1],[30.1,46.4],[30.5,46.1],[29.7,45.6],[30.1,45.9],[29.7,45.6],[29.6,45.8],[29.6,44.9],[29.0,44.7],[28.9,45.0],[28.6,43.5],[27.3,42.4],[27.7,42.4],[29.0,41.0],[27.5,41.0],[26.2,40.0],[26.8,40.6],[25.1,41.0],[23.7,40.8],[24.4,40.2],[23.7,40.4],[23.9,39.9],[22.9,40.6],[22.6,40.5],[23.4,39.2],[22.9,39.4],[23.1,39.0],[22.5,38.9],[24.1,38.2],[24.0,37.6],[23.5,38.0],[23.0,37.9],[23.5,37.4],[22.7,37.6],[23.2,36.4],[22.6,36.8],[22.5,36.4],[22.1,37.0],[21.7,36.8],[21.1,37.9],[21.4,38.2],[22.9,37.9],[23.2,38.2],[21.1,38.3],[20.7,38.8],[21.1,39.0],[20.7,39.0],[19.3,40.4],[19.6,41.8],[18.8,42.5],[17.0,43.0],[17.7,42.8],[16.9,43.4],[16.0,43.5],[14.6,45.3],[13.9,44.8],[13.5,45.8],[12.1,45.4],[12.4,44.2],[13.6,43.6],[14.8,42.0],[16.2,41.9],[16.0,41.5],[18.5,40.1],[18.3,39.8],[17.9,40.3],[16.9,40.4],[16.5,39.8],[17.2,39.0],[16.6,38.8],[16.1,37.9],[15.6,38.0],[16.2,38.9],[15.7,40.0],[11.1,42.4],[10.2,44.0],[8.7,44.4],[6.2,43.0],[4.1,43.6],[3.3,43.3],[3.0,42.8],[3.2,41.9],[1.0,41.0],[0.0,39.9],[-0.2,39.7],[-0.2,39.1],[0.0,38.9],[0.2,38.7],[0.0,38.6],[-0.5,38.3],[-0.7,37.6],[-1.5,37.5],[-2.1,36.7],[-4.4,36.7],[-5.6,36.0],[-6.9,37.3],[-9.0,37.0],[-8.9,38.4],[-8.6,38.4],[-9.2,38.4],[-8.9,39.0],[-9.5,38.8],[-8.8,40.1],[-8.6,42.3],[-9.3,43.1],[-7.7,43.8],[-7.0,43.5],[-1.6,43.4],[-1.1,45.6],[-1.2,45.7],[-1.1,46.3],[-1.8,46.5],[-2.4,47.5],[-4.4,47.8],[-4.6,48.3],[-4.2,48.3],[-4.8,48.5],[-3.1,48.9],[-2.7,48.5],[-1.4,48.6],[-1.9,49.7],[0.0,49.3],[1.7,50.2],[1.6,50.9],[4.3,51.4],[3.4,51.5],[4.6,51.7],[4.0,52.0],[4.7,53.0],[5.3,52.3],[5.8,52.6],[5.3,53.1],[5.9,53.4],[7.4,53.2],[7.1,53.6],[8.0,53.7],[8.5,53.4],[8.7,53.9],[9.8,53.5],[8.6,54.3],[9.0,54.5],[8.6,54.9],[8.3,54.8],[8.6,57.1],[10.7,57.7],[10.1,56.7],[11.0,56.4],[9.6,55.7],[9.4,54.8],[10.1,54.3],[11.1,54.4],[10.9,54.0],[13.0,54.4],[14.6,53.6],[14.7,54.0],[17.9,54.8],[18.8,54.3],[19.9,54.6],[19.4,54.2],[20.4,54.7],[19.9,54.6],[19.9,54.9],[20.6,55.1],[21.1,55.7],[20.5,55.0],[21.2,55.0],[21.0,56.5],[21.7,57.6],[22.6,57.8],[23.6,57.0],[24.4,57.2],[24.6,58.3],[23.7,58.3],[23.5,59.2],[25.7,59.7],[27.9,59.4],[28.1,59.8],[30.3,60.0],[28.6,60.4],[28.7,60.7],[22.9,59.8],[23.1,60.4],[22.5,60.2],[21.4,60.6],[21.8,61.5],[21.1,62.8],[25.5,65.0],[24.6,65.8],[22.6,65.9],[22.4,65.5],[21.7,65.8],[21.7,65.2],[21.2,65.3],[21.6,64.4],[20.7,63.8],[18.1,62.8],[17.7,63.0],[17.2,60.7],[18.0,60.6],[19.1,59.7],[18.1,59.4],[18.7,59.3],[17.9,58.8],[17.7,59.2],[17.5,58.8],[16.2,58.6],[16.9,58.5],[16.4,58.5],[16.7,57.4],[15.8,56.1],[14.7,56.2],[14.2,55.4],[12.8,55.4],[12.4,56.3],[12.9,56.6],[11.7,57.7],[11.9,58.3],[11.6,57.9],[11.7,58.4],[11.2,58.4],[10.8,59.9],[10.4,59.1],[9.5,59.1],[8.2,58.1],[7.0,58.0],[5.7,58.6],[5.6,59.0],[6.3,58.8],[6.6,59.1],[5.9,59.1],[6.6,59.6],[5.6,59.3],[5.2,59.5],[7.1,60.5],[5.5,59.9],[5.8,60.4],[5.4,60.1],[5.2,60.4],[5.8,60.7],[5.3,60.5],[4.9,60.8],[5.6,60.9],[5.0,61.0],[6.6,61.2],[7.1,60.9],[7.7,61.2],[7.6,61.5],[7.3,61.2],[6.8,61.4],[6.5,61.2],[5.2,61.1],[5.7,61.4],[5.0,61.4],[5.9,61.5],[5.0,61.6],[5.2,61.9],[6.8,61.9],[5.2,61.9],[5.1,62.2],[6.3,62.1],[5.9,62.2],[6.6,62.1],[6.7,62.3],[7.2,62.1],[6.3,62.6],[8.1,62.7],[7.0,63.0],[8.5,62.7],[7.9,63.0],[8.7,62.8],[8.5,63.4],[9.7,63.6],[9.8,63.3],[11.0,63.4],[11.4,64.1],[10.4,63.6],[9.5,63.6],[11.0,64.6],[11.2,64.3],[11.9,64.4],[11.4,64.7],[12.2,65.0],[11.3,64.9],[13.0,65.3],[12.0,65.2],[12.7,65.9],[13.2,65.8],[12.7,66.1],[14.2,66.3],[13.0,66.2],[14.0,66.8],[13.5,67.0],[15.5,67.1],[14.3,67.3],[15.9,67.6],[14.8,67.9],[15.9,67.9],[15.3,68.1],[16.0,68.3],[16.5,67.8],[16.3,68.4],[17.9,68.4],[16.5,68.5],[17.7,68.7],[18.1,69.5],[19.5,69.2],[18.9,69.6],[19.7,69.8],[19.6,69.4],[20.3,70.0],[19.9,69.3],[21.2,70.0],[22.1,69.7],[21.6,70.3],[23.5,70.0],[24.6,71.0],[25.9,70.9],[25.2,70.1],[26.7,71.0],[26.5,70.4],[27.1,70.5],[27.7,71.1],[28.6,71.0],[27.9,70.4],[29.0,70.9],[31.0,70.4],[30.2,70.1],[28.6,70.2],[29.5,69.7],[30.3,69.9],[31.3,69.6],[32.1,69.9],[33.1,69.7],[32.1,69.7],[32.2,69.4],[33.5,69.4],[33.0,68.9],[33.6,69.3],[35.3,69.3],[39.8,68.1],[41.4,67.1],[39.1,66.1],[31.9,67.1],[33.7,66.4],[33.0,66.2],[34.9,65.9],[34.2,65.4],[34.8,64.5],[37.4,63.8],[38.0,64.3],[36.5,64.7],[36.8,65.2],[38.4,64.8],[38.0,64.6],[38.4,64.8],[40.5,64.5],[39.7,65.5],[40.7,66.0],[42.2,66.5],[44.1,66.0],[44.2,68.3],[43.3,68.7],[46.5,68.1],[46.7,67.8],[44.9,67.4],[46.0,66.8],[47.6,66.9],[47.8,67.6],[49.1,67.6],[48.6,67.9],[52.2,68.6],[52.3,68.3],[53.9,69.0],[54.6,69.0],[53.6,68.8],[53.2,68.2],[54.8,68.1],[55.4,68.5],[57.3,68.5],[59.0,69.0],[59.8,68.3],[59.9,68.7],[61.2,68.8],[60.2,69.6],[60.8,69.9],[66.2,69.1],[65.5,69.1],[68.3,68.1],[69.3,68.9],[68.1,69.5],[66.8,69.6],[66.7,71.1],[68.3,71.6],[69.4,72.9],[71.6,72.9],[72.9,72.7],[71.8,71.5],[72.8,70.9],[72.5,69.0],[73.6,68.4],[71.7,66.9],[69.1,66.6],[72.1,66.2],[74.8,67.7],[74.7,68.8],[76.6,69.0],[77.1,67.8],[78.8,67.5],[77.5,67.7],[78.2,68.2],[77.7,68.9],[75.9,69.3],[73.8,69.2],[74.3,70.6],[73.0,71.4],[75.0,72.2],[74.8,72.8],[76.1,71.2],[78.5,70.9],[76.0,71.9],[78.0,71.8],[77.5,72.2],[78.4,72.4],[81.5,71.7],[83.3,71.7],[82.0,70.6],[82.8,71.0],[82.4,70.2],[83.6,69.7],[83.7,71.6],[80.9,72.4],[80.5,73.6],[87.2,73.8],[85.9,74.9],[87.0,74.6],[87.0,75.1],[94.1,75.9],[92.8,75.9],[93.3,76.1],[96.1,76.1],[95.7,75.8],[98.8,76.3],[99.8,76.0],[98.9,76.5],[101.1,76.5],[101.4,77.1],[104.1,77.7],[106.3,77.4],[104.2,77.1],[107.5,76.9],[106.5,76.5],[111.1,76.8],[113.9,75.8],[113.6,75.5],[112.3,75.8],[113.6,75.2],[107.0,73.6],[105.5,72.7],[106.3,73.2],[111.0,73.7],[109.7,73.7],[110.0,74.0],[111.6,74.1],[112.3,73.7],[112.8,74.0],[113.5,73.2],[115.7,73.7],[118.9,73.5],[118.4,73.2],[119.8,73.0],[122.8,72.9],[124.4,73.8],[126.3,73.3],[128.8,73.2],[129.5,72.7],[128.4,72.5],[129.6,72.2],[128.3,72.1],[131.0,70.7],[132.8,72.0],[133.8,71.4],[136.0,71.6],[137.9,71.1],[138.1,71.6],[140.1,71.4],[139.3,71.9],[140.2,72.3],[139.1,72.3],[141.3,72.6],[140.9,72.9],[146.9,72.4],[144.2,72.2],[146.9,72.3],[146.0,71.9],[145.5,72.2],[145.3,71.6],[147.1,72.3],[148.4,72.3],[150.1,71.9],[148.8,71.7],[152.5,70.8],[155.9,71.1],[158.9,70.9],[161.1,69.2],[162.3,69.7],[166.9,69.5],[167.8,69.8],[168.3,69.2],[170.5,68.8],[171.2,69.0],[170.2,69.6],[170.5,70.1],[173.2,69.8],[176.1,69.9],[180.0,69.0]],[[31.9,31.5],[32.3,31.2],[32.6,29.9],[32.5,29.9],[32.6,29.0],[33.6,27.8],[35.1,24.5],[35.8,23.9],[35.5,23.9],[35.7,22.9],[36.9,22.1],[37.3,21.1],[37.1,21.2],[37.4,18.9],[38.6,18.1],[39.7,15.1],[39.9,15.5],[40.2,14.9],[41.2,14.6],[43.3,12.5],[43.4,12.0],[42.5,11.5],[43.2,11.6],[44.6,10.4],[45.8,10.9],[46.4,10.7],[47.4,11.2],[49.4,11.3],[50.8,12.0],[51.3,11.8],[51.0,10.4],[51.4,10.4],[50.9,10.3],[50.8,9.4],[48.0,4.5],[46.0,2.4],[43.6,0.7],[41.3,-2.0],[40.8,-1.9],[41.0,-2.3],[40.2,-2.7],[39.2,-4.7],[38.8,-6.1],[39.6,-7.0],[39.2,-7.9],[39.4,-7.8],[39.3,-8.3],[39.7,-10.0],[40.6,-10.7],[40.3,-11.3],[40.6,-12.7],[40.4,-12.9],[40.8,-14.8],[39.9,-16.4],[36.9,-17.9],[36.3,-18.9],[34.9,-19.9],[34.6,-19.7],[34.7,-20.6],[35.5,-22.2],[35.5,-24.1],[32.5,-26.0],[32.8,-26.3],[33.0,-26.1],[32.4,-28.5],[31.3,-29.5],[30.0,-31.3],[27.0,-33.6],[24.8,-34.2],[22.6,-34.0],[20.0,-34.8],[18.8,-34.1],[18.4,-34.3],[17.8,-32.8],[18.3,-32.5],[18.2,-31.7],[14.9,-26.3],[14.5,-22.5],[11.8,-18.0],[11.7,-15.8],[12.5,-13.4],[13.7,-12.2],[13.9,-11.0],[13.0,-9.1],[13.4,-8.4],[12.3,-6.1],[12.7,-6.0],[12.2,-5.7],[11.7,-4.5],[9.6,-2.4],[8.7,-0.7],[9.1,-0.7],[9.4,0.4],[9.5,0.1],[10.0,0.2],[9.3,0.5],[9.7,0.5],[9.7,1.1],[9.3,1.2],[10.0,3.1],[9.5,3.8],[9.8,3.8],[9.7,4.1],[9.2,3.9],[8.8,4.7],[8.6,4.5],[8.2,4.9],[8.3,4.5],[7.3,4.4],[7.1,4.7],[7.0,4.4],[6.8,4.7],[6.9,4.4],[6.7,4.6],[6.7,4.3],[6.0,4.3],[5.4,5.2],[5.7,5.5],[5.4,5.4],[5.2,5.6],[5.5,5.6],[5.1,5.7],[5.4,6.0],[5.1,5.8],[4.4,6.4],[3.4,6.4],[3.8,6.6],[1.3,6.2],[0.0,5.6],[-2.0,4.8],[-4.0,5.3],[-6.1,5.0],[-7.5,4.4],[-8.7,4.8],[-11.2,6.8],[-12.5,7.4],[-12.5,7.8],[-13.3,8.4],[-12.8,8.6],[-13.2,8.5],[-13.3,9.3],[-13.7,9.5],[-13.5,9.8],[-14.5,10.2],[-14.7,11.1],[-15.1,10.9],[-15.0,11.2],[-15.2,11.0],[-15.5,11.3],[-15.0,11.6],[-15.5,11.8],[-14.9,12.0],[-16.0,11.7],[-15.9,12.0],[-16.4,12.1],[-16.0,12.3],[-16.8,12.4],[-16.2,12.6],[-16.8,12.6],[-16.7,13.5],[-16.4,13.2],[-15.6,13.5],[-16.5,13.4],[-16.5,13.9],[-17.5,14.7],[-16.6,15.7],[-16.0,17.7],[-16.5,19.4],[-16.2,20.2],[-16.9,21.2],[-17.1,20.8],[-17.0,21.8],[-15.7,24.0],[-15.9,23.8],[-14.9,24.7],[-14.5,26.2],[-13.7,26.7],[-12.9,28.0],[-11.5,28.3],[-10.2,29.3],[-9.7,30.1],[-9.8,31.4],[-9.3,32.5],[-6.8,34.0],[-5.9,35.8],[-5.5,35.9],[-4.7,35.2],[-3.0,35.4],[-2.8,35.1],[-2.0,35.1],[-0.9,35.7],[0.0,35.8],[1.1,36.5],[3.9,36.9],[5.3,36.6],[6.4,37.1],[7.9,36.8],[9.7,37.3],[10.4,36.7],[11.0,37.1],[10.5,36.1],[11.2,35.2],[10.0,34.2],[10.2,33.8],[12.3,32.8],[13.4,32.9],[15.2,32.4],[15.7,31.4],[17.9,30.9],[19.0,30.3],[20.1,30.9],[20.1,32.2],[21.7,32.9],[23.1,32.6],[23.3,32.2],[25.0,32.0],[25.2,31.5],[27.0,31.4],[29.1,30.8],[31.0,31.6],[31.9,31.5]],[[-81.1,8.8],[-79.9,9.4],[-79.9,9.3],[-80.1,9.0],[-79.8,9.0],[-79.6,9.1],[-79.5,8.9],[-80.5,8.2],[-80.0,7.5],[-80.4,7.2],[-80.9,7.2],[-81.1,7.9],[-81.5,7.7],[-81.8,8.2],[-82.7,8.3],[-82.9,8.0],[-83.4,8.7],[-83.3,8.4],[-83.6,8.4],[-83.6,9.0],[-84.7,10.0],[-85.3,10.3],[-84.9,9.8],[-85.1,9.6],[-85.7,9.9],[-85.7,10.8],[-86.0,10.9],[-85.7,11.1],[-87.7,12.9],[-87.3,12.9],[-87.4,13.4],[-88.7,13.3],[-88.5,13.2],[-91.3,13.9],[-94.3,16.1],[-96.6,15.6],[-101.1,17.3],[-102.0,18.0],[-103.5,18.3],[-105.5,20.0],[-105.7,20.4],[-105.2,20.6],[-105.5,20.8],[-105.2,21.5],[-106.0,22.9],[-108.0,24.6],[-108.0,25.1],[-109.4,25.7],[-109.1,26.3],[-110.5,27.3],[-110.5,27.9],[-111.1,27.9],[-112.2,29.0],[-113.1,31.2],[-115.0,31.9],[-114.6,30.0],[-112.8,28.4],[-112.7,27.8],[-111.4,26.5],[-110.7,24.4],[-109.8,24.1],[-109.5,23.2],[-110.0,22.9],[-110.3,23.6],[-112.2,24.8],[-112.2,26.1],[-113.2,27.0],[-113.6,26.7],[-115.0,27.7],[-114.0,27.7],[-114.3,27.9],[-114.0,28.5],[-115.7,29.8],[-117.4,33.3],[-118.5,34.0],[-120.6,34.6],[-120.6,35.1],[-122.4,37.2],[-122.5,37.8],[-122.0,37.5],[-122.3,38.1],[-123.0,38.0],[-123.7,38.9],[-124.4,40.4],[-124.1,41.4],[-124.6,42.8],[-124.0,46.2],[-123.4,46.2],[-124.1,46.3],[-123.8,47.0],[-124.2,46.9],[-124.7,48.4],[-122.8,48.1],[-123.2,47.4],[-122.6,47.9],[-122.5,47.5],[-122.9,47.0],[-122.2,47.5],[-122.5,48.8],[-123.2,49.0],[-123.2,49.7],[-124.0,49.5],[-123.5,49.7],[-123.9,50.2],[-124.3,49.7],[-124.8,50.0],[-124.3,50.5],[-125.1,50.3],[-124.8,50.9],[-125.1,50.4],[-125.6,50.4],[-125.5,50.7],[-125.7,50.4],[-126.3,50.6],[-125.5,51.0],[-126.2,50.7],[-126.6,50.8],[-126.2,50.9],[-127.5,51.0],[-126.7,51.2],[-127.8,51.2],[-127.1,51.4],[-127.8,51.3],[-127.2,51.7],[-127.7,51.5],[-127.9,51.8],[-127.0,52.7],[-127.9,52.2],[-128.0,52.5],[-128.4,52.3],[-127.8,52.7],[-129.0,53.5],[-128.1,53.5],[-128.8,53.5],[-128.7,54.0],[-129.3,53.4],[-130.1,53.9],[-129.6,54.2],[-130.5,54.4],[-130.4,54.6],[-130.0,54.3],[-130.4,54.7],[-129.7,55.0],[-130.2,55.1],[-129.9,55.9],[-130.1,55.3],[-130.9,54.8],[-130.7,55.8],[-131.0,56.1],[-132.2,55.6],[-131.5,56.2],[-133.6,57.2],[-133.1,57.4],[-133.7,57.7],[-132.9,57.5],[-133.6,57.8],[-133.1,57.9],[-134.1,58.1],[-133.7,58.5],[-134.1,58.2],[-134.8,58.4],[-135.3,59.5],[-135.1,58.2],[-135.9,58.4],[-136.2,59.1],[-136.2,58.8],[-137.0,59.1],[-136.0,58.4],[-136.7,58.2],[-139.9,59.5],[-139.5,60.0],[-139.3,59.6],[-138.9,59.8],[-139.5,60.1],[-140.3,59.7],[-141.4,60.1],[-144.3,60.0],[-144.9,60.5],[-145.9,60.5],[-146.0,60.8],[-146.7,60.7],[-146.1,60.8],[-146.7,60.9],[-146.3,61.1],[-147.4,60.9],[-147.5,61.2],[-147.9,60.8],[-147.7,61.3],[-148.7,60.8],[-147.9,60.4],[-148.4,59.9],[-149.4,60.1],[-149.5,59.7],[-149.7,60.0],[-149.7,59.6],[-151.7,59.2],[-150.9,59.8],[-151.9,59.8],[-151.4,60.7],[-150.4,61.0],[-149.0,60.8],[-150.1,61.2],[-149.2,61.5],[-150.6,61.4],[-154.1,59.4],[-154.2,59.0],[-153.2,58.9],[-154.2,58.1],[-155.6,57.8],[-159.6,55.6],[-159.8,55.9],[-161.2,55.4],[-161.6,55.6],[-162.0,55.1],[-162.6,55.3],[-162.6,55.0],[-163.0,55.0],[-163.4,54.8],[-161.8,55.9],[-160.3,55.8],[-160.3,56.3],[-157.4,57.5],[-157.5,58.4],[-156.8,59.0],[-158.2,58.6],[-158.5,59.1],[-158.9,58.4],[-160.3,59.1],[-162.1,58.6],[-161.5,59.1],[-162.2,60.2],[-164.1,59.8],[-164.5,60.6],[-163.4,60.7],[-165.1,60.9],[-164.8,61.1],[-165.6,61.1],[-166.1,61.5],[-164.4,63.2],[-163.3,63.0],[-162.3,63.5],[-161.1,63.5],[-160.7,63.9],[-161.5,64.4],[-160.8,64.7],[-161.7,64.8],[-162.8,64.3],[-163.1,64.7],[-163.2,64.4],[-166.2,64.6],[-167.0,65.2],[-166.1,65.3],[-168.1,65.7],[-164.4,66.6],[-163.8,66.1],[-161.1,66.1],[-162.5,67.0],[-161.6,66.4],[-160.2,66.5],[-161.5,66.5],[-161.7,67.0],[-163.7,67.1],[-164.2,67.6],[-166.8,68.3],[-166.2,68.9],[-164.0,69.0],[-161.9,70.3],[-160.1,70.6],[-159.8,70.3],[-159.7,70.8],[-157.8,70.9],[-156.5,71.4],[-155.6,71.2],[-156.0,70.7],[-155.1,71.1],[-154.2,70.8],[-152.3,70.8],[-152.6,70.5],[-151.2,70.4],[-143.3,70.1],[-135.3,68.6],[-136.0,69.2],[-134.5,69.7],[-134.2,69.2],[-133.0,69.4],[-129.7,70.3],[-130.9,69.3],[-127.4,70.1],[-128.0,70.6],[-125.5,69.3],[-124.5,70.2],[-124.4,69.3],[-121.9,69.8],[-117.1,68.9],[-115.0,68.9],[-113.9,68.4],[-115.2,68.2],[-115.1,67.8],[-111.9,67.7],[-110.0,68.0],[-108.0,67.3],[-108.5,67.1],[-107.2,66.3],[-107.8,67.0],[-107.1,66.8],[-107.0,67.1],[-108.0,67.8],[-105.7,68.6],[-107.6,68.2],[-108.8,68.3],[-106.2,68.9],[-105.0,68.2],[-103.4,68.2],[-102.2,67.7],[-98.9,67.7],[-98.6,68.1],[-97.3,67.5],[-97.2,68.0],[-98.1,67.9],[-98.7,68.4],[-97.3,68.5],[-96.4,68.3],[-96.7,68.0],[-95.9,68.3],[-96.4,67.5],[-95.3,67.2],[-95.5,68.1],[-93.5,68.6],[-93.8,69.0],[-94.6,68.8],[-94.3,69.3],[-93.3,69.4],[-96.2,69.9],[-95.8,70.7],[-96.6,70.8],[-94.5,72.0],[-91.5,70.2],[-92.4,70.2],[-92.9,69.7],[-90.3,69.5],[-91.4,69.4],[-90.2,68.2],[-89.3,69.2],[-88.2,68.9],[-87.5,67.1],[-86.5,67.3],[-85.6,68.7],[-84.7,68.7],[-85.5,69.9],[-82.5,69.7],[-83.3,69.5],[-81.3,69.2],[-82.0,68.9],[-81.2,68.6],[-82.6,68.4],[-81.2,67.5],[-83.3,66.3],[-83.9,66.9],[-85.2,66.9],[-83.8,66.1],[-86.8,66.5],[-85.9,66.2],[-87.3,65.3],[-89.8,66.0],[-90.9,65.9],[-86.9,65.1],[-88.1,64.1],[-90.0,64.2],[-90.7,63.4],[-93.8,64.2],[-93.9,63.9],[-92.2,63.7],[-92.5,63.5],[-91.7,63.7],[-90.6,63.2],[-91.4,62.8],[-92.4,62.8],[-91.9,62.6],[-93.6,62.0],[-93.3,61.7],[-94.8,60.5],[-95.0,59.1],[-94.3,58.4],[-94.2,58.8],[-93.2,58.7],[-92.4,57.4],[-92.8,56.9],[-90.8,57.3],[-85.2,55.2],[-82.3,55.2],[-82.3,52.9],[-80.6,51.7],[-80.6,51.3],[-79.8,51.1],[-79.3,51.7],[-78.9,51.2],[-79.0,51.8],[-78.4,52.2],[-79.0,54.2],[-79.8,54.6],[-77.6,55.3],[-76.5,56.4],[-77.0,58.0],[-78.6,58.7],[-77.2,60.0],[-77.5,60.8],[-78.2,60.8],[-77.5,61.5],[-78.2,62.3],[-77.4,62.6],[-74.5,62.1],[-73.7,62.5],[-72.3,61.6],[-71.6,61.6],[-71.6,61.2],[-69.9,60.8],[-69.5,61.1],[-69.6,60.1],[-70.9,60.0],[-69.7,60.0],[-69.8,59.3],[-69.2,59.3],[-69.5,58.8],[-69.8,59.1],[-70.3,58.8],[-68.3,58.8],[-68.7,58.0],[-68.0,58.6],[-67.7,58.0],[-66.4,58.9],[-66.0,58.3],[-66.1,58.8],[-65.3,59.0],[-65.7,59.3],[-65.0,59.4],[-65.5,59.7],[-64.8,60.4],[-64.4,60.2],[-64.7,60.0],[-63.4,59.2],[-64.1,59.0],[-63.1,59.1],[-62.9,58.7],[-63.6,58.3],[-62.6,58.5],[-63.4,58.0],[-62.4,58.2],[-62.7,57.9],[-61.9,57.6],[-62.5,57.5],[-61.4,57.1],[-61.7,56.6],[-62.5,56.8],[-61.7,56.5],[-62.2,56.5],[-61.6,56.3],[-62.0,56.2],[-61.3,56.2],[-61.8,56.0],[-60.6,55.8],[-60.7,55.5],[-60.3,55.8],[-60.7,55.0],[-59.8,55.3],[-60.0,55.1],[-59.4,55.2],[-59.9,54.7],[-59.2,55.2],[-59.4,55.0],[-59.0,55.2],[-59.0,54.8],[-57.9,54.9],[-58.2,54.7],[-57.3,54.6],[-59.6,54.0],[-58.4,54.2],[-60.8,53.2],[-58.2,54.2],[-57.1,53.9],[-57.4,53.4],[-56.5,53.8],[-55.8,53.3],[-56.2,52.8],[-55.8,52.6],[-56.5,52.6],[-55.6,52.4],[-56.3,52.4],[-55.7,52.1],[-57.0,51.4],[-58.7,51.3],[-59.9,50.3],[-66.5,50.3],[-67.4,49.3],[-70.0,48.3],[-69.9,47.8],[-71.2,46.8],[-68.2,48.6],[-66.2,49.2],[-64.6,49.1],[-64.3,48.4],[-65.2,48.0],[-66.8,48.0],[-65.8,47.9],[-65.7,47.6],[-64.8,47.8],[-65.4,47.1],[-64.8,47.1],[-64.7,46.3],[-63.3,45.7],[-61.9,45.9],[-61.0,45.3],[-61.3,45.2],[-63.7,44.7],[-63.6,44.4],[-64.3,44.6],[-65.5,43.5],[-66.2,43.8],[-66.1,44.5],[-64.5,45.3],[-64.1,45.0],[-63.4,45.4],[-64.9,45.3],[-64.3,45.9],[-66.5,45.1],[-67.2,45.2],[-66.9,44.8],[-68.1,44.3],[-68.2,44.6],[-68.8,44.3],[-68.8,44.7],[-69.2,43.9],[-69.8,44.1],[-69.8,43.7],[-70.3,43.7],[-71.1,42.4],[-70.3,41.7],[-70.1,42.0],[-70.0,41.6],[-71.2,41.5],[-71.4,41.8],[-71.5,41.4],[-73.6,41.0],[-74.3,40.5],[-74.1,39.8],[-74.9,38.9],[-75.5,39.7],[-75.1,38.4],[-75.9,37.1],[-75.6,38.0],[-76.4,38.9],[-75.9,39.5],[-76.6,39.3],[-76.3,38.0],[-77.2,38.7],[-77.3,38.3],[-76.2,37.9],[-76.4,37.6],[-76.9,38.0],[-76.3,37.6],[-76.5,37.2],[-76.8,37.5],[-76.4,37.1],[-77.0,37.2],[-76.0,36.9],[-75.5,35.8],[-76.0,36.7],[-75.8,36.1],[-76.2,36.3],[-76.7,35.9],[-76.1,36.0],[-76.0,35.6],[-75.8,36.0],[-75.7,35.6],[-76.2,35.3],[-77.0,35.5],[-76.5,35.3],[-77.0,35.0],[-76.3,34.9],[-78.8,33.8],[-80.6,32.3],[-80.8,32.5],[-80.7,32.2],[-81.6,31.2],[-80.0,26.8],[-80.6,25.0],[-80.6,25.2],[-81.1,25.1],[-81.0,25.6],[-81.7,25.9],[-82.0,27.0],[-82.4,26.9],[-82.7,27.5],[-82.4,27.9],[-82.9,27.9],[-82.6,28.9],[-83.7,29.9],[-84.2,30.1],[-85.4,29.7],[-85.6,30.3],[-86.5,30.4],[-86.2,30.5],[-87.2,30.3],[-87.0,30.6],[-88.0,30.2],[-87.8,30.4],[-88.0,30.8],[-88.1,30.3],[-90.4,30.2],[-89.2,29.9],[-89.7,29.6],[-89.0,29.2],[-89.4,28.9],[-89.8,29.5],[-90.2,29.6],[-90.1,29.1],[-90.4,29.3],[-90.9,29.1],[-91.8,29.8],[-92.3,29.5],[-93.8,29.7],[-93.9,30.0],[-93.8,29.7],[-94.8,29.4],[-94.5,29.6],[-95.0,29.7],[-95.1,29.1],[-96.2,28.5],[-96.0,28.7],[-96.7,28.7],[-96.4,28.4],[-97.2,28.2],[-97.4,27.3],[-97.8,27.3],[-97.4,27.3],[-97.1,26.0],[-97.5,25.0],[-97.4,25.4],[-97.8,25.3],[-97.9,24.5],[-97.9,22.6],[-97.8,22.1],[-95.9,18.7],[-95.2,18.7],[-94.4,18.1],[-92.3,18.7],[-91.6,18.4],[-90.7,19.4],[-90.3,21.1],[-88.1,21.6],[-86.8,21.3],[-87.7,19.7],[-87.4,19.6],[-87.8,18.2],[-88.1,18.9],[-88.4,18.4],[-88.1,18.4],[-88.2,17.0],[-88.9,15.9],[-88.1,15.7],[-85.0,16.0],[-83.4,15.3],[-83.2,14.3],[-83.9,11.3],[-82.2,9.0],[-81.8,8.9],[-81.9,9.2],[-81.1,8.8]],[[-73.4,-53.0],[-72.9,-52.5],[-73.7,-52.8],[-73.7,-52.0],[-73.0,-52.1],[-73.0,-52.4],[-72.8,-52.0],[-72.9,-52.5],[-72.5,-51.8],[-73.1,-51.5],[-72.9,-51.2],[-73.4,-51.5],[-72.6,-51.8],[-73.4,-51.6],[-73.2,-52.0],[-73.4,-51.6],[-73.4,-52.0],[-73.9,-51.6],[-73.7,-51.1],[-74.2,-50.9],[-73.3,-50.7],[-73.6,-50.4],[-74.0,-50.9],[-74.0,-50.4],[-74.7,-50.2],[-73.9,-50.3],[-74.3,-49.6],[-73.6,-49.7],[-74.0,-49.2],[-74.4,-49.4],[-74.1,-48.7],[-74.4,-48.6],[-73.8,-48.4],[-74.7,-48.0],[-73.4,-48.3],[-73.7,-47.9],[-73.2,-48.0],[-73.7,-47.6],[-74.7,-47.7],[-73.9,-47.5],[-74.5,-47.5],[-73.9,-47.2],[-74.2,-46.8],[-74.9,-46.8],[-74.9,-46.4],[-75.5,-46.7],[-75.3,-46.9],[-75.6,-46.7],[-74.9,-46.4],[-74.6,-46.0],[-75.1,-45.9],[-74.7,-45.8],[-74.4,-46.0],[-74.1,-45.8],[-74.3,-46.1],[-74.0,-46.2],[-74.5,-46.2],[-73.9,-46.1],[-73.6,-46.5],[-73.1,-45.7],[-73.6,-45.8],[-73.5,-45.5],[-72.8,-45.4],[-73.5,-45.2],[-72.5,-44.5],[-73.3,-44.2],[-72.7,-43.8],[-73.1,-43.5],[-72.8,-42.5],[-72.5,-42.6],[-72.8,-42.3],[-72.5,-42.5],[-72.4,-42.2],[-72.9,-41.9],[-72.3,-41.4],[-72.6,-41.6],[-73.0,-41.5],[-73.8,-41.7],[-73.5,-41.6],[-74.0,-41.0],[-73.2,-39.4],[-73.7,-37.3],[-73.2,-37.1],[-71.6,-33.6],[-71.7,-30.6],[-71.3,-29.9],[-71.5,-28.9],[-70.4,-25.4],[-70.6,-23.5],[-70.1,-21.4],[-70.1,-20.0],[-70.3,-18.4],[-71.5,-17.3],[-75.1,-15.4],[-75.9,-14.7],[-76.4,-13.9],[-76.2,-13.4],[-77.7,-11.3],[-79.0,-8.2],[-80.0,-6.8],[-81.2,-6.0],[-80.9,-5.7],[-81.3,-4.3],[-80.0,-3.4],[-79.7,-2.6],[-79.9,-2.2],[-80.2,-2.7],[-80.9,-2.3],[-80.9,-1.1],[-80.3,-0.7],[-80.5,-0.4],[-79.9,0.2],[-80.1,0.8],[-78.9,1.1],[-79.0,1.6],[-78.5,1.8],[-78.6,2.4],[-77.8,2.7],[-77.1,3.6],[-77.0,3.9],[-77.5,4.2],[-77.3,6.6],[-78.4,7.9],[-78.1,8.4],[-78.4,8.3],[-79.1,9.0],[-79.5,9.0],[-79.9,9.4],[-79.6,9.6],[-79.0,9.6],[-77.9,9.1],[-76.8,7.9],[-76.9,8.6],[-75.6,9.5],[-75.7,10.1],[-75.3,10.8],[-74.8,11.1],[-74.3,11.0],[-74.1,11.3],[-73.3,11.3],[-71.7,12.5],[-71.1,12.1],[-72.0,11.6],[-71.6,10.7],[-72.1,9.8],[-71.7,9.1],[-71.1,9.3],[-71.0,9.7],[-71.6,10.8],[-70.1,11.6],[-69.8,11.4],[-69.8,11.7],[-70.2,11.6],[-70.0,12.2],[-69.6,11.5],[-68.4,11.2],[-68.1,10.5],[-66.2,10.7],[-65.1,10.1],[-63.6,10.5],[-64.3,10.7],[-61.9,10.7],[-62.9,10.4],[-62.3,9.8],[-61.6,9.9],[-60.9,9.4],[-60.9,8.6],[-60.2,8.6],[-59.0,8.0],[-58.5,7.3],[-58.7,6.4],[-58.3,6.9],[-57.1,5.8],[-54.2,5.9],[-52.3,4.9],[-51.7,4.1],[-51.5,4.4],[-51.3,4.3],[-50.8,2.1],[-49.9,1.7],[-50.1,1.2],[-49.9,1.2],[-51.3,-0.1],[-51.7,-1.0],[-52.0,-1.4],[-52.7,-1.6],[-52.2,-1.7],[-50.9,-0.9],[-50.5,-1.9],[-49.3,-1.7],[-49.7,-2.7],[-49.5,-2.4],[-48.7,-1.4],[-48.4,-1.7],[-48.1,-1.6],[-48.5,-1.5],[-48.1,-0.7],[-47.4,-0.8],[-47.3,-0.6],[-46.3,-1.1],[-46.2,-0.9],[-46.1,-1.3],[-46.0,-1.0],[-45.7,-1.4],[-45.4,-1.3],[-45.5,-1.5],[-45.3,-1.3],[-45.2,-1.9],[-44.8,-1.4],[-44.5,-2.1],[-45.0,-2.4],[-44.4,-2.3],[-44.7,-2.6],[-44.8,-3.4],[-43.4,-2.3],[-42.3,-2.9],[-40.0,-2.8],[-38.5,-3.7],[-37.2,-5.0],[-35.6,-5.1],[-35.3,-5.5],[-34.8,-7.2],[-34.9,-8.4],[-38.1,-12.7],[-38.5,-13.0],[-38.7,-12.6],[-38.8,-12.8],[-39.1,-17.7],[-39.7,-18.4],[-39.8,-19.6],[-41.1,-21.5],[-41.0,-22.0],[-42.0,-22.5],[-42.0,-23.0],[-43.1,-23.0],[-43.1,-22.7],[-43.6,-23.1],[-44.4,-22.9],[-45.4,-23.8],[-46.4,-23.9],[-47.6,-24.7],[-48.2,-25.5],[-48.7,-25.4],[-48.3,-25.6],[-48.8,-26.3],[-48.5,-27.1],[-48.8,-28.5],[-49.7,-29.3],[-50.8,-31.1],[-52.1,-32.2],[-50.6,-30.5],[-51.3,-30.0],[-51.1,-30.4],[-52.3,-31.8],[-52.6,-33.1],[-54.2,-34.7],[-56.2,-34.9],[-57.9,-34.5],[-58.4,-33.9],[-58.4,-33.1],[-58.6,-34.4],[-57.2,-35.3],[-57.4,-36.0],[-56.7,-36.3],[-56.7,-36.9],[-57.5,-38.1],[-58.5,-38.5],[-61.1,-39.0],[-62.3,-38.8],[-62.0,-39.4],[-62.3,-39.3],[-62.4,-40.9],[-63.8,-41.2],[-65.0,-40.7],[-65.0,-42.1],[-64.5,-42.4],[-63.8,-42.1],[-63.6,-42.6],[-64.1,-42.9],[-64.4,-42.5],[-65.0,-42.7],[-64.3,-43.0],[-65.3,-43.7],[-65.5,-44.9],[-66.9,-45.3],[-67.6,-46.1],[-66.8,-47.0],[-65.7,-47.2],[-65.8,-47.9],[-67.6,-49.0],[-67.9,-50.0],[-68.3,-50.1],[-68.7,-49.8],[-68.4,-50.2],[-69.4,-51.1],[-69.0,-51.6],[-69.6,-51.6],[-69.0,-51.6],[-68.4,-52.3],[-69.2,-52.2],[-70.9,-52.7],[-71.3,-53.9],[-72.5,-53.4],[-71.9,-53.2],[-72.0,-53.6],[-71.3,-53.1],[-71.5,-52.6],[-72.9,-52.6],[-73.0,-53.1],[-73.4,-53.0]],[[146.2,-38.7],[146.3,-39.0],[145.4,-38.5],[145.5,-38.2],[144.7,-38.3],[145.1,-38.1],[144.9,-37.8],[143.6,-38.9],[140.6,-38.0],[139.7,-37.2],[139.6,-36.2],[139.7,-36.3],[139.5,-36.0],[138.9,-35.5],[138.1,-35.6],[138.6,-34.8],[138.1,-34.1],[137.8,-35.1],[136.9,-35.3],[137.0,-34.9],[137.5,-34.9],[137.5,-34.1],[138.0,-33.6],[137.8,-32.5],[137.8,-33.0],[135.9,-34.5],[136.0,-35.0],[135.1,-34.6],[135.5,-34.6],[134.7,-33.2],[134.1,-32.9],[134.2,-32.5],[131.2,-31.5],[126.0,-32.3],[124.2,-33.0],[123.5,-33.9],[119.9,-33.9],[118.0,-35.1],[116.6,-35.1],[115.1,-34.4],[115.0,-33.5],[115.7,-33.3],[115.9,-32.0],[115.1,-30.5],[114.9,-29.1],[113.2,-26.1],[113.8,-26.6],[113.5,-25.5],[113.7,-26.2],[113.9,-25.9],[114.2,-26.3],[113.4,-24.4],[114.0,-21.9],[114.3,-22.5],[114.6,-21.8],[116.8,-20.5],[117.4,-20.8],[119.1,-20.0],[121.1,-19.5],[122.4,-18.1],[122.2,-17.3],[122.9,-16.4],[123.6,-17.6],[123.6,-17.0],[123.9,-17.3],[124.0,-16.8],[123.5,-16.7],[123.6,-16.2],[124.4,-16.6],[125.0,-16.4],[124.4,-16.3],[124.8,-15.8],[124.5,-16.0],[124.4,-15.7],[124.7,-15.3],[125.2,-15.6],[124.8,-15.2],[125.5,-15.2],[125.1,-14.7],[125.6,-14.2],[125.9,-14.7],[126.0,-13.9],[126.2,-14.3],[126.5,-13.9],[126.6,-14.3],[126.9,-13.7],[127.4,-13.9],[128.2,-14.7],[128.0,-15.5],[128.1,-15.2],[128.4,-15.5],[128.2,-15.1],[128.6,-14.8],[129.1,-14.9],[129.1,-15.3],[129.3,-14.9],[129.6,-15.2],[130.0,-14.7],[129.4,-14.3],[129.8,-13.5],[130.3,-13.4],[130.4,-12.7],[130.7,-12.7],[130.6,-12.4],[131.0,-12.7],[130.8,-12.4],[131.3,-12.0],[131.5,-12.3],[132.8,-12.2],[132.7,-11.6],[131.8,-11.3],[132.0,-11.1],[133.5,-11.9],[133.9,-11.7],[134.2,-12.2],[134.7,-12.0],[135.2,-12.3],[135.9,-12.0],[135.7,-12.2],[136.0,-12.1],[136.0,-12.5],[136.6,-11.9],[137.0,-12.3],[136.5,-12.8],[136.5,-13.3],[135.9,-13.3],[136.1,-13.7],[135.4,-14.9],[136.7,-15.9],[139.0,-16.9],[139.6,-17.5],[140.6,-17.6],[141.7,-15.0],[141.5,-13.9],[142.0,-12.6],[141.6,-12.6],[142.1,-12.0],[142.1,-11.0],[142.5,-10.7],[143.5,-12.8],[143.8,-14.4],[144.5,-14.2],[145.3,-14.9],[145.4,-16.4],[146.0,-16.9],[146.3,-18.9],[148.8,-20.2],[149.6,-22.6],[149.8,-22.4],[150.1,-22.7],[150.0,-22.1],[150.6,-22.7],[150.7,-22.3],[150.8,-23.5],[151.8,-24.0],[153.2,-25.9],[153.0,-27.3],[153.6,-28.6],[153.1,-31.1],[152.4,-32.2],[152.5,-32.4],[151.2,-33.5],[150.6,-34.9],[150.8,-35.1],[150.2,-35.7],[150.0,-37.5],[147.7,-37.9],[147.5,-38.1],[148.0,-37.9],[146.2,-38.7]],[[-44.7,60.0],[-44.5,60.5],[-45.2,60.1],[-44.6,60.7],[-45.2,60.4],[-45.2,60.8],[-46.0,60.6],[-45.4,61.0],[-46.2,60.7],[-45.2,61.2],[-47.7,60.8],[-47.9,61.3],[-49.1,61.4],[-48.3,61.5],[-49.3,61.5],[-48.6,61.6],[-49.2,61.7],[-48.8,62.0],[-49.5,61.8],[-48.8,62.1],[-49.7,62.0],[-49.3,62.3],[-50.3,62.5],[-49.7,63.0],[-50.4,62.8],[-50.1,63.2],[-51.1,63.3],[-50.2,63.4],[-51.2,63.4],[-50.5,63.7],[-51.6,63.7],[-50.9,63.9],[-51.6,64.0],[-50.1,64.1],[-51.8,64.2],[-50.2,64.4],[-50.9,64.6],[-49.6,64.3],[-51.0,65.2],[-50.7,64.7],[-52.0,64.2],[-52.2,64.7],[-51.3,65.0],[-52.2,64.8],[-52.0,65.3],[-52.6,65.3],[-50.5,65.7],[-51.2,65.8],[-52.5,65.4],[-53.2,65.8],[-51.8,66.1],[-53.5,66.0],[-50.3,66.8],[-51.0,67.0],[-53.7,66.1],[-53.1,66.3],[-53.6,66.5],[-52.4,66.5],[-53.5,66.6],[-52.2,66.8],[-53.9,67.2],[-51.5,67.3],[-53.8,67.4],[-50.3,67.9],[-52.3,67.8],[-51.6,68.0],[-53.7,67.5],[-53.2,68.0],[-52.1,68.0],[-53.3,68.2],[-50.3,67.9],[-51.4,68.2],[-50.8,68.5],[-53.5,68.3],[-52.2,68.6],[-50.7,68.5],[-51.1,69.1],[-50.4,68.9],[-50.0,69.2],[-51.2,69.2],[-50.2,70.1],[-52.4,70.0],[-54.6,70.7],[-52.9,70.8],[-50.6,70.3],[-52.0,71.0],[-50.9,71.0],[-52.2,71.1],[-51.5,71.3],[-52.5,71.2],[-51.4,71.5],[-53.0,71.4],[-51.7,71.7],[-53.3,71.7],[-53.6,72.4],[-53.9,71.4],[-55.9,71.7],[-54.4,72.2],[-55.3,71.9],[-54.7,72.4],[-55.6,72.5],[-54.3,72.5],[-55.7,73.1],[-56.1,74.3],[-57.3,74.1],[-56.2,74.6],[-60.9,76.2],[-63.4,76.4],[-65.4,76.0],[-67.1,76.3],[-66.5,75.9],[-68.5,76.1],[-69.6,76.4],[-67.9,76.7],[-71.4,77.1],[-66.4,77.1],[-69.1,77.3],[-66.2,77.3],[-66.2,77.6],[-69.3,77.5],[-73.1,78.2],[-69.0,79.0],[-66.0,79.1],[-63.8,80.1],[-67.0,80.1],[-67.5,80.3],[-64.1,81.1],[-63.1,80.7],[-63.5,81.2],[-61.8,81.0],[-61.8,81.8],[-59.8,81.9],[-57.2,81.3],[-60.1,82.0],[-55.2,82.3],[-54.8,81.6],[-53.7,82.0],[-50.3,81.6],[-51.7,82.5],[-45.3,81.8],[-45.6,82.3],[-43.3,82.2],[-46.5,82.8],[-40.9,82.4],[-41.2,82.7],[-45.9,82.9],[-44.3,83.3],[-39.7,82.7],[-38.9,83.5],[-26.8,83.3],[-34.8,83.2],[-36.9,82.7],[-26.2,83.2],[-26.9,82.8],[-21.9,82.6],[-25.8,82.2],[-32.8,82.2],[-34.3,81.8],[-26.2,82.0],[-27.8,81.4],[-22.9,82.1],[-24.8,80.5],[-21.1,81.6],[-18.4,81.4],[-16.8,81.9],[-12.9,81.7],[-14.8,80.9],[-21.3,80.6],[-16.1,80.5],[-20.6,80.1],[-20.4,79.8],[-17.6,80.0],[-21.8,78.1],[-22.0,77.7],[-20.9,78.0],[-19.2,77.7],[-21.1,77.5],[-18.4,77.3],[-18.3,76.8],[-22.7,76.7],[-21.8,76.2],[-19.8,76.2],[-21.9,76.0],[-19.4,75.7],[-19.6,75.1],[-22.5,75.5],[-20.6,75.2],[-22.5,75.2],[-20.6,75.1],[-21.1,74.6],[-19.0,74.5],[-19.6,74.2],[-22.1,74.6],[-22.5,74.1],[-21.8,73.6],[-21.7,74.1],[-20.3,73.9],[-20.4,73.5],[-22.4,73.2],[-24.1,73.7],[-22.2,73.6],[-24.1,73.8],[-24.5,73.5],[-25.8,73.9],[-24.7,73.5],[-26.0,73.2],[-27.3,73.5],[-26.4,73.2],[-27.7,73.1],[-25.1,73.1],[-27.5,72.8],[-26.6,72.5],[-25.3,72.8],[-24.6,72.5],[-26.3,72.4],[-25.3,72.4],[-25.5,72.1],[-24.6,72.4],[-22.5,71.9],[-23.2,71.6],[-21.9,71.7],[-22.6,71.5],[-21.8,71.5],[-22.3,71.1],[-21.5,70.5],[-22.4,70.5],[-22.5,70.9],[-23.4,70.5],[-24.6,71.3],[-28.4,72.0],[-27.3,71.7],[-28.5,71.5],[-25.4,71.3],[-26.8,70.9],[-27.9,71.2],[-29.3,70.5],[-26.5,70.5],[-28.6,70.1],[-27.4,70.0],[-25.3,70.4],[-22.1,70.1],[-26.4,68.7],[-29.4,68.2],[-30.0,68.4],[-30.1,68.1],[-31.6,68.1],[-32.6,68.6],[-32.1,67.9],[-33.2,67.7],[-34.8,66.3],[-35.9,66.4],[-35.6,66.1],[-37.0,65.9],[-37.3,66.1],[-37.2,65.7],[-37.8,65.9],[-37.2,66.3],[-37.9,66.4],[-38.2,65.6],[-39.9,65.6],[-40.2,65.0],[-41.1,65.1],[-40.3,64.3],[-41.6,64.3],[-40.6,64.1],[-40.5,63.7],[-41.5,63.9],[-40.7,63.6],[-41.6,63.5],[-41.1,63.3],[-41.9,63.5],[-41.3,63.1],[-42.1,63.2],[-41.8,62.8],[-43.2,62.7],[-42.1,62.4],[-43.0,62.5],[-42.1,62.0],[-42.9,61.8],[-42.2,61.7],[-43.1,61.6],[-42.4,61.5],[-43.3,61.3],[-42.6,61.1],[-43.6,61.1],[-42.7,61.1],[-43.5,60.8],[-42.9,60.5],[-44.2,60.6],[-43.1,60.1],[-44.1,60.4],[-44.7,60.0]],[[150.0,-10.1],[150.9,-10.2],[150.2,-10.7],[149.7,-10.3],[147.7,-10.1],[146.1,-8.1],[144.9,-7.8],[144.8,-7.4],[144.5,-7.7],[144.4,-7.4],[144.5,-7.8],[143.6,-7.4],[143.9,-8.0],[143.4,-7.9],[143.7,-8.2],[142.2,-8.2],[143.4,-8.8],[142.6,-9.3],[142.2,-9.1],[141.1,-9.2],[140.0,-8.0],[139.0,-8.3],[139.1,-7.6],[138.7,-7.2],[139.2,-7.1],[138.5,-7.0],[138.9,-6.8],[138.4,-6.3],[138.4,-5.7],[138.1,-5.7],[138.1,-5.4],[135.2,-4.5],[134.6,-4.1],[134.9,-3.9],[134.0,-3.9],[133.6,-3.5],[133.8,-2.9],[133.4,-3.9],[132.9,-4.1],[132.8,-3.3],[131.9,-2.8],[132.7,-2.8],[133.2,-2.4],[133.7,-2.7],[133.9,-2.1],[132.3,-2.3],[132.0,-1.5],[130.9,-1.4],[131.2,-0.8],[132.4,-0.3],[134.0,-0.7],[134.2,-2.4],[134.5,-2.9],[134.6,-2.5],[135.1,-3.4],[135.8,-3.1],[136.4,-2.2],[137.2,-2.1],[137.1,-1.8],[137.9,-1.5],[144.5,-3.8],[145.8,-4.9],[145.8,-5.5],[147.6,-6.1],[147.9,-6.7],[147.0,-6.7],[147.2,-7.5],[148.1,-8.1],[148.6,-9.1],[149.3,-9.0],[149.2,-9.5],[150.0,-9.6],[149.7,-9.8],[150.0,-10.1]],[[115.0,-4.0],[114.6,-4.2],[114.5,-3.4],[113.6,-3.5],[113.6,-3.1],[113.0,-2.9],[111.9,-3.6],[111.7,-2.8],[110.3,-3.0],[110.0,-1.1],[109.4,-1.3],[109.6,-1.0],[109.2,-0.7],[109.6,-0.7],[109.1,-0.5],[109.3,0.0],[108.9,0.3],[108.9,1.2],[109.6,2.1],[109.9,1.7],[111.2,1.4],[111.4,2.7],[113.0,3.2],[114.0,4.6],[115.4,4.9],[115.6,5.2],[115.4,5.4],[115.9,5.6],[116.7,7.0],[116.8,6.5],[117.2,7.0],[117.7,6.4],[117.6,5.9],[118.0,6.1],[117.9,5.7],[118.3,5.8],[119.3,5.4],[118.1,4.9],[118.6,4.4],[117.4,4.2],[117.8,3.6],[117.0,3.6],[118.1,2.3],[117.7,2.2],[117.8,1.9],[119.0,1.0],[118.4,0.8],[117.9,1.1],[118.0,0.8],[117.5,0.1],[117.6,-0.8],[116.9,-1.3],[116.7,-1.1],[116.2,-1.8],[116.6,-2.2],[116.3,-3.0],[116.1,-2.9],[116.3,-3.1],[115.0,-4.0]],[[45.0,-25.5],[44.0,-25.0],[43.2,-22.3],[43.5,-21.3],[44.5,-20.0],[43.9,-17.5],[44.4,-16.2],[46.2,-15.7],[46.5,-16.0],[46.5,-15.5],[47.0,-15.2],[46.9,-15.6],[47.2,-15.5],[47.0,-15.2],[47.5,-14.7],[47.5,-15.1],[47.8,-14.2],[48.0,-14.3],[47.9,-13.6],[48.3,-13.8],[48.8,-13.4],[48.7,-12.4],[49.3,-12.0],[49.2,-12.3],[49.9,-13.0],[50.5,-15.4],[50.2,-16.0],[49.9,-15.4],[49.6,-15.5],[49.8,-16.8],[49.4,-17.2],[49.4,-18.2],[47.1,-25.0],[45.0,-25.5]],[[-66.0,62.0],[-71.6,63.1],[-72.1,63.4],[-71.2,63.6],[-72.6,63.8],[-73.3,64.7],[-73.6,64.3],[-74.6,64.9],[-74.5,64.4],[-78.0,64.4],[-77.4,65.5],[-75.8,65.2],[-73.5,65.4],[-74.5,66.2],[-73.1,66.7],[-72.1,66.7],[-73.0,66.8],[-72.2,67.3],[-73.7,68.7],[-74.2,68.5],[-75.5,69.0],[-76.6,68.7],[-75.6,69.2],[-76.2,69.7],[-77.2,69.6],[-77.0,70.0],[-77.6,69.7],[-79.0,70.7],[-79.6,70.4],[-78.8,69.9],[-81.7,70.1],[-80.9,69.7],[-83.0,70.3],[-81.8,69.9],[-85.8,70.0],[-86.4,70.5],[-87.9,70.2],[-88.8,70.5],[-89.5,71.1],[-85.0,71.2],[-84.8,70.9],[-84.5,71.6],[-86.0,72.0],[-85.2,72.3],[-84.1,72.0],[-85.7,72.9],[-84.0,72.7],[-85.5,73.0],[-83.7,73.0],[-85.0,73.3],[-81.5,73.7],[-80.2,72.7],[-81.0,71.9],[-79.8,72.5],[-77.7,71.7],[-78.9,72.2],[-77.0,72.1],[-78.6,72.4],[-77.6,72.8],[-75.2,72.5],[-76.4,71.9],[-74.2,72.1],[-75.4,71.7],[-74.6,71.7],[-75.0,71.2],[-73.6,71.8],[-73.9,71.0],[-72.5,71.7],[-71.2,71.3],[-72.6,70.6],[-70.6,71.1],[-72.0,70.4],[-71.2,70.5],[-71.5,70.0],[-69.9,70.9],[-70.6,70.5],[-69.4,70.8],[-68.3,70.5],[-70.2,70.0],[-68.7,70.2],[-70.0,69.6],[-68.2,70.3],[-67.3,70.0],[-67.2,69.7],[-70.1,69.5],[-67.2,69.5],[-66.7,69.2],[-69.0,69.4],[-68.1,69.2],[-69.0,69.0],[-68.2,69.2],[-67.8,68.8],[-69.4,68.8],[-66.7,68.4],[-67.9,68.3],[-67.0,68.3],[-66.7,67.9],[-66.3,68.1],[-66.4,67.8],[-65.9,68.0],[-66.0,67.6],[-65.8,68.0],[-65.3,67.6],[-64.7,68.0],[-65.2,67.6],[-64.5,67.8],[-64.0,67.3],[-64.8,67.4],[-64.0,67.3],[-64.7,67.0],[-63.5,67.2],[-63.8,66.9],[-63.1,67.3],[-63.8,66.8],[-62.8,67.0],[-62.7,66.7],[-62.0,67.1],[-61.3,66.7],[-62.2,66.6],[-61.5,66.3],[-62.9,66.3],[-61.9,66.0],[-62.9,66.1],[-62.7,65.6],[-63.5,65.9],[-63.5,64.9],[-65.5,65.7],[-64.4,66.4],[-65.9,65.9],[-65.5,66.4],[-66.0,66.1],[-66.7,66.6],[-67.9,66.6],[-67.1,66.0],[-68.4,66.1],[-68.2,65.4],[-67.3,65.7],[-66.7,64.7],[-66.7,65.0],[-66.3,64.6],[-65.7,64.8],[-65.0,64.4],[-65.7,64.3],[-64.6,64.0],[-64.5,63.2],[-65.3,63.8],[-64.9,62.6],[-67.9,63.8],[-67.7,63.4],[-69.0,63.8],[-66.0,62.0]],[[104.0,-5.3],[101.6,-3.2],[100.3,-0.9],[99.1,0.3],[98.8,1.7],[97.8,2.3],[96.9,3.7],[95.5,4.7],[95.2,5.6],[97.5,5.3],[98.3,4.4],[98.2,4.1],[99.8,3.2],[100.9,1.8],[101.0,2.3],[102.4,0.8],[102.9,0.7],[103.1,0.5],[102.7,0.2],[103.3,0.5],[103.7,0.3],[103.3,-0.7],[104.4,-1.0],[104.5,-2.0],[104.9,-2.1],[104.7,-2.6],[104.8,-2.3],[105.6,-2.4],[106.1,-3.2],[105.7,-5.9],[105.3,-5.4],[105.2,-5.8],[104.5,-5.5],[104.6,-5.9],[104.0,-5.3]],[[136.0,33.7],[135.8,33.4],[135.1,33.9],[135.3,34.7],[134.2,34.7],[132.6,34.1],[132.4,34.4],[132.1,33.8],[130.9,33.9],[130.9,34.3],[133.1,35.6],[136.1,35.7],[136.8,37.4],[137.3,37.5],[136.9,37.1],[137.3,36.8],[139.4,38.1],[140.1,39.7],[140.1,40.0],[139.7,39.9],[139.9,40.6],[140.3,41.3],[141.1,40.9],[140.8,41.4],[141.5,41.4],[142.1,39.5],[141.5,38.3],[140.9,38.2],[141.0,37.0],[140.6,36.3],[140.9,35.7],[139.9,34.9],[140.1,35.6],[139.8,35.7],[139.7,35.1],[139.2,35.3],[138.8,34.6],[138.7,35.1],[138.2,34.6],[137.0,34.6],[137.4,34.8],[137.0,35.0],[136.9,34.7],[136.7,35.1],[136.5,34.7],[136.9,34.3],[136.0,33.7]],[[-113.6,69.0],[-116.5,69.4],[-117.4,70.0],[-111.4,70.3],[-113.8,70.7],[-117.7,70.6],[-118.3,71.0],[-115.0,71.5],[-118.2,71.4],[-117.7,71.7],[-119.1,71.8],[-118.5,72.5],[-114.5,73.4],[-114.5,72.6],[-112.8,73.0],[-111.2,72.7],[-112.0,72.3],[-111.0,72.3],[-110.7,72.6],[-109.7,72.4],[-110.7,73.0],[-109.9,73.0],[-107.8,71.6],[-108.2,73.2],[-106.8,73.3],[-105.3,72.8],[-104.5,71.0],[-101.0,70.2],[-101.0,69.7],[-101.4,69.9],[-102.6,69.5],[-103.5,69.7],[-103.2,69.1],[-102.3,69.5],[-101.8,69.0],[-105.1,68.9],[-106.6,69.5],[-109.0,68.7],[-113.2,68.5],[-113.6,69.0]],[[0.0,50.8],[-3.5,50.7],[-3.6,50.2],[-5.7,50.1],[-4.2,51.2],[-3.1,51.2],[-2.3,51.8],[-3.4,51.4],[-5.3,51.9],[-3.9,52.6],[-4.1,52.9],[-4.8,52.8],[-4.2,53.2],[-2.7,53.4],[-3.1,53.5],[-2.8,54.2],[-3.2,54.1],[-3.6,54.5],[-3.1,55.0],[-4.9,54.9],[-4.9,54.6],[-5.1,54.9],[-4.9,55.9],[-4.4,55.9],[-4.8,56.2],[-5.3,55.9],[-5.8,55.3],[-5.0,56.7],[-6.2,56.7],[-5.4,57.1],[-5.8,57.9],[-5.1,57.8],[-5.0,58.6],[-3.0,58.6],[-4.4,57.5],[-1.8,57.6],[-2.5,56.6],[-3.4,56.4],[-2.6,56.3],[-3.8,56.1],[-2.1,55.9],[-1.2,54.6],[-0.1,54.1],[0.0,53.8],[-0.8,53.7],[-0.2,53.7],[0.0,53.5],[-0.0,52.9],[1.3,52.9],[1.8,52.5],[0.9,51.6],[0.3,51.5],[1.4,51.4],[1.4,51.2],[0.0,50.8]],[[-77.1,83.1],[-77.0,83.1],[-66.4,82.9],[-68.6,82.6],[-63.6,82.8],[-61.1,82.4],[-62.4,82.0],[-65.8,81.6],[-69.3,81.7],[-66.6,81.5],[-70.0,81.1],[-64.6,81.4],[-69.5,80.4],[-70.8,80.6],[-70.1,80.2],[-72.4,80.2],[-70.5,80.1],[-71.5,79.7],[-74.2,79.9],[-73.2,79.5],[-78.0,79.4],[-74.4,79.0],[-78.9,79.1],[-74.6,78.6],[-76.6,78.5],[-75.0,78.3],[-76.9,78.2],[-75.9,78.0],[-78.2,78.0],[-78.7,77.3],[-82.0,77.7],[-81.8,77.2],[-78.0,77.0],[-78.4,76.5],[-81.1,76.1],[-82.7,76.8],[-82.3,76.4],[-83.4,76.8],[-83.2,76.4],[-84.3,76.7],[-85.2,76.3],[-86.6,76.6],[-86.7,76.3],[-87.5,76.6],[-87.6,76.3],[-88.4,76.8],[-88.6,76.4],[-89.7,76.6],[-86.6,77.2],[-88.2,77.9],[-84.5,77.3],[-82.3,78.1],[-84.8,77.5],[-84.6,78.6],[-85.5,78.1],[-85.8,78.4],[-87.5,78.1],[-86.9,78.7],[-85.1,78.9],[-82.3,78.6],[-83.3,78.8],[-81.5,79.1],[-84.7,79.0],[-83.4,79.1],[-86.5,80.3],[-83.8,80.2],[-80.6,79.6],[-83.2,80.3],[-76.5,80.9],[-79.0,80.9],[-76.8,81.5],[-80.9,80.7],[-83.1,80.5],[-81.7,80.8],[-83.2,80.8],[-86.1,80.5],[-85.5,80.8],[-82.3,81.2],[-87.5,80.6],[-89.4,80.9],[-84.6,81.3],[-89.7,81.0],[-87.2,81.5],[-90.4,81.4],[-89.5,81.6],[-91.9,81.7],[-88.0,82.1],[-84.5,81.9],[-86.9,82.2],[-85.2,82.5],[-80.4,82.0],[-82.4,82.7],[-77.1,83.1]],[[119.5,-5.0],[119.5,-3.6],[118.9,-3.6],[118.8,-2.8],[119.4,-1.9],[119.3,-1.2],[119.7,-0.6],[119.9,-0.9],[119.6,-0.0],[119.8,-0.1],[120.0,0.7],[120.3,1.0],[120.6,0.8],[120.9,1.4],[124.0,0.8],[125.2,1.7],[124.3,0.4],[120.3,0.4],[120.1,-0.6],[120.7,-1.4],[121.1,-1.4],[121.6,-0.8],[123.5,-0.8],[121.7,-1.9],[121.3,-1.8],[122.5,-3.2],[122.2,-3.6],[122.9,-4.4],[122.1,-4.5],[122.0,-4.9],[121.5,-4.8],[121.6,-4.1],[120.9,-3.6],[121.1,-2.7],[120.8,-2.6],[120.2,-3.0],[120.5,-5.6],[119.4,-5.6],[119.5,-5.0]],[[170.0,-46.3],[169.0,-46.7],[167.7,-46.2],[166.7,-46.2],[166.8,-45.3],[167.2,-45.5],[167.0,-45.1],[168.4,-44.0],[169.2,-44.0],[170.7,-43.1],[172.1,-40.9],[173.0,-40.5],[172.7,-40.7],[173.2,-41.3],[174.3,-41.0],[173.9,-41.3],[174.3,-41.2],[174.3,-41.7],[172.8,-43.1],[172.7,-43.6],[173.1,-43.9],[172.2,-43.9],[171.7,-43.5],[172.2,-43.9],[171.3,-44.0],[170.8,-45.9],[170.0,-46.3]],[[114.0,-8.6],[110.7,-8.2],[108.9,-7.6],[107.8,-7.7],[106.4,-7.4],[106.5,-7.0],[105.2,-6.8],[105.8,-6.5],[106.0,-5.9],[108.3,-6.2],[108.9,-6.8],[110.4,-7.0],[111.0,-6.4],[112.5,-6.8],[113.2,-7.7],[114.4,-7.8],[114.6,-8.8],[114.0,-8.6]],[[174.9,-41.0],[175.1,-39.9],[173.8,-39.3],[174.6,-38.8],[175.0,-37.8],[174.5,-37.1],[174.9,-37.1],[174.5,-37.0],[174.2,-36.5],[174.4,-36.6],[174.5,-36.3],[173.9,-36.0],[174.0,-36.4],[172.7,-34.4],[173.0,-34.4],[173.2,-35.0],[173.4,-34.8],[174.1,-35.3],[174.3,-35.2],[174.3,-35.8],[174.9,-36.4],[174.7,-36.9],[175.6,-37.2],[175.5,-36.5],[176.0,-37.7],[177.2,-38.0],[178.0,-37.5],[178.6,-37.7],[178.0,-39.1],[177.0,-39.2],[176.0,-41.2],[175.2,-41.6],[174.6,-41.3],[174.9,-41.0]],[[-55.2,47.0],[-56.0,47.0],[-54.7,47.7],[-56.1,47.5],[-55.8,48.0],[-56.9,47.5],[-58.3,47.8],[-59.2,47.6],[-59.4,47.9],[-58.3,48.5],[-59.3,48.5],[-58.4,49.1],[-57.9,49.0],[-58.2,49.4],[-57.7,49.5],[-57.4,50.7],[-55.9,51.6],[-55.5,51.4],[-56.1,51.4],[-55.7,51.1],[-56.9,49.5],[-56.2,50.2],[-56.2,49.9],[-55.5,50.0],[-56.1,49.4],[-55.2,49.5],[-55.4,49.0],[-54.5,49.6],[-54.5,49.3],[-53.5,49.3],[-54.2,48.4],[-53.0,48.5],[-54.0,48.2],[-53.6,48.1],[-53.9,47.9],[-53.6,47.5],[-52.9,48.2],[-53.3,47.5],[-52.8,47.8],[-52.6,47.5],[-53.2,46.6],[-53.6,46.6],[-53.6,47.2],[-54.2,46.8],[-53.8,47.4],[-54.1,47.9],[-55.2,47.0]],[[-75.0,19.9],[-77.7,19.8],[-77.1,20.4],[-77.2,20.7],[-78.1,20.8],[-78.8,21.6],[-81.8,22.2],[-82.2,22.4],[-81.6,22.5],[-81.9,22.7],[-82.8,22.7],[-84.0,21.9],[-85.0,21.9],[-84.3,22.0],[-84.0,22.7],[-81.1,23.2],[-79.8,22.9],[-76.9,21.3],[-75.7,21.1],[-75.7,20.7],[-74.1,20.2],[-75.0,19.9]],[[124.0,13.0],[123.3,13.0],[122.5,14.0],[122.6,13.2],[121.7,14.0],[121.3,13.6],[120.6,13.8],[121.0,14.6],[120.6,14.8],[120.5,14.4],[120.1,14.8],[119.7,16.0],[119.9,16.4],[120.4,16.2],[120.6,18.5],[122.3,18.4],[122.1,17.8],[122.5,16.9],[121.4,15.3],[121.7,14.4],[122.2,13.9],[122.2,14.2],[122.8,14.3],[123.1,13.7],[123.3,14.1],[123.7,13.9],[124.0,13.7],[123.5,13.6],[123.8,13.1],[124.2,13.1],[124.1,12.5],[124.0,13.0]],[[-17.0,63.8],[-18.7,63.4],[-21.1,63.9],[-22.7,63.8],[-21.4,64.4],[-24.0,64.9],[-21.8,65.0],[-22.6,65.2],[-21.7,65.5],[-24.5,65.5],[-23.8,65.5],[-24.1,65.8],[-23.3,65.7],[-23.5,66.2],[-22.4,65.8],[-23.1,66.4],[-21.3,66.0],[-21.1,65.2],[-20.4,66.1],[-19.4,65.7],[-18.8,66.2],[-18.1,65.6],[-18.3,66.2],[-16.6,66.1],[-16.2,66.5],[-15.4,66.2],[-14.5,66.4],[-15.2,66.1],[-13.5,65.1],[-14.2,65.0],[-13.7,64.9],[-15.0,64.2],[-17.0,63.8]],[[125.0,5.9],[124.1,6.4],[124.3,7.4],[123.7,7.8],[123.4,7.4],[122.6,7.8],[122.2,6.9],[121.9,7.1],[122.2,8.0],[123.4,8.7],[123.8,8.4],[123.7,8.0],[124.4,8.6],[124.7,8.5],[124.8,9.0],[125.5,9.0],[125.4,9.8],[126.2,9.3],[126.1,8.6],[126.4,8.5],[126.6,7.3],[126.2,6.9],[126.2,6.3],[125.7,7.3],[125.4,6.7],[125.7,6.0],[125.4,5.6],[125.3,6.1],[125.0,5.9]],[[-8.0,51.9],[-9.8,51.4],[-9.5,51.7],[-10.2,51.6],[-9.6,51.9],[-10.4,51.8],[-9.8,52.2],[-10.4,52.2],[-8.7,52.7],[-9.9,52.6],[-8.9,53.2],[-10.2,53.4],[-9.6,53.8],[-10.1,54.2],[-8.5,54.2],[-8.1,54.6],[-8.8,54.7],[-8.0,55.2],[-7.6,55.0],[-7.4,55.4],[-6.9,55.2],[-7.3,55.0],[-6.1,55.2],[-5.4,54.5],[-6.4,54.0],[-6.3,52.2],[-8.0,51.9]],[[143.3,42.0],[141.7,42.6],[141.0,42.3],[140.5,42.6],[140.3,42.2],[141.2,41.8],[140.0,41.6],[139.8,42.6],[140.5,43.0],[140.3,43.3],[141.4,43.3],[141.9,45.5],[143.7,44.1],[144.8,43.9],[145.3,44.3],[145.2,43.3],[145.8,43.4],[144.0,42.9],[143.3,42.0]],[[142.0,46.0],[142.3,51.1],[141.6,52.3],[141.8,53.4],[142.8,53.7],[142.3,54.3],[142.7,54.4],[143.2,51.5],[144.7,48.6],[144.0,49.3],[143.0,49.1],[142.5,47.8],[143.6,46.4],[143.4,46.0],[143.4,46.5],[142.5,46.7],[142.0,46.0]],[[-71.2,18.0],[-71.4,17.6],[-72.1,18.2],[-73.9,18.0],[-74.5,18.4],[-74.2,18.7],[-72.4,18.5],[-72.8,19.0],[-72.7,19.5],[-73.5,19.7],[-72.8,20.0],[-70.0,19.7],[-69.7,19.3],[-69.2,19.3],[-69.6,19.1],[-68.3,18.6],[-68.6,18.2],[-70.7,18.4],[-71.2,18.0]],[[-120.3,72.0],[-120.6,71.5],[-123.1,71.1],[-124.9,72.0],[-126.0,72.0],[-123.8,73.8],[-124.7,74.4],[-121.5,74.6],[-119.1,74.0],[-117.6,74.3],[-115.3,73.5],[-120.3,72.0]],[[80.3,6.0],[79.7,8.2],[79.8,8.0],[80.1,9.6],[80.4,9.5],[79.9,9.8],[80.2,9.8],[81.4,8.5],[81.9,7.0],[81.3,6.2],[80.3,6.0]],[[146.0,-43.3],[145.3,-42.6],[145.2,-42.2],[145.6,-42.4],[144.7,-41.4],[144.7,-40.7],[146.6,-41.3],[148.1,-40.8],[148.4,-42.2],[148.2,-42.0],[148.0,-43.2],[147.2,-42.7],[146.9,-43.6],[146.0,-43.3]],[[-92.2,75.0],[-93.1,76.4],[-95.4,76.2],[-96.8,77.0],[-93.7,76.9],[-93.6,76.4],[-91.0,76.7],[-91.5,76.5],[-89.2,76.2],[-91.6,76.3],[-90.2,76.1],[-91.2,75.8],[-89.9,76.0],[-88.9,75.4],[-88.8,75.7],[-86.6,75.4],[-81.6,75.8],[-79.6,75.5],[-80.4,75.0],[-79.3,74.9],[-81.8,74.5],[-83.5,74.9],[-83.6,74.5],[-87.7,74.5],[-88.6,74.9],[-90.0,74.5],[-92.2,75.0]],[[-66.7,-55.0],[-72.0,-54.6],[-70.8,-54.3],[-70.8,-54.6],[-70.1,-54.6],[-70.9,-54.1],[-69.8,-54.6],[-69.5,-54.3],[-69.3,-54.7],[-69.0,-54.5],[-70.1,-54.1],[-69.3,-53.4],[-70.4,-53.4],[-70.4,-52.8],[-68.8,-52.6],[-67.8,-53.8],[-65.1,-54.6],[-66.7,-55.0]],[[58.3,74.0],[57.5,74.2],[57.9,73.8],[56.6,73.9],[57.6,73.6],[56.4,73.7],[56.7,73.2],[54.1,73.3],[55.8,73.6],[53.7,73.8],[55.0,74.2],[56.4,74.0],[55.1,74.2],[57.0,74.7],[56.0,75.2],[61.1,76.3],[64.8,76.3],[68.6,77.0],[68.4,76.2],[61.3,75.3],[59.2,74.4],[58.2,74.5],[58.3,74.0]],[[-81.0,63.4],[-82.5,63.7],[-83.0,64.2],[-85.2,63.1],[-85.7,63.7],[-87.2,63.6],[-86.2,64.1],[-85.6,65.9],[-84.9,65.2],[-84.5,65.5],[-81.8,64.5],[-82.0,64.0],[-80.9,64.1],[-80.1,63.8],[-81.0,63.4]],[[-115.6,75.0],[-117.7,75.3],[-115.0,75.7],[-117.2,75.6],[-114.8,75.9],[-116.7,75.9],[-114.6,76.2],[-115.9,76.3],[-114.9,76.5],[-111.2,75.5],[-108.9,75.5],[-110.4,76.4],[-109.1,76.8],[-108.0,75.8],[-106.8,75.7],[-106.6,76.1],[-105.4,75.9],[-106.0,75.1],[-108.8,75.1],[-112.4,74.4],[-114.4,74.7],[-111.0,75.3],[-113.9,75.1],[-114.0,75.5],[-115.6,75.0]],[[-94.2,79.0],[-90.3,79.2],[-95.1,79.3],[-94.3,79.8],[-96.6,79.9],[-96.7,80.1],[-94.4,80.0],[-96.6,80.4],[-93.8,80.5],[-95.5,80.8],[-93.5,81.4],[-88.3,80.1],[-87.6,80.4],[-87.4,79.5],[-85.7,79.6],[-84.9,79.3],[-87.6,78.6],[-88.2,79.0],[-88.9,78.1],[-90.0,78.6],[-89.5,78.1],[-92.1,78.2],[-93.0,78.5],[-91.7,78.6],[-94.2,79.0]],[[15.4,77.0],[13.9,77.5],[16.1,77.5],[14.7,77.7],[17.0,77.9],[13.9,77.7],[13.6,78.1],[17.4,78.4],[16.6,78.7],[15.4,78.5],[15.3,78.9],[13.0,78.2],[10.7,79.5],[13.8,79.9],[12.3,79.6],[14.0,79.3],[14.7,79.8],[16.5,78.9],[16.3,80.1],[17.7,79.4],[18.3,79.6],[21.5,78.7],[19.0,78.4],[17.0,76.6],[15.4,77.0]],[[-50.8,-0.8],[-50.3,-0.1],[-48.4,-0.3],[-48.8,-1.4],[-49.8,-1.8],[-50.6,-1.8],[-50.8,-1.1],[-50.5,-1.0],[-50.8,-0.8]],[[130.7,31.0],[130.8,31.7],[130.6,31.2],[130.1,31.4],[130.7,32.6],[130.5,33.3],[130.1,33.1],[130.4,32.7],[129.7,32.6],[129.7,33.1],[130.0,32.8],[129.6,33.3],[131.0,33.8],[132.1,32.9],[131.3,31.4],[130.7,31.0]],[[120.9,22.0],[120.0,23.1],[120.1,23.6],[121.6,25.3],[122.0,25.0],[120.9,22.0]],[[151.1,-6.0],[149.6,-6.3],[148.3,-5.6],[149.9,-5.5],[150.1,-5.0],[150.1,-5.5],[150.9,-5.5],[151.7,-4.9],[151.5,-4.2],[152.2,-4.1],[152.4,-4.3],[151.9,-5.0],[152.1,-5.4],[151.1,-6.0]],[[-85.0,71.3],[-87.0,71.2],[-90.0,71.5],[-89.1,73.2],[-86.6,73.9],[-84.8,73.7],[-86.3,72.7],[-86.1,72.0],[-85.0,71.3]],[[109.0,18.4],[108.6,19.3],[109.3,19.9],[110.9,20.0],[111.0,19.6],[110.4,18.7],[109.6,18.2],[109.0,18.4]],[[-97.0,71.7],[-98.2,71.6],[-98.2,71.9],[-98.2,71.4],[-99.2,71.4],[-102.7,72.7],[-102.2,73.1],[-100.2,72.8],[-99.8,73.2],[-101.6,73.5],[-100.4,73.4],[-100.9,73.8],[-97.0,73.7],[-98.5,73.0],[-96.5,72.8],[-97.0,71.7]],[[54.0,70.7],[53.5,71.5],[51.9,71.5],[51.4,71.8],[53.7,72.6],[52.4,72.7],[53.6,72.9],[53.2,73.2],[54.8,73.3],[56.5,73.2],[55.1,72.6],[55.2,71.9],[57.6,70.7],[54.0,70.7]],[[-125.7,49.0],[-127.1,50.1],[-127.9,50.1],[-127.4,50.6],[-128.0,50.4],[-128.4,50.8],[-125.4,50.3],[-123.3,48.5],[-125.1,48.7],[-124.8,49.3],[-125.7,49.0]],[[124.0,-10.3],[123.5,-10.4],[123.7,-9.6],[125.1,-8.6],[127.3,-8.4],[124.0,-10.3]],[[15.0,36.7],[12.7,37.6],[12.5,38.0],[15.7,38.3],[15.0,36.7]],[[-95.0,72.0],[-95.3,74.0],[-90.2,73.9],[-92.1,72.7],[-94.3,72.8],[-93.5,72.4],[-95.0,72.0]],[[8.5,39.0],[8.2,40.9],[9.2,41.3],[9.8,40.5],[9.6,39.3],[8.5,39.0]],[[138.0,74.8],[137.0,75.6],[138.8,76.2],[140.6,75.6],[141.4,76.2],[145.4,75.5],[143.4,75.0],[142.4,75.7],[143.6,74.9],[138.0,74.8]],[[133.0,33.0],[132.6,32.8],[132.4,33.5],[132.0,33.3],[132.9,34.1],[133.1,33.9],[133.9,34.4],[134.6,34.2],[134.8,33.8],[134.2,33.2],[133.6,33.6],[133.0,33.0]],[[128.0,-0.3],[128.4,-0.9],[127.7,-0.2],[127.4,1.0],[127.9,2.2],[128.0,1.3],[127.6,0.9],[128.7,1.6],[128.7,1.1],[128.2,0.8],[128.9,0.2],[127.9,0.5],[128.0,-0.3]],[[128.0,-3.1],[129.0,-2.8],[130.3,-3.0],[130.9,-3.9],[129.9,-3.3],[128.4,-3.5],[128.2,-3.1],[127.9,-3.6],[128.0,-3.1]],[[167.0,-22.3],[164.9,-21.4],[164.0,-20.1],[167.0,-22.3]],[[-100.0,75.0],[-100.1,75.0],[-100.8,75.4],[-99.6,75.7],[-102.9,75.6],[-100.9,75.8],[-101.9,76.4],[-99.9,75.9],[-101.0,76.5],[-99.1,76.4],[-98.5,76.7],[-97.3,75.4],[-98.0,75.0],[-100.0,75.0]],[[-117.0,77.4],[-115.4,77.3],[-117.1,76.3],[-117.8,76.8],[-119.8,75.9],[-120.9,76.2],[-122.6,75.9],[-119.2,77.3],[-117.0,77.4]],[[117.0,-9.1],[116.7,-8.7],[117.1,-8.4],[118.3,-8.7],[117.7,-8.2],[117.9,-8.1],[119.2,-8.6],[117.0,-9.1]],[[96.0,79.0],[92.9,79.6],[97.7,80.2],[97.7,79.8],[98.8,80.1],[100.1,79.8],[100.0,78.9],[96.0,79.0]],[[27.0,79.9],[23.7,79.2],[20.1,79.5],[21.7,79.8],[18.7,79.7],[17.7,80.1],[19.6,80.1],[19.6,80.5],[22.3,80.0],[22.8,80.5],[23.1,80.1],[24.8,80.3],[27.0,79.9]],[[123.0,-8.3],[121.7,-8.9],[119.8,-8.7],[120.4,-8.2],[121.5,-8.6],[122.4,-8.5],[122.9,-8.1],[123.0,-8.3]],[[-99.0,68.9],[-98.0,69.9],[-95.2,68.9],[-96.5,68.5],[-99.0,68.9]],[[123.2,10.0],[123.3,9.3],[123.0,9.0],[122.4,9.8],[122.9,10.1],[123.2,11.0],[123.6,10.8],[123.2,10.0]],[[125.0,11.3],[125.0,11.8],[124.3,12.6],[125.1,12.6],[125.5,12.2],[125.8,11.0],[125.0,11.3]],[[138.0,-8.4],[137.6,-8.4],[138.2,-7.5],[139.1,-7.6],[139.0,-8.1],[138.0,-8.4]],[[106.7,-3.0],[105.9,-2.8],[105.8,-2.1],[105.1,-2.1],[105.3,-1.6],[106.0,-1.6],[106.3,-2.4],[106.8,-2.6],[106.7,-3.0]],[[118.0,8.9],[117.2,8.3],[119.3,10.5],[119.2,11.0],[119.5,10.7],[119.5,11.4],[119.7,10.5],[118.8,9.9],[118.0,8.9]],[[122.0,10.4],[121.9,11.9],[122.9,11.4],[123.2,11.6],[123.1,11.2],[122.0,10.4]],[[-99.0,77.9],[-102.8,78.4],[-104.4,78.3],[-103.3,78.7],[-105.0,78.8],[-105.5,79.3],[-100.4,78.8],[-99.0,77.9]],[[100.3,78.0],[102.5,79.4],[102.5,78.8],[103.9,79.2],[105.5,78.5],[100.3,78.0]],[[-80.1,73.0],[-80.8,73.8],[-77.4,73.6],[-76.1,72.9],[-79.3,72.7],[-80.1,73.0]],[[-77.0,17.8],[-77.7,17.9],[-78.3,18.4],[-76.9,18.4],[-76.2,17.9],[-77.0,17.8]],[[120.0,-10.0],[118.9,-9.5],[119.9,-9.3],[120.8,-10.0],[120.5,-10.3],[120.0,-10.0]],[[-59.8,46.0],[-61.3,45.5],[-61.6,46.0],[-60.4,47.0],[-60.4,46.3],[-61.2,45.7],[-60.8,45.7],[-60.3,46.3],[-59.8,46.0]],[[178.6,-18.0],[177.9,-18.3],[177.2,-18.0],[178.2,-17.3],[178.6,-18.0]],[[-155.8,19.0],[-155.9,20.3],[-154.8,19.5],[-155.8,19.0]],[[49.4,39.3],[49.5,40.2],[50.4,40.4],[49.5,40.7],[47.7,42.6],[47.7,43.9],[47.4,43.5],[46.7,44.6],[47.4,45.7],[48.8,45.8],[49.3,46.6],[51.2,47.1],[52.9,47.0],[53.2,46.6],[52.7,45.5],[53.3,45.3],[51.4,45.4],[51.0,44.9],[51.6,44.5],[50.3,44.7],[50.2,44.4],[50.8,44.2],[51.3,43.2],[52.7,42.7],[52.4,42.1],[52.9,41.1],[52.9,42.0],[53.7,42.1],[54.8,41.0],[53.7,40.6],[52.9,41.1],[52.7,40.3],[53.0,39.7],[52.9,40.0],[53.6,40.0],[53.7,39.5],[53.3,39.7],[53.2,39.2],[53.6,39.4],[54.0,38.9],[54.0,36.8],[51.9,36.6],[49.2,37.6],[48.8,38.9],[49.3,39.3],[49.4,39.3]],[[-86.2,43.0],[-86.6,41.9],[-87.4,41.6],[-87.9,43.2],[-87.3,44.8],[-88.0,44.7],[-87.0,45.9],[-86.6,45.6],[-85.5,46.1],[-83.9,46.0],[-84.3,46.4],[-85.0,46.5],[-85.0,46.8],[-87.3,46.5],[-87.8,46.9],[-88.5,46.8],[-88.6,47.2],[-90.4,46.6],[-91.0,46.6],[-90.9,47.0],[-92.1,46.8],[-89.1,48.5],[-88.7,48.4],[-88.5,48.9],[-88.6,48.4],[-88.2,48.6],[-88.3,49.0],[-86.4,48.8],[-85.9,48.0],[-84.8,48.0],[-84.5,46.5],[-80.8,46.0],[-79.7,44.9],[-80.1,44.5],[-80.9,44.6],[-81.7,45.3],[-81.3,44.6],[-81.7,43.3],[-82.4,43.0],[-82.8,44.0],[-83.9,43.7],[-83.3,44.3],[-83.4,45.3],[-85.0,45.8],[-85.5,44.8],[-85.6,45.2],[-86.3,44.7],[-86.2,43.0]],[[31.6,-2.0],[32.0,-0.1],[32.7,0.3],[33.0,0.1],[33.4,0.5],[33.5,0.2],[34.0,0.3],[34.3,-0.4],[34.7,-0.1],[34.8,-0.3],[34.1,-0.6],[34.0,-1.5],[33.2,-2.0],[33.8,-2.2],[33.4,-2.6],[32.9,-2.4],[33.0,-2.9],[32.8,-3.0],[32.8,-2.5],[32.2,-2.3],[31.8,-2.8],[31.6,-2.0]],[[61.5,44.7],[60.7,44.0],[61.0,43.6],[59.8,43.4],[59.5,43.8],[58.3,43.8],[58.2,44.9],[58.7,45.8],[59.5,45.8],[59.4,46.3],[59.9,46.1],[60.2,46.7],[61.1,46.5],[61.7,46.7],[60.9,46.1],[60.9,45.6],[62.0,45.0],[61.5,44.7]],[[29.0,-4.3],[29.3,-3.3],[29.9,-5.8],[29.7,-6.3],[30.6,-7.0],[31.2,-8.8],[30.5,-8.5],[30.1,-7.3],[29.2,-6.1],[29.2,-4.1],[29.0,-4.3]],[[109.5,55.7],[110.0,55.7],[109.6,54.1],[108.5,53.5],[109.0,53.4],[106.3,52.3],[105.9,51.7],[104.8,51.5],[103.7,51.7],[105.2,51.9],[106.6,52.7],[108.2,53.9],[109.5,55.7]],[[-123.5,65.2],[-122.1,65.8],[-122.8,66.0],[-121.2,66.1],[-123.0,66.3],[-124.8,65.9],[-125.0,66.3],[-119.8,67.0],[-119.0,66.9],[-120.5,66.4],[-118.6,66.3],[-117.6,66.7],[-117.8,65.7],[-119.7,65.8],[-119.5,65.3],[-121.2,64.8],[-120.4,65.6],[-122.0,64.9],[-123.5,65.2]],[[-115.0,60.9],[-117.7,61.3],[-116.0,61.2],[-115.5,61.7],[-114.6,61.9],[-116.0,62.8],[-113.3,62.0],[-110.7,62.9],[-108.9,62.8],[-111.4,62.6],[-111.7,62.4],[-110.4,62.7],[-109.7,62.7],[-110.8,62.5],[-109.9,62.6],[-111.1,62.4],[-113.7,61.0],[-115.0,60.9]],[[33.9,-9.7],[34.0,-9.5],[34.5,-10.0],[35.0,-11.5],[34.7,-12.4],[35.2,-14.4],[34.6,-14.1],[34.0,-12.3],[34.3,-11.6],[33.9,-9.7]],[[-81.7,42.5],[-80.1,42.5],[-80.4,42.6],[-78.9,43.0],[-79.1,42.6],[-81.7,41.5],[-83.5,41.7],[-82.7,42.7],[-82.4,42.4],[-83.0,42.3],[-82.9,42.0],[-81.7,42.5]],[[-98.4,53.0],[-99.2,53.3],[-98.9,53.9],[-97.9,53.7],[-98.0,54.4],[-97.7,54.1],[-96.3,51.2],[-96.7,50.4],[-96.7,51.6],[-97.3,51.4],[-97.5,52.1],[-98.0,51.9],[-98.9,52.9],[-98.5,53.0],[-98.4,53.0]],[[-75.8,44.5],[-76.4,44.1],[-76.2,43.6],[-76.9,43.3],[-79.8,43.3],[-79.1,43.8],[-77.1,43.9],[-76.8,44.1],[-77.6,44.1],[-75.8,44.5]],[[30.9,61.7],[33.0,60.7],[31.4,59.9],[29.8,61.2],[30.9,61.7]],[[74.2,46.4],[75.1,46.8],[78.3,46.5],[79.3,46.7],[78.4,46.3],[75.5,46.7],[74.2,46.0],[74.1,45.0],[73.4,45.8],[74.2,46.4]],[[15.2,13.0],[14.0,12.5],[13.2,13.9],[13.6,14.0],[13.9,13.3],[14.2,13.5],[14.2,13.2],[15.2,13.0]],[[27.8,61.1],[27.3,61.7],[28.1,61.5],[28.9,61.8],[27.3,62.5],[27.7,62.9],[26.9,63.6],[29.0,62.4],[27.9,62.8],[27.9,62.3],[29.3,62.2],[29.3,62.6],[29.9,62.4],[29.7,61.8],[28.3,61.4],[28.9,61.2],[27.9,61.1],[27.8,61.1]],[[34.6,62.9],[35.8,62.4],[36.5,61.2],[35.9,60.9],[34.8,61.0],[35.7,61.1],[34.3,61.8],[34.0,62.5],[34.7,62.0],[34.5,62.6],[35.1,62.0],[35.6,62.2],[34.6,62.9]],[[-53.7,-2.2],[-54.1,-2.4],[-55.0,-2.5],[-55.4,-3.6],[-55.2,-2.4],[-54.7,-2.4],[-55.6,-2.2],[-55.1,-2.2],[-55.6,-2.0],[-56.7,-2.6],[-57.5,-2.4],[-58.6,-3.4],[-59.7,-3.2],[-61.8,-4.0],[-62.4,-3.7],[-63.5,-4.5],[-63.6,-4.1],[-63.3,-4.0],[-64.7,-3.4],[-64.8,-3.6],[-65.3,-2.8],[-66.0,-2.5],[-67.4,-2.5],[-68.1,-3.5],[-69.2,-3.4],[-69.6,-3.9],[-69.4,-4.1],[-69.9,-4.4],[-70.3,-3.9],[-71.5,-3.7],[-71.8,-3.2],[-73.0,-3.5],[-72.7,-3.3],[-72.9,-3.2],[-72.4,-3.3],[-71.8,-3.2],[-71.4,-3.7],[-70.3,-3.8],[-69.8,-4.3],[-69.4,-4.1],[-69.6,-3.9],[-69.3,-3.4],[-68.1,-3.4],[-67.4,-2.5],[-65.4,-2.4],[-64.3,-3.5],[-63.1,-4.1],[-62.4,-3.7],[-61.9,-3.9],[-61.0,-3.6],[-60.8,-3.2],[-59.9,-3.2],[-60.6,-3.0],[-61.6,-1.5],[-63.6,-0.4],[-66.3,-0.4],[-65.9,-0.2],[-63.7,-0.3],[-61.6,-1.4],[-60.0,-3.2],[-58.4,-3.2],[-57.6,-2.4],[-56.7,-2.6],[-56.0,-1.9],[-54.9,-2.0],[-54.5,-2.1],[-54.6,-2.4],[-54.3,-2.4],[-52.7,-1.6],[-53.7,-2.2]],[[120.2,60.3],[118.2,59.7],[116.8,60.4],[115.0,60.7],[112.4,59.2],[115.0,60.7],[116.9,60.4],[118.3,59.7],[121.2,60.7],[124.1,60.6],[129.2,61.8],[129.5,63.2],[126.5,64.4],[125.3,63.9],[123.7,64.1],[119.0,63.5],[123.7,64.1],[125.3,63.9],[126.2,64.3],[124.4,65.1],[123.0,67.5],[125.8,70.5],[127.5,70.8],[127.3,71.4],[127.6,70.8],[125.8,70.5],[123.3,67.8],[124.4,65.3],[128.3,63.8],[133.2,63.4],[133.3,63.1],[135.6,62.7],[135.1,60.4],[134.5,60.4],[135.0,60.4],[135.2,61.2],[135.5,62.7],[133.3,63.1],[133.2,63.4],[129.5,63.5],[130.1,62.3],[128.7,61.3],[124.1,60.6],[121.3,60.6],[120.7,60.4],[121.1,60.1],[120.2,60.3]],[[24.6,0.7],[22.4,2.2],[19.3,1.5],[18.4,0.9],[18.4,-0.0],[16.2,-2.1],[16.2,-3.1],[16.1,-2.2],[17.7,-0.4],[18.2,2.4],[17.8,-0.4],[18.5,1.0],[20.2,2.0],[22.5,2.2],[24.6,0.7]],[[65.9,63.8],[65.1,63.0],[68.6,61.3],[74.5,61.2],[78.1,60.6],[79.3,59.5],[81.2,59.1],[83.9,57.7],[84.5,57.1],[84.0,56.3],[84.4,57.1],[83.0,58.1],[79.3,59.5],[78.2,60.4],[75.2,61.0],[69.2,61.1],[69.9,60.7],[69.9,59.8],[68.9,59.4],[68.2,58.2],[68.9,59.5],[69.9,59.8],[69.8,60.6],[65.0,63.0],[65.8,63.9],[65.2,65.1],[65.7,66.1],[66.5,66.7],[69.0,66.8],[68.1,66.5],[66.5,66.6],[65.8,66.1],[65.3,65.1],[65.9,63.8]],[[-55.8,-27.4],[-58.8,-27.5],[-59.6,-29.5],[-59.6,-30.6],[-60.7,-32.0],[-60.5,-33.2],[-60.8,-31.9],[-59.7,-30.8],[-59.6,-29.3],[-59.4,-29.0],[-58.9,-27.5],[-58.4,-27.2],[-55.8,-27.4]],[[105.8,10.0],[105.1,10.7],[104.5,12.5],[104.9,11.6],[105.6,12.3],[106.0,12.4],[105.8,14.9],[105.3,15.2],[105.5,15.7],[104.7,16.5],[104.8,17.4],[104.0,18.3],[103.1,18.1],[103.3,18.4],[104.0,18.3],[104.8,17.4],[104.8,16.5],[105.4,16.0],[105.9,15.0],[105.9,14.1],[106.2,13.6],[106.0,13.5],[106.1,12.3],[105.0,11.6],[105.4,10.6],[106.4,10.3],[105.3,10.6],[105.8,10.0]],[[130.3,46.8],[132.5,47.7],[131.2,47.7],[132.5,47.7],[136.0,49.0],[136.4,49.6],[136.2,49.8],[136.7,49.9],[136.9,50.5],[140.2,51.9],[140.4,52.4],[139.7,53.0],[140.7,53.1],[139.8,52.9],[140.5,52.3],[140.0,51.7],[140.4,52.0],[140.2,51.7],[140.8,51.6],[139.0,51.3],[137.3,50.6],[137.4,50.2],[137.1,50.3],[135.8,48.8],[133.3,47.9],[132.0,47.2],[130.3,46.8]],[[87.6,64.0],[87.3,63.4],[89.0,62.4],[87.2,63.4],[88.0,65.7],[87.5,66.4],[86.2,66.6],[86.0,69.4],[84.0,69.8],[85.4,69.8],[86.2,69.5],[86.3,66.6],[87.5,66.4],[87.9,65.8],[89.0,66.0],[90.0,65.7],[90.4,64.8],[92.1,64.4],[90.4,64.8],[90.0,65.6],[88.8,65.9],[88.0,65.8],[87.6,64.0]],[[119.6,32.2],[118.8,32.1],[118.3,31.3],[116.2,29.7],[116.1,29.2],[116.7,29.1],[116.5,28.8],[115.9,29.2],[116.2,29.7],[114.3,30.6],[114.9,30.6],[115.5,30.1],[116.3,29.8],[118.3,31.3],[118.7,32.2],[119.6,32.2]],[[-67.5,6.2],[-67.1,7.1],[-66.3,7.7],[-65.6,7.9],[-64.8,7.7],[-62.3,8.6],[-62.2,8.9],[-62.4,9.7],[-62.1,8.7],[-61.6,8.6],[-64.1,7.9],[-64.8,7.6],[-65.6,7.9],[-66.3,7.6],[-67.5,6.2]],[[-71.3,46.7],[-75.8,44.5],[-74.0,45.4],[-76.4,45.5],[-77.7,46.2],[-76.4,45.5],[-74.0,45.5],[-71.3,46.8],[-71.3,46.7]],[[-124.8,64.4],[-125.3,64.9],[-128.7,65.6],[-128.7,66.3],[-130.8,67.3],[-132.8,67.2],[-134.3,67.7],[-134.2,68.7],[-133.7,67.5],[-130.4,67.3],[-128.6,66.4],[-128.7,65.7],[-125.1,64.9],[-124.8,64.4]],[[89.7,24.0],[89.7,25.7],[90.6,26.2],[89.8,25.7],[89.7,24.0]],[[-157.9,64.9],[-160.0,62.9],[-160.1,61.9],[-162.0,61.6],[-162.5,62.0],[-163.9,62.1],[-164.5,62.8],[-163.9,62.2],[-162.2,62.0],[-161.9,61.6],[-160.1,62.2],[-160.2,62.7],[-157.9,64.9]],[[57.0,65.4],[56.2,66.3],[54.3,65.5],[52.1,65.4],[52.1,67.6],[54.1,68.2],[52.1,67.6],[52.2,65.5],[54.3,65.5],[56.2,66.3],[57.0,65.4]],[[-51.4,-2.3],[-51.6,-1.8],[-50.7,-1.8],[-51.0,-2.2],[-50.8,-2.5],[-51.3,-1.8],[-51.4,-2.3]],[[-52.3,-1.7],[-51.9,-3.0],[-52.3,-1.7]],[[69.6,28.3],[68.3,27.6],[67.9,27.0],[68.4,25.7],[67.8,24.1],[68.0,23.9],[67.7,23.9],[68.4,25.7],[67.9,27.0],[68.3,27.6],[69.6,28.3]],[[6.4,8.7],[6.8,7.8],[9.0,7.9],[6.8,7.8],[6.5,5.4],[6.7,7.8],[6.4,8.7]],[[43.4,56.7],[44.7,56.1],[46.6,56.4],[47.9,56.2],[49.1,55.5],[47.9,56.1],[46.6,56.4],[44.6,56.1],[43.4,56.7]],[[42.8,57.5],[43.7,57.7],[43.1,56.6],[42.8,57.5]],[[-12.8,15.1],[-14.3,16.6],[-16.1,16.5],[-16.4,16.3],[-16.1,16.6],[-14.3,16.6],[-13.5,16.2],[-12.8,15.1]],[[45.1,62.0],[42.0,63.1],[41.4,63.8],[41.8,64.3],[40.5,64.6],[41.8,64.3],[41.4,63.8],[42.1,63.1],[45.1,62.0]],[[87.8,25.1],[89.2,23.9],[88.1,24.5],[87.9,25.0],[87.8,25.1]],[[160.8,68.5],[158.5,68.7],[156.3,67.6],[153.9,67.5],[156.2,67.7],[156.1,68.0],[157.5,68.3],[158.5,68.8],[160.7,68.6],[160.8,68.5]],[[111.4,23.5],[110.1,23.4],[111.4,23.5],[111.7,23.2],[112.8,23.2],[113.2,22.6],[112.8,23.1],[111.6,23.1],[111.4,23.5]],[[44.0,34.1],[44.5,33.9],[44.6,33.1],[45.6,32.6],[46.7,32.5],[46.9,32.0],[46.7,32.5],[45.8,32.4],[44.6,33.1],[44.4,33.9],[44.0,34.1]],[[-49.7,-2.7],[-49.7,-3.8],[-49.7,-2.7]],[[34.1,-16.7],[34.9,-17.0],[35.5,-18.0],[34.9,-17.0],[34.1,-16.7]],[[105.1,72.8],[102.1,71.9],[103.0,71.5],[102.0,71.9],[99.6,71.4],[105.0,72.8],[105.1,72.8]],[[123.7,72.1],[122.5,71.0],[123.7,72.0],[120.6,72.9],[123.7,72.1]],[[-7.3,13.1],[-4.5,14.2],[-7.3,13.1]],[[150.0,71.2],[147.5,70.3],[147.4,69.0],[147.4,70.3],[150.0,71.2]],[[-121.2,61.9],[-123.4,62.3],[-123.2,63.0],[-123.3,62.3],[-121.2,61.9]],[[-3.1,16.6],[-1.2,17.0],[-3.1,16.6]],[[4.6,9.4],[6.1,8.8],[4.6,9.4]],[[-8.8,11.6],[-7.7,12.7],[-8.8,11.6]],[[106.5,20.3],[105.4,21.3],[106.5,20.3]],[[47.4,47.0],[48.0,46.3],[47.4,47.0]],[[41.3,57.5],[42.6,57.4],[41.4,57.5],[41.3,57.5]],[[-3.8,16.1],[-3.2,16.4],[-3.8,16.1]],[[-1.1,17.1],[-0.6,17.0],[-1.1,17.1]],[[40.3,47.2],[39.4,47.1],[40.2,47.2],[40.3,47.2]],[[-0.4,17.0],[-0.1,16.4],[-0.4,17.0]],[[119.6,32.3],[119.6,32.4],[119.3,32.7],[119.6,32.3]],[[106.8,10.7],[106.8,11.1],[106.8,10.7]],[[0.9,14.8],[1.1,14.5],[0.9,14.8]],[[-0.1,16.3],[0.0,16.2],[0.3,15.8],[0.0,16.2],[-0.1,16.3]],[[-9.3,11.1],[-9.0,11.4],[-9.3,11.1]],[[3.6,11.8],[3.9,11.6],[3.6,11.8]],[[-4.2,14.6],[-4.2,14.7],[-3.9,15.0],[-4.2,14.6]],[[0.8,15.4],[0.6,15.0],[0.7,15.3],[0.8,15.4]],[[-180.0,-77.8],[-179.1,-77.9],[-176.5,-78.3],[-163.3,-78.6],[-158.6,-77.9],[-158.2,-77.1],[-151.9,-77.4],[-148.4,-75.7],[-145.5,-75.4],[-140.9,-75.5],[-135.4,-74.6],[-128.2,-74.3],[-127.1,-73.3],[-124.0,-73.9],[-122.4,-73.7],[-115.2,-74.1],[-114.2,-73.9],[-110.6,-74.2],[-108.4,-75.3],[-106.6,-74.7],[-101.8,-75.1],[-101.2,-74.7],[-102.5,-74.5],[-101.4,-74.2],[-103.0,-73.6],[-101.3,-73.6],[-103.3,-73.1],[-103.4,-72.3],[-98.7,-71.7],[-96.2,-71.8],[-94.2,-72.5],[-90.7,-72.8],[-89.9,-72.4],[-82.2,-73.8],[-80.5,-73.0],[-78.7,-73.4],[-77.4,-73.3],[-77.4,-73.0],[-79.3,-73.0],[-78.9,-72.3],[-72.2,-73.1],[-72.6,-72.3],[-75.4,-71.8],[-73.3,-71.3],[-73.3,-70.8],[-76.5,-71.1],[-73.9,-70.5],[-75.8,-69.9],[-74.8,-69.7],[-73.5,-70.3],[-72.9,-69.4],[-71.7,-69.6],[-72.0,-69.0],[-70.5,-68.8],[-68.4,-70.1],[-68.8,-69.4],[-67.1,-69.3],[-66.6,-68.2],[-67.5,-67.0],[-66.5,-67.3],[-66.5,-66.6],[-65.7,-66.7],[-65.7,-66.1],[-63.8,-65.6],[-63.8,-65.0],[-63.1,-65.2],[-61.0,-64.0],[-57.3,-63.2],[-56.8,-63.6],[-58.3,-63.7],[-58.8,-64.6],[-59.5,-64.3],[-60.7,-64.7],[-59.5,-65.2],[-61.2,-65.0],[-62.2,-65.3],[-60.5,-66.0],[-60.0,-66.8],[-61.5,-69.4],[-59.7,-72.5],[-61.7,-74.8],[-52.7,-76.8],[-50.4,-77.0],[-48.7,-77.8],[-36.0,-78.2],[-33.7,-77.3],[-26.6,-76.1],[-27.7,-75.6],[-25.2,-75.1],[-25.7,-74.1],[-23.9,-73.9],[-22.1,-74.3],[-19.2,-72.7],[-12.9,-72.0],[-12.3,-71.3],[-8.7,-70.5],[-3.4,-70.4],[-1.7,-70.0],[-0.9,-69.8],[0.0,-69.6],[0.3,-70.1],[0.9,-69.9],[4.1,-70.3],[5.7,-70.0],[7.4,-70.2],[8.5,-69.9],[12.8,-70.1],[14.8,-69.5],[15.6,-69.8],[17.7,-69.7],[19.0,-70.0],[19.9,-69.7],[24.6,-70.3],[33.6,-68.7],[37.1,-69.7],[38.1,-69.3],[37.3,-69.7],[38.8,-70.1],[39.9,-68.8],[46.3,-67.7],[46.4,-67.3],[48.5,-67.6],[49.3,-67.4],[48.3,-67.0],[49.2,-66.8],[50.9,-67.2],[50.4,-66.3],[53.8,-65.8],[55.6,-66.0],[57.2,-66.5],[56.9,-67.0],[59.1,-67.4],[69.6,-67.7],[70.4,-68.7],[72.7,-68.6],[74.3,-69.3],[73.7,-69.8],[74.5,-69.8],[77.9,-69.1],[78.8,-68.2],[81.3,-67.8],[81.7,-67.3],[84.5,-67.0],[84.0,-66.7],[86.0,-66.3],[89.6,-66.8],[92.0,-66.5],[94.3,-66.6],[95.6,-66.2],[95.5,-65.3],[96.4,-65.0],[98.0,-65.7],[100.2,-65.7],[100.9,-65.4],[102.5,-65.9],[102.9,-65.1],[104.0,-65.5],[103.9,-66.0],[108.8,-66.9],[110.7,-66.5],[110.9,-66.0],[113.2,-65.8],[114.5,-66.5],[117.6,-67.0],[120.7,-66.9],[122.0,-66.5],[122.6,-66.8],[124.3,-66.5],[124.9,-66.7],[126.3,-66.2],[128.8,-67.0],[130.4,-66.1],[134.7,-66.0],[142.5,-67.0],[143.5,-66.8],[144.7,-67.2],[146.2,-66.7],[145.3,-67.5],[147.7,-68.3],[150.9,-68.3],[151.4,-68.6],[153.9,-68.3],[155.4,-69.0],[159.8,-69.5],[161.1,-70.3],[166.7,-70.6],[170.2,-71.7],[170.3,-71.3],[171.0,-71.8],[169.8,-72.2],[169.2,-73.5],[166.6,-73.6],[166.3,-74.1],[164.8,-74.1],[165.4,-74.6],[164.1,-74.6],[162.6,-75.2],[165.8,-75.5],[162.5,-75.5],[162.3,-77.0],[164.4,-78.1],[166.9,-77.9],[166.7,-77.2],[180.0,-77.8]]];
/* DEVIL GeoINT v3.1: client-side map uses the exact locally enriched IOC records only.
   Coastlines are actual geographic reference lines. No fake attacks, no third-party calls. */
let geoMode='points',geoZoom=1,geoPanX=0,geoPanY=0,geoPage=1;
let geoSelected=null,geoMouseDown=null,geoFetchId=0;
const geoHost=$('atlasBox');
function geoParams(){const p=new URLSearchParams();for(const [k,id] of [['country','geoCountry'],['source','geoSource'],['q','geoSearch']]){let v=$(id).value.trim();if(v)p.set(k,v)}return p}
function geoWorldCoords(lon,lat,w,h){return [((lon+180)/360*w-w/2)*geoZoom+w/2+geoPanX,((90-lat)/180*h-h/2)*geoZoom+h/2+geoPanY]}
function geoNearest(x,y,maxDist=13){const pts=v3Atlas?.points||[],rect=$('atlasCanvas').getBoundingClientRect();let closest=null,best=maxDist*maxDist;for(const p of pts){const [px,py]=geoWorldCoords(p.lon,p.lat,rect.width,rect.height),ds=(px-x)**2+(py-y)**2;if(ds<best){best=ds;closest=p}}return closest}
function geoClamp(){geoZoom=Math.max(1,Math.min(7,geoZoom));const r=geoHost?.getBoundingClientRect();if(r){geoPanX=Math.max(-r.width*(geoZoom-1)/2,Math.min(r.width*(geoZoom-1)/2,geoPanX));geoPanY=Math.max(-r.height*(geoZoom-1)/2,Math.min(r.height*(geoZoom-1)/2,geoPanY))}}
function geoDrawCoast(c,w,h){c.save();c.strokeStyle='#357086c2';c.lineWidth=Math.max(.4,Math.min(1.1,.75*geoZoom**.12));c.beginPath();for(const poly of GEO_COASTS){let prev=null;for(const p of poly){const [x,y]=geoWorldCoords(p[0],p[1],w,h);if(prev&&Math.abs(x-prev[0])<w*geoZoom*.25)c.lineTo(x,y);else c.moveTo(x,y);prev=[x,y]}}c.stroke();c.restore()}
function v3AtlasDraw(){const canvas=$('atlasCanvas'),box=$('atlasBox');if(!canvas||!box)return;const setup=v3CanvasPrep(canvas,box.clientHeight||490);if(!setup)return;const {c,w,h}=setup;c.clearRect(0,0,w,h);let g=c.createRadialGradient(w*.51,h*.5,10,w*.51,h*.5,Math.max(w,h)*.65);g.addColorStop(0,'#153747');g.addColorStop(1,'#07101e');c.fillStyle=g;c.fillRect(0,0,w,h);
for(let lon=-180;lon<=180;lon+=30){let [x]=geoWorldCoords(lon,0,w,h);c.beginPath();c.moveTo(x,0);c.lineTo(x,h);c.strokeStyle=lon===0?'#4fc3d046':'#27566f65';c.lineWidth=lon===0?1.25:.7;c.stroke()}for(let lat=-90;lat<=90;lat+=30){let [,y]=geoWorldCoords(0,lat,w,h);c.beginPath();c.moveTo(0,y);c.lineTo(w,y);c.strokeStyle=lat===0?'#4fc3d046':'#27566f65';c.stroke()}
geoDrawCoast(c,w,h);
const points=v3Atlas?.points||[];
if(geoMode==='heat'){
 c.save();c.globalCompositeOperation='lighter';for(const p of points){const [x,y]=geoWorldCoords(p.lon,p.lat,w,h);if(x< -60||x>w+60||y< -60||y>h+60)continue;const radius=22*Math.min(2,Math.sqrt(geoZoom)),grad=c.createRadialGradient(x,y,0,x,y,radius);grad.addColorStop(0,'#c3ff7855');grad.addColorStop(.42,'#29df9e20');grad.addColorStop(1,'#22f4c600');c.fillStyle=grad;c.beginPath();c.arc(x,y,radius,0,Math.PI*2);c.fill()}c.restore();
}else if(geoMode==='clusters'){
 const grouped=new Map(),size=35;for(const p of points){const [x,y]=geoWorldCoords(p.lon,p.lat,w,h);if(x<0||x>w||y<0||y>h)continue;const key=Math.floor(x/size)+':'+Math.floor(y/size);let slot=grouped.get(key);if(!slot){slot={x:0,y:0,n:0};grouped.set(key,slot)}slot.x+=x;slot.y+=y;slot.n++}for(const s of grouped.values()){let x=s.x/s.n,y=s.y/s.n,r=Math.min(20,7+Math.log2(s.n+1)*2.4);c.beginPath();c.arc(x,y,r+4,0,Math.PI*2);c.fillStyle='#2deed325';c.fill();c.beginPath();c.arc(x,y,r,0,Math.PI*2);c.fillStyle='#12596cee';c.strokeStyle='#6effd3';c.lineWidth=1.5;c.fill();c.stroke();c.fillStyle='#effffa';c.textAlign='center';c.textBaseline='middle';c.font='700 10px monospace';c.fillText(String(s.n),x,y)}c.textAlign='left';c.textBaseline='alphabetic';
}else{
 for(const p of points){let [x,y]=geoWorldCoords(p.lon,p.lat,w,h);if(x< -20||x>w+20||y< -20||y>h+20)continue;const selected=p.ip===geoSelected;const r=selected?6.5:Math.min(4,2.3+geoZoom*.25);c.beginPath();c.arc(x,y,r*3,0,Math.PI*2);c.fillStyle=selected?'#ffc27448':'#37f4ba14';c.fill();c.beginPath();c.arc(x,y,r,0,Math.PI*2);c.fillStyle=selected?'#ffcf8b':'#9cffb3';c.shadowBlur=selected?17:8;c.shadowColor=selected?'#ffbb70':'#69ffa0';c.fill();c.shadowBlur=0;if(selected){c.beginPath();c.arc(x,y,12,0,Math.PI*2);c.strokeStyle='#ffc274';c.lineWidth=1.2;c.stroke()}}
}
if(!points.length){c.fillStyle='#93b4c6';c.textAlign='center';c.font='12px monospace';c.fillText('NO ENRICHED IOC POINTS MATCH THE CURRENT FILTER',w/2,h/2);c.textAlign='left'}text('geoZoomLabel',Math.round(geoZoom*100)+'% SCALE')}
function geoUpdateDropdown(id,options,field,label){const select=$(id),previous=select.value,values=options.map(x=>String(x[field]));if(select.options.length!==options.length+1 || Array.from(select.options).slice(1).some((x,i)=>x.value!==values[i])){select.replaceChildren();select.append(elt('option','',label));for(const item of options){const o=elt('option','',String(item[field])+' · '+fmt(item.count));o.value=String(item[field]);select.append(o)}select.value=values.includes(previous)?previous:''}}
function geoRenderCountries(d){const box=$('geoRanking');box.replaceChildren();const items=(d.countries||[]).slice(0,14),largest=Math.max(1,...items.map(x=>x.count));if(!items.length){box.append(elt('div','empty','No country data found.'));return}for(const item of items){const btn=elt('button','geo-country'+($('geoCountry').value===item.code?' selected':''));btn.type='button';const line=elt('div','geo-country-top');line.append(elt('span','',item.code),elt('b','',fmt(item.count)));btn.append(line);const bar=elt('div','geo-country-bar'),span=elt('i');span.style.width=(item.count/largest*100).toFixed(1)+'%';bar.append(span);btn.append(bar);btn.addEventListener('click',()=>{$('geoCountry').value=($('geoCountry').value===item.code?'':item.code);geoPage=1;v3LoadAtlas()});box.append(btn)}}
function geoShowTable(d){const tbody=$('geoRows');tbody.replaceChildren();const items=d.items||[];if(!items.length){const tr=elt('tr'),td=elt('td','empty','No matching geocoded indicators. Try clearing the filters.');td.colSpan=5;tr.append(td);tbody.append(tr)}for(const p of items){const tr=elt('tr');tr.append(elt('td','value',p.ip),elt('td','',p.country),elt('td','',Number(p.lat).toFixed(3)+' / '+Number(p.lon).toFixed(3)),elt('td','',p.sources.join(', ')));const td=elt('td'),btn=elt('button','btn secondary','INSPECT');btn.type='button';btn.addEventListener('click',()=>geoSelect(p.ip));td.append(btn);tr.append(td);tbody.append(tr)}text('geoPageInfo',fmt(d.total||0)+' MATCHES · PAGE '+fmt(d.page||1)+' / '+Math.max(1,Math.ceil((d.total||0)/(d.limit||25))));$('geoPrev').disabled=geoPage<=1;$('geoNext').disabled=geoPage*25>=(d.total||0)}
async function geoFetchTable(){const params=geoParams();params.set('page',String(geoPage));try{geoShowTable(await api('/api/atlas/records?'+params.toString()))}catch(e){text('geoPageInfo','RECORDS UNAVAILABLE');$('geoRows').replaceChildren(elt('tr','', ''))}}
function geoInspectorRow(box,k,v){const line=elt('div','geo-inspector-line');line.append(elt('span','',k),elt('b','',String(v)));box.append(line)}
async function geoSelect(ip){geoSelected=ip;v3AtlasDraw();const box=$('geoInspector');box.replaceChildren(elt('div','v3small','Loading exact IOC evidence...'));try{const d=await api('/api/atlas/ip?ip='+encodeURIComponent(ip));box.replaceChildren();if(!d.found){box.append(elt('div','v3small','Exact match unavailable.'));return}const p=d.record;box.append(elt('div','v3small','SELECTED INTELLIGENCE RECORD'),elt('strong','',p.ip));geoInspectorRow(box,'COUNTRY',p.country);geoInspectorRow(box,'LAT / LON',p.lat+' / '+p.lon);geoInspectorRow(box,'FEEDS',p.sources.join(', '));geoInspectorRow(box,'INTEL MATCHES',String(d.intelligence.matches.length));const note=elt('div','geo-mini-note','Approximate GeoIP location is not evidence of attack origin.');box.append(note);const btn=elt('button','btn secondary','OPEN THREAT INTELLIGENCE →');btn.type='button';btn.addEventListener('click',()=>{nav('intelligence');$('lookupValue').value=p.ip;lookup()});box.append(btn)}catch(e){box.replaceChildren(elt('div','empty','IOC lookup unavailable.'))}}
async function v3LoadAtlas(){const token=++geoFetchId,params=geoParams();try{const d=await api('/api/atlas?'+params.toString());if(token!==geoFetchId)return;v3Atlas=d;text('atlasMode',d.mode||'NOT CONFIGURED');text('geoTotal',fmt(d.total_geocoded||0));text('geoCountries',fmt(d.country_count||0));text('geoFiltered',fmt(d.total_filtered||0));text('geoRendered',fmt((d.points||[]).length));text('atlasNote',d.note||'No geographic enrichment');text('geoSampleNote',d.truncated?'VISUAL SAMPLE · '+fmt((d.points||[]).length)+' OF '+fmt(d.total_filtered):'ALL FILTERED POINTS SHOWN');geoUpdateDropdown('geoCountry',d.countries||[],'code','ALL COUNTRIES');geoUpdateDropdown('geoSource',d.sources||[],'name','ALL SOURCES');geoRenderCountries(d);v3AtlasDraw();await geoFetchTable()}catch(e){text('atlasMode','GEOINT OFFLINE');text('atlasNote','Cannot load geolocation data; check service logs.');v3Atlas={points:[]};v3AtlasDraw()}}
function geoZoomAction(factor){geoZoom*=factor;geoClamp();v3AtlasDraw()}
$('geoApply').addEventListener('click',()=>{geoPage=1;v3LoadAtlas()});$('geoClear').addEventListener('click',()=>{$('geoSearch').value='';$('geoCountry').value='';$('geoSource').value='';geoPage=1;geoSelected=null;geoZoom=1;geoPanX=geoPanY=0;v3LoadAtlas()});$('geoSearch').addEventListener('keydown',e=>{if(e.key==='Enter'){geoPage=1;v3LoadAtlas()}});$('geoCountry').addEventListener('change',()=>{geoPage=1;v3LoadAtlas()});$('geoSource').addEventListener('change',()=>{geoPage=1;v3LoadAtlas()});
for(const [mode,id] of [['points','geoModePoints'],['heat','geoModeHeat'],['clusters','geoModeClusters']])$(id).addEventListener('click',()=>{geoMode=mode;for(const v of ['geoModePoints','geoModeHeat','geoModeClusters'])$(v).classList.toggle('active',v===id);v3AtlasDraw()});
$('geoZoomIn').addEventListener('click',()=>geoZoomAction(1.45));$('geoZoomOut').addEventListener('click',()=>geoZoomAction(1/1.45));$('geoZoomReset').addEventListener('click',()=>{geoZoom=1;geoPanX=geoPanY=0;v3AtlasDraw()});
$('geoPrev').addEventListener('click',()=>{geoPage=Math.max(1,geoPage-1);geoFetchTable()});$('geoNext').addEventListener('click',()=>{geoPage++;geoFetchTable()});
geoHost.addEventListener('wheel',e=>{if(state.current!=='atlas')return;e.preventDefault();geoZoomAction(e.deltaY<0?1.17:1/1.17)},{passive:false});
geoHost.addEventListener('pointerdown',e=>{if(e.target.closest('button'))return;geoMouseDown={x:e.clientX,y:e.clientY,panX:geoPanX,panY:geoPanY,moved:false};geoHost.setPointerCapture(e.pointerId)});
geoHost.addEventListener('pointermove',e=>{if(state.current!=='atlas')return;const rect=geoHost.getBoundingClientRect(),x=e.clientX-rect.left,y=e.clientY-rect.top;if(geoMouseDown){const dx=e.clientX-geoMouseDown.x,dy=e.clientY-geoMouseDown.y;if(Math.abs(dx)+Math.abs(dy)>5)geoMouseDown.moved=true;if(geoMouseDown.moved){geoPanX=geoMouseDown.panX+dx;geoPanY=geoMouseDown.panY+dy;geoClamp();v3AtlasDraw()}$('geoTooltip').hidden=true;return}const p=geoNearest(x,y);const tip=$('geoTooltip');if(!p){tip.hidden=true;geoHost.style.cursor='grab';return}tip.hidden=false;tip.replaceChildren(elt('strong','',p.ip),elt('span','',p.country+' · '+Number(p.lat).toFixed(2)+', '+Number(p.lon).toFixed(2)));tip.style.left=Math.min(rect.width-195,Math.max(8,x+16))+'px';tip.style.top=Math.max(6,Math.min(rect.height-75,y-16))+'px';geoHost.style.cursor='crosshair'});
geoHost.addEventListener('pointerup',e=>{if(!geoMouseDown)return;const down=geoMouseDown;geoMouseDown=null;if(!down.moved){const rect=geoHost.getBoundingClientRect(),p=geoNearest(e.clientX-rect.left,e.clientY-rect.top,17);if(p)geoSelect(p.ip)}});
geoHost.addEventListener('pointercancel',()=>{geoMouseDown=null;$('geoTooltip').hidden=true});geoHost.addEventListener('pointerleave',()=>{$('geoTooltip').hidden=true});
function v3FillCaseDetail(r){const box=$('caseDetail');box.replaceChildren();if(!r){box.append(elt('div','v3small','Select a detection row to inspect the stored fields.'));return}box.append(elt('div','v3small',r.id+' · CORRELATION REFERENCE'));box.append(elt('div','v3key',r.ip));for(const [k,v] of [['INTEL SOURCE',r.source],['OBSERVATIONS',r.observations],['FIRST STORED',nfmt(r.first_seen)],['LAST STORED',nfmt(r.last_seen)],['ACTIVITY FLAG',r.activity],['REVIEW STATUS',r.status]]){const row=elt('div','v3row');row.append(elt('span','',k),elt('b','',v==null?'—':String(v)));box.append(row)}const btn=elt('button','btn secondary','↗ INSPECT EXACT IOC');btn.style.marginTop='15px';btn.addEventListener('click',()=>{nav('intelligence');$('lookupValue').value=r.ip;lookup()});box.append(btn)}
function v3RenderCases(){const q=($('caseSearch')?.value||'').toLowerCase();const filtered=v3Cases.filter(r=>(r.ip+' '+r.source+' '+r.id).toLowerCase().includes(q));const box=$('caseRows');box.replaceChildren();if(!filtered.length){const tr=elt('tr'),td0=elt('td','empty','No matching correlation records. Zero matches do not establish network safety.');td0.colSpan=5;tr.append(td0);box.append(tr);return}for(const r of filtered){const tr=elt('tr');tr.append(elt('td','',r.id),elt('td','',r.ip),elt('td','',fmt(r.observations)));const cell=elt('td'),pill=elt('span','v3monopill '+(r.observations>=2?'warn':'good'),r.activity);cell.append(pill);tr.append(cell);const action=elt('td'),btn=elt('button','btn secondary','INSPECT');btn.addEventListener('click',()=>v3FillCaseDetail(r));action.append(btn);tr.append(action);box.append(tr)}}
async function v3LoadCases(){try{const d=await api('/api/cases');v3Cases=d.items||[];text('cTotal',fmt(d.total));text('cRepeat',fmt(v3Cases.filter(x=>x.observations>=2).length));text('cUnreviewed',fmt(d.total));v3RenderCases()}catch(e){const box=$('caseRows');box.replaceChildren();let tr=elt('tr'),td0=elt('td','empty','Correlation DB unavailable: '+e.message);td0.colSpan=5;tr.append(td0);box.append(tr)}}
$('caseSearch').addEventListener('input',v3RenderCases);$('caseRefresh').addEventListener('click',v3LoadCases);
window.addEventListener('resize',()=>{if(state.current==='atlas')v3AtlasDraw();if(state.current==='pulse'&&v3Metrics)v3RenderPulse(v3Metrics)});
setInterval(()=>{if(state.current==='pulse'||state.current==='overview')v3FetchPulse()},5000);
setTimeout(v3FetchPulse,350);

</script>
</body>
</html>
'''


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def reply(self, data, content_type='application/json; charset=utf-8', code=200, extra=None):
        if not isinstance(data, (str, bytes)):
            data = json.dumps(data, ensure_ascii=False, separators=(',', ':'), default=str)
        body = data.encode('utf-8') if isinstance(data, str) else data
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        self.send_header('Permissions-Policy', 'geolocation=(), camera=(), microphone=()')
        self.send_header('Content-Security-Policy',
                         "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                         "img-src 'self' data:; connect-src 'self'; font-src 'none'; "
                         "form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (ConnectionResetError, BrokenPipeError):
            pass

    def do_GET(self):
        if len(self.path) > 2048:
            self.reply({'error': 'Request too long'}, code=414)
            return
        u = urlsplit(self.path)
        args = parse_qs(u.query, keep_blank_values=True)
        get = lambda k, default='': args.get(k, [default])[0]
        try:
            if u.path == '/':
                self.reply(HTML, 'text/html; charset=utf-8')
            elif u.path == '/api/status':
                self.reply(counts())
            elif u.path == '/api/indicators':
                self.reply(search_indicators(get('q'), get('kind'), get('source'),
                                             int(get('page', '1')), int(get('limit', '40'))))
            elif u.path == '/api/search':
                self.reply(search_indicators(get('q'), limit=75)['items'])  # v1 compatibility
            elif u.path == '/api/lookup':
                self.reply(exact_lookup(get('value')))
            elif u.path == '/api/telemetry':
                self.reply(live_metrics())
            elif u.path == '/api/atlas':
                self.reply(geo_atlas(get('country'), get('source'), get('q')))
            elif u.path == '/api/atlas/records':
                self.reply(geo_records(get('country'), get('source'), get('q'), int(get('page', '1'))))
            elif u.path == '/api/atlas/ip':
                self.reply(geo_inspect(get('ip')))
            elif u.path == '/api/cases':
                self.reply(triage_queue())
            elif u.path == '/api/events':
                self.reply({'items': get_events(100),
                            'total': one('events.db', 'SELECT COUNT(*) AS n FROM detections')})
            elif u.path == '/api/system':
                self.reply(diagnostic())
            elif u.path == '/api/export.csv':
                self.reply(export_csv(get('q'), get('kind'), get('source')),
                           'text/csv; charset=utf-8', extra={
                               'Content-Disposition': 'attachment; filename="devil-indicators.csv"',
                           })
            elif u.path == '/healthz':
                self.reply({'ok': True, 'service': 'devil-dashboard', 'version': VERSION})
            else:
                self.reply({'error': 'Not found'}, code=404)
        except (ValueError, OverflowError):
            self.reply({'error': 'Invalid query parameter'}, code=400)
        except Exception:
            LOG.exception('Request failure on endpoint %s', u.path)
            self.reply({'error': 'Internal dashboard error'}, code=500)

    def log_message(self, fmt, *args):
        # Access logging is done by Nginx; avoid logging sensitive lookup strings.
        pass


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32


if __name__ == '__main__':
    LOG.info('DEVIL v%s listening ONLY on %s:%s · data=%s', VERSION, HOST, PORT, DATA)
    Server((HOST, PORT), Handler).serve_forever(poll_interval=0.5)
