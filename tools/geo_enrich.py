#!/usr/bin/env python3
"""Offline exact-match GeoIP enrichment for DEVIL, from licensed DB-IP data.

Reads only local files, never downloads, uploads or modifies the input SQLite DB.
License and attribution details: docs/GEOIP.md.
"""
from __future__ import annotations
import argparse
import bisect
import csv
import gzip
import ipaddress
import math
import os
import sqlite3
import tempfile
from pathlib import Path


def read_targets(db_path: Path):
    con = sqlite3.connect(db_path.resolve().as_uri() + '?mode=ro', uri=True)
    target = {4: {}, 6: {}}
    try:
        for (value,) in con.execute("SELECT DISTINCT value FROM indicators WHERE kind='ip'"):
            try:
                addr = ipaddress.ip_address(str(value))
                if addr.is_global:
                    target[addr.version][int(addr)] = str(addr)
            except ValueError:
                continue
    finally:
        con.close()
    return {v: (sorted(d), d) for v, d in target.items()}


def enrich(db_path: Path, dataset: Path, output: Path, progress_every: int = 0):
    targets = read_targets(db_path)
    matched = {}
    scanned = 0
    opener = gzip.open if dataset.suffix == '.gz' else open
    with opener(dataset, 'rt', encoding='utf-8-sig', newline='') as stream:
        for row in csv.reader(stream):
            scanned += 1
            if len(row) < 8:
                continue
            try:
                lo = ipaddress.ip_address(row[0])
                hi = ipaddress.ip_address(row[1])
                if lo.version != hi.version or int(lo) > int(hi):
                    continue
                country = row[3].strip().upper()
                if len(country) != 2 or not country.isalpha() or country == 'ZZ':
                    continue
                lat, lon = float(row[6]), float(row[7])
                if not (math.isfinite(lat) and math.isfinite(lon)):
                    continue
                if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                    continue
            except (ValueError, IndexError):
                continue
            keys, lookup = targets[lo.version]
            first = bisect.bisect_left(keys, int(lo))
            last = bisect.bisect_right(keys, int(hi))
            for key in keys[first:last]:
                ip = lookup[key]
                if ip not in matched:
                    matched[ip] = (lat, lon, country)
            if progress_every and scanned % progress_every == 0:
                print(f'RANGES_SCANNED={scanned:,} IPS_MATCHED={len(matched):,}', flush=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile('w', newline='', encoding='utf-8', dir=output.parent,
                                         prefix='.geo_enrichment.', suffix='.tmp', delete=False) as stream:
            tmp = Path(stream.name)
            writer = csv.writer(stream)
            writer.writerow(['ip', 'latitude', 'longitude', 'country'])
            for ip in sorted(matched, key=lambda x: (ipaddress.ip_address(x).version, int(ipaddress.ip_address(x)))):
                lat, lon, country = matched[ip]
                writer.writerow([ip, lat, lon, country])
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, output)
    finally:
        if tmp and tmp.exists():
            tmp.unlink()
    return {'ranges_scanned': scanned, 'targets': sum(len(v[0]) for v in targets.values()),
            'matched': len(matched), 'output': str(output)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--intelligence-db', required=True, type=Path)
    p.add_argument('--geo-dataset', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--progress-every', type=int, default=1_000_000)
    args = p.parse_args()
    if not args.intelligence_db.is_file() or not args.geo_dataset.is_file():
        p.error('Database and GeoIP dataset must both exist')
    if args.progress_every < 0:
        p.error('--progress-every must be nonnegative')
    for k, v in enrich(args.intelligence_db, args.geo_dataset, args.output, args.progress_every).items():
        print(f'{k.upper()}={v}')
    print('ATTRIBUTION_REQUIRED=DB-IP City Lite (verify dataset-specific terms)')


if __name__ == '__main__':
    main()
