#!/usr/bin/env python3
"""Create synthetic documentation-only data in a new directory; never touch production DBs."""
from __future__ import annotations
import argparse
import sqlite3
from pathlib import Path

INDICATORS = [
    ('ip', '192.0.2.10', 'SYNTHETIC_DEMO', '', '2026-10-15T11:00:00+00:00', '2026-10-16T10:00:00+00:00'),
    ('ip', '198.51.100.20', 'SYNTHETIC_DEMO', '', '2026-10-15T11:20:00+00:00', '2026-10-16T10:00:00+00:00'),
    ('ip', '203.0.113.30', 'SYNTHETIC_DEMO', '', '2026-10-15T11:45:00+00:00', '2026-10-16T10:00:00+00:00'),
    ('domain', 'example.invalid', 'SYNTHETIC_DEMO', '', '2026-10-15T12:00:00+00:00', '2026-10-16T10:00:00+00:00'),
]


def build(output: Path):
    output.mkdir(parents=True, exist_ok=True)
    intel, events = output / 'intelligence.db', output / 'events.db'
    if intel.exists() or events.exists():
        raise FileExistsError('Refusing to overwrite existing files; choose a fresh directory')
    con = sqlite3.connect(intel)
    try:
        con.execute('''CREATE TABLE indicators (
            kind TEXT, value TEXT, source TEXT, example_url TEXT,
            first_seen TEXT, last_seen TEXT, PRIMARY KEY (kind,value,source))''')
        con.executemany('INSERT INTO indicators VALUES (?,?,?,?,?,?)', INDICATORS)
        con.commit()
    finally:
        con.close()
    con = sqlite3.connect(events)
    try:
        con.execute('''CREATE TABLE detections (
            ip TEXT, source TEXT, first_seen TEXT, last_seen TEXT,
            observations INTEGER, PRIMARY KEY (ip,source))''')
        con.execute('''CREATE TABLE pending_alerts (
            ip TEXT, source TEXT, sent_at TEXT, PRIMARY KEY (ip,source))''')
        con.commit()
    finally:
        con.close()
    return intel, events


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    try:
        a, _ = build(args.output)
    except FileExistsError as e:
        p.error(str(e))
    print(f'SYNTHETIC_DEMO_ONLY={a.parent}')
    print('INDICATORS=4; NO REAL THREATS; EVENTS=0; GEOIP=NOT_CONFIGURED')


if __name__ == '__main__':
    main()
