"""No Internet required: synthetic DB-IP-shaped ranges."""
import csv
import gzip
import sqlite3
import tempfile
import unittest
from pathlib import Path
from tools import geo_enrich


class GeoTests(unittest.TestCase):
    def test_stream_match_and_reject_reserved_or_nan(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            dbpath = p / 'intelligence.db'
            with sqlite3.connect(dbpath) as con:
                con.execute('CREATE TABLE indicators(kind TEXT,value TEXT)')
                con.executemany('INSERT INTO indicators VALUES (?,?)', [
                    ('ip','9.9.9.9'), ('ip','8.8.8.8'), ('ip','192.0.2.1'),
                    ('ip','1.1.1.1'), ('ip','invalid'), ('domain','example.com')])
            gz = p / 'dbip.csv.gz'
            with gzip.open(gz, 'wt', newline='') as stream:
                csv.writer(stream).writerows([
                    ['0.0.0.0','0.255.255.255','ZZ','ZZ','','','0','0'],
                    ['8.8.8.0','8.8.8.255','NA','US','','','37.5','-121.5'],
                    ['9.9.9.9','9.9.9.9','NA','US','','','40.0','-73.5'],
                    ['1.1.1.0','1.1.1.255','OC','AU','','','nan','151.2'],
                    ['192.0.2.0','192.0.2.255','AF','EG','','','30.0','31.0'],
                ])
            output = p / 'geo_enrichment.csv'
            result = geo_enrich.enrich(dbpath, gz, output)
            self.assertEqual(result['matched'], 2)
            with output.open(newline='') as f:
                rows = list(csv.DictReader(f))
            self.assertEqual({r['ip'] for r in rows}, {'8.8.8.8','9.9.9.9'})
            self.assertEqual({r['country'] for r in rows}, {'US'})


if __name__ == '__main__':
    unittest.main()
