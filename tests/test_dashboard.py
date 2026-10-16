"""Offline tests exercising v3.1 API and synthetic input."""
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import urlopen
import dashboard
from tools import make_demo_data


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data = Path(self.temp.name)
        make_demo_data.build(self.data)
        previous = dashboard.DATA
        dashboard.DATA = self.data
        self.addCleanup(setattr, dashboard, 'DATA', previous)
        dashboard._GEO_CACHE['key'] = None

    def test_counts_and_lookup(self):
        counts = dashboard.counts()
        self.assertEqual((counts['total'], counts['ip'], counts['domain']), (4, 3, 1))
        self.assertEqual(counts['detections'], 0)
        self.assertEqual(dashboard.exact_lookup('example.invalid')['verdict'], 'INTEL_MATCH')
        self.assertEqual(dashboard.exact_lookup('absent.invalid')['verdict'], 'NOT_IN_LOCAL_FEED')

    def test_search_and_safe_export(self):
        self.assertEqual(dashboard.search_indicators('%')['total'], 0)
        self.assertEqual(dashboard.search_indicators('192.0.2.10')['total'], 1)
        self.assertEqual(dashboard.search_indicators(kind='domain')['total'], 1)
        result = dashboard.export_csv('', '', '')
        self.assertIn('example.invalid', result)
        self.assertIn('kind,value,source', result)

    def test_exact_atlas_and_public_ip_checks(self):
        self.assertFalse(dashboard.geo_atlas()['enabled'])
        with sqlite3.connect(self.data / 'intelligence.db') as db:
            db.execute("INSERT INTO indicators VALUES ('ip','9.9.9.9','SYNTHETIC_TEST','',NULL,NULL)")
        (self.data / 'geo_enrichment.csv').write_text(
            'ip,latitude,longitude,country\n9.9.9.9,40.5,-74.0,US\n'
            '8.8.8.8,38.0,-80.0,US\n192.0.2.10,30.0,31.0,EG\n', encoding='utf-8')
        dashboard._GEO_CACHE['key'] = None
        atlas = dashboard.geo_atlas()
        self.assertEqual(atlas['total_geocoded'], 1)
        self.assertEqual(atlas['total_filtered'], 1)
        self.assertEqual(atlas['points'][0]['ip'], '9.9.9.9')
        self.assertEqual(dashboard.geo_atlas(country='EG')['total_filtered'], 0)
        self.assertFalse(dashboard.geo_inspect('8.8.8.8')['found'])
        self.assertTrue(dashboard.geo_inspect('9.9.9.9')['found'])

    def test_http_api(self):
        server = dashboard.Server(('127.0.0.1', 0), dashboard.Handler)
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        base = f'http://127.0.0.1:{server.server_port}'
        for path in ('/healthz', '/api/status', '/api/atlas', '/api/telemetry', '/api/indicators'):
            with self.subTest(path=path):
                with urlopen(base + path, timeout=5) as response:
                    self.assertEqual(response.status, 200)
                    self.assertIn('application/json', response.headers['Content-Type'])
                    self.assertIsInstance(json.load(response), dict)
        with urlopen(base + '/', timeout=5) as response:
            self.assertIn('DEVIL', response.read(3000).decode())
        with urlopen(base + '/healthz', timeout=5) as response:
            self.assertEqual(json.load(response)['version'], '3.1.0')


if __name__ == '__main__':
    unittest.main()
