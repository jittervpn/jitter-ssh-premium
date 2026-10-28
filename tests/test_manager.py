import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from http.server import ThreadingHTTPServer

spec = importlib.util.spec_from_file_location('jitter', Path(__file__).parents[1] / 'jitter.py')
jitter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jitter)

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.now = 1800000000
        self.calls = []
        self.processes = ''
        self.cfg = dict(host='example.org', ssh_port=2222, ssl_port=4443, free_days=2, max_users=100, agent_token='test-only-not-production')
        self.m = jitter.Manager(self.tmp.name, self.cfg, self.execute, lambda: self.now)
        self.system_user = patch('jitter.pwd.getpwnam', side_effect=KeyError()) if False else patch.object(jitter.pwd, 'getpwnam', side_effect=KeyError())
        self.system_user.start()
    def tearDown(self):
        self.system_user.stop()
        self.m.db.close()
        self.tmp.cleanup()
    def execute(self, *args, stdin=None):
        self.calls.append(args)
        return self.processes if args[0] == 'ps' else ''
    def create(self, **extra):
        return self.m.create(dict(device='client-1', username='jxalice', **extra))
    def test_two_day_trial(self):
        account = self.create(days=365, max_login=32)
        self.assertEqual(account['expires_at'], self.now + 2 * 86400)
        self.assertEqual(account['max_login'], 1)
    def test_single_free_claim(self):
        self.create()
        self.now += 3 * 86400
        with self.assertRaises(jitter.Error):
            self.m.create(dict(device='client-1', username='jxbob'))
    def test_paid_reference_is_idempotent(self):
        first = self.create(paid=True, ref='payment-1', days=30, max_login=2)
        second = self.create(paid=True, ref='payment-1', days=30, max_login=2)
        self.assertEqual(first, second)
        self.assertEqual(sum(c[0] == 'useradd' for c in self.calls), 1)
        self.assertEqual(first['expires_at'], self.now + 30 * 86400)
        self.assertEqual(first['max_login'], 2)
    def test_payment_identity_cannot_change(self):
        self.create(paid=True, ref='payment-1')
        with self.assertRaises(jitter.Error):
            self.m.create(dict(device='other', paid=True, ref='payment-1'))
    def test_username_injection_rejected(self):
        with self.assertRaises(jitter.Error):
            self.m.create(dict(device='a', username='jxfoo;rm -rf /'))
        self.assertEqual(self.calls, [])
    def test_existing_linux_user_not_modified(self):
        with patch.object(jitter.pwd, 'getpwnam', return_value=object()):
            with self.assertRaises(jitter.Error):
                self.create()
        self.assertEqual(self.calls, [])
    def test_password_is_encrypted(self):
        account = self.create()
        encrypted = self.m.db.execute('SELECT password FROM accounts').fetchone()[0]
        self.assertNotIn(account['password'].encode(), encrypted)
        self.assertEqual(self.m.account('client-1')['password'], account['password'])
    def test_expiry_disables_and_hides_account(self):
        self.create()
        self.now += 2 * 86400
        self.m.maintain()
        self.assertIn(('usermod', '-L', '--', 'jxalice'), self.calls)
        self.assertIsNone(self.m.account('client-1'))
    def test_limit_counts_only_tunnel_processes(self):
        self.create()
        self.processes = '10 80 sshd: jxalice\n11 70 sshd: jxalice\n12 60 sshd: jxalice [priv]\n13 40 other-command\n'
        self.m.maintain()
        self.assertIn(('kill', '-TERM', '--', '11'), self.calls)
        self.assertNotIn(('kill', '-TERM', '--', '10'), self.calls)
        self.assertNotIn(('kill', '-TERM', '--', '12'), self.calls)
    def test_no_processes_is_valid_status(self):
        self.create()
        def execute(*args, **kwargs):
            if args[0] == 'ps':
                raise subprocess.CalledProcessError(1, args)
            return ''
        self.m.run = execute
        self.assertEqual(self.m.status()['online'], 0)
    def test_suspended_account_not_renewed(self):
        self.create()
        self.m.update('jxalice', 'suspend')
        with self.assertRaises(jitter.Error):
            self.m.update('jxalice', 'renew', 30)
    def test_backup_reads_back(self):
        self.create()
        backup = sqlite3.connect(self.m.backup())
        self.assertEqual(backup.execute('SELECT username FROM accounts').fetchone()[0], 'jxalice')
        backup.close()
    def test_store_http_create_then_read(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), jitter.Handler)
        server.manager = self.m
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f'http://127.0.0.1:{server.server_port}'
        headers = {'x-agent-token': self.cfg['agent_token'], 'x-jx-device': 'store-user', 'Content-Type': 'application/json'}
        try:
            with self.assertRaises(HTTPError) as denied:
                urlopen(origin + '/status')
            self.assertEqual(denied.exception.code, 401)
            body = json.dumps(dict(device='store-user', username='jxstore', paid=True, days=30, max_login=2, ref='mp-1-0')).encode()
            created = json.load(urlopen(Request(origin + '/create', body, headers)))['account']
            response = urlopen(Request(origin + '/account', headers=headers))
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
            readback = json.load(response)['account']
            self.assertEqual(readback, created)
            self.assertEqual(json.load(urlopen(Request(origin + '/status', headers=headers)))['active'], 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

if __name__ == '__main__':
    unittest.main()
