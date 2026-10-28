#!/usr/bin/python3
"""Jitter Premium: separate Linux SSH tunnel manager and authenticated TLS agent."""
import argparse
import datetime as dt
import fcntl
from functools import wraps
import hmac
import ipaddress
import itertools
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import sqlite3
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.fernet import Fernet

ROOT = Path(os.environ.get('JITTER_STATE', '/var/lib/jitter-premium'))
CONFIG = Path(os.environ.get('JITTER_CONFIG', '/etc/jitter-premium/config.json'))
LOCK = threading.RLock()
NAME = re.compile(r'^jx[a-z0-9_]{3,20}$')

class Error(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status

def run(*args, stdin=None):
    return subprocess.run(args, input=stdin, text=True, capture_output=True, check=True, timeout=20).stdout.strip()

def number(value, low, high):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise Error(f'Valor entero requerido entre {low} y {high}')
    return value

def identity(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 128 or any(ord(c) < 32 for c in value):
        raise Error('Identidad de cliente inválida')
    return value

def config():
    return json.loads(CONFIG.read_text())

def serialized(fn):
    @wraps(fn)
    def wrapped(self, *args, **kwargs):
        with LOCK, (self.root / 'manager.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            return fn(self, *args, **kwargs)
    return wrapped

class Manager:
    def __init__(self, root=ROOT, settings=None, executor=run, clock=time.time):
        self.root, self.cfg, self.run, self.clock = Path(root), settings or config(), executor, clock
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        key = self.root / 'encryption.key'
        if not key.exists():
            with key.open('xb') as f:
                f.write(Fernet.generate_key())
            key.chmod(0o600)
        self.crypt = Fernet(key.read_bytes())
        self.db = sqlite3.connect(self.root / 'accounts.sqlite', check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        (self.root / 'accounts.sqlite').chmod(0o600)
        self.db.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS accounts (
          username TEXT PRIMARY KEY, device TEXT NOT NULL, password BLOB NOT NULL,
          expires_at INTEGER NOT NULL, max_login INTEGER NOT NULL, plan TEXT NOT NULL,
          ref TEXT UNIQUE, state TEXT NOT NULL DEFAULT 'active');
        CREATE TABLE IF NOT EXISTS free_claims (device TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS audit (at INTEGER NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS peers (name TEXT PRIMARY KEY, public_key TEXT UNIQUE, ip TEXT UNIQUE, config BLOB NOT NULL);
        ''')

    def audit(self, action, subject):
        self.db.execute('INSERT INTO audit VALUES (?,?,?)', (int(self.clock()), action, subject))

    def public(self, row):
        return {k: row[k] for k in ('username', 'device', 'expires_at', 'max_login', 'plan', 'state')}

    @serialized
    def account(self, device):
        with LOCK:
            row = self.db.execute("SELECT * FROM accounts WHERE device=? AND state='active' AND expires_at>? ORDER BY (plan='premium') DESC, expires_at DESC LIMIT 1", (identity(device), int(self.clock()))).fetchone()
            return self.credentials(row) if row else None

    def credentials(self, row):
        out = self.public(row)
        out.update(password=self.crypt.decrypt(row['password']).decode(), host=self.cfg['host'], port=self.cfg['ssh_port'], ssl_port=self.cfg['ssl_port'])
        return out

    @serialized
    def create(self, body):
        device = identity(body.get('device'))
        paid = body.get('paid', False)
        if not isinstance(paid, bool):
            raise Error('paid debe ser booleano')
        days = number(body.get('days', self.cfg['free_days']) if paid else self.cfg['free_days'], 1, 365)
        limit = number(body.get('max_login', 1) if paid else 1, 1, 32)
        ref = identity(body.get('ref')) if paid else None
        requested = body.get('username', '')
        if not isinstance(requested, str):
            raise Error('Nombre inválido')
        username = requested or 'jx' + secrets.token_hex(6)
        if not NAME.fullmatch(username):
            raise Error('Usa prefijo jx seguido de 3 a 20 letras minúsculas, números o guion bajo')
        with LOCK:
            if paid:
                existing = self.db.execute('SELECT * FROM accounts WHERE ref=?', (ref,)).fetchone()
                if existing:
                    if existing['device'] != device:
                        raise Error('Referencia asignada a otro cliente', 409)
                    if existing['state'] != 'active' or existing['expires_at'] <= self.clock():
                        raise Error('Referencia ya entregada; cuenta no vigente', 409)
                    return self.credentials(existing)
            elif self.db.execute('SELECT 1 FROM free_claims WHERE device=?', (device,)).fetchone():
                raise Error('Prueba gratuita ya utilizada', 409)
            active = self.db.execute("SELECT COUNT(*) FROM accounts WHERE state='active' AND expires_at>?", (int(self.clock()),)).fetchone()[0]
            if active >= self.cfg['max_users']:
                raise Error('Servidor sin cupos', 409)
            if self.db.execute('SELECT 1 FROM accounts WHERE username=?', (username,)).fetchone():
                raise Error('Nombre ocupado', 409)
            # Never adopt, overwrite or delete an existing Linux account.
            try:
                pwd.getpwnam(username)
            except KeyError:
                pass
            else:
                raise Error('Nombre ocupado en el sistema', 409)
            password = secrets.token_urlsafe(18)
            expires = int(self.clock()) + days * 86400
            created = False
            try:
                self.run('useradd', '--no-create-home', '--shell', '/usr/sbin/nologin', '--gid', 'jxclients', '--', username)
                created = True
                self.run('chpasswd', stdin=f'{username}:{password}\n')
                date = dt.datetime.fromtimestamp(expires, dt.timezone.utc).date() + dt.timedelta(days=1)
                self.run('chage', '-E', date.isoformat(), username)
                with self.db:
                    self.db.execute('INSERT INTO accounts (username,device,password,expires_at,max_login,plan,ref) VALUES (?,?,?,?,?,?,?)', (username, device, self.crypt.encrypt(password.encode()), expires, limit, 'premium' if paid else 'free', ref))
                    if not paid:
                        self.db.execute('INSERT INTO free_claims VALUES (?)', (device,))
                    self.audit('create', username)
            except Exception:
                if created:
                    self.run('userdel', '--', username)
                raise
            return self.credentials(self.db.execute('SELECT * FROM accounts WHERE username=?', (username,)).fetchone())

    def sessions(self, username):
        try:
            lines = self.run('ps', '-u', username, '-o', 'pid=,etimes=,args=').splitlines()
        except subprocess.CalledProcessError as e:
            if e.returncode == 1:
                return []  # ps exits 1 when the account has no processes.
            raise
        found = []
        for line in lines:
            parts = line.strip().split(None, 2)
            if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit() and parts[2] == f'sshd: {username}':
                found.append((int(parts[0]), int(parts[1])))
        return sorted(found, key=lambda p: p[1], reverse=True)

    def disconnect(self, username):
        for pid, _ in self.sessions(username):
            self.run('kill', '-TERM', '--', str(pid))

    @serialized
    def maintain(self):
        with LOCK:
            for row in self.db.execute("SELECT * FROM accounts WHERE state='active'").fetchall():
                if row['expires_at'] <= self.clock():
                    self.run('usermod', '-L', '--', row['username'])
                    self.disconnect(row['username'])
                    with self.db:
                        self.db.execute("UPDATE accounts SET state='expired' WHERE username=?", (row['username'],))
                        self.audit('expire', row['username'])
                else:
                    for pid, _ in self.sessions(row['username'])[row['max_login']:]:
                        self.run('kill', '-TERM', '--', str(pid))

    @serialized
    def update(self, username, action, days=30):
        with LOCK:
            row = self.db.execute('SELECT * FROM accounts WHERE username=?', (username,)).fetchone()
            if not row:
                raise Error('Cuenta no encontrada', 404)
            if action == 'renew':
                if row['state'] == 'deleted':
                    raise Error('Cuenta eliminada', 409)
                if row['state'] == 'suspended':
                    raise Error('Cuenta suspendida; no se reactiva con renovación', 409)
                expires = max(int(self.clock()), row['expires_at']) + number(days, 1, 365) * 86400
                date = dt.datetime.fromtimestamp(expires, dt.timezone.utc).date() + dt.timedelta(days=1)
                self.run('chage', '-E', date.isoformat(), username)
                self.run('usermod', '-U', '--', username)
                with self.db:
                    self.db.execute("UPDATE accounts SET state='active',expires_at=? WHERE username=?", (expires, username))
                    self.audit(action, username)
                return
            if action not in ('suspend', 'delete'):
                raise Error('Acción inválida')
            if row['state'] == 'deleted':
                return
            self.run('usermod', '-L', '--', username)
            self.disconnect(username)
            if action == 'delete':
                self.run('userdel', '--', username)
            with self.db:
                self.db.execute('UPDATE accounts SET state=? WHERE username=?', ('deleted' if action == 'delete' else 'suspended', username))
                self.audit(action, username)

    @serialized
    def status(self):
        with LOCK:
            rows = self.db.execute("SELECT * FROM accounts WHERE state='active' AND expires_at>?", (int(self.clock()),)).fetchall()
            return dict(ok=True, version='0.1.0', host=self.cfg['host'], country=self.cfg.get('country', ''), city=self.cfg.get('city', ''), flag=self.cfg.get('flag', ''), active=len(rows), max=self.cfg['max_users'], online=sum(len(self.sessions(r['username'])) for r in rows), premium_active=sum(r['plan'] == 'premium' for r in rows), premium_sold=self.db.execute("SELECT COUNT(*) FROM accounts WHERE plan='premium'").fetchone()[0], protocols=['ssh', 'ssh-tls', 'wireguard'])

    @serialized
    def peer(self, name, remove=False):
        if not re.fullmatch(r'[a-z][a-z0-9_-]{2,24}', name):
            raise Error('Nombre de peer inválido')
        with LOCK:
            existing = self.db.execute('SELECT * FROM peers WHERE name=?', (name,)).fetchone()
            if remove:
                if existing:
                    self.run('wg', 'set', 'jxwg0', 'peer', existing['public_key'], 'remove')
                    try:
                        with self.db:
                            self.db.execute('DELETE FROM peers WHERE name=?', (name,))
                            self.audit('wg-delete', name)
                            self.save_peers()
                    except Exception:
                        self.run('wg', 'set', 'jxwg0', 'peer', existing['public_key'], 'allowed-ips', existing['ip'] + '/32')
                        self.save_peers()
                        raise
                return ''
            if existing:
                return self.crypt.decrypt(existing['config']).decode()
            # Dedicated subnet; install preflight verifies it does not conflict.
            network = ipaddress.ip_network(self.cfg['wg_network'])
            if network.version != 4 or network.prefixlen < 24:
                raise Error('WireGuard requiere una subred IPv4 /24 o menor')
            used = {r[0] for r in self.db.execute('SELECT ip FROM peers')}
            address = next((str(h) for h in itertools.islice(network.hosts(), 1, None) if str(h) not in used), None)
            if not address:
                raise Error('Sin direcciones WireGuard', 409)
            private = self.run('wg', 'genkey')
            public = self.run('wg', 'pubkey', stdin=private + '\n')
            server_key = self.run('wg', 'show', 'jxwg0', 'public-key')
            text = f"[Interface]\nPrivateKey = {private}\nAddress = {address}/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = {server_key}\nEndpoint = {self.cfg['host']}:{self.cfg['wg_port']}\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
            self.run('wg', 'set', 'jxwg0', 'peer', public, 'allowed-ips', address + '/32')
            try:
                with self.db:
                    self.db.execute('INSERT INTO peers VALUES (?,?,?,?)', (name, public, address, self.crypt.encrypt(text.encode())))
                    self.audit('wg-add', name)
                    self.save_peers()
            except Exception:
                self.run('wg', 'set', 'jxwg0', 'peer', public, 'remove')
                self.save_peers()
                raise
            return text

    def save_peers(self):
        base = Path('/etc/jitter-premium/wireguard.base').read_text()
        peers = ''.join(f"\n[Peer]\nPublicKey = {r['public_key']}\nAllowedIPs = {r['ip']}/32\n" for r in self.db.execute('SELECT * FROM peers'))
        target = Path('/etc/wireguard/jxwg0.conf')
        temp = target.with_suffix('.tmp')
        temp.write_text(base + peers)
        temp.chmod(0o600)
        temp.replace(target)

    @serialized
    def backup(self):
        with LOCK:
            directory = self.root / 'backups'
            directory.mkdir(mode=0o700, exist_ok=True)
            target = directory / f'accounts-{time.time_ns()}.sqlite'
            dest = sqlite3.connect(target)
            try:
                self.db.backup(dest)
            finally:
                dest.close()
            target.chmod(0o600)
            return str(target)

class Handler(BaseHTTPRequestHandler):
    server_version = 'Jitter'
    def log_message(self, *args):
        pass  # Do not log client IDs, URLs, tokens or account credentials.

    def reply(self, code, data):
        raw = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def handle_api(self, method):
        try:
            self.connection.settimeout(10)
            supplied = self.headers.get('x-agent-token', '')
            if not hmac.compare_digest(supplied.encode(), self.server.manager.cfg['agent_token'].encode()):
                return self.reply(401, {'ok': False, 'error': 'No autorizado'})
            if self.path.startswith('/v2/'):
                return self.reply(501, {'ok': False, 'error': 'V2Ray no incluido en esta versión'})
            m = self.server.manager
            if method == 'GET' and self.path == '/status':
                return self.reply(200, m.status())
            if method == 'GET' and self.path == '/account':
                return self.reply(200, {'ok': True, 'account': m.account(self.headers.get('x-jx-device', ''))})
            if method == 'POST' and self.path == '/create':
                if 'Transfer-Encoding' in self.headers:
                    raise Error('Transferencia no permitida')
                size = int(self.headers.get('Content-Length', '0'))
                if not 1 <= size <= 4096:
                    raise Error('Cuerpo inválido o demasiado grande', 413)
                body = json.loads(self.rfile.read(size))
                if not isinstance(body, dict):
                    raise Error('Se requiere un objeto JSON')
                header = self.headers.get('x-jx-device')
                if header and body.get('device', header) != header:
                    raise Error('Identidad inconsistente')
                if header:
                    body['device'] = header
                return self.reply(200, {'ok': True, 'account': m.create(body)})
            return self.reply(404, {'ok': False, 'error': 'Operación no encontrada'})
        except Error as e:
            self.reply(e.status, {'ok': False, 'error': str(e)})
        except (ValueError, UnicodeDecodeError):
            self.reply(400, {'ok': False, 'error': 'Solicitud inválida'})
        except Exception:
            self.reply(500, {'ok': False, 'error': 'Operación fallida; revisar el servicio en el VPS'})
    def do_GET(self):
        self.handle_api('GET')
    def do_POST(self):
        self.handle_api('POST')

class Server(ThreadingHTTPServer):
    # Bound concurrent connections, including incomplete TLS handshakes.
    daemon_threads = True
    def __init__(self, address, manager, tls):
        self.manager, self.tls = manager, tls
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(address, Handler)
    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        super().process_request(request, address)
    def process_request_thread(self, request, address):
        try:
            request.settimeout(10)
            secured = self.tls.wrap_socket(request, server_side=True)
            super().process_request_thread(secured, address)
        except (OSError, ssl.SSLError):
            request.close()
        finally:
            self.slots.release()

def main():
    parser = argparse.ArgumentParser(description='Jitter Premium')
    parser.add_argument('action', choices=['serve', 'maintain', 'status', 'list', 'create', 'renew', 'suspend', 'delete', 'backup', 'wg-add', 'wg-delete'])
    parser.add_argument('name', nargs='?', default='')
    parser.add_argument('--device', default='local-admin')
    parser.add_argument('--days', type=int, default=30)
    parser.add_argument('--limit', type=int, default=1)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Ejecutar como root')
    m = Manager()
    if args.action == 'serve':
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(m.cfg['tls_cert'], m.cfg['tls_key'])
        Server((m.cfg['bind'], m.cfg['api_port']), m, tls).serve_forever()
    elif args.action == 'maintain':
        m.maintain()
    elif args.action == 'status':
        print(json.dumps(m.status(), indent=2))
    elif args.action == 'list':
        print(json.dumps([m.public(r) for r in m.db.execute('SELECT * FROM accounts')], indent=2))
    elif args.action == 'create':
        print(json.dumps(m.create(dict(username=args.name, device=args.device, paid=True, days=args.days, max_login=args.limit, ref='admin-' + secrets.token_hex(12))), indent=2))
    elif args.action in ('renew', 'suspend', 'delete'):
        m.update(args.name, args.action, args.days)
    elif args.action == 'backup':
        print(m.backup())
    else:
        print(m.peer(args.name, remove=args.action == 'wg-delete'))

if __name__ == '__main__':
    main()
