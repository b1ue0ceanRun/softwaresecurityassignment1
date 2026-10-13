"""Three local HTTP services. Start each role in a separate process."""
import argparse
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

HOST = '127.0.0.1'
VULN = os.environ.get('LAB_VULN', '')
ROLES = {'alice': 'user', 'bob': 'user', 'admin': 'admin'}
# Synthetic classroom credentials only; passwords are hashed before serving.
USERS = {name: (name.encode(), hashlib.pbkdf2_hmac('sha256',
         (name + '-pass').encode(), name.encode(), 200000)) for name in ROLES}


class Denied(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


def require(condition, status=403, message='forbidden'):
    if not condition:
        raise Denied(status, message)


def request(port, path, data, token=''):
    req = Request(f'http://{HOST}:{port}{path}',
                  json.dumps(data).encode(),
                  {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token})
    try:
        with urlopen(req, timeout=5) as response:  # nosec B310: fixed loopback HTTP
            return response.status, json.load(response)
    except HTTPError as error:
        return error.code, json.load(error)


def forward(port, path, data, token=''):
    status, value = request(port, path, data, token)
    if status != 200:
        raise Denied(status, value.get('error', 'downstream error'))
    return value


class Service:
    def __init__(self, role, resource_port, processor_port):
        self.role = role
        self.resource_port, self.processor_port = resource_port, processor_port
        self.api_key = os.environ.get('API_RESOURCE_KEY', '') if role != 'processor' else ''
        require(role == 'processor' or len(self.api_key) >= 32, 500, 'missing service secret')
        self.sessions, self.caps = {}, {}
        self.db = sqlite3.connect(':memory:')
        self.db.execute('CREATE TABLE users (name TEXT, salt BLOB, digest BLOB)')
        self.db.executemany('INSERT INTO users VALUES (?, ?, ?)',
                            [(name, *values) for name, values in USERS.items()])
        self.notes = {1: {'id': 1, 'owner': 'alice', 'text': 'Alice private note'},
                      2: {'id': 2, 'owner': 'bob', 'text': 'Bob private note'}}

    def call_resource(self, path, data, token):
        return forward(self.resource_port, path, data, token)

    def dispatch(self, path, data, token):
        if path == '/health':
            return {'service': self.role}
        if self.role == 'api':
            return self.api(path, data, token)
        if self.role == 'resource':
            return self.resource(path, data, token)
        require(path == '/job', 404, 'not found')
        raise Denied(404, 'not implemented')

    def api(self, path, data, token):
        raise Denied(404, 'not implemented')

    def resource(self, path, data, token):
        if path == '/grant':
            require(hmac.compare_digest(token, self.api_key), 401, 'invalid service identity')
            user, role, action, rid, aud = (data[k] for k in ('user', 'role', 'action', 'id', 'audience'))
            require(user in ROLES and role in ('user', 'admin'))
            require(action in ('read', 'create', 'stats') and aud in ('api', 'processor'))
            require(aud != 'processor' or action == 'read')
            if action == 'read':
                require(type(rid) is int and rid in self.notes, 404, 'note not found')
                require(VULN == 'idor' or self.notes[rid]['owner'] == user)
            if action == 'stats':
                require(role == 'admin')
            cap = secrets.token_urlsafe(32)
            self.caps[cap] = {'user': user, 'action': action, 'id': rid,
                              'audience': aud, 'expires': time.time() + 30}
            return {'capability': cap}
        require(path in ('/read', '/create', '/stats'), 404, 'not found')
        require(token in self.caps, 401, 'invalid capability')
        cap = self.caps[token]
        require(cap['expires'] > time.time(), 401, 'expired capability')
        require(cap['action'] == path[1:] and cap['audience'] == data.get('audience'))
        if path == '/read':
            rid = data['id']
            require(type(rid) is int and rid in self.notes, 404, 'note not found')
            require((VULN == 'deputy' and cap['audience'] == 'processor') or rid == cap['id'])
            return self.notes[rid]
        if path == '/stats':
            return {'count': len(self.notes)}
        text = data['text']
        require(isinstance(text, str) and (VULN == 'validation' or 0 < len(text) <= 2000),
                400, 'invalid text')
        rid = max(self.notes, default=0) + 1
        self.notes[rid] = {'id': rid, 'owner': cap['user'], 'text': text}
        return self.notes[rid]


def serve(role, port, resource_port, processor_port):
    service = Service(role, resource_port, processor_port)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Do not log credentials, capabilities or private note contents.

        def do_POST(self):
            try:
                require(self.headers.get('Content-Type') == 'application/json', 415, 'JSON required')
                size = int(self.headers.get('Content-Length', '0'))
                require(0 < size <= 8192, 413, 'invalid body size')
                data = json.loads(self.rfile.read(size))
                require(isinstance(data, dict), 400, 'object required')
                header = self.headers.get('Authorization', '')
                token = header[7:] if header.startswith('Bearer ') else ''
                result = service.dispatch(self.path, data, token)
                status = 200
            except Denied as error:
                status, result = error.status, {'error': error.message}
            except (KeyError, ValueError, TypeError, AttributeError):
                status, result = 400, {'error': 'malformed request'}
            except (OSError, TimeoutError):
                status, result = 502, {'error': 'downstream unavailable'}
            payload = json.dumps(result).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = HTTPServer((HOST, port), Handler)
    server.timeout = 5
    server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('role', choices=('api', 'resource', 'processor'))
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--resource-port', type=int, default=8102)
    parser.add_argument('--processor-port', type=int, default=8103)
    args = parser.parse_args()
    serve(args.role, args.port, args.resource_port, args.processor_port)
