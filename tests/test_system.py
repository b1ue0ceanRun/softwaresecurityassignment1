import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from app import Service, Denied, request


class Cluster:
    def __init__(self, mode=''):
        self.mode = mode
        self.processes = []
        self.ports = []
        sockets = []
        for _ in range(3):
            sock = socket.socket()
            sock.bind(('127.0.0.1', 0))
            sockets.append(sock)
            self.ports.append(sock.getsockname()[1])
        for sock in sockets:
            sock.close()
        self.key = secrets.token_urlsafe(32)

    def __enter__(self):
        try:
            for role, port in zip(('api', 'resource', 'processor'), self.ports):
                env = {**os.environ, 'LAB_VULN': self.mode}
                env.pop('API_RESOURCE_KEY', None)
                if role != 'processor':
                    env['API_RESOURCE_KEY'] = self.key
                self.processes.append(subprocess.Popen(
                    [sys.executable, 'app.py', role, '--port', str(port),
                     '--resource-port', str(self.ports[1]), '--processor-port', str(self.ports[2])],
                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            deadline = time.monotonic() + 15
            for port in self.ports:
                while True:
                    try:
                        if request(port, '/health', {})[0] == 200:
                            break
                    except OSError:
                        pass
                    if time.monotonic() > deadline:
                        raise RuntimeError('service startup failed')
                    time.sleep(.05)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        for process in self.processes:
            process.terminate()
        for process in self.processes:
            process.wait(timeout=5)

    def call(self, path, data, token='', component=0):
        return request(self.ports[component], path, data, token)

    def login(self, user):
        status, body = self.call('/login', {'username': user, 'password': user + '-pass'})
        assert status == 200
        return body['token']


class IntegrationTests(unittest.TestCase):
    def test_fixed_functions_and_boundaries(self):
        with Cluster() as c:
            alice, bob, admin = [c.login(u) for u in ('alice', 'bob', 'admin')]
            status, note = c.call('/create', {'text': 'hello', 'owner': 'bob'}, alice)
            self.assertEqual(status, 200)
            self.assertEqual(note['owner'], 'alice')
            self.assertEqual(c.call('/read', {'id': note['id']}, alice)[0], 200)
            self.assertEqual(c.call('/read', {'id': note['id']}, bob)[0], 403)
            self.assertEqual(c.call('/read', {'id': 2}, alice)[0], 403)
            self.assertEqual(c.call('/read', {'id': 1}, bob)[0], 403)
            self.assertEqual(c.call('/stats', {}, alice)[0], 403)
            self.assertEqual(c.call('/stats', {}, admin), (200, {'count': 3}))
            self.assertEqual(c.call('/export', {'id': 1}, alice),
                             (200, {'export': 'Note 1\nAlice private note\n'}))
            self.assertEqual(c.call('/job', {'id': 2}, alice, 2)[0], 401)
            self.assertEqual(c.call('/read', {'id': 1})[0], 401)
            self.assertEqual(c.call('/login', {'username': 'alice', 'password': 'wrong'})[0], 401)
            self.assertEqual(c.call('/stats', {}, c.call('/login', {
                'username': 'alice', 'password': 'alice-pass', 'role': 'admin'})[1]['token'])[0], 403)
            self.assertEqual(c.call('/create', {'text': ''}, alice)[0], 400)
            self.assertEqual(c.call('/create', {'text': 23}, alice)[0], 400)
            self.assertEqual(c.call('/create', {'text': 'x' * 9000}, alice)[0], 413)
            self.assertEqual(c.call('/unknown', {}, alice)[0], 404)
            self.assertEqual(c.call('/login', {})[0], 400)
            self.assertEqual(c.call('/grant', {'user': 'alice'}, '', 1)[0], 401)
            grant = c.call('/grant', {'user': 'alice', 'role': 'user', 'action': 'read',
                         'id': 1, 'audience': 'processor'}, c.key, 1)[1]['capability']
            self.assertEqual(c.call('/read', {'id': 1, 'audience': 'api'}, grant, 1)[0], 403)
            self.assertEqual(c.call('/stats', {'audience': 'processor'}, grant, 1)[0], 403)
            self.assertEqual(c.call('/job', {'id': 2}, grant, 2)[0], 403)

    def test_four_vulnerabilities_before_and_after(self):
        evidence = []
        for mode in ('validation', 'sql', 'idor', 'deputy'):
            for enabled in (True, False):
                with self.subTest(vulnerability=mode, enabled=enabled), Cluster(mode if enabled else '') as c:
                    alice = c.login('alice')
                    if mode == 'validation':
                        status, body = c.call('/create', {'text': 'x' * 2001}, alice)
                        expected = 200 if enabled else 400
                    elif mode == 'sql':
                        status, body = c.call('/login', {'username': "alice' --", 'password': 'alice-pass'})
                        expected = 200 if enabled else 401
                    elif mode == 'idor':
                        status, body = c.call('/read', {'id': 2}, alice)
                        expected = 200 if enabled else 403
                        if enabled:
                            self.assertEqual(body['owner'], 'bob')
                    else:
                        status, body = c.call('/export', {'id': 1, 'source_id': 2}, alice)
                        expected = 200 if enabled else 403
                        if enabled:
                            self.assertIn('Bob private note', body['export'])
                    self.assertEqual(status, expected)
                    evidence.append({'vulnerability': mode, 'fixture_enabled': enabled,
                                     'status': status, 'expected': expected, 'passed': status == expected})
        Path('evidence').mkdir(exist_ok=True)
        Path('evidence/vulnerabilities.json').write_text(json.dumps(evidence, indent=2) + '\n')

    def test_expired_authority(self):
        old = os.environ.get('API_RESOURCE_KEY')
        os.environ['API_RESOURCE_KEY'] = 'a' * 32
        try:
            api = Service('api', 1, 2)
            api.sessions['expired'] = ('alice', 'user', time.time() - 1)
            with self.assertRaises(Denied) as caught:
                api.api('/read', {'id': 1}, 'expired')
            self.assertEqual(caught.exception.status, 401)
            resource = Service('resource', 1, 2)
            resource.caps['expired'] = {'expires': time.time() - 1}
            with self.assertRaises(Denied) as caught:
                resource.resource('/read', {'id': 1}, 'expired')
            self.assertEqual(caught.exception.status, 401)
        finally:
            if old is None:
                os.environ.pop('API_RESOURCE_KEY')
            else:
                os.environ['API_RESOURCE_KEY'] = old


if __name__ == '__main__':
    unittest.main()
