"""Optional real Go/Rust clients; build recipes are in docs/testing.md."""
import contextlib
import http.server
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest

from .support import AgentProcess


def certificate(directory):
    config = directory / 'certificate.cnf'
    config.write_text('''[req]
distinguished_name=dn
x509_extensions=ext
prompt=no
[dn]
CN=connectivity.macdbg.invalid
[ext]
subjectAltName=DNS:connectivity.macdbg.invalid,IP:127.0.0.1
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
''')
    cert, key = directory / 'server.crt', directory / 'server.key'
    ca, ca_key, csr = directory / 'ca.crt', directory / 'ca.key', directory / 'server.csr'
    ca_config = directory / 'ca.cnf'
    ca_config.write_text('''[req]
distinguished_name=dn
x509_extensions=ext
prompt=no
[dn]
CN=MacDBG ephemeral test CA
[ext]
basicConstraints=critical,CA:true
keyUsage=critical,keyCertSign,cRLSign
''')
    commands = [
        ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1',
         '-config', str(ca_config), '-keyout', str(ca_key), '-out', str(ca)],
        ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-config', str(config),
         '-keyout', str(key), '-out', str(csr)],
        ['x509', '-req', '-in', str(csr), '-CA', str(ca), '-CAkey', str(ca_key),
         '-CAcreateserial', '-days', '1', '-sha256', '-extfile', str(config),
         '-extensions', 'ext', '-out', str(cert)],
    ]
    for command in commands:
        subprocess.run(['/usr/bin/openssl'] + command, check=True, capture_output=True, timeout=15)
    return cert, key, ca


@contextlib.contextmanager
def responder(cert=None, key=None):
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.connection.settimeout(10)
            body = self.rfile.read(int(self.headers['Content-Length']))
            received.append((self.path, dict(self.headers), body))
            self.send_response(200)
            self.send_header('Content-Length', '14')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(b'fixture-online')

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    if cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield '{}://127.0.0.1:{}'.format('https' if cert else 'http', server.server_port), received
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


class LanguageNetworkTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix='md-language-', dir='/private/tmp')
        self.addCleanup(scratch.cleanup)
        self.directory = Path(scratch.name)
        # File paths exceed the old 256-byte trace string limit.
        self.files = self.directory / ('a' * 120) / ('b' * 120)
        self.files.mkdir(parents=True)
        self.cert, self.key, self.ca = certificate(self.directory)
        self.env = {'MACDBG_STATE_DIR': scratch.name, 'PYTHONDONTWRITEBYTECODE': '1'}

    def binary(self, language):
        value = os.environ.get('MACDBG_' + language.upper() + '_FIXTURE')
        if not value:
            self.skipTest('Set MACDBG_' + language.upper() + '_FIXTURE to the ARM64 fixture')
        self.assertTrue(Path(value).is_file(), value)
        return value

    def exercise(self, language, tls=False, spoof=False, trust=True, returns=False):
        binary = self.binary(language)
        expected = 'language={}&marker=benign-analyst-payload'.format(language)
        with responder(self.cert if tls else None, self.key if tls else None) as (base, received):
            url = ('{}://connectivity.macdbg.invalid:{}'.format('https' if tls else 'http',
                                                              443 if tls else 80)
                   if spoof else base) + '/analyst-check'
            arguments = [str(self.files), str(self.ca) if trust else '-']
            if not spoof:
                native = subprocess.run([binary, url] + arguments, capture_output=True,
                                        text=True, timeout=40)
                self.assertEqual(native.returncode, 0, native.stdout + native.stderr)
                self.assertEqual(received.pop()[2].decode(), expected)
            with AgentProcess(binary, url, arguments, self.env) as agent:
                if spoof:
                    rule = {'host': 'connectivity.macdbg.invalid', 'port': 443 if tls else 80,
                            'body': 'fixture-online'}
                    if tls:
                        rule.update(tls_cert=str(self.cert), tls_key=str(self.key))
                    configured = agent.cmd('offline_network', {'rules': [rule]})
                    self.assertTrue(configured['ok'], configured)
                enabled = agent.cmd('tracer_enable', {'returns': returns})
                self.assertTrue(enabled['ok'], enabled)
                result = agent.cmd('continue', {'timeout': 40}, timeout=45)
                self.assertEqual(result.get('event'), 'exited', result)
                rows = agent.cmd('trace_hits')['hits']
                events = agent.cmd('analysis_events')['hits']
                self.assertFalse(agent.cmd('offline_network')['enabled'])
            if not trust:
                self.assertNotEqual(result['exit']['code'], 0, result)
                self.assertFalse(any(row.get('http_requests') for row in rows))
                return
            self.assertEqual(result['exit']['code'], 0, result)
            self.assertIn('fixture-online', result['console'])
            self.assertTrue(any(str(self.files / (language + '-analyst-marker.txt')) in row['call']
                                for row in rows), 'file access lost from trace')
            requests = [request for row in rows for request in row.get('http_requests', [])
                        if request.get('url') == '/analyst-check' and request.get('complete')]
            self.assertEqual(len(requests), 1, requests)
            request = requests[0]
            self.assertEqual(request['body']['text'], expected)
            headers = {h['name'].lower(): h['value'] for h in request['headers']}
            self.assertEqual(headers['x-macdbg-fixture'], 'benign-' + language)
            if spoof:
                self.assertTrue(any(e.get('category') == 'NETWORK' and
                                    e.get('scheme') == ('https' if tls else 'http') for e in events), events)
                self.assertFalse(received, 'simulation unexpectedly used unrelated server')
            else:
                self.assertEqual(len(received), 1)
                self.assertEqual(received[0][2].decode(), expected)
            if returns:
                self.assertTrue(any(r.get('phase') == 'return' and r.get('category') == 'NET' and
                                    'fixture-online' in r.get('payload', {}).get('text', '')
                                    for r in rows), 'response body missing')

    def test_go_http_file_and_payload(self): self.exercise('go')
    def test_go_https_plaintext(self): self.exercise('go', tls=True)
    def test_go_http_simulation(self): self.exercise('go', spoof=True)
    def test_go_https_simulation(self): self.exercise('go', tls=True, spoof=True)
    def test_go_https_untrusted_certificate_fails(self): self.exercise('go', tls=True, spoof=True, trust=False)
    def test_go_http_response(self): self.exercise('go', returns=True)
    def test_rust_http_file_and_payload(self): self.exercise('rust')
    def test_rust_https_plaintext(self): self.exercise('rust', tls=True)
    def test_rust_http_simulation(self): self.exercise('rust', spoof=True)
    def test_rust_https_simulation(self): self.exercise('rust', tls=True, spoof=True)
    def test_rust_https_untrusted_certificate_fails(self): self.exercise('rust', tls=True, spoof=True, trust=False)
    def test_rust_http_response(self): self.exercise('rust', returns=True)
