"""Local checks of credential preparation and the controlled streaming fixture."""
import base64
import json
import ssl
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from fixture import handler, ACCESS, GRANT
from prepare import prepare, GATEWAY, ISSUER


class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        prepare(cls.root)
        cls.server = ThreadingHTTPServer(('localhost', 0), handler(cls.root / 'fixture'))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.root / 'fixture/tls.pem', cls.root / 'fixture/tls.key')
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f'https://localhost:{cls.server.server_port}'
        cls.context = ssl.create_default_context(cafile=str(cls.root / 'client/ca.pem'))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(); cls.temp.cleanup()

    def open(self, path, data=None, headers=None):
        req = urllib.request.Request(self.url + path, data=data, headers=headers or {})
        try: return urllib.request.urlopen(req, context=self.context, timeout=3)
        except urllib.error.HTTPError as response: return response

    def token(self, exchanged=False):
        client = 'stream-gateway' if exchanged else 'stream-agent'
        filename = 'exchange-secret' if exchanged else 'agent-secret'
        auth = base64.b64encode((client + ':' + (self.root / 'fixture' / filename).read_text()).encode()).decode()
        form = {'grant_type': 'client_credentials', 'resource': GATEWAY + '/mcp', 'scope': 'stream:call'}
        if exchanged:
            form = {'grant_type': GRANT, 'subject_token': self.token(), 'subject_token_type': ACCESS,
                'requested_token_type': ACCESS, 'resource': 'urn:stream:mcp', 'scope': 'stream:execute'}
        with self.open('/token', urllib.parse.urlencode(form).encode(), {'Authorization': 'Basic ' + auth,
            'Content-Type': 'application/x-www-form-urlencoded'}) as response:
            self.assertEqual(response.status, 200)
            return json.load(response)['access_token']

    def test_configuration_and_separated_credentials(self):
        config = json.loads((self.root / 'gateway/kong.json').read_text())
        self.assertEqual(len(config['services']), 3)
        for service in config['services']:
            self.assertTrue(service['tls_verify'])
            self.assertEqual(service['retries'], 0)
            self.assertFalse(service['routes'][0]['response_buffering'])
            self.assertEqual(len(service['routes'][0]['plugins']), 2)
        for directory in ('gateway', 'client'):
            self.assertFalse((self.root / directory / 'signing.key').exists())
        self.assertFalse((self.root / 'client/exchange-secret').exists())

    def test_gated_sse_response_and_identity(self):
        message = {'jsonrpc': '2.0', 'id': 'local', 'method': 'tools/call', 'params': {
            'name': 'probe', 'arguments': {'fixture_id': 'local'}, '_meta': {'progressToken': 'local'}}}
        with self.open('/mcp', json.dumps(message).encode(), {'Authorization': 'Bearer ' + self.token(True)}) as response:
            self.assertEqual(response.headers.get_content_type(), 'text/event-stream')
            self.assertIn(b'notifications/progress', response.readline())
            self.assertEqual(response.readline(), b'\n')
            with self.open('/control/local') as record_response: record = json.load(record_response)
            self.assertFalse(record['completed'])
            self.assertEqual(record['identity']['act'], {'sub': 'stream-gateway'})
            with self.open('/release/local', b'{}') as released: self.assertEqual(released.status, 200)
            self.assertIn(b'"result"', response.read())

    def test_backend_rejects_original_token(self):
        message = {'jsonrpc': '2.0', 'id': 'unauthorized', 'method': 'tools/call', 'params': {}}
        with self.open('/mcp', json.dumps(message).encode(), {'Authorization': 'Bearer ' + self.token()}) as response:
            self.assertEqual(response.status, 401)


if __name__ == '__main__': unittest.main()
