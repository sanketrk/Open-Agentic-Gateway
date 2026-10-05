"""Black-box streaming tests through the production Kong image and plugins."""
import base64
import concurrent.futures
import http.client
import json
import os
import ssl
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from prepare import GATEWAY, ISSUER


class StreamingGateway(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = Path(os.environ.get('STREAMING_CREDENTIALS', '/credentials'))
        cls.context = ssl.create_default_context(cafile=str(directory / 'ca.pem'))
        cls.secret = (directory / 'agent-secret').read_text()

    def open(self, url, data=None, headers=None, timeout=4):
        request = urllib.request.Request(url, data=data, headers=headers or {})
        try: return urllib.request.urlopen(request, context=self.context, timeout=timeout)
        except urllib.error.HTTPError as response: return response

    def control(self, identifier):
        with self.open(ISSUER + '/control/' + identifier) as response:
            self.assertEqual(response.status, 200)
            return json.load(response)

    def release(self, identifier):
        with self.open(ISSUER + '/release/' + identifier, b'{}') as response:
            self.assertEqual(response.status, 200)

    def token(self, path, scope='stream:call'):
        form = urllib.parse.urlencode({'grant_type': 'client_credentials', 'resource': GATEWAY + path, 'scope': scope}).encode()
        auth = base64.b64encode(('stream-agent:' + self.secret).encode()).decode()
        with self.open(ISSUER + '/token', form, {'Content-Type': 'application/x-www-form-urlencoded',
                                              'Authorization': 'Basic ' + auth}) as response:
            self.assertEqual(response.status, 200)
            return json.load(response)['access_token']

    def start(self, protocol='mcp', mode='gated', operation=None, token=True, headers=None, path=None):
        identifier = uuid.uuid4().hex
        if protocol == 'mcp':
            path = path or '/mcp'
            method = operation or 'tools/call'
            params = {'_meta': {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                'io.modelcontextprotocol/clientCapabilities': {}, 'progressToken': identifier},
                'arguments': {'fixture_id': identifier, 'mode': mode}}
            if method == 'tools/call': params['name'] = 'probe'
            message = {'jsonrpc': '2.0', 'id': identifier, 'method': method, 'params': params}
            request_headers = {'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': method,
                'Mcp-Session-Id': 'legacy-request', 'Last-Event-ID': 'legacy-event'}
            if method == 'tools/call': request_headers['Mcp-Name'] = 'probe'
            audience_path = path
        else:
            path = path or ('/a2a' if protocol == 'a2a-rpc' else '/a2a/rest/message:stream')
            audience_path = '/a2a'
            params = {'message': {'messageId': identifier, 'role': 'ROLE_USER', 'parts': [{'text': 'probe'}]},
                      'metadata': {'fixture_id': identifier, 'mode': mode}}
            message = {'jsonrpc': '2.0', 'id': identifier, 'method': operation or 'SendStreamingMessage',
                       'params': params} if protocol == 'a2a-rpc' else params
            request_headers = {'A2A-Version': '1.0'}
        request_headers.update({'Content-Type': 'application/a2a+json' if protocol == 'a2a-rest' else 'application/json',
                                'Accept': 'application/json, text/event-stream'})
        if token: request_headers['Authorization'] = 'Bearer ' + (self.token(audience_path) if token is True else token)
        request_headers.update(headers or {})
        response = self.open(GATEWAY + path, json.dumps(message).encode(), request_headers)
        return identifier, message, response

    def event(self, response):
        fields = []
        while True:
            line = response.readline(65537)
            self.assertTrue(line, 'stream ended before next complete event')
            self.assertLessEqual(len(line), 65536)
            if line in (b'\n', b'\r\n'):
                if fields: return json.loads(b'\n'.join(fields))
            elif line.startswith(b'data: '): fields.append(line[6:].rstrip(b'\r\n'))

    def wait_disconnected(self, identifier):
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            record = self.control(identifier)
            if record.get('disconnected'): return record
            time.sleep(0.05)
        self.fail('client disconnect did not reach upstream: ' + identifier)

    def check_gated_stream(self, protocol, operation=None, path=None):
        identifier, message, response = self.start(protocol, operation=operation, path=path)
        try:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers.get_content_type(), 'text/event-stream')
            first = self.event(response)  # Cannot arrive if Kong buffers until completion.
            record = self.control(identifier)
            self.assertFalse(record['completed'])
            self.assertEqual(first, record['events'][0])
            self.assertEqual(record['message'], message)
            self.assertEqual(record['identity'], {'sub': 'stream-agent',
                'aud': 'urn:stream:' + ('mcp' if protocol == 'mcp' else 'a2a'),
                'scope': 'stream:execute', 'act': {'sub': 'stream-gateway'}})
            if protocol == 'mcp':
                self.assertIsNone(response.headers.get('Mcp-Session-Id'))
                self.assertIsNone(record['headers']['Mcp-Session-Id'])
                self.assertIsNone(record['headers']['Last-Event-ID'])
                self.assertEqual(record['headers']['Mcp-Method'], message['method'])
            self.release(identifier)
            events = [first] + [self.event(response) for _ in record['events'][1:]]
            self.assertEqual(events, record['events'])
            self.assertEqual(response.read(), b'')
            self.assertEqual(self.control(identifier)['attempts'], 1)
            return events
        finally:
            response.close()
            # Also free the fixture gate if an assertion failed.
            if self.control(identifier)['attempts']: self.release(identifier)

    def test_mcp_current_revision_progress_and_final_response(self):
        events = self.check_gated_stream('mcp')
        self.assertEqual(events[0]['method'], 'notifications/progress')
        self.assertEqual(events[-1]['result']['content'][0]['text'], 'done')

    def test_mcp_post_subscription_stream(self):
        events = self.check_gated_stream('mcp', 'subscriptions/listen')
        self.assertEqual([e['method'] for e in events],
                         ['notifications/tools/list_changed', 'notifications/resources/updated'])

    def test_a2a_rpc_stream_and_task_subscription(self):
        for operation in ('SendStreamingMessage', 'SubscribeToTask'):
            with self.subTest(operation=operation):
                events = self.check_gated_stream('a2a-rpc', operation)
                self.assertIn('artifactUpdate', events[1]['result'])
                self.assertEqual(events[-1]['result']['statusUpdate']['status']['state'], 'TASK_STATE_COMPLETED')

    def test_a2a_rest_stream_and_task_subscription(self):
        for path in ('/a2a/rest/message:stream', '/a2a/rest/tasks/task-1:subscribe'):
            with self.subTest(path=path):
                events = self.check_gated_stream('a2a-rest', path=path)
                self.assertNotIn('jsonrpc', events[0])
                self.assertIn('artifactUpdate', events[1])

    def test_invalid_authentication_never_reaches_streaming_upstream(self):
        for protocol, audience in (('mcp', '/mcp'), ('a2a-rpc', '/a2a'), ('a2a-rest', '/a2a')):
            for token, status in ((False, 401), ('invalid-token', 401),
                                  (self.token(audience, 'unrelated'), 403)):
                with self.subTest(protocol=protocol, status=status):
                    identifier, _, response = self.start(protocol, token=token)
                    with response:
                        self.assertEqual(response.status, status)
                        self.assertNotEqual(response.headers.get_content_type(), 'text/event-stream')
                        response.read()
                    self.assertEqual(self.control(identifier)['attempts'], 0)
        identifier, _, response = self.start('mcp', token=self.token('/a2a'))
        with response: self.assertEqual(response.status, 401)
        self.assertEqual(self.control(identifier)['attempts'], 0)

    def test_current_mcp_header_mismatch_and_legacy_get_are_rejected(self):
        identifier, _, response = self.start(headers={'Mcp-Name': 'wrong'})
        with response:
            self.assertEqual(response.status, 400)
            self.assertIn('error', json.load(response))
        self.assertEqual(self.control(identifier)['attempts'], 0)
        with self.open(GATEWAY + '/mcp', headers={'MCP-Protocol-Version': '2026-07-28',
                                                 'Accept': 'text/event-stream'}) as response:
            self.assertEqual(response.status, 405)

    def test_client_disconnect_closes_upstream_stream(self):
        for protocol, operation in (('mcp', 'tools/call'), ('mcp', 'subscriptions/listen'),
                                    ('a2a-rpc', 'SendStreamingMessage'), ('a2a-rest', None)):
            with self.subTest(protocol=protocol, operation=operation):
                identifier, _, response = self.start(protocol, operation=operation)
                self.assertEqual(response.status, 200)
                self.event(response)
                response.close()
                record = self.wait_disconnected(identifier)
                self.assertFalse(record['completed'])
                self.assertEqual(record['attempts'], 1)

    def test_idle_upstream_timeout_ends_stream_without_final_result(self):
        identifier, _, response = self.start(path='/mcp-timeout')
        try:
            self.assertEqual(response.status, 200)
            self.event(response)
            started = time.monotonic()
            try: tail = response.read()
            except http.client.IncompleteRead as error: tail = error.partial
            self.assertLess(time.monotonic() - started, 3)
            self.assertNotIn(b'"result"', tail)
            self.assertFalse(self.wait_disconnected(identifier)['completed'])
        finally: response.close()

    def test_truncated_sse_is_not_rewritten_or_retried(self):
        identifier, _, response = self.start(mode='truncated')
        with response:
            self.assertEqual(response.status, 200)
            self.event(response)
            self.assertEqual(response.read(), b'data: {"partial":')
        self.assertEqual(self.control(identifier)['attempts'], 1)

    def test_upstream_failure_is_not_retried(self):
        identifier, _, response = self.start(mode='fail-before-headers')
        with response: self.assertEqual(response.status, 502)
        self.assertEqual(self.control(identifier)['attempts'], 1)

    def test_concurrent_streams_do_not_wait_for_other_final_responses(self):
        def stream(index):
            return self.check_gated_stream('mcp' if index % 2 == 0 else 'a2a-rpc')
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(len(list(pool.map(stream, range(8)))), 8)

    def test_slow_reader_does_not_block_unrelated_stream(self):
        identifier, _, response = self.start(mode='bulk')
        try:
            self.assertEqual(response.status, 200)
            self.event(response)
            # Leave 2 MiB unread while a separate stream completes.
            self.check_gated_stream('a2a-rpc')
            self.release(identifier)
            for _ in range(128): self.assertEqual(self.event(response)['method'], 'notifications/message')
            self.assertIn('result', self.event(response))
            self.assertEqual(response.read(), b'')
        finally: response.close()


if __name__ == '__main__': unittest.main()
