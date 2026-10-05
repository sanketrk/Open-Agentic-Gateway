"""Controlled transport fixture, not a complete MCP/A2A server or production STS."""
import base64
import hmac
import json
import socket
import ssl
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt
from prepare import GATEWAY, ISSUER, POLICIES

GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange'
ACCESS = 'urn:ietf:params:oauth:token-type:access_token'


def handler(directory):
    directory = Path(directory)
    signing = (directory / 'signing.key').read_bytes()
    jwks = json.loads((directory / 'jwks.json').read_text())
    public = jwt.PyJWK.from_dict(jwks['keys'][0]).key
    records, lock = {}, threading.Lock()

    def issue(audience, scope, actor=False, expires=120):
        now = int(time.time())
        claims = dict(iss=ISSUER, sub='stream-agent', aud=audience, scope=scope, iat=now, exp=now + expires)
        if actor: claims['act'] = {'sub': 'stream-gateway'}
        return jwt.encode(claims, signing, algorithm='RS256', headers={'kid': 'stream-test'})

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *args): pass

        def send(self, status, value):
            data = json.dumps(value).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def body(self):
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 65536: raise ValueError('body length')
            return self.rfile.read(length)

        def do_GET(self):
            if self.path == '/healthz': return self.send(200, {'ok': True})
            if self.path == '/jwks': return self.send(200, jwks)
            if self.path == '/.well-known/oauth-authorization-server':
                return self.send(200, {'issuer': ISSUER, 'jwks_uri': ISSUER + '/jwks',
                    'token_endpoint': ISSUER + '/token', 'response_types_supported': [],
                    'token_endpoint_auth_methods_supported': ['client_secret_basic'],
                    'grant_types_supported': ['client_credentials', GRANT]})
            if self.path.startswith('/control/'):
                with lock:
                    record = records.get(self.path.split('/')[-1])
                    data = {k: v for k, v in record.items() if k != 'release'} if record else {'attempts': 0}
                return self.send(200, data)
            return self.send(404, {})

        def authenticated_client(self, client, secret_file):
            header = self.headers.get('Authorization', '')
            if not header.startswith('Basic '): raise PermissionError()
            try:
                user, password = base64.b64decode(header[6:], validate=True).decode().split(':', 1)
            except (ValueError, UnicodeError): raise PermissionError() from None
            if user != client or not hmac.compare_digest(password, (directory / secret_file).read_text()):
                raise PermissionError()

        def token(self, raw):
            form = urllib.parse.parse_qs(raw.decode(), strict_parsing=True)
            if any(len(v) != 1 for v in form.values()): raise ValueError('repeated form field')
            form = {k: v[0] for k, v in form.items()}
            if form.get('grant_type') == 'client_credentials':
                self.authenticated_client('stream-agent', 'agent-secret')
                audience = form.get('resource', '')
                if audience not in [GATEWAY + path for path in POLICIES]: raise ValueError('audience')
                # Explicit negative-test grants issued only by this disposable fixture.
                scope = form.get('scope', 'stream:call')
                if scope not in ('stream:call', 'unrelated'): raise ValueError('scope')
                token = issue(audience, scope)
            elif form.get('grant_type') == GRANT:
                self.authenticated_client('stream-gateway', 'exchange-secret')
                if (form.get('subject_token_type') != ACCESS or form.get('requested_token_type') != ACCESS
                        or form.get('scope') != 'stream:execute'): raise ValueError('exchange policy')
                resource = form.get('resource')
                audiences = [GATEWAY + p for p, policy in POLICIES.items() if policy[0] == resource]
                if not audiences: raise ValueError('resource')
                claims = jwt.decode(form['subject_token'], public, algorithms=['RS256'], issuer=ISSUER,
                                    audience=audiences, options={'require': ['exp', 'sub', 'iat']})
                if claims.get('scope') != 'stream:call' or claims['sub'] != 'stream-agent': raise ValueError('subject')
                token = issue(resource, 'stream:execute', actor=True)
            else: raise ValueError('grant')
            return self.send(200, {'access_token': token, 'token_type': 'Bearer',
                'issued_token_type': ACCESS, 'expires_in': 120})

        def do_POST(self):
            try:
                raw = self.body()
                if self.path == '/token': return self.token(raw)
                if self.path.startswith('/release/'):
                    with lock: record = records.get(self.path.split('/')[-1])
                    if not record: return self.send(404, {})
                    record['release'].set()
                    return self.send(200, {'released': True})
                if self.path not in ('/mcp', '/rpc', '/message:stream', '/tasks/task-1:subscribe'):
                    return self.send(404, {})
                protocol = 'mcp' if self.path == '/mcp' else 'a2a'
                token = self.headers.get('Authorization', '').removeprefix('Bearer ')
                claims = jwt.decode(token, public, algorithms=['RS256'], issuer=ISSUER,
                    audience='urn:stream:' + protocol, options={'require': ['exp', 'sub', 'iat']})
                if claims.get('act') != {'sub': 'stream-gateway'} or claims.get('scope') != 'stream:execute':
                    raise PermissionError()
                message = json.loads(raw)
                params = message.get('params', {}) if self.path in ('/mcp', '/rpc') else message
                options = params.get('arguments', {}) if protocol == 'mcp' else params.get('metadata', {})
                fixture_id, mode = options['fixture_id'], options.get('mode', 'gated')
                with lock:
                    old = records.get(fixture_id)
                    record = dict(attempts=(old['attempts'] if old else 0) + 1, release=threading.Event(),
                        completed=False, disconnected=False, path=self.path, message=message,
                        headers={name: self.headers.get(name) for name in
                            ('MCP-Protocol-Version', 'Mcp-Method', 'Mcp-Name', 'Mcp-Session-Id', 'Last-Event-ID', 'A2A-Version')},
                        identity={k: claims[k] for k in ('sub', 'aud', 'scope', 'act')})
                    records[fixture_id] = record
                if mode == 'fail-before-headers':
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                return self.stream(record, protocol, message, params, mode)
            except PermissionError: return self.send(401, {'error': 'unauthorized'})
            except jwt.PyJWTError: return self.send(401, {'error': 'invalid token'})
            except (ValueError, KeyError, TypeError): return self.send(400, {'error': 'invalid fixture request'})

        def stream(self, record, protocol, message, params, mode):
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-store')
            # Intentionally omit X-Accel-Buffering: this suite must verify Kong's
            # route configuration, rather than relying on an upstream override.
            self.send_header('Connection', 'close')
            if protocol == 'mcp': self.send_header('Mcp-Session-Id', 'must-be-stripped')
            self.end_headers()
            self.close_connection = True
            rpc = self.path in ('/mcp', '/rpc')
            def event(value):
                self.wfile.write(('data: ' + json.dumps(value, separators=(',', ':')) + '\n\n').encode())
                self.wfile.flush()
            def wrap(value):
                return {'jsonrpc': '2.0', 'id': message.get('id'), 'result': value} if rpc else value
            if protocol == 'mcp':
                subscription = message['method'] == 'subscriptions/listen'
                first = {'jsonrpc': '2.0', 'method': 'notifications/tools/list_changed', 'params': {}} if subscription else {
                    'jsonrpc': '2.0', 'method': 'notifications/progress',
                    'params': {'progressToken': params.get('_meta', {}).get('progressToken', 'probe'), 'progress': 1}}
                final = {'jsonrpc': '2.0', 'method': 'notifications/resources/updated',
                         'params': {'uri': 'test://resource'}} if subscription else wrap({'content': [{'type': 'text', 'text': 'done'}]})
                values = [first, final]
            else:
                task = {'id': 'task-1', 'contextId': 'context-1', 'status': {'state': 'TASK_STATE_WORKING'}}
                values = [wrap({'task': task}), wrap({'artifactUpdate': {'taskId': 'task-1', 'contextId': 'context-1',
                    'artifact': {'artifactId': 'artifact-1', 'parts': [{'text': 'chunk'}]}, 'lastChunk': True}}),
                    wrap({'statusUpdate': {'taskId': 'task-1', 'contextId': 'context-1', 'status': {'state': 'TASK_STATE_COMPLETED'}}})]
            with lock: record['events'] = values
            try:
                event(values[0])
                if mode == 'truncated':
                    self.wfile.write(b'data: {"partial":'); self.wfile.flush()
                    return
                if mode == 'bulk':
                    payload = {'jsonrpc': '2.0', 'method': 'notifications/message', 'params': {'data': 'x' * 16384}}
                    for _ in range(128): event(payload)
                # The test releases this gate only after reading the first event.
                # Polling the socket detects cancellation without depending on a
                # later business event or a broken-pipe write.
                deadline = time.monotonic() + 10
                self.connection.settimeout(0.1)
                while not record['release'].is_set():
                    if time.monotonic() >= deadline: return
                    try:
                        if self.connection.recv(1) == b'':
                            with lock: record['disconnected'] = True
                            return
                    except (socket.timeout, TimeoutError): pass
                self.connection.settimeout(5)
                for value in values[1:]: event(value)
                with lock: record['completed'] = True
            except (OSError, ssl.SSLError):
                with lock: record['disconnected'] = True
            finally:
                with lock: record['closed'] = True
    return Handler


def main():
    directory = Path('/credentials')
    server = ThreadingHTTPServer(('0.0.0.0', 8443), handler(directory))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(directory / 'tls.pem', directory / 'tls.key')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == '__main__': main()
