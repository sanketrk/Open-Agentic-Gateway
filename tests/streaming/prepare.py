"""Generate disposable, separated test credentials and real Kong configuration."""
import datetime
import json
import secrets
from pathlib import Path

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

ISSUER = 'https://fixture:8443'
GATEWAY = 'https://gateway:8443'
POLICIES = {
    '/mcp': ('urn:stream:mcp', 'mcp'),
    '/mcp-timeout': ('urn:stream:mcp', 'mcp'),
    '/a2a': ('urn:stream:a2a', 'a2a'),
}


def prepare(root):
    root = Path(root)
    for name in ('fixture', 'gateway', 'client'): (root / name).mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Disposable streaming test CA')])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
          .not_valid_after(now + datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
          .sign(ca_key, hashes.SHA256()))
    for target in ('fixture', 'gateway', 'client'):
        (root / target / 'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for target in ('fixture', 'gateway'):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, target)])
        certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(target), x509.DNSName('localhost')]), False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(ca_key, hashes.SHA256()))
        (root / target / 'tls.pem').write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        (root / target / 'tls.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    signing = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (root / 'fixture' / 'signing.key').write_bytes(signing.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(signing.public_key()))
    jwk.update(kid='stream-test', alg='RS256', use='sig')
    (root / 'fixture' / 'jwks.json').write_text(json.dumps({'keys': [jwk]}))
    for filename, target in (('agent-secret', 'client'), ('exchange-secret', 'gateway')):
        secret = secrets.token_urlsafe(32)
        (root / 'fixture' / filename).write_text(secret)
        (root / target / filename).write_text(secret)
    services = []
    ca_id = 'd72b6acd-c9c8-4a31-a168-449611c7490c'
    for path, (resource, protocol) in POLICIES.items():
        audience = GATEWAY + path
        if protocol == 'mcp':
            metadata = '/.well-known/oauth-protected-resource' + path
            plugin = {'name': 'mcp', 'config': {'resource_url': audience,
                'resource_metadata_url': GATEWAY + metadata, 'metadata_paths': [metadata],
                'legacy_protocol_versions': [], 'audience': audience, 'scopes_supported': ['stream:call']}}
            paths = ['~' + path + '$', '~' + metadata + '$']
            upstream = '/mcp'
        else:
            plugin = {'name': 'a2a', 'config': {'rpc_path': path, 'rest_path': path + '/rest',
                'card_path': '/card', 'public_card': False, 'protocol_versions': ['1.0'], 'audience': audience}}
            paths = ['~' + path + '$', '~' + path + '/rest/']
            upstream = '/rpc'
        plugin['config'].update(authorization_servers=[{'issuer': ISSUER,
            'discovery_url': ISSUER + '/.well-known/oauth-authorization-server'}],
            required_scopes=['stream:call'], signing_algorithms=['RS256'], forward_bearer_token=False)
        exchange = {'name': 'token-exchange', 'config': {'token_endpoint': ISSUER + '/token',
            'gateway_audience': audience, 'resource': resource, 'client_id': 'stream-gateway',
            'client_secret_file': '/credentials/exchange-secret', 'scopes': ['stream:execute']}}
        services.append({'name': path[1:], 'url': ISSUER + upstream, 'tls_verify': True, 'ca_certificates': [ca_id],
            'retries': 0, 'connect_timeout': 3000, 'read_timeout': 700 if path.endswith('timeout') else 15000,
            'write_timeout': 15000, 'routes': [{'name': path[1:], 'paths': paths, 'strip_path': True,
                'path_handling': 'v0', 'request_buffering': False, 'response_buffering': False,
                'plugins': [plugin, exchange]}]})
    (root / 'gateway' / 'kong.json').write_text(json.dumps({'_format_version': '3.0', 'services': services,
        'ca_certificates': [{'id': ca_id, 'cert': ca.public_bytes(serialization.Encoding.PEM).decode()}]}))
    # Disposable test volumes are readable by arbitrary container UIDs; each service
    # mounts only its own directory. No secrets are printed or checked in.
    for path in root.rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o644)


if __name__ == '__main__': prepare('/runtime')
