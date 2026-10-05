"""TLS-verified gateway-only calls; backend tokens remain inside the gateway."""
import base64
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Protocol


class GatewayError(Exception): pass


def https_url(value, origin=False):
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or any(c.isspace() for c in value)
            or origin and parsed.path not in ("", "/")):
        raise ValueError("A verified HTTPS URL without credentials, query or fragment is required")
    parsed.port
    return value.rstrip("/") if origin else value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None


class _Transport:
    def __init__(self, ca_file=None, timeout=15):
        self.http = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(
            context=ssl.create_default_context(cafile=ca_file)))
        self.timeout = timeout

    def request(self, url, data=None, headers=None, on_notification=None):
        req = urllib.request.Request(url, data=data, headers=headers or {})
        try: response = self.http.open(req, timeout=self.timeout)
        except urllib.error.HTTPError as error: response = error
        with response:
            if response.status >= 300: raise GatewayError(f"HTTP {response.status}")
            if response.headers.get_content_type() == "text/event-stream":
                request = json.loads(data) if data else {}
                if "id" not in request: raise GatewayError("Unexpected SSE response")
                return response.status, _read_sse(response, request["id"], on_notification)
            body = response.read(1048577)
            if len(body) > 1048576: raise GatewayError("Response exceeds SDK size limit")
            if response.status >= 300: raise GatewayError(f"HTTP {response.status}")
            try: return response.status, json.loads(body) if body else None
            except (ValueError, UnicodeError): raise GatewayError("Invalid JSON response") from None


def _read_sse(response, request_id, on_notification=None):
    """Consume bounded UTF-8 SSE frames until the correlated RPC response arrives."""
    total, fields, event = 0, [], ""
    while True:
        line = response.readline(1048577)
        total += len(line)
        if total > 1048576: raise GatewayError("Response exceeds SDK size limit")
        if not line: raise GatewayError("SSE stream ended before RPC response")
        try: line = line.decode("utf-8").rstrip("\r\n")
        except UnicodeError: raise GatewayError("Invalid UTF-8 SSE response") from None
        if not line:
            if fields and event in ("", "message"):
                try: message = json.loads("\n".join(fields))
                except ValueError: raise GatewayError("Invalid JSON SSE event") from None
                if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                    raise GatewayError("Invalid RPC SSE event")
                if "id" in message:
                    if message["id"] != request_id or "method" in message:
                        raise GatewayError("Unexpected RPC SSE response")
                    return message
                if not isinstance(message.get("method"), str):
                    raise GatewayError("Invalid RPC SSE notification")
                if on_notification: on_notification(message)
            fields, event = [], ""
        elif not line.startswith(":"):
            field, _, value = line.partition(":")
            if value.startswith(" "): value = value[1:]
            if field == "data": fields.append(value)
            elif field == "event": event = value


class TokenProvider(Protocol):
    def get_token(self, audience: str, scopes: tuple[str, ...]) -> str: ...


class OAuthClientCredentials:
    """Standard client credentials with the RFC 8707 gateway resource parameter."""
    def __init__(self, *, token_endpoint, client_id, client_secret, ca_file=None):
        self.token_endpoint = https_url(token_endpoint)
        if not client_id or not client_secret: raise ValueError("Agent client credentials are required")
        self.client_id, self.client_secret = client_id, client_secret
        self.transport = _Transport(ca_file)

    def get_token(self, audience, scopes):
        form = urllib.parse.urlencode({"grant_type": "client_credentials", "resource": audience, "scope": " ".join(scopes)})
        credentials = urllib.parse.quote_plus(self.client_id) + ":" + urllib.parse.quote_plus(self.client_secret)
        status, data = self.transport.request(self.token_endpoint, form.encode(), {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Basic " + base64.b64encode(credentials.encode()).decode()})
        if (status != 200 or not isinstance(data, dict) or str(data.get("token_type", "")).lower() != "bearer"
                or not isinstance(data.get("access_token"), str) or not data["access_token"]):
            raise GatewayError("Invalid agent token response")
        return data["access_token"]


def relative_path(value):
    parsed = urllib.parse.urlsplit(value)
    if (not value.startswith("/") or parsed.scheme or parsed.netloc or parsed.query or parsed.fragment
            or "%" in value or "\\" in value or any(c.isspace() for c in value)
            or any(segment in (".", "..") for segment in value.split("/"))):
        raise ValueError("Endpoint must be a gateway-relative path")


@dataclass(frozen=True)
class Endpoint:
    path: str
    audience: str
    scopes: tuple[str, ...]
    protocol: str
    binding: str = "JSONRPC"

    def __post_init__(self):
        relative_path(self.path)
        if not self.audience or not self.scopes or self.protocol not in ("mcp", "a2a"):
            raise ValueError("Audience, scopes and MCP/A2A protocol are required")
        if self.binding not in ("JSONRPC", "HTTP+JSON") or self.protocol == "mcp" and self.binding != "JSONRPC":
            raise ValueError("REST binding is available only for A2A")


class GatewayClient:
    def __init__(self, *, gateway_url, token_provider, ca_file=None):
        self.gateway_url = https_url(gateway_url, origin=True)
        self.token_provider = token_provider
        self.transport = _Transport(ca_file)

    def _rpc(self, endpoint, token, method, params, notification=False, on_notification=None):
        if endpoint.protocol == "mcp" and endpoint.audience != self.gateway_url + endpoint.path:
            raise ValueError("MCP audience must equal its public gateway resource URI")
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token):
            raise GatewayError("Invalid agent access token")
        body = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notification: body["id"] = str(uuid.uuid4())
        headers = {"Content-Type": "application/json", "Authorization": "Bearer " + token}
        if endpoint.protocol == "a2a": headers["A2A-Version"] = "1.0"
        else: headers.update({"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25"})
        options = {"on_notification": on_notification} if on_notification else {}
        status, data = self.transport.request(self.gateway_url + endpoint.path, json.dumps(body).encode(), headers, **options)
        if notification:
            if status != 202: raise GatewayError("Expected accepted notification")
            return None
        if (status != 200 or not isinstance(data, dict) or data.get("jsonrpc") != "2.0"
                or data.get("id") != body["id"] or "error" in data or "result" not in data):
            raise GatewayError("RPC request failed")
        return data["result"]

    def agent_card(self, path):
        relative_path(path)
        status, card = self.transport.request(self.gateway_url + path, headers={"A2A-Version": "1.0"})
        if status != 200 or not isinstance(card, dict): raise GatewayError("Invalid Agent Card")
        return card

    def send_message(self, endpoint, text):
        if endpoint.protocol != "a2a": raise ValueError("An A2A endpoint is required")
        token = self.token_provider.get_token(endpoint.audience, endpoint.scopes)
        params = {"message": {"messageId": str(uuid.uuid4()), "role": "ROLE_USER", "parts": [{"text": text}]}}
        if endpoint.binding == "HTTP+JSON":
            if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", token):
                raise GatewayError("Invalid agent access token")
            status, data = self.transport.request(self.gateway_url + endpoint.path.rstrip("/") + "/message:send",
                json.dumps(params).encode(), {"Content-Type": "application/json", "A2A-Version": "1.0",
                                             "Authorization": "Bearer " + token})
            if (status != 200 or not isinstance(data, dict) or "error" in data
                    or sum(key in data for key in ("message", "task")) != 1
                    or not isinstance(data.get("message", data.get("task")), dict)):
                raise GatewayError("Invalid A2A REST response")
            return data
        return self._rpc(endpoint, token, "SendMessage", {"message": {
            "messageId": str(uuid.uuid4()), "role": "ROLE_USER", "parts": [{"text": text}]}})

    def call_tool(self, endpoint, name, arguments, *, on_progress=None):
        if endpoint.protocol != "mcp": raise ValueError("An MCP endpoint is required")
        if endpoint.audience != self.gateway_url + endpoint.path:
            raise ValueError("MCP audience must equal its public gateway resource URI")
        status, metadata = self.transport.request(self.gateway_url + "/.well-known/oauth-protected-resource" + endpoint.path)
        if status != 200 or not isinstance(metadata, dict) or metadata.get("resource") != endpoint.audience:
            raise GatewayError("Invalid MCP protected-resource metadata")
        token = self.token_provider.get_token(endpoint.audience, endpoint.scopes)
        initialized = self._rpc(endpoint, token, "initialize", {"protocolVersion": "2025-11-25",
            "capabilities": {}, "clientInfo": {"name": "open-agentic-gateway-sdk", "version": "0.1.0"}})
        if initialized.get("protocolVersion") != "2025-11-25": raise GatewayError("Unsupported MCP version")
        self._rpc(endpoint, token, "notifications/initialized", {}, notification=True)
        tools = self._rpc(endpoint, token, "tools/list", {})["tools"]
        if not any(tool.get("name") == name for tool in tools): raise GatewayError("Tool is not advertised")
        params = {"name": name, "arguments": arguments}
        progress_token = str(uuid.uuid4())
        def notification(message):
            progress = message.get("params", {})
            if (message.get("method") == "notifications/progress" and isinstance(progress, dict)
                    and progress.get("progressToken") == progress_token):
                on_progress(progress)
        if on_progress: params["_meta"] = {"progressToken": progress_token}
        result = self._rpc(endpoint, token, "tools/call", params,
                           on_notification=notification if on_progress else None)
        if result.get("isError"): raise GatewayError("MCP tool reported an error")
        return result
