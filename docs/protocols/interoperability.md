# Open Agentic Gateway interoperability profile

This project is a transport-aware MCP gateway and a separate administrator control plane. Protocols are provider-neutral; Kong is the chosen proxy implementation, and OpenShift is an optional deployment target. Identity-provider selection does not require changing code. The two authentication roles are distinct:

- **Control plane:** an OIDC relying party authenticating administrators through authorization code flow.
- **MCP gateway:** an OAuth protected resource verifying agents' access tokens. OIDC ID tokens are not MCP access tokens.

## OIDC profile

Implemented: issuer-bound OIDC discovery, code flow with PKCE S256, state and nonce, asymmetric JWT verification, client audience/authorized-party validation, OAuth response issuer validation, standard client-secret authentication or public-client PKCE, opaque browser access tokens when authorizing from ID-token claims, and discovered RP-Initiated Logout with local fallback.

Administrator roles/permissions are **not standardized by OIDC**. The trusted claim source, RFC 6901 pointer, and required value are configurable. Provider-specific authorization parameters are opt-in extensions. Default login requires only `openid profile email` scopes and contains no vendor `audience` parameter. If an API resource is requested, `OIDC_RESOURCE` uses RFC 8707 and is included in both authorization and token requests.

Supported signature algorithms are RS256/384/512, ES256/384, and EdDSA when explicitly configured. HS algorithms, encrypted ID tokens, dynamic OIDC client registration, refresh-token storage, token introspection, client assertions, and back-channel logout are not implemented. API bearer authentication and access-token administrator claim policies require signed JWTs. The implementation is tested against protocol fixtures, not OpenID-certified or verified against every issuer.

References: [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html), [Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html), [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html), [PKCE](https://www.rfc-editor.org/rfc/rfc7636), [OAuth response issuer](https://www.rfc-editor.org/rfc/rfc9207).

## MCP transport and authorization profile

The gateway supports Streamable HTTP revision `2026-07-28`, with configurable compatibility for `2025-11-25` and `2025-03-26`. It is not an MCP server or client implementation. The upstream handles tool schemas, method existence, response semantics, MRTR, subscriptions, cancellation, and session lifecycle for legacy revisions.

The gateway enforces JSON POST envelopes, JSON/SSE Accept negotiation, current request metadata/header agreement, required method/name headers, Origin policy, and OAuth authentication. Current extension notifications are not required to carry request-only method headers. Current requests are stateless; legacy session/resume headers are stripped for them. Legacy GET/DELETE/session routing remains available when configured. Unknown extension methods and unrecognized `Mcp-Param-*` headers pass through; upstream servers validate recognized custom parameter headers against their schemas. Unsupported transport requests get HTTP errors; full MCP error semantics remain the server's responsibility.

Each MCP server is a separate protected resource with its own canonical public HTTPS resource URI, metadata endpoint, expected token audience, and scopes. Default/sample and generated audiences use that resource URI. Clients use protected-resource metadata to select an authorization server and must send the RFC 8707 `resource` parameter in both authorization and token requests. The gateway does not initiate agent authorization, register OAuth clients, or issue tokens. The selected authorization server and agent must implement their portions of the MCP OAuth flow, including supported client registration and mix-up protection. A vendor-specific `audience` parameter alone does not replace MCP's `resource` requirement.

JWT access tokens are verified against explicitly configured issuer/discovery pairs, allowed algorithms, expiry, audience, and required scopes. Opaque MCP access tokens are not supported by this profile. Resource metadata, 401 challenges, and insufficient-scope responses support OAuth discovery and step-up flows. Token forwarding is disabled by default; any opt-in forwarding must remain within the same protected-resource trust boundary and must not forward a token to an unrelated API. Enforce backend network isolation separately.

An optional [RFC 8693 exchange plugin](../plugins/token-exchange.md) obtains separate backend tokens after incoming-token validation. It requires an explicitly trusted STS; issued tokens are validated by the backend.

No universal MCP conformance or provider certification is claimed. Live tests still need a conforming agent, authorization server, and upstream MCP server. Unit/runtime tests validate this gateway's implemented boundaries. The independent [gateway streaming suite](../gateway/setup.md#gateway-streaming-integration-tests) exercises real Kong with controlled MCP/A2A upstreams, including current-revision MCP POST streams and subscriptions.

References: [MCP Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http), [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), [resource indicators](https://www.rfc-editor.org/rfc/rfc8707), [protected-resource metadata](https://www.rfc-editor.org/rfc/rfc9728), [bearer tokens](https://www.rfc-editor.org/rfc/rfc6750).

## A2A transport profile

The optional [A2A plugin](a2a.md) validates JSON-RPC HTTP requests, version selection, and JWT authorization while proxying Agent Cards and unbuffered responses. It supports 1.0/0.3 transport profiles, with task semantics and card accuracy enforced by upstream agents. It also supports the A2A 1.0 HTTP+JSON/REST operation paths, including message and task-subscription streams. REST POST requests accept `application/a2a+json` and compatible `application/json`. It does not implement gRPC, protocol translation, or complete A2A conformance.

## Gateway comparison with Apigee

Last source review: **2026-10-05**. This compares proxying external MCP servers and A2A agents. It does not compare protocol-server implementations or claim universal conformance. Vendor features change; re-check the linked primary documentation before selecting a product or publishing an updated comparison.

A gateway routes requests, authenticates callers, applies access policy, preserves protocol data and streaming responses, handles disconnects/timeouts, and optionally exchanges credentials. MCP sampling/elicitation, resource contents, subscription management, and A2A task storage/execution belong to clients and upstream servers. Their absence from a gateway is not itself a proxy support gap.

| Gateway responsibility | Open Agentic Gateway | Apigee / Apigee X | Apigee hybrid |
| --- | --- | --- | --- |
| MCP HTTP routing | Dedicated MCP plugin and per-server protected resources | Configured API proxies to external MCP backends | Same proxy approach |
| A2A JSON-RPC / REST routing | Dedicated A2A plugin; explicit 1.0 REST operation paths | Configured API proxies to agent endpoints | Same proxy approach |
| SSE response forwarding | Unbuffered; tested through real Kong | Native SSE support | Native SSE support in 1.15.0+ |
| MCP protocol validation | Explicit version, envelope, metadata/header, Origin, and Accept checks | Equivalent checks require configured policies; a complete built-in profile was not established by the documentation reviewed | Same qualification |
| A2A protocol validation | Explicit version/envelope checks and REST path/method validation | Equivalent checks require configured policies | Same qualification |
| Caller identity and permissions | Configured JWT issuer, audience, algorithm, and scope checks | Configured JWT/OAuth policies | Same policy approach |
| Target-specific token exchange | Packaged RFC 8693 plugin and route resource/scope mapping | Implement using policies and an external STS callout | Same approach |
| Disconnects, timeouts, event order | Selected configurations verified by integration tests | Validate the selected proxy/policy/deployment configuration | Same qualification |
| A2A gRPC binding | Not implemented | Unary gRPC passthrough documented; does not establish streaming-binding support | gRPC API proxies documented as unsupported |

Apigee's documented foundations are [SSE streaming](https://docs.cloud.google.com/apigee/docs/api-platform/develop/server-sent-events), [VerifyJWT](https://docs.cloud.google.com/apigee/docs/api-platform/reference/policies/verify-jwt-policy), and [ServiceCallout](https://docs.cloud.google.com/apigee/docs/api-platform/reference/policies/service-callout-policy). Mapping these building blocks to our exact protocol and STS policies is an architectural assessment, not evidence of a tested equivalent deployment. Its [gRPC proxy documentation](https://docs.cloud.google.com/apigee/docs/api-platform/fundamentals/build-simple-api-proxy#creating-grpc-api-proxies) limits support to unary passthrough and excludes hybrid.

Apigee Edge separately documents [HTTP request/response streaming](https://docs.apigee.com/api-platform/develop/enabling-streaming). Policies that inspect payloads may cause buffering or errors. Do not assume Edge has the same SSE/EventFlow capabilities as modern Apigee, or claim complete MCP/A2A coverage without testing its actual deployment.

Apigee's built-in MCP server is a separate feature: [hybrid 1.17.0+](https://docs.cloud.google.com/apigee/docs/api-platform/apigee-mcp/enable-mcp) can expose existing APIs as tools. The [MCP overview](https://docs.cloud.google.com/apigee/docs/api-platform/apigee-mcp/apigee-mcp-overview) documents its methods and limitations, including the currently stated SSE limitation. Those server limitations do not establish limitations of an API proxy in front of an external MCP server.

Open Agentic Gateway packages a focused, inspectable protocol/identity profile and reproducible tests. Apigee supplies a broader API-management platform from which an equivalent HTTP gateway profile can be assembled. Our CI evidence verifies our selected configuration; it does not prove Apigee cannot match it or establish production capacity for this project. See the [streaming suite](../gateway/setup.md#gateway-streaming-integration-tests) for the exact boundary and deployment checks.

## Tracking MCP and A2A revisions

Tracking is currently **manual and review-driven**. CI verifies the committed protocol profiles; it does not fetch specifications, detect new upstream versions, or automatically upgrade protocol support. A protocol named `latest` in an external URL does not change the gateway's accepted versions.

### Reviewed support inventory

Inventory reviewed: **2026-10-05**. These are implemented project profiles, not a promise to accept every future upstream release.

| Component | Implemented profile | Evidence and limits |
| --- | --- | --- |
| MCP gateway | `2026-07-28`; configurable legacy `2025-11-25` and `2025-03-26` | [Handler](../../gateway/plugins/mcp/handler.lua), [schema](../../gateway/plugins/mcp/schema.lua), [unit checks](../../tests/handler_spec.lua); current POST/SSE and subscription transport tested through Kong |
| A2A gateway | `1.0` JSON-RPC and HTTP+JSON/REST; legacy `0.3` JSON-RPC | [Handler](../../gateway/plugins/a2a/handler.lua), [schema](../../gateway/plugins/a2a/schema.lua), [unit checks](../../tests/a2a_spec.lua); 1.0 streaming paths tested through Kong; no gRPC or tenant-prefixed REST routing |
| Python SDK and banking MCP servers | `2025-11-25` stateless initialization/tool profile with JSON or POST SSE | [SDK profile](../../sdk/python/README.md#current-profile); no current-revision MCP lifecycle, MRTR, persistent sessions, or resumption |
| Python SDK and banking A2A agent | `1.0` synchronous SendMessage, JSON-RPC and REST | [SDK profile](../../sdk/python/README.md#current-profile); A2A streaming/task lifecycle is outside this SDK profile |

Gateway support and SDK/demo support are tracked separately. Forwarding an extension payload is not the same as testing its full client/server interaction. The [independent streaming fixtures](../../tests/streaming/test_gateway.py) validate transport, policy, and forwarding boundaries; they are not complete conforming protocol servers.

### Upstream sources to review

Use the official [MCP specification](https://modelcontextprotocol.io/specification/) and [MCP project](https://github.com/modelcontextprotocol/modelcontextprotocol), plus the official [A2A specification](https://a2a-protocol.org/latest/specification/) and [A2A releases](https://github.com/a2aproject/A2A/releases), to identify published revisions and changes. Review stable releases separately from proposals, draft SEPs, and development-branch changes.

For the committed profiles, use versioned references: [MCP 2026-07-28 Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http), [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), and [A2A 1.0 specification](https://a2a-protocol.org/v1.0.0/specification/). Record a versioned URL and upstream tag/commit when available in the compatibility review so future changes to a `latest` page do not silently redefine the acceptance criteria.

### Maintainer revision workflow

Before a project release and whenever adopting a newly published protocol revision:

1. Open a compatibility issue or PR recording the upstream revision, source URLs/tag/commit, review date, and affected bindings. Classify each change as gateway-required, upstream/client-owned, or outside our supported profile.
2. Review method/path mapping, media types, version negotiation, metadata headers, discovery, authorization, errors, streams, disconnect/cancellation, and backward compatibility. Do not add a version to an allowlist before checking its wire behavior.
3. Update affected handlers/schemas, the control-plane validator/configuration generator/UI, sample configurations and embedded OpenShift configuration. Update the SDK and examples only when their profiles are being expanded; otherwise explicitly retain their narrower inventory entries.
4. Add positive and negative unit/runtime checks for changed boundaries. Extend the real-Kong streaming suite when stream delivery, subscriptions, cancellation, bindings, or exchange behavior changes. Keep legacy-profile regression tests when retaining compatibility.
5. Run the relevant checks and [CI workflow](../../.github/workflows/ci.yml), including real gateway integration tests. Record which behaviors were tested, merely passed through, or not supported. External SDK/server interoperability needs its own evidence; fixture success alone is not conformance certification.
6. Update this inventory and its review date, the protocol guides, migration guidance, and comparison review date if vendor claims changed. Link the compatibility PR to the supporting CI run. Advertise only profiles actually implemented and tested; deployment ingress and load limits remain separately verified.

This workflow maintains explicit support claims while allowing contributors to report new revisions. Automatic monitoring or scheduled upstream checks can be added later; none are configured by this documentation change.

## Migration from provider-specific configuration

Replace `AUTH0_*` variables with generic `OIDC_*` settings as shown in the optional provider example. Replace the old Secret with `open-agentic-control-plane-oidc`, containing `issuer`, `client-id`, and `client-secret`. Configure a trusted administrator claim explicitly; OIDC login alone never authorizes registry administration. Replace opaque sample audience aliases with each server's public resource URI in the IdP/API configuration and issue fresh tokens before publishing the revised gateway configuration. Review the generated snapshot and verify rollout and authenticated requests.
