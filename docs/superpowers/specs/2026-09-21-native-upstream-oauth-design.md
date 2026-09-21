# Native Upstream OAuth Design

**Date:** 2026-09-21
**Status:** Approved in chat; pending written-spec review

## Goal

Complete MetaMCP's native OAuth client support for upstream MCP servers and release it safely to the personal Mimir deployment. The feature must support OAuth discovery, dynamic client registration, PKCE authorization, token exchange, refresh, loopback redirect overrides, authorization servers hosted separately from the MCP resource server, and RFC 8707 resource indicators.

Although Mimir is currently a single-user deployment, OAuth credentials and in-progress authorization flows will be isolated per application user. This keeps the data model safe if additional users are added later and eliminates the current shared-session behavior for public MCP server definitions.

## Existing Work

The working tree already contains a substantial uncommitted implementation spanning the database schema, backend OAuth procedures, MCP client connection and refresh behavior, frontend authorization flow, validation, documentation, and tests. This work is the implementation baseline and must be preserved unless a test or review demonstrates that a portion needs replacement.

The current implementation already provides:

- server-side discovery, dynamic client registration, PKCE, and authorization URL generation;
- server-side authorization-code exchange and token persistence;
- proactive and reactive token refresh;
- optional loopback redirect URI overrides for constrained providers;
- UI controls for authorizing an MCP server;
- a nullable `mcp_servers.redirect_uri` migration;
- focused backend tests for the added behavior.

## Security and Ownership Model

Every OAuth session belongs to both an MCP server and an application user. The database must enforce uniqueness for `(mcp_server_uuid, user_id)` rather than for the server alone.

All OAuth procedures that read or mutate client registration data, PKCE material, authorization state, discovery data, or tokens must receive the authenticated user ID and verify that the user may access the referenced MCP server. Private servers remain accessible only to their owner. Public server definitions may be used by authenticated users, but each user receives a separate OAuth session and separate credentials.

OAuth responses returned to the frontend must expose only the fields required by the browser flow. Token and client-secret retrieval must not become a general-purpose API when the backend can perform the operation itself.

Authorization attempts must use high-entropy, single-use state generated and persisted by the backend. State is bound to the user, MCP server, redirect URI, and the PKCE verifier. A successful or terminally failed exchange consumes the attempt so it cannot be replayed.

## Persistence Model

The OAuth persistence layer will store, per user and MCP server:

- dynamically registered or pre-registered client information;
- access, refresh, and expiry token data;
- PKCE verifier and expected state for the active authorization attempt;
- the effective redirect URI;
- MCP OAuth discovery state needed to reproduce the authorization decision during token exchange and refresh;
- the validated resource indicator, when supplied by discovery.

The migration will be additive. Existing OAuth rows will be assigned to the owning user of a private MCP server where that relationship is unambiguous. Rows that cannot be assigned safely, including rows for public servers without a user, will not be silently shared; they will be discarded or left unusable so that the user must authorize again. This is acceptable because authorization can be repeated and avoids misattributing credentials.

Repositories and serializers will require the user ID as part of every session lookup and update. Tests will cover isolation between users, public-server sessions, migration behavior where practical, and concurrent or stale authorization state.

## OAuth Protocol Flow

### Authorization start

The frontend calls one backend `startAuthorization` procedure with the MCP server UUID and optional loopback redirect override already stored for that server. The backend:

1. verifies access to the server;
2. performs protected-resource and authorization-server discovery with the MCP SDK;
3. loads a pre-registered client or performs dynamic client registration;
4. validates and persists the SDK discovery state and RFC 8707 resource indicator;
5. creates PKCE and a single-use state value;
6. persists the attempt in the user's OAuth session;
7. returns only the authorization URL and opaque state needed for navigation.

Both the manual Authorize button and automatic recovery from an MCP `401` use this procedure. Browser-side discovery and dynamic registration are removed from the active flow, eliminating provider CORS dependence.

### Callback and token exchange

The callback forwards the authorization response to the backend. The backend resolves the authorization attempt from state and the authenticated user, verifies all bindings, and exchanges the code using the exact authorization-server metadata, redirect URI, PKCE verifier, and resource indicator saved at authorization start.

The callback must not require server identity or trusted protocol state from `sessionStorage`. Browser storage may be retained only for presentation or backward-compatible navigation, never as the authority for the exchange. This permits callbacks in a different tab and the documented loopback-host rewrite flow.

### Token use and refresh

The backend loads tokens by `(user_id, mcp_server_uuid)` when constructing an upstream MCP connection. A token approaching expiry is refreshed before use. A qualifying upstream `401`, or an OAuth-signaling `403`, causes a single synchronized refresh and one retry. Refresh uses the persisted authorization-server metadata and resource indicator rather than rediscovering from an assumed resource origin.

Bare non-OAuth `403` responses remain non-refreshable because they cannot be distinguished safely from authorization-policy failures.

## Endpoint Validation and Network Policy

Authorization, token, registration, discovery, and MCP resource endpoints must use syntactically valid `http` or `https` URLs. Loopback redirect overrides remain restricted to `http` on `127.0.0.1`, `localhost`, or `[::1]`, with no fragment.

MetaMCP is intentionally allowed to connect to user-configured private-network and Tailscale endpoints. Loading an MCP URL from the database prevents request-time URL substitution but does not constitute SSRF prevention. This capability and its trust assumption will be documented explicitly. No private-address denylist will be introduced for this personal deployment because it would block intended use cases.

## Frontend Behavior

The MCP server detail page and Inspector share the same server-side authorization-start helper. On an OAuth challenge they persist only non-sensitive navigation context, redirect the current browser to the returned authorization URL, and show actionable errors when discovery, registration, or authorization cannot begin.

The callback displays progress, success, or a sanitized failure. It never renders client secrets, access tokens, refresh tokens, PKCE verifiers, or raw upstream response bodies. Successful authorization invalidates relevant frontend queries and returns the user to the originating MCP server or Inspector context when available.

New user-facing strings will be added consistently to all locale bundles already shipped by the application.

## Error Handling and Observability

Backend errors will distinguish access denial, invalid or replayed state, provider discovery failure, dynamic registration failure, token exchange failure, and refresh failure without leaking secrets. Logs may include server UUID, provider origin, HTTP status, and protocol stage; they must redact authorization codes, tokens, client secrets, verifiers, and complete callback query strings.

A failed refresh preserves a still-valid access token when safe. Invalid-grant and equivalent terminal errors clear unusable authorization material and require reauthorization. Connection retries remain bounded to prevent loops.

## Testing Strategy

Implementation follows test-driven development. Each behavioral change begins with a failing focused test and proceeds through red, green, and refactor.

Required automated coverage includes:

- repository isolation by user and MCP server;
- ownership enforcement for every OAuth procedure;
- independent OAuth sessions for two users of one public MCP server;
- state binding, single use, mismatch, expiry, and replay rejection;
- discovery with a separate authorization server;
- dynamic and pre-registered clients;
- RFC 8707 resource propagation through authorize, exchange, and refresh;
- loopback redirect validation and callback completion without authoritative `sessionStorage`;
- server-side automatic authorization after an MCP challenge;
- proactive refresh, reactive refresh, refresh synchronization, and bounded retry;
- secret redaction in errors and serialized frontend responses.

Before release, the complete backend test suite, workspace type checks, lint, production build, migration validation, and Docker image build must succeed. A container smoke test must verify `/health`, login, server access, and database migration. The deployed Mimir instance must then pass a real authorize/callback/token-use check against an OAuth-enabled upstream MCP server.

## Release to Mimir

The standard production Compose file points at the mutable upstream image `ghcr.io/metatool-ai/metamcp:latest`, so it cannot release this working tree directly. The release will use an immutable custom image built from the verified commit.

The deployment sequence is:

1. commit and push the verified feature branch;
2. connect to Mimir through `ssh://fabrimat@mimir.larosa.work:2222`;
3. inspect the active Compose project, architecture, environment, current image ID or digest, and available disk space without printing secrets;
4. create and validate a PostgreSQL backup;
5. build or transfer an image tagged with the Git commit SHA;
6. configure a Compose override to select that image and disable forced pulling of upstream `latest`;
7. recreate only the application service and allow the entrypoint to run migrations;
8. verify container health, migration logs, frontend/backend availability, and the real OAuth flow.

The previous image ID receives a local rollback tag before deployment. If application verification fails, the override is returned to that image and only the application service is recreated. Additive database columns and tables may remain in place for rollback; the database backup is restored only if a migration damages existing data.

## Implementation Boundaries

This change does not introduce multi-tenant administration, encrypted-at-rest application-level token storage, a general outbound-network sandbox, or support for non-HTTP OAuth endpoints. It does not redesign MetaMCP's downstream OAuth server or Better Auth login system except where shared types or routing must remain compatible.

The release is complete only after independent review finds no unresolved critical or important issues and the Mimir deployment passes its health and OAuth smoke checks.
