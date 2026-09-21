## OAuth

sequenceDiagram
participant Client as MCP Client
participant Auth as MetaMCP OAuth Server
participant User as User/Browser
participant API as MetaMCP API

    Note over Client,API: OAuth 2.1 Dynamic Registration & Authorization Flow

    Client->>Auth: POST /oauth/register<br/>{redirect_uris, client_name, ...}
    Auth-->>Client: {client_id, endpoints, security_note}

    Note over Client,Auth: PKCE Authorization Code Flow

    Client->>Client: Generate code_verifier & code_challenge
    Client->>User: Redirect to /oauth/authorize<br/>?client_id=...&code_challenge=...
    User->>Auth: GET /oauth/authorize (with PKCE)

    alt User Not Authenticated
        Auth-->>User: Redirect to /login
        User->>Auth: Login credentials
        Auth-->>User: Redirect back to authorize
    end

    Auth-->>User: Redirect to client<br/>?code=...&state=...
    User->>Client: Authorization code received

    Client->>Auth: POST /oauth/token<br/>{code, code_verifier, client_id}
    Auth->>Auth: Verify PKCE (S256)
    Auth-->>Client: {access_token, token_type, expires_in}

    Client->>API: API Request<br/>Authorization: Bearer {access_token}
    API-->>Client: Protected resource response

### Upstream OAuth

MetaMCP can act as an OAuth client to a remote MCP server, enabling authorized access to those upstream servers. This section describes the opposite direction from the diagram above: MetaMCP obtaining credentials from an upstream authorization server on behalf of the user.

#### Session ownership

Upstream OAuth sessions are scoped to both the signed-in MetaMCP user and the MCP server. Client registration, PKCE material, discovery state, access tokens, and refresh tokens are never shared between users. A public MCP server can be configured and viewed by multiple users, but every user authorizes it separately and receives a separate OAuth session. An unauthenticated public request does not borrow another user's credentials.

The browser starts authorization with only the MCP server UUID. The backend checks that the caller owns the private server or that the server is public, then loads the server configuration and the caller's session. The callback sends only `code` and the self-identifying `upstream.*` state. The backend derives the candidate server UUID from that state, checks access again, verifies the complete one-time state against the caller's session, and returns the verified UUID after exchange. The callback therefore does not depend on `sessionStorage`, a stored server URL, client data, tokens, or a browser-held PKCE verifier.

#### Discovery, registration, and resource indicators

Discovery, dynamic client registration, PKCE setup, authorization URL construction, token exchange, and refresh run on the backend. This avoids browser CORS restrictions and keeps client secrets and token material out of frontend storage. Complete pre-registered authorization and token endpoints take precedence when configured.

The MCP protected resource may publish an authorization server on a different origin. MetaMCP persists the authorization server and protected-resource metadata selected during authorization and reuses that same context for code exchange and refresh; it does not assume that the MCP server itself is the authorization server. When genuine protected-resource metadata provides a compatible OAuth resource indicator, MetaMCP sends that value consistently. It does not invent a resource indicator when none was discovered.

#### Network trust and private addresses

Resolving the upstream URL from an authorized database row prevents a browser caller from substituting an arbitrary URL in the authorization or exchange request, but this alone is not a complete SSRF defense. A stored URL can still point to loopback, link-local, private, or otherwise sensitive network services. Only trusted users should be allowed to configure MCP servers, and deployments should enforce appropriate outbound-network policy, DNS controls, and egress filtering for their environment. Public server configuration is shared; OAuth credentials are not.

#### The loopback-redirect problem

Some upstream MCP servers only accept **loopback** redirect URIs at dynamic client registration (RFC 7591). Reclaim.ai is a verified example. MetaMCP normally sends `${APP_URL}/fe-oauth/callback`. For any self-hosted deployment that is not on localhost (for example, a Tailscale hostname), such an upstream rejects registration with HTTP 400 `invalid_redirect_uri`.

Putting a TLS certificate on the hostname does **not** help — these upstreams reject non-loopback hosts over `https` too. The discriminator is the host, not the scheme.

#### The per-server redirect URI override

Each MCP server has an optional **Redirect URI override** field under _Advanced OAuth_ in the server's settings. Accepted values are:

- Scheme `http` only (not `https`)
- Hostname exactly `127.0.0.1`, `localhost`, or `[::1]`
- Any port (or none)
- Any path and query
- No URL fragment

Everything else is rejected at validation time, including all `https` URLs and all non-loopback hosts. This is deliberate: the override exists only for loopback-constrained upstreams, and permitting arbitrary hosts would create an authorization-code exfiltration vector.

Prefer `127.0.0.1` over `localhost` (RFC 8252 §8.3). A recommended example is `http://127.0.0.1:33418/fe-oauth/callback` — keep the path as `/fe-oauth/callback` so only the host and port differ from MetaMCP's normal callback, making the manual step below a one-word edit.

Setting only the override with no pre-registered `client_id` is valid and supported: MetaMCP will still use dynamic client registration.

#### Completing the flow

Because the redirect points at loopback, nothing is listening there, so the browser cannot deliver the code back automatically. Follow these steps:

1. Open the MCP server's detail page and click **Authorize**. MetaMCP performs discovery, dynamic client registration, and builds the authorization URL server-side, then sends the browser to the upstream's consent screen.
2. Approve on the upstream.
3. The browser is redirected to the loopback URL and shows a connection error. That is expected. The authorization code is in the address bar.
4. Replace only the `http://127.0.0.1:<port>` part of the URL with your MetaMCP base URL, keeping the callback path and the **complete query string**, then press Enter. The target browser session must be signed in to the same MetaMCP user that started authorization.
5. MetaMCP's callback validates the one-time `state`, exchanges the code server-side, stores the caller's tokens, and redirects to the UUID returned by the verified exchange.

If you reach MetaMCP through an SSH tunnel on that same loopback port, step 4 happens automatically: the callback page detects the origin mismatch and forwards the complete query string to the configured application origin.

#### Reauthorization and expiry

MetaMCP refreshes expired upstream tokens server-side. A frontend connection that receives an upstream `401` starts the same backend authorization flow automatically; MetaMCP/namespace connections retain their separate downstream authentication path. Concurrent `401` handlers are coalesced so the browser begins only one authorization attempt.

Clicking **Authorize** explicitly starts a fresh attempt for the current user. A newer attempt replaces the older pending state, so finish the most recent consent flow. Some providers return a bare `403` without a usable OAuth challenge; MetaMCP cannot safely classify every such response as token expiry. If refresh or automatic recovery cannot proceed, use **Authorize** again.

#### Deploying these changes

- `docker-compose.yml` pins `image: ghcr.io/metatool-ai/metamcp:latest`, a prebuilt upstream image. Changes in a local checkout do **not** reach a deployment that uses it.
- To run your own build, build from the repo's `Dockerfile` (or use `docker-compose.dev.yml`, which builds from `Dockerfile.dev`) and point your compose file at that image.
- Upstream-OAuth features depend on database migrations. Run `pnpm --filter backend db:migrate` (or `db:migrate:dev` against `.env.local`) after deploying a newer build.
- Consider pinning a specific image digest rather than `:latest`, so it is unambiguous which build a deployment is running.
