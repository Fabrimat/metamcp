// Server-side OAuthClientProvider used ONLY to build the upstream
// authorize URL (RFC 6749 §4.1.1) via the MCP SDK's `auth()` orchestrator.
//
// WHY THIS EXISTS: MetaMCP authenticates to upstream MCP servers as an
// OAuth client. Running discovery + dynamic client registration (DCR) +
// authorize-URL construction in the browser (the original
// DbOAuthClientProvider in apps/frontend/lib/oauth-provider.ts) is
// unfixably broken for upstreams that don't set CORS headers on their
// discovery/DCR endpoints — verified live against Reclaim.ai:
// `/.well-known/oauth-authorization-server` returns 200 with no
// Access-Control-Allow-Origin (the browser can't read the body), and
// `OPTIONS` on its DCR endpoint returns 403. Node's `fetch` (used inside
// the MCP SDK's `auth()` when called from here) is not subject to CORS.
//
// Token exchange and refresh already moved server-side for the same
// reason — see oauth.impl.ts's exchangeToken/refreshToken and
// token-exchange.ts. This provider finishes the migration for discovery +
// DCR + the authorize redirect itself.
//
// Constructed fresh per `startAuthorization` tRPC call
// (apps/backend/src/trpc/oauth.impl.ts). Exchange and refresh also pass this
// provider to the SDK resource selector, while persisting tokens directly.
import {
  OAuthClientProvider,
  OAuthDiscoveryState,
} from "@modelcontextprotocol/sdk/client/auth.js";
import {
  OAuthClientInformation,
  OAuthClientInformationMixed,
  OAuthClientMetadata,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";

import { oauthSessionsRepository } from "../../db/repositories";
import { resolveRedirectUri } from "../../trpc/pre-registered-oauth";
import logger from "../../utils/logger";
import { createUpstreamState } from "./state";
import { redactToken } from "./token-exchange";

export interface OAuthUpstreamClientProviderOptions {
  mcpServerUuid: string;
  userId: string;
  serverUrl: string;
  // mcp_servers.redirect_uri — a per-server loopback override for
  // upstreams that only accept http://127.0.0.1 / http://localhost
  // redirect URIs (e.g. Reclaim.ai). Null means "use MetaMCP's own
  // APP_URL-derived callback".
  redirectUriOverride: string | null;
}

function clientInfoAsRecord(ci: unknown): Record<string, unknown> | null {
  if (!ci || typeof ci !== "object") return null;
  return ci as Record<string, unknown>;
}

export class OAuthUpstreamClientProvider implements OAuthClientProvider {
  private readonly mcpServerUuid: string;
  private readonly userId: string;
  private readonly redirectUriOverride: string | null;
  private pendingState: string | undefined;

  // Populated by redirectToAuthorization() instead of navigating — see
  // that method. The tRPC handler (oauth.impl.ts) reads this after
  // `auth()` resolves with 'REDIRECT'.
  authorizationUrl: URL | undefined;

  constructor(options: OAuthUpstreamClientProviderOptions) {
    this.mcpServerUuid = options.mcpServerUuid;
    this.userId = options.userId;
    this.redirectUriOverride = options.redirectUriOverride;
  }

  private async loadSession() {
    return oauthSessionsRepository.findByMcpServerAndUser(
      this.mcpServerUuid,
      this.userId,
    );
  }

  get redirectUrl(): string {
    return this.redirectUriOverride ?? resolveRedirectUri();
  }

  get clientMetadata(): OAuthClientMetadata {
    // Mirrors the browser-side DbOAuthClientProvider
    // (apps/frontend/lib/oauth-provider.ts) so a client registered via
    // either path looks identical to the upstream.
    return {
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      client_name: "MetaMCP",
      client_uri: "https://github.com/metatool-ai/metamcp",
    };
  }

  async clientInformation(): Promise<OAuthClientInformationMixed | undefined> {
    const session = await this.loadSession();
    const ci = clientInfoAsRecord(session?.client_information);
    if (!ci || typeof ci.client_id !== "string") return undefined;
    return ci as unknown as OAuthClientInformationMixed;
  }

  // CRITICAL: force redirect_uris[0] to the exact redirectUrl used for
  // *this* flow before persisting, regardless of what the upstream's DCR
  // response echoed back. Without this, an upstream that returns a
  // different (or absent) redirect_uris would cause token-exchange's
  // `client_information.redirect_uris[0] ?? resolveRedirectUri()`
  // (oauth.impl.ts exchangeToken) to send a mismatched `redirect_uri` at
  // the token endpoint. RFC 6749 §4.1.3 requires it to be byte-identical
  // to the value used in the /authorize request, so a mismatch here is a
  // guaranteed `invalid_grant` at exchange time.
  async saveClientInformation(
    clientInformation: OAuthClientInformationMixed,
  ): Promise<void> {
    const patched: Record<string, unknown> = {
      ...clientInformation,
      _metamcp_registration: "dynamic",
      redirect_uris: [this.redirectUrl],
    };
    await oauthSessionsRepository.upsert({
      mcp_server_uuid: this.mcpServerUuid,
      user_id: this.userId,
      client_information: patched as unknown as OAuthClientInformation,
    });
    logger.info(
      `[oauth] DCR registered client — server=${this.mcpServerUuid} ` +
        `client_id=${clientInformation.client_id} ` +
        `client_secret=${redactToken(
          (clientInformation as { client_secret?: string }).client_secret,
        )}`,
    );
  }

  // Deliberately always undefined: this provider exists only to build the
  // authorize URL. Returning a real token here would let `auth()` treat
  // the flow as already-authorized (or attempt a refresh) and skip the
  // redirect branch entirely — see `authInternal` in the SDK's
  // client/auth.js — AND it would bypass the refresh mutex in
  // refresh-on-401.ts, a separate code path that owns token refresh.
  // Token persistence after the callback happens in oauth.impl.ts's
  // exchangeToken, not here.
  async tokens(): Promise<OAuthTokens | undefined> {
    return undefined;
  }

  // Never actually invoked: `tokens()` above always returns undefined and
  // `redirectUrl` is always defined, so `auth()` always takes the
  // redirect-authorization branch, never the direct-token-fetch or
  // refresh branches that would call this. Throw loudly instead of
  // silently no-op'ing so a future SDK behaviour change can't quietly
  // drop tokens on the floor.
  async saveTokens(): Promise<void> {
    throw new Error(
      "OAuthUpstreamClientProvider.saveTokens should never be invoked — " +
        "token persistence happens in oauth.impl.ts's exchangeToken after " +
        "the upstream redirects back with an authorization code.",
    );
  }

  // Capture instead of navigate — this runs on the backend, so there is no
  // browser to redirect. The tRPC handler reads `this.authorizationUrl`
  // after `auth()` resolves with 'REDIRECT'.
  redirectToAuthorization(authorizationUrl: URL): void {
    this.authorizationUrl = authorizationUrl;
  }

  // RFC 6749 §10.12 CSRF defence — server-side twin of
  // DbOAuthClientProvider.state() in apps/frontend/lib/oauth-provider.ts.
  // Persisted so exchangeToken (oauth.impl.ts) can validate the round
  // trip when the upstream redirects back.
  async state(): Promise<string> {
    // The SDK does not re-save complete cached (including synthesized
    // pre-registered) discovery. Persist the context used for this redirect.
    const discovery = await this.discoveryState();
    if (discovery) await this.saveDiscoveryState(discovery);
    this.pendingState = createUpstreamState(this.mcpServerUuid);
    return this.pendingState;
  }

  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    if (!this.pendingState) throw new Error("Authorization state missing");
    await oauthSessionsRepository.upsert({
      mcp_server_uuid: this.mcpServerUuid,
      user_id: this.userId,
      code_verifier: codeVerifier,
      expected_state: this.pendingState,
    });
  }

  async codeVerifier(): Promise<string> {
    const session = await this.loadSession();
    if (!session?.code_verifier) {
      throw new Error("No code verifier saved for session");
    }
    return session.code_verifier;
  }

  // Bootstraps `auth()` from the pre-registered authorization_endpoint /
  // token_endpoint fields (see pre-registered-oauth.ts /
  // buildPreRegisteredClientInformation) instead of running RFC 9728 +
  // RFC 8414 discovery. This is what makes the pre-registered
  // authorization_endpoint field actually take effect on the authorize
  // side: the SDK's startAuthorization() reads metadata.authorization_endpoint,
  // never clientInformation.authorization_endpoint, so without this the
  // field only ever affected the (already server-side) token-exchange path.
  //
  // Resource metadata is retained only when actually discovered. Without it,
  // the SDK can discover PRM; no artificial resource indicator is introduced.
  //
  // Complete pre-registered endpoints take precedence, followed by persisted
  // discovery. With neither available, the SDK performs normal discovery.
  async discoveryState(): Promise<OAuthDiscoveryState | undefined> {
    const session = await this.loadSession();
    const ci = clientInfoAsRecord(session?.client_information);
    const authorizationEndpoint =
      typeof ci?.authorization_endpoint === "string"
        ? ci.authorization_endpoint
        : undefined;
    const tokenEndpoint =
      typeof ci?.token_endpoint === "string" ? ci.token_endpoint : undefined;
    if (!authorizationEndpoint || !tokenEndpoint) {
      return (session?.discovery_state ?? undefined) as unknown as
        | OAuthDiscoveryState
        | undefined;
    }

    let authorizationServerUrl: string;
    try {
      authorizationServerUrl = new URL(authorizationEndpoint).origin;
    } catch {
      // Malformed pre-registered URL — fall back to normal discovery
      // rather than feeding startAuthorization() an unparsable base.
      return undefined;
    }

    return {
      ...(session?.discovery_state as unknown as
        | OAuthDiscoveryState
        | undefined),
      authorizationServerUrl,
      authorizationServerMetadata: {
        issuer: authorizationServerUrl,
        authorization_endpoint: authorizationEndpoint,
        token_endpoint: tokenEndpoint,
        response_types_supported: ["code"],
      },
    };
  }

  async saveDiscoveryState(state: OAuthDiscoveryState): Promise<void> {
    await oauthSessionsRepository.upsert({
      mcp_server_uuid: this.mcpServerUuid,
      user_id: this.userId,
      discovery_state: state as unknown as Record<string, unknown>,
    });
  }
}
