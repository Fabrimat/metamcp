import { randomBytes, timingSafeEqual } from "node:crypto";

import { auth } from "@modelcontextprotocol/sdk/client/auth.js";
import { OAuthError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { OAuthClientInformation } from "@modelcontextprotocol/sdk/shared/auth.js";
import {
  ExchangeOAuthTokenRequestSchema,
  ExchangeOAuthTokenResponseSchema,
  GetOAuthSessionRequestSchema,
  GetOAuthSessionResponseSchema,
  RefreshOAuthTokenRequestSchema,
  RefreshOAuthTokenResponseSchema,
  StartOAuthAuthorizationRequestSchema,
  StartOAuthAuthorizationResponseSchema,
  UpsertOAuthSessionRequestSchema,
  UpsertOAuthSessionResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import logger from "@/utils/logger";

import {
  mcpServersRepository,
  oauthSessionsRepository,
} from "../db/repositories";
import { OAuthSessionsSerializer } from "../db/serializers";
import {
  isQuarantinedOAuthClient,
  OAuthClientConfirmationRequiredError,
} from "../lib/oauth-upstream/client-registration";
import { OAuthUpstreamClientProvider } from "../lib/oauth-upstream/provider";
import { tryRefreshUpstreamTokens } from "../lib/oauth-upstream/refresh-on-401";
import { parseUpstreamState } from "../lib/oauth-upstream/state";
import {
  exchangeAuthorizationCode,
  OAuthTokens,
  redactToken,
  resolveOAuthTokenContext,
  resolveTokenEndpointAuthMethod,
  UpstreamTokenError,
  withExpiresAt,
} from "../lib/oauth-upstream/token-exchange";

// Fallback used ONLY when the persisted client_information has no
// redirect_uris[0] (e.g. a session that predates this field). Whenever
// client_information.redirect_uris[0] IS present, the caller uses that
// value directly instead of this function — see the `redirectUri`
// resolution below — because it is byte-identical to whatever was actually
// sent at registration/authorize (including a per-server loopback
// override), which recomputing from APP_URL here cannot guarantee: the
// frontend derives its callback from NEXT_PUBLIC_APP_URL ||
// window.location.origin while this function reads APP_URL, and the two
// can diverge.
//
// The frontend computes its default callback as
// `getAppUrl() + "/fe-oauth/callback"` with no normalization
// (apps/frontend/lib/oauth-provider.ts), so we mirror that verbatim — no
// trailing-slash stripping. If APP_URL ends in a slash, both sides produce
// a double slash; the only requirement is that the two values match.
function resolveRedirectUri(): string {
  const appUrl = process.env.APP_URL;
  if (!appUrl) {
    throw new Error(
      "APP_URL environment variable is required for OAuth callback resolution",
    );
  }
  return appUrl + "/fe-oauth/callback";
}

function clientInfoAsRecord(
  ci: OAuthClientInformation | null | undefined,
): Record<string, unknown> | null {
  if (!ci) return null;
  return ci as unknown as Record<string, unknown>;
}

function upstreamErrorResponse(error: UpstreamTokenError) {
  return {
    success: false as const,
    error: error.oauthError?.error ?? "upstream_error",
    error_description: error.oauthError?.error_description ?? error.message,
    upstream_status: error.status,
  };
}

// Authorize the caller against the referenced MCP server and resolve its
// upstream URL from the database.
//
// SECURITY: this function exists so the upstream URL is *never* taken
// from a caller-supplied input. Doing so would allow any authenticated
// user to direct MetaMCP's server-side fetch (and the OAuth code +
// client_secret it carries) at an attacker-controlled host.
//
// The function returns one of:
//   { ok: true, url } — owned/public server with a valid HTTP(S) URL
//   { ok: false, error } — typed error envelope safe to return to caller
type ResolveServerResult =
  | { ok: true; url: string }
  | { ok: false; error: { error: string; error_description: string } };

async function resolveOwnedServerUrl(
  mcpServerUuid: string,
  userId: string,
): Promise<ResolveServerResult> {
  const server = await mcpServersRepository.findByUuid(mcpServerUuid);
  if (!server) {
    return {
      ok: false,
      error: {
        error: "server_not_found",
        error_description: "MCP server not found",
      },
    };
  }
  // Match the access rules used elsewhere: a server with a `user_id` is
  // private to that user; a server with `user_id === null` is public.
  if (server.user_id && server.user_id !== userId) {
    return {
      ok: false,
      error: {
        error: "access_denied",
        error_description:
          "You can only run OAuth flows against servers you own",
      },
    };
  }
  if (
    !server.url ||
    server.type === "STDIO" ||
    !/^https?:\/\//i.test(server.url)
  ) {
    return {
      ok: false,
      error: {
        error: "server_not_oauth_capable",
        error_description:
          "This MCP server is not an HTTP-style server, so OAuth flows are not applicable.",
      },
    };
  }
  return { ok: true, url: server.url };
}

export const oauthImplementations = {
  get: async (
    input: z.infer<typeof GetOAuthSessionRequestSchema>,
    userId: string,
  ): Promise<z.infer<typeof GetOAuthSessionResponseSchema>> => {
    try {
      const serverResolution = await resolveOwnedServerUrl(
        input.mcp_server_uuid,
        userId,
      );
      if (!serverResolution.ok) {
        return {
          success: false as const,
          error: serverResolution.error.error,
          message: serverResolution.error.error_description,
        };
      }

      const session = await oauthSessionsRepository.findByMcpServerAndUser(
        input.mcp_server_uuid,
        userId,
      );

      if (!session) {
        return {
          success: false as const,
          error: "session_not_found",
          message: "OAuth session not found",
        };
      }

      return {
        success: true as const,
        data: OAuthSessionsSerializer.serializeOAuthSession(session),
        message: "OAuth session retrieved successfully",
      };
    } catch (error) {
      logger.error("Error fetching OAuth session:", error);
      return {
        success: false as const,
        error: "internal_error",
        message: "Failed to fetch OAuth session",
      };
    }
  },

  upsert: async (
    input: z.infer<typeof UpsertOAuthSessionRequestSchema>,
    userId: string,
  ): Promise<z.infer<typeof UpsertOAuthSessionResponseSchema>> => {
    try {
      const serverResolution = await resolveOwnedServerUrl(
        input.mcp_server_uuid,
        userId,
      );
      if (!serverResolution.ok) {
        return {
          success: false as const,
          error: serverResolution.error.error,
        };
      }

      const session = await oauthSessionsRepository.upsert({
        mcp_server_uuid: input.mcp_server_uuid,
        user_id: userId,
        ...(input.client_information && {
          client_information: input.client_information,
        }),
        ...(input.tokens && { tokens: input.tokens }),
        ...(input.code_verifier && { code_verifier: input.code_verifier }),
        // Legacy session-upsert callers still need the nonce persisted.
        // A missing nonce now makes exchangeToken fail closed.
        ...(input.expected_state && {
          expected_state: input.expected_state,
        }),
      });

      if (!session) {
        return {
          success: false as const,
          error: "Failed to upsert OAuth session",
        };
      }

      return {
        success: true as const,
        data: OAuthSessionsSerializer.serializeOAuthSession(session),
        message: "OAuth session upserted successfully",
      };
    } catch (error) {
      logger.error("Error upserting OAuth session:", error);
      return {
        success: false as const,
        error: error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  // Server-side authorization-code-to-token exchange.
  //
  // The frontend's /fe-oauth/callback page forwards the authorization code
  // here instead of running the SDK's `exchangeAuthorization` in the
  // browser, because most enterprise OAuth providers (Salesforce, Okta,
  // Auth0, Microsoft Entra, ServiceNow, ...) do not return CORS headers
  // on their token endpoints. The fetch succeeds on the wire but the
  // browser blocks the response body, leaving tokens unpersisted.
  exchangeToken: async (
    input: z.infer<typeof ExchangeOAuthTokenRequestSchema>,
    userId: string,
  ): Promise<z.infer<typeof ExchangeOAuthTokenResponseSchema>> => {
    const invalidState = {
      success: false as const,
      error: "invalid_state",
      error_description:
        "OAuth state mismatch or expired flow. Re-initiate authorization.",
    };
    const mcpServerUuid = parseUpstreamState(input.state);
    if (!mcpServerUuid) return invalidState;
    // Resolve the upstream URL from the DB (NOT from the request). This is
    // the SSRF guard: an attacker-supplied URL would otherwise steer the
    // discovery + token POST at an attacker-controlled host, leaking the
    // authorization code, PKCE verifier, client_id, and client_secret.
    const serverResolution = await resolveOwnedServerUrl(mcpServerUuid, userId);
    if (!serverResolution.ok) {
      return { success: false as const, ...serverResolution.error };
    }
    const serverUrl = serverResolution.url;

    const session = await oauthSessionsRepository.findByMcpServerAndUser(
      mcpServerUuid,
      userId,
    );
    if (!session) {
      return {
        success: false as const,
        error: "session_not_found",
        error_description:
          "No OAuth session found for this MCP server. The authorize flow may have been started against a different server.",
      };
    }
    // The UUID only routes the lookup; authorize this callback using the full
    // nonce belonging to the authenticated user's composite session.
    const expectedState = Buffer.from(session.expected_state ?? "", "utf8");
    const receivedState = Buffer.from(input.state, "utf8");
    if (
      !expectedState.length ||
      expectedState.length !== receivedState.length ||
      !timingSafeEqual(expectedState, receivedState)
    )
      return invalidState;

    if (!session.code_verifier) {
      return {
        success: false as const,
        error: "code_verifier_missing",
        error_description:
          "OAuth session has no code_verifier. The authorize flow must be re-initiated.",
      };
    }

    const clientInformation = clientInfoAsRecord(session.client_information);
    const clientId =
      clientInformation && typeof clientInformation.client_id === "string"
        ? (clientInformation.client_id as string)
        : null;
    if (!clientId) {
      return {
        success: false as const,
        error: "client_information_missing",
        error_description:
          "OAuth session has no client_id. Dynamic registration may have failed, or the pre-registered OAuth client form was not filled in.",
      };
    }

    const clientSecret =
      typeof clientInformation?.client_secret === "string"
        ? (clientInformation.client_secret as string)
        : undefined;

    // Use the redirect_uri that was actually registered/authorized rather
    // than recomputing it — this is the byte-identical guarantee RFC 6749
    // §4.1.3 requires between the /authorize and token-exchange requests,
    // and it automatically carries a per-server loopback override (see
    // pre-registered-oauth.ts) without this function needing to know about
    // it. Falls back to the APP_URL derivation for sessions whose
    // client_information predates this field.
    const registeredRedirectUris = clientInformation?.redirect_uris;
    const redirectUri =
      Array.isArray(registeredRedirectUris) &&
      typeof registeredRedirectUris[0] === "string" &&
      registeredRedirectUris[0].length > 0
        ? registeredRedirectUris[0]
        : resolveRedirectUri();

    // Claim atomically before any discovery/token request. The marker cannot
    // parse as a callback state, and only this claim can consume or restore it.
    const claimMarker = `upstream-claim.${randomBytes(32).toString("base64url")}`;
    const claimed = await oauthSessionsRepository.compareAndSetExpectedState(
      mcpServerUuid,
      userId,
      input.state,
      claimMarker,
    );
    if (!claimed) return invalidState;

    let tokens: OAuthTokens;
    try {
      const { tokenEndpoint, discovered, resource } =
        await resolveOAuthTokenContext({
          clientInformation,
          discoveryState: session.discovery_state,
          serverUrl,
          provider: new OAuthUpstreamClientProvider({
            mcpServerUuid,
            userId,
            serverUrl,
            redirectUriOverride: null,
          }),
        });
      const authMethod = resolveTokenEndpointAuthMethod({
        clientInformation,
        discovered,
        hasSecret: Boolean(clientSecret),
      });
      tokens = await exchangeAuthorizationCode({
        tokenEndpoint,
        code: input.code,
        codeVerifier: session.code_verifier,
        redirectUri,
        clientId,
        clientSecret,
        authMethod,
        resource,
      });
    } catch (error) {
      // Restore retryable attempts only while our claim is still current. A
      // newer authorize call may have replaced it while the request was pending.
      const terminal =
        error instanceof UpstreamTokenError &&
        error.status >= 400 &&
        error.status < 500 &&
        error.status !== 408 &&
        error.status !== 429 &&
        error.oauthError &&
        !["temporarily_unavailable", "server_error"].includes(
          error.oauthError.error,
        );
      await oauthSessionsRepository.compareAndSetExpectedState(
        mcpServerUuid,
        userId,
        claimMarker,
        terminal ? null : input.state,
      );
      if (error instanceof UpstreamTokenError) {
        logger.warn(
          `[oauth] upstream token exchange failed — server=${mcpServerUuid} ` +
            `status=${error.status} error=${error.oauthError?.error ?? "unknown"}`,
        );
        return upstreamErrorResponse(error);
      }
      // Any other thrown value is a programmer bug, not an upstream issue.
      // Surface it via logger.error and re-throw so tRPC returns a 500 to
      // the caller instead of masking it as `internal_error`.
      logger.error(
        `[oauth] exchangeToken unexpected error for server ${mcpServerUuid}:`,
        error,
      );
      throw error;
    }

    // Compute the absolute expiry NOW, at the moment the response was
    // received, so the proactive-refresh gate in client.ts has something
    // to act on. See withExpiresAt's doc comment for why.
    tokens = withExpiresAt(tokens);

    await oauthSessionsRepository.upsert({
      mcp_server_uuid: mcpServerUuid,
      user_id: userId,
      tokens,
    });

    // Database errors fail closed. A false CAS means a newer authorize attempt
    // has superseded this claim; preserve that newer state.
    await oauthSessionsRepository.compareAndSetExpectedState(
      mcpServerUuid,
      userId,
      claimMarker,
      null,
    );

    logger.info(
      `[oauth] token exchange succeeded — server=${mcpServerUuid} ` +
        `access_token=${redactToken(tokens.access_token)} ` +
        `refresh_token=${redactToken(tokens.refresh_token)}`,
    );

    return {
      success: true as const,
      data: { mcp_server_uuid: mcpServerUuid },
      message: "OAuth tokens persisted",
    };
  },

  // Server-side refresh-token grant. Companion to exchangeToken — same CORS
  // rationale. Reads the current refresh_token from oauth_sessions, POSTs
  // to the upstream token endpoint, persists the new tokens (preserving the
  // refresh_token if the response omits it).
  // tRPC frontend mutation. Delegates to the shared refresh primitive so
  // an in-process mutex collapses simultaneous refresh attempts (including
  // a proxy 401 retry) into a single upstream POST. Without the mutex,
  // providers that rotate refresh tokens would consume the token on the
  // first call and reject the second with `invalid_grant`.
  refreshToken: async (
    input: z.infer<typeof RefreshOAuthTokenRequestSchema>,
    userId: string,
  ): Promise<z.infer<typeof RefreshOAuthTokenResponseSchema>> => {
    const serverResolution = await resolveOwnedServerUrl(
      input.mcp_server_uuid,
      userId,
    );
    if (!serverResolution.ok) {
      return { success: false as const, ...serverResolution.error };
    }

    const result = await tryRefreshUpstreamTokens({
      uuid: input.mcp_server_uuid,
      name: "frontend-refresh",
      url: serverResolution.url,
      oauth_user_id: userId,
    });

    switch (result.status) {
      case "refreshed":
        return { success: true as const, message: "OAuth tokens refreshed" };
      case "no_session":
        return {
          success: false as const,
          error: "session_not_found",
          error_description: "No OAuth session for this MCP server.",
        };
      case "no_refresh_token":
        return {
          success: false as const,
          error: "no_refresh_token",
          error_description:
            "OAuth session has no refresh_token; the user must re-authorize.",
        };
      case "no_client_id":
        return {
          success: false as const,
          error: "client_information_missing",
          error_description:
            "OAuth session has no client_id; cannot refresh tokens.",
        };
      case "failed":
        return {
          success: false as const,
          error: result.error ?? "upstream_error",
          error_description: result.errorDescription,
          upstream_status: result.upstreamStatus,
        };
    }
  },

  // Server-side authorize-URL construction. Runs discovery, dynamic client
  // registration (or uses pre-registered endpoints — see
  // OAuthUpstreamClientProvider.discoveryState), PKCE, and `state`
  // generation entirely server-side via the MCP SDK's `auth()`
  // orchestrator, then returns the resulting authorize URL for the
  // frontend to navigate the browser to. Same CORS rationale as
  // exchangeToken/refreshToken above: some upstreams (verified against
  // Reclaim.ai) don't set CORS headers on discovery or DCR endpoints, so
  // the browser-side DbOAuthClientProvider
  // (apps/frontend/lib/oauth-provider.ts) can never complete those steps
  // for them.
  startAuthorization: async (
    input: z.infer<typeof StartOAuthAuthorizationRequestSchema>,
    userId: string,
  ): Promise<z.infer<typeof StartOAuthAuthorizationResponseSchema>> => {
    // Same SSRF guard as exchangeToken/refreshToken: the upstream URL is
    // resolved from the DB, never from the caller.
    const serverResolution = await resolveOwnedServerUrl(
      input.mcp_server_uuid,
      userId,
    );
    if (!serverResolution.ok) {
      return { success: false as const, ...serverResolution.error };
    }
    const serverUrl = serverResolution.url;

    // resolveOwnedServerUrl already confirmed this row exists and is
    // owned by `userId` — fetched again here only for the `redirect_uri`
    // column, which that helper doesn't expose.
    const server = await mcpServersRepository.findByUuid(input.mcp_server_uuid);

    const provider = new OAuthUpstreamClientProvider({
      mcpServerUuid: input.mcp_server_uuid,
      userId,
      serverUrl,
      redirectUriOverride: server?.redirect_uri ?? null,
    });

    // SEP-835 scope selection: pass the user's pre-registered scope (if
    // any) as `options.scope` so it takes precedence exactly as the SDK
    // intends — auth()'s precedence is options.scope > PRM
    // scopes_supported > clientMetadata.scope, and our clientMetadata
    // never carries a scope, so this is the only way a pre-registered
    // scope reaches DCR/authorize.
    const session = await oauthSessionsRepository.findByMcpServerAndUser(
      input.mcp_server_uuid,
      userId,
    );
    const clientInformation = clientInfoAsRecord(session?.client_information);
    if (isQuarantinedOAuthClient(clientInformation)) {
      return {
        success: false as const,
        error: "oauth_client_confirmation_required",
        error_description:
          "Confirm the saved OAuth client configuration before authorizing.",
      };
    }
    const scope =
      typeof clientInformation?.scope === "string" &&
      clientInformation.scope.length > 0
        ? clientInformation.scope
        : undefined;

    try {
      const result = await auth(provider, { serverUrl, scope });
      if (result !== "REDIRECT" || !provider.authorizationUrl) {
        // auth() only resolves 'AUTHORIZED' when tokens() returns a value
        // or redirectUrl is falsy — neither is possible for this provider
        // (see provider.ts). Defensive: something changed upstream in the
        // SDK, or a future refactor broke that invariant.
        logger.error(
          `[oauth] startAuthorization: auth() returned '${result}' without ` +
            `an authorization URL for server=${input.mcp_server_uuid}`,
        );
        return {
          success: false as const,
          error: "unexpected_auth_result",
          error_description:
            "Could not build an authorize URL for this server.",
        };
      }
      // SECURITY: reject a non-http(s) authorize URL before ever returning
      // it. The frontend (mcp-servers/[uuid]/page.tsx) assigns
      // `authorization_url` directly to `window.location.href`, and this
      // URL is built by the MCP SDK from the upstream's discovered or
      // pre-registered authorization_endpoint — data controlled by
      // whoever configured this mcp_servers row, not by MetaMCP. zod's
      // `.url()` on the response schema accepts `javascript:` (it's a
      // syntactically valid URL), so nothing upstream of this check
      // constrains the scheme. `provider.authorizationUrl` is already a
      // `URL` (built via `new URL(...)` inside the SDK's
      // startAuthorization — see client/auth.js), so checking `.protocol`
      // here is equivalent to parsing the string ourselves, without
      // regexing it.
      if (
        provider.authorizationUrl.protocol !== "http:" &&
        provider.authorizationUrl.protocol !== "https:"
      ) {
        logger.error(
          `[oauth] startAuthorization: rejected non-http(s) authorization URL ` +
            `scheme '${provider.authorizationUrl.protocol}' for server=${input.mcp_server_uuid}`,
        );
        return {
          success: false as const,
          error: "unsafe_authorization_url",
          error_description:
            "The upstream's authorization endpoint uses a URL scheme MetaMCP does not allow.",
        };
      }

      logger.info(
        `[oauth] startAuthorization succeeded — server=${input.mcp_server_uuid}`,
      );
      return {
        success: true as const,
        data: { authorization_url: provider.authorizationUrl.href },
        message: "Authorization URL created",
      };
    } catch (error) {
      if (
        provider.clientConfirmationRequired ||
        error instanceof OAuthClientConfirmationRequiredError ||
        (error instanceof Error &&
          "code" in error &&
          error.code === "oauth_client_confirmation_required")
      ) {
        return {
          success: false as const,
          error: "oauth_client_confirmation_required",
          error_description:
            "Confirm the saved OAuth client configuration before authorizing.",
        };
      }
      // SDK error messages can include raw response bodies and credentials.
      const allowedCodes = new Set([
        "invalid_client",
        "invalid_redirect_uri",
        "invalid_scope",
        "invalid_client_metadata",
        "unauthorized_client",
        "server_error",
        "temporarily_unavailable",
      ]);
      const code =
        error instanceof OAuthError && allowedCodes.has(error.errorCode)
          ? error.errorCode
          : "upstream_error";
      logger.warn(
        `[oauth] startAuthorization failed — server=${input.mcp_server_uuid} error=${code}`,
      );
      return {
        success: false as const,
        error: code,
        error_description:
          "Upstream OAuth authorization failed. Check the configured client and provider endpoints, then retry.",
      };
    }
  },
};
