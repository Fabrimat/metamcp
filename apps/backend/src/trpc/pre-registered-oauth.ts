import { OAuthClientInformation } from "@modelcontextprotocol/sdk/shared/auth.js";
import { OAuthClientInfoRequest } from "@repo/zod-types";

import type { OAuthSessionsRepository } from "../db/repositories/oauth-sessions.repo";
import { resolveOAuthClientMetadataUrl } from "../lib/oauth-upstream/client-metadata-url";
import { isManualOAuthClient } from "../lib/oauth-upstream/client-registration";

// Build the full `oauth_sessions.client_information` jsonb from
// user-supplied pre-registration fields. `redirectUri` is resolved by the
// caller (persistPreRegisteredOAuthClient, below): the per-server
// `redirect_uri` override when the user set one, else MetaMCP's own
// APP_URL-derived callback. The override can't be misused to redirect the
// authorization code to an arbitrary host because it is constrained to
// loopback URLs only at the zod schema boundary (see
// isValidLoopbackRedirectUri in @repo/zod-types) before it ever reaches
// this function.
export function buildPreRegisteredClientInformation(
  oauth: OAuthClientInfoRequest,
  redirectUri: string,
): Record<string, unknown> | null {
  if (!oauth.client_id || oauth.client_id.trim() === "") {
    return null;
  }

  const clientInfo: Record<string, unknown> = {
    _metamcp_registration: "manual",
    client_id: oauth.client_id.trim(),
    redirect_uris: [redirectUri],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: oauth.token_endpoint_auth_method ?? "none",
  };

  if (oauth.client_secret && oauth.client_secret.trim() !== "") {
    clientInfo.client_secret = oauth.client_secret;
  }
  if (oauth.scope && oauth.scope.trim() !== "") {
    clientInfo.scope = oauth.scope.trim();
  }
  if (
    oauth.authorization_endpoint &&
    oauth.authorization_endpoint.trim() !== ""
  ) {
    clientInfo.authorization_endpoint = oauth.authorization_endpoint.trim();
  }
  if (oauth.token_endpoint && oauth.token_endpoint.trim() !== "") {
    clientInfo.token_endpoint = oauth.token_endpoint.trim();
  }

  return clientInfo;
}

// Resolve MetaMCP's own OAuth callback URL from APP_URL.
export function resolveRedirectUri(): string {
  const clientMetadataUrl = resolveOAuthClientMetadataUrl();
  if (clientMetadataUrl) return clientMetadataUrl;
  const appUrl = process.env.APP_URL;
  if (!appUrl) {
    throw new Error(
      "APP_URL environment variable is required to derive the OAuth callback URL",
    );
  }
  return `${appUrl.replace(/\/$/, "")}/fe-oauth/callback`;
}

// Persist (or wipe) the pre-registered OAuth client information attached to
// an MCP server. Called after a server upsert when the request includes the
// optional `oauth_client_info` block.
export async function persistPreRegisteredOAuthClient(
  mcpServerUuid: string,
  userId: string,
  oauth: OAuthClientInfoRequest,
  repo: OAuthSessionsRepository,
  // The redirect_uri override as stored on mcp_servers.redirect_uri BEFORE
  // this call — i.e. the value from before the caller's update is applied.
  // Used below to detect an actual change and invalidate a now-stale
  // registration. Defaults to null for the `create` call site, where the
  // server row is brand new and there is nothing to compare against (a
  // first-ever redirect_uri is never a "change").
  previousRedirectUriOverride: string | null = null,
): Promise<void> {
  // Per-server loopback override wins when set; otherwise fall back to
  // MetaMCP's own APP_URL-derived callback (today's behaviour).
  const redirectUriOverride =
    oauth.redirect_uri && oauth.redirect_uri.trim() !== ""
      ? oauth.redirect_uri.trim()
      : null;
  const redirectUri = redirectUriOverride ?? resolveRedirectUri();
  const clientInfo = buildPreRegisteredClientInformation(oauth, redirectUri);

  const existing = await repo.findByMcpServerAndUser(mcpServerUuid, userId);
  const redirectChanged =
    redirectUriOverride !== (previousRedirectUriOverride ?? null);
  if (redirectChanged) {
    await repo.invalidateRedirectDependentSessions(mcpServerUuid, redirectUri);
  }

  // Redirect-only edits do not clear explicitly configured client credentials.
  if (oauth.client_id === undefined) return;
  if (!clientInfo) {
    if (existing) await repo.deleteByMcpServerAndUser(mcpServerUuid, userId);
    return;
  }
  const previousClient = existing?.client_information as Record<
    string,
    unknown
  > | null;
  // Older forms may resubmit a DCR client ID on a redirect-only edit.
  if (
    redirectChanged &&
    previousClient?.client_id === clientInfo.client_id &&
    !isManualOAuthClient(previousClient) &&
    !oauth.confirm_client_information &&
    !oauth.authorization_endpoint &&
    !oauth.token_endpoint &&
    !oauth.client_secret
  )
    return;

  await repo.upsert({
    mcp_server_uuid: mcpServerUuid,
    user_id: userId,
    client_information: clientInfo as unknown as OAuthClientInformation,
  });
}
