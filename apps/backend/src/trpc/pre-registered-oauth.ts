import { OAuthClientInformation } from "@modelcontextprotocol/sdk/shared/auth.js";
import { OAuthClientInfoRequest } from "@repo/zod-types";

import type { OAuthSessionsRepository } from "../db/repositories/oauth-sessions.repo";

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

  // Snapshot whether a session already existed BEFORE this call touches
  // anything. Read once and reused below by both branches so a brand-new
  // client_id + redirect_uri pair entered for the very first time (nothing
  // to invalidate) is never confused with an edit to an already-registered
  // one (which does need invalidating) — see the override-changed check
  // near the bottom of this function.
  const existingBeforeThisCall = await repo.findByMcpServerAndUser(
    mcpServerUuid,
    userId,
  );

  // If client_id is absent the section was effectively cleared by the user.
  // Drop any pre-registered session so the SDK falls back to dynamic
  // registration on the next authorize attempt.
  if (!clientInfo) {
    if (existingBeforeThisCall) {
      await repo.deleteByMcpServerAndUser(mcpServerUuid, userId);
    }
    return;
  }

  await repo.upsert({
    mcp_server_uuid: mcpServerUuid,
    user_id: userId,
    // The repo type narrows `client_information` to the MCP SDK's 4-field
    // OAuthClientInformation. The underlying jsonb column accepts the full
    // RFC 7591 shape we want to round-trip, so we widen via an explicit cast.
    client_information: clientInfo as unknown as OAuthClientInformation,
  });

  // The redirect_uri override just changed from what was stored before this
  // call (A -> B, unset -> set, or set -> unset all count; a resubmit of
  // the same value does not). When it has — and a session already existed
  // — the client_information just upserted above, and any tokens/
  // code_verifier already on that row, were issued against the OLD
  // pairing: token exchange derives its redirect_uri from
  // client_information.redirect_uris[0] (see token-exchange.ts), so a
  // stale row would make the next authorize build its URL with the NEW
  // override while token exchange still sends the OLD one, and the
  // upstream would reject with invalid_grant.
  //
  // This check MUST run after the upsert above, not before: the edit form
  // prefills oauth_client_info.client_id from whatever is already in
  // client_information — including a client_id the SDK dynamically
  // registered, not just one the user typed in — so a redirect_uri-only
  // edit still resubmits that (now-stale) client_id, and the upsert above
  // just paired it with the NEW redirect_uri without the upstream ever
  // having agreed to that pairing. Deleting last, unconditionally,
  // guarantees a clean slate — no row at all — so the next authorize
  // re-registers from scratch instead of masking the mismatch. Discarding
  // tokens/code_verifier here is intentional, not collateral damage: they
  // were issued against the old client/redirect_uri pairing and are
  // unusable regardless, so re-authorization is required either way.
  // Mirrors the deleteByMcpServerAndUser call above for the "user cleared
  // client_id" case.
  const redirectUriOverrideChanged =
    redirectUriOverride !== (previousRedirectUriOverride ?? null);
  if (redirectUriOverrideChanged && existingBeforeThisCall) {
    await repo.deleteByMcpServerAndUser(mcpServerUuid, userId);
  }
}
