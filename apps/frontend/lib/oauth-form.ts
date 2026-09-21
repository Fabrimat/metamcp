import type {
  EditServerFormData,
  OAuthClientInfoRequest,
} from "@repo/zod-types";

export function oauthEditPayload(
  data: Partial<EditServerFormData>,
  dirty: Record<string, unknown>,
): OAuthClientInfoRequest | undefined {
  if (
    data.type === "STDIO" ||
    !Object.keys(dirty).some((key) => key.startsWith("oauth_") && dirty[key])
  )
    return undefined;
  if (
    !Object.keys(dirty).some(
      (key) =>
        key.startsWith("oauth_") && key !== "oauth_redirect_uri" && dirty[key],
    )
  ) {
    return { redirect_uri: data.oauth_redirect_uri?.trim() || "" };
  }
  return {
    client_id: data.oauth_client_id?.trim() || "",
    client_secret: data.oauth_client_secret || undefined,
    authorization_endpoint: data.oauth_authorization_endpoint || undefined,
    token_endpoint: data.oauth_token_endpoint || undefined,
    scope: data.oauth_scope || undefined,
    token_endpoint_auth_method: data.oauth_token_endpoint_auth_method || "none",
    redirect_uri: data.oauth_redirect_uri?.trim() || "",
  };
}
