export type OAuthClientRegistrationKind =
  | "manual"
  | "dynamic"
  | "legacy_unconfirmed"
  | "empty";

export class OAuthClientConfirmationRequiredError extends Error {
  readonly code = "oauth_client_confirmation_required";

  constructor() {
    super("Confirm the saved OAuth client configuration before authorizing.");
    this.name = "OAuthClientConfirmationRequiredError";
  }
}

export function classifyOAuthClientRegistration(
  client: Record<string, unknown> | null | undefined,
): OAuthClientRegistrationKind {
  if (!client) return "empty";

  const marker = client._metamcp_registration;
  if (marker === "manual" || marker === "dynamic") return marker;
  if (marker === "legacy_unconfirmed") return "legacy_unconfirmed";

  // Old explicit pre-registrations did not carry a provenance marker, but
  // configured endpoints prove they were supplied manually.
  if (client.authorization_endpoint || client.token_endpoint) return "manual";

  // An unmarked client_id may be either an old manual registration or an old
  // DCR result. Preserve it, but quarantine it until the user confirms it.
  if (typeof client.client_id === "string" && client.client_id.trim() !== "") {
    return "legacy_unconfirmed";
  }

  return "empty";
}

export function isManualOAuthClient(
  client: Record<string, unknown> | null | undefined,
): boolean {
  return classifyOAuthClientRegistration(client) === "manual";
}

export function isQuarantinedOAuthClient(
  client: Record<string, unknown> | null | undefined,
): boolean {
  return client?._metamcp_registration === "legacy_unconfirmed";
}
