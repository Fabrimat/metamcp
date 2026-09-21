export function isManualOAuthClient(
  client: Record<string, unknown> | null | undefined,
): boolean {
  // Legacy explicit endpoints identify pre-registration. New writes always
  // carry an internal provenance marker, including manual client-id-only data.
  return (
    client?._metamcp_registration === "manual" ||
    (client?._metamcp_registration !== "dynamic" &&
      Boolean(client?.authorization_endpoint || client?.token_endpoint))
  );
}
