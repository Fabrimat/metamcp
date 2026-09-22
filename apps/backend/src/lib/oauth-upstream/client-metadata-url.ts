export function resolveOAuthClientMetadataUrl(
  env: NodeJS.ProcessEnv = process.env,
): string | undefined {
  const value = env.OAUTH_CLIENT_METADATA_URL;
  if (value === undefined) return undefined;

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(
      "OAUTH_CLIENT_METADATA_URL must be a valid HTTPS URL with a non-root path",
    );
  }

  if (
    value.length === 0 ||
    url.protocol !== "https:" ||
    url.pathname === "/" ||
    url.username !== "" ||
    url.password !== "" ||
    value.includes("?") ||
    value.includes("#") ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new Error(
      "OAUTH_CLIENT_METADATA_URL must use HTTPS with a non-root path and no credentials, query, or fragment",
    );
  }

  return value;
}
