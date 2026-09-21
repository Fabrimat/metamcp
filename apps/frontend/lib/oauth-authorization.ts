type StartAuthorization = (input: {
  mcp_server_uuid: string;
}) => Promise<unknown>;

type Navigate = (authorizationUrl: string) => void;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export class OAuthAuthorizationError extends Error {
  readonly code: string;
  readonly description?: string;

  constructor(code: string, description?: string) {
    super(description ? `${code}: ${description}` : code);
    this.name = "OAuthAuthorizationError";
    this.code = code;
    this.description = description;
  }
}

export async function beginUpstreamAuthorization(
  mcpServerUuid: string,
  start: StartAuthorization,
  navigate: Navigate,
): Promise<void> {
  const result = await start({ mcp_server_uuid: mcpServerUuid });

  if (isRecord(result) && result.success === false) {
    const code =
      typeof result.error === "string" ? result.error : "oauth_error";
    const description =
      typeof result.error_description === "string"
        ? result.error_description
        : undefined;
    throw new OAuthAuthorizationError(code, description);
  }

  const authorizationUrl =
    isRecord(result) &&
    result.success === true &&
    isRecord(result.data) &&
    typeof result.data.authorization_url === "string"
      ? result.data.authorization_url
      : undefined;

  if (!authorizationUrl) {
    throw new OAuthAuthorizationError("invalid_authorization_response");
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(authorizationUrl);
  } catch {
    throw new OAuthAuthorizationError("invalid_authorization_response");
  }
  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    throw new OAuthAuthorizationError("invalid_authorization_response");
  }

  navigate(authorizationUrl);
}

export function shouldStartUpstreamOAuth({
  is401,
  isMetaMCP,
}: {
  is401: boolean;
  isMetaMCP: boolean;
}): boolean {
  return is401 && !isMetaMCP;
}
