import { getServerSpecificKey, SESSION_KEYS } from "./constants";

export type OAuthCallbackResult =
  | { kind: "success"; code: string; state: string; iss?: string }
  | { kind: "error"; error: string; errorDescription?: string };

export function parseOAuthCallback(search: string): OAuthCallbackResult {
  const params = new URLSearchParams(search);
  const upstreamError = params.get("error");
  if (upstreamError) {
    return {
      kind: "error",
      error: upstreamError,
      errorDescription: params.get("error_description") ?? undefined,
    };
  }

  const code = params.get("code");
  const state = params.get("state");
  if (!code || !state) {
    return {
      kind: "error",
      error: "missing_callback_parameters",
      errorDescription:
        "The OAuth callback URL is missing the authorization code or state. Please restart authorization.",
    };
  }

  if (!state.startsWith("upstream.")) {
    return {
      kind: "error",
      error: "invalid_callback_state",
      errorDescription: "The OAuth callback state is not an upstream flow.",
    };
  }

  const iss = params.get("iss") ?? undefined;
  return { kind: "success", code, state, ...(iss ? { iss } : {}) };
}

type StorageReader = Pick<Storage, "getItem" | "removeItem">;

type UpstreamExchange = (input: {
  code: string;
  state: string;
  iss?: string;
}) => Promise<unknown>;

type DownstreamCompletion = (input: {
  authorizationCode: string;
  returnUuid: string;
  serverUrl: string;
}) => Promise<{ result: string; tokens: unknown }>;

export type OAuthCallbackCompletion =
  | { kind: "redirected"; flow: "upstream" | "downstream" }
  | { kind: "error"; error: string; errorDescription?: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function clearDownstreamCallbackContext(
  storage: StorageReader,
  serverUrl: string | null,
): void {
  if (serverUrl) {
    storage.removeItem(
      getServerSpecificKey(SESSION_KEYS.CODE_VERIFIER, serverUrl),
    );
  }
  storage.removeItem(SESSION_KEYS.SERVER_URL);
  storage.removeItem(SESSION_KEYS.MCP_SERVER_UUID);
}

export async function completeOAuthCallback(
  search: string,
  {
    storage,
    exchangeUpstream,
    completeDownstream,
    navigate,
  }: {
    storage: StorageReader;
    exchangeUpstream: UpstreamExchange;
    completeDownstream: DownstreamCompletion;
    navigate: (path: string) => void;
  },
): Promise<OAuthCallbackCompletion> {
  const params = new URLSearchParams(search);
  const state = params.get("state");

  // Route on the state before touching browser storage. A stale downstream
  // context must never gain authority over an upstream callback.
  if (state?.startsWith("upstream.")) {
    const callback = parseOAuthCallback(search);
    if (callback.kind === "error") return callback;

    try {
      const result = await exchangeUpstream({
        code: callback.code,
        state: callback.state,
        ...(callback.iss ? { iss: callback.iss } : {}),
      });
      if (isRecord(result) && result.success === false) {
        return {
          kind: "error",
          error:
            typeof result.error === "string" ? result.error : "oauth_error",
          errorDescription:
            typeof result.error_description === "string"
              ? result.error_description
              : undefined,
        };
      }

      const mcpServerUuid =
        isRecord(result) &&
        result.success === true &&
        isRecord(result.data) &&
        typeof result.data.mcp_server_uuid === "string"
          ? result.data.mcp_server_uuid
          : undefined;
      if (!mcpServerUuid) {
        return { kind: "error", error: "invalid_exchange_response" };
      }

      navigate(`/mcp-servers/${mcpServerUuid}`);
      return { kind: "redirected", flow: "upstream" };
    } catch (error) {
      return {
        kind: "error",
        error: "callback_failed",
        errorDescription:
          error instanceof Error
            ? error.message
            : "Unexpected error during OAuth callback.",
      };
    }
  }

  const serverUrl = storage.getItem(SESSION_KEYS.SERVER_URL);
  const returnUuid = storage.getItem(SESSION_KEYS.MCP_SERVER_UUID);
  const providerError = params.get("error");
  if (providerError) {
    clearDownstreamCallbackContext(storage, serverUrl);
    return {
      kind: "error",
      error: providerError,
      errorDescription: params.get("error_description") ?? undefined,
    };
  }

  const code = params.get("code");
  if (!code || !state || !serverUrl || !returnUuid) {
    clearDownstreamCallbackContext(storage, serverUrl);
    return {
      kind: "error",
      error: "missing_callback_parameters",
      errorDescription:
        "The downstream OAuth callback is missing its code, state, or browser session context. Please restart authorization.",
    };
  }

  try {
    const completion = await completeDownstream({
      authorizationCode: code,
      returnUuid,
      serverUrl,
    });
    const hasAccessToken =
      isRecord(completion.tokens) &&
      typeof completion.tokens.access_token === "string" &&
      completion.tokens.access_token.length > 0;
    if (completion.result !== "AUTHORIZED" || !hasAccessToken) {
      clearDownstreamCallbackContext(storage, serverUrl);
      return {
        kind: "error",
        error: "downstream_authorization_failed",
        errorDescription:
          "The downstream OAuth provider did not return an authorized token session.",
      };
    }

    // Preserve client information and tokens for the namespace reconnect;
    // only one-shot callback routing and PKCE verifier state is transient.
    clearDownstreamCallbackContext(storage, serverUrl);
    navigate(`/namespaces/${returnUuid}`);
    return { kind: "redirected", flow: "downstream" };
  } catch (error) {
    clearDownstreamCallbackContext(storage, serverUrl);
    return {
      kind: "error",
      error: "callback_failed",
      errorDescription:
        error instanceof Error
          ? error.message
          : "Unexpected error during OAuth callback.",
    };
  }
}
