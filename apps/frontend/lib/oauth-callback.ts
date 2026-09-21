export type OAuthCallbackResult =
  | { kind: "success"; code: string; state: string }
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

  return { kind: "success", code, state };
}
