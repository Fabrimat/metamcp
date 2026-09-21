import { OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";
import {
  OAuthClientInformation,
  OAuthClientInformationSchema,
  OAuthClientMetadata,
  OAuthMetadata,
  OAuthTokens,
  OAuthTokensSchema,
} from "@modelcontextprotocol/sdk/shared/auth.js";

import { getServerSpecificKey, SESSION_KEYS } from "./constants";
import { getAppUrl } from "./env";

// base64url (RFC 4648 §5) encoding of a byte array. Uses btoa for the
// classic base64 step then trims/replaces to the url-safe variant. Browsers
// only — the SDK's `auth()` calls this from `state()` which runs in the
// browser path; no need for a Node fallback here.
function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// OAuth client provider that works with a specific MCP server
class DbOAuthClientProvider implements OAuthClientProvider {
  protected serverUrl: string;

  constructor(serverUrl: string) {
    this.serverUrl = serverUrl;
  }

  get redirectUrl() {
    return getAppUrl() + "/fe-oauth/callback";
  }

  get clientMetadata(): OAuthClientMetadata {
    return {
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      client_name: "MetaMCP",
      client_uri: "https://github.com/metatool-ai/metamcp",
    };
  }

  async clientInformation() {
    try {
      const key = getServerSpecificKey(
        SESSION_KEYS.CLIENT_INFORMATION,
        this.serverUrl,
      );
      const storedInfo = sessionStorage.getItem(key);
      if (storedInfo) {
        return await OAuthClientInformationSchema.parseAsync(
          JSON.parse(storedInfo),
        );
      }

      return undefined;
    } catch (error) {
      console.error("Error retrieving client information:", error);
      return undefined;
    }
  }

  async saveClientInformation(clientInformation: OAuthClientInformation) {
    const key = getServerSpecificKey(
      SESSION_KEYS.CLIENT_INFORMATION,
      this.serverUrl,
    );
    sessionStorage.setItem(key, JSON.stringify(clientInformation));
  }

  async tokens() {
    try {
      const key = getServerSpecificKey(SESSION_KEYS.TOKENS, this.serverUrl);
      const storedTokens = sessionStorage.getItem(key);
      if (storedTokens) {
        return await OAuthTokensSchema.parseAsync(JSON.parse(storedTokens));
      }

      return undefined;
    } catch (error) {
      console.error("Error retrieving tokens:", error);
      return undefined;
    }
  }

  async saveTokens(tokens: OAuthTokens) {
    const key = getServerSpecificKey(SESSION_KEYS.TOKENS, this.serverUrl);
    sessionStorage.setItem(key, JSON.stringify(tokens));
  }

  redirectToAuthorization(authorizationUrl: URL) {
    window.location.href = authorizationUrl.href;
  }

  async state(): Promise<string> {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return base64UrlEncode(bytes);
  }

  async saveCodeVerifier(codeVerifier: string) {
    const key = getServerSpecificKey(
      SESSION_KEYS.CODE_VERIFIER,
      this.serverUrl,
    );
    sessionStorage.setItem(key, codeVerifier);
  }

  async codeVerifier() {
    const key = getServerSpecificKey(
      SESSION_KEYS.CODE_VERIFIER,
      this.serverUrl,
    );
    const codeVerifier = sessionStorage.getItem(key);
    if (!codeVerifier) {
      throw new Error("No code verifier saved for session");
    }

    return codeVerifier;
  }

  clear() {
    sessionStorage.removeItem(
      getServerSpecificKey(SESSION_KEYS.CLIENT_INFORMATION, this.serverUrl),
    );
    sessionStorage.removeItem(
      getServerSpecificKey(SESSION_KEYS.TOKENS, this.serverUrl),
    );
    sessionStorage.removeItem(
      getServerSpecificKey(SESSION_KEYS.CODE_VERIFIER, this.serverUrl),
    );
  }
}

// Debug version that overrides redirect URL and allows saving server OAuth metadata
export class DebugDbOAuthClientProvider extends DbOAuthClientProvider {
  get redirectUrl(): string {
    return getAppUrl() + "/fe-oauth/callback/debug";
  }

  saveServerMetadata(metadata: OAuthMetadata) {
    const key = getServerSpecificKey(
      SESSION_KEYS.SERVER_METADATA,
      this.serverUrl,
    );
    sessionStorage.setItem(key, JSON.stringify(metadata));
  }

  getServerMetadata(): OAuthMetadata | null {
    const key = getServerSpecificKey(
      SESSION_KEYS.SERVER_METADATA,
      this.serverUrl,
    );
    const metadata = sessionStorage.getItem(key);
    if (!metadata) {
      return null;
    }
    return JSON.parse(metadata);
  }

  clear() {
    super.clear();
    sessionStorage.removeItem(
      getServerSpecificKey(SESSION_KEYS.SERVER_METADATA, this.serverUrl),
    );
  }
}

// The browser provider remains only for the MetaMCP/namespace compatibility
// path. Upstream MCP servers authorize through the backend-owned flow.
export function createAuthProvider(
  _mcpServerUuid: string,
  serverUrl: string,
): DbOAuthClientProvider {
  return new DbOAuthClientProvider(serverUrl);
}

// Factory function to create a debug OAuth provider for a specific MCP server
export function createDebugAuthProvider(
  _mcpServerUuid: string,
  serverUrl: string,
): DebugDbOAuthClientProvider {
  return new DebugDbOAuthClientProvider(serverUrl);
}
