import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { pathToFileURL } from "node:url";

import { resolveOAuthClientMetadataUrl } from "./lib/oauth-upstream/client-metadata-url";
import { parseUpstreamState } from "./lib/oauth-upstream/state";

const METADATA_PATH = "/oauth/client-metadata";
const CALLBACK_PATH = "/fe-oauth/callback";

interface GatewayLogger {
  info(message: string): void;
  error(message: string): void;
}

interface GatewayOptions {
  env?: NodeJS.ProcessEnv;
  logger?: GatewayLogger;
}

const securityHeaders = {
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

const metadataHeaders = {
  ...securityHeaders,
  "Access-Control-Allow-Origin": "*",
  "Cache-Control": "public, max-age=300",
  "Content-Type": "application/json; charset=utf-8",
};

const callbackHeaders = {
  ...securityHeaders,
  "Cache-Control": "no-store",
  Pragma: "no-cache",
};

function sendEmpty(
  response: ServerResponse,
  status: number,
  headers: Record<string, string> = securityHeaders,
) {
  response.writeHead(status, { ...headers, "Content-Length": "0" });
  response.end();
}

function isMalformedPercentEncoding(rawUrl: string): boolean {
  const queryIndex = rawUrl.indexOf("?");
  if (queryIndex < 0) return false;
  return /%(?![0-9a-f]{2})/i.test(rawUrl.slice(queryIndex + 1));
}

function isSafeOpaqueValue(value: string, maximumLength: number): boolean {
  const hasUnsafeCharacter = [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127 || codePoint === 0xfffd;
  });
  return (
    value.length > 0 && value.length <= maximumLength && !hasUnsafeCharacter
  );
}

function isSafeErrorCode(value: string): boolean {
  return (
    value.length > 0 && value.length <= 256 && /^[A-Za-z0-9._~-]+$/.test(value)
  );
}

function isSafeIssuer(value: string): boolean {
  if (
    !isSafeOpaqueValue(value, 2048) ||
    !/^https:\/\//i.test(value) ||
    value !== value.trim() ||
    value.includes("?") ||
    value.includes("#")
  ) {
    return false;
  }
  try {
    const issuer = new URL(value);
    return (
      issuer.protocol === "https:" &&
      !issuer.username &&
      !issuer.password &&
      !issuer.search &&
      !issuer.hash
    );
  } catch {
    return false;
  }
}

function resolvePrivateCallbackUrl(env: NodeJS.ProcessEnv): URL | null {
  const appUrl = env.APP_URL;
  if (!appUrl) return null;
  try {
    const parsed = new URL(appUrl);
    if (
      (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash
    ) {
      return null;
    }
    return new URL(`${appUrl.replace(/\/$/, "")}${CALLBACK_PATH}`);
  } catch {
    return null;
  }
}

function parseCallback(requestUrl: string, url: URL): URLSearchParams | null {
  if (isMalformedPercentEncoding(requestUrl)) return null;

  const keys = [...url.searchParams.keys()];
  const hasCallbackQuery = keys.length > 0;
  if (!hasCallbackQuery) return new URLSearchParams();

  const codeValues = url.searchParams.getAll("code");
  const stateValues = url.searchParams.getAll("state");
  const errorValues = url.searchParams.getAll("error");
  const descriptionValues = url.searchParams.getAll("error_description");
  const issuerValues = url.searchParams.getAll("iss");
  const allowed =
    codeValues.length > 0
      ? new Set(["code", "state", "iss"])
      : new Set(["error", "error_description", "state", "iss"]);

  if (
    keys.some((key) => !allowed.has(key)) ||
    stateValues.length !== 1 ||
    codeValues.length > 1 ||
    errorValues.length > 1 ||
    descriptionValues.length > 1 ||
    issuerValues.length > 1 ||
    (codeValues.length === 1) === (errorValues.length === 1)
  ) {
    return null;
  }

  const state = stateValues[0];
  if (
    !state ||
    !isSafeOpaqueValue(state, 4096) ||
    parseUpstreamState(state) === null
  )
    return null;

  const output = new URLSearchParams();
  if (codeValues.length === 1) {
    const code = codeValues[0];
    if (!code || !isSafeOpaqueValue(code, 8192)) return null;
    output.set("code", code);
  } else {
    const error = errorValues[0];
    if (!error || !isSafeErrorCode(error)) return null;
    output.set("error", error);
    if (descriptionValues.length === 1) {
      const description = descriptionValues[0];
      if (!description || !isSafeOpaqueValue(description, 2048)) return null;
      output.set("error_description", description);
    }
  }
  output.set("state", state);
  if (issuerValues.length === 1) {
    const issuer = issuerValues[0];
    if (!issuer || !isSafeIssuer(issuer)) return null;
    output.set("iss", issuer);
  }
  return output;
}

export function createOAuthPublicGateway(options: GatewayOptions = {}) {
  const env = options.env ?? process.env;
  const logger = options.logger ?? console;

  return createServer((request: IncomingMessage, response: ServerResponse) => {
    const requestUrl = request.url ?? "/";
    const queryIndex = requestUrl.indexOf("?");
    const rawPath =
      queryIndex < 0 ? requestUrl : requestUrl.slice(0, queryIndex);
    if (rawPath !== METADATA_PATH) {
      sendEmpty(response, 404);
      return;
    }

    let url: URL;
    try {
      url = new URL(requestUrl, "http://oauth-gateway.invalid");
    } catch {
      sendEmpty(response, 400, callbackHeaders);
      return;
    }

    let clientMetadataUrl: string | undefined;
    try {
      clientMetadataUrl = resolveOAuthClientMetadataUrl(env);
    } catch {
      logger.error(
        "OAuth public gateway metadata URL configuration is invalid",
      );
      sendEmpty(response, 500, callbackHeaders);
      return;
    }
    if (!clientMetadataUrl) {
      sendEmpty(
        response,
        404,
        url.searchParams.size > 0 ? callbackHeaders : securityHeaders,
      );
      return;
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
      sendEmpty(response, 405, callbackHeaders);
      return;
    }

    const callbackParams = parseCallback(requestUrl, url);
    if (
      callbackParams === null ||
      (request.method === "HEAD" && callbackParams.size > 0)
    ) {
      sendEmpty(response, 400, callbackHeaders);
      return;
    }

    if (callbackParams.size > 0) {
      const callbackUrl = resolvePrivateCallbackUrl(env);
      if (!callbackUrl) {
        logger.error("OAuth public gateway APP_URL configuration is invalid");
        sendEmpty(response, 500, callbackHeaders);
        return;
      }
      callbackUrl.search = callbackParams.toString();
      response.writeHead(303, {
        ...callbackHeaders,
        "Content-Length": "0",
        Location: callbackUrl.href,
      });
      response.end();
      return;
    }

    const body = JSON.stringify({
      client_id: clientMetadataUrl,
      client_name: "MetaMCP",
      redirect_uris: [clientMetadataUrl],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    });
    response.writeHead(200, {
      ...metadataHeaders,
      "Content-Length": String(Buffer.byteLength(body)),
    });
    response.end(request.method === "HEAD" ? undefined : body);
  });
}

function resolveGatewayPort(env: NodeJS.ProcessEnv): number {
  const raw = env.OAUTH_PUBLIC_GATEWAY_PORT ?? "12010";
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(
      "OAUTH_PUBLIC_GATEWAY_PORT must be an integer from 1 to 65535",
    );
  }
  return port;
}

function isMainModule(): boolean {
  const entry = process.argv[1];
  return Boolean(entry && pathToFileURL(entry).href === import.meta.url);
}

if (isMainModule()) {
  const port = resolveGatewayPort(process.env);
  const server = createOAuthPublicGateway();
  server.listen(port, "0.0.0.0", () => {
    console.info(`OAuth public gateway listening on port ${port}`);
  });
}
