import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type {
  FetchLike,
  Transport,
} from "@modelcontextprotocol/sdk/shared/transport.js";
import type { Request } from "express";
import { z } from "zod";

import {
  mcpServersRepository,
  oauthSessionsRepository,
} from "../../db/repositories";
import { transformDockerUrl } from "../../lib/metamcp/client";
import { tryRefreshUpstreamTokens } from "../../lib/oauth-upstream/refresh-on-401";

export async function createDirectHttpTransport(
  req: Request,
): Promise<Transport> {
  const uuid = z.string().uuid().parse(req.query.mcp_server_uuid);
  const userId = (req as Request & { user?: { id: string } }).user?.id;
  if (!userId) throw new Error("Authentication required");
  const server = await mcpServersRepository.findByUuid(uuid);
  if (!server || (server.user_id && server.user_id !== userId))
    throw new Error("MCP server access denied");
  if (
    !server.url ||
    !["SSE", "STREAMABLE_HTTP"].includes(server.type) ||
    server.type !== req.query.transportType ||
    !/^https?:\/\//i.test(server.url)
  )
    throw new Error("Invalid MCP server transport");
  if (server.error_status === "ERROR")
    throw new Error("MCP server is in error state");
  const url = new URL(transformDockerUrl(server.url));
  const refreshParams = {
    uuid,
    name: server.name,
    url: server.url,
    oauth_user_id: userId,
  };
  const authenticatedFetch: FetchLike = async (input, init) => {
    // SDK endpoints must stay on the configured resource origin. No browser
    // URL, auth header, token endpoint, or OAuth credential is authoritative.
    const target = new URL(
      input instanceof globalThis.Request ? input.url : String(input),
    );
    if (target.origin !== url.origin)
      throw new Error("Unexpected upstream origin");
    let tokens = (
      await oauthSessionsRepository.findByMcpServerAndUser(uuid, userId)
    )?.tokens;
    let refreshUsed = false;
    if (
      tokens?.refresh_token &&
      typeof tokens.expires_at === "number" &&
      tokens.expires_at <= Date.now() + 60000
    ) {
      refreshUsed = true;
      const refreshed = await tryRefreshUpstreamTokens(refreshParams);
      if (refreshed.status === "refreshed") tokens = refreshed.tokens;
    }
    const send = () => {
      const headers = new Headers(init?.headers);
      for (const [name, value] of Object.entries(server.headers ?? {}))
        headers.set(name, value);
      const token = tokens?.access_token || server.bearerToken;
      if (token) headers.set("Authorization", `Bearer ${token}`);
      return fetch(input, { ...init, headers });
    };
    const response = await send();
    if (response.status !== 401 || refreshUsed || !tokens?.refresh_token)
      return response;
    const refreshed = await tryRefreshUpstreamTokens(refreshParams);
    if (refreshed.status !== "refreshed" || !refreshed.tokens) return response;
    await response.body?.cancel();
    tokens = refreshed.tokens;
    return send();
  };
  const transport =
    server.type === "SSE"
      ? new SSEClientTransport(url, { fetch: authenticatedFetch })
      : new StreamableHTTPClientTransport(url, { fetch: authenticatedFetch });
  try {
    await transport.start();
    return transport;
  } catch (error) {
    await transport.close();
    throw error;
  }
}
