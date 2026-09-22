const RECLAIM_MCP_HOSTNAME = "mcp.reclaim.ai";

export const RECLAIM_LOOPBACK_REDIRECT_URI =
  "http://127.0.0.1:33418/oauth/client-metadata";

export const RECLAIM_TUNNEL_COMMAND = "ssh -N -L 33418:127.0.0.1:12010 mimir";

export function getReclaimOAuthGuide({
  serverUrl,
  errorCode,
}: {
  serverUrl: string;
  errorCode?: string;
}) {
  if (errorCode !== "server_error") return null;

  try {
    if (new URL(serverUrl).hostname !== RECLAIM_MCP_HOSTNAME) return null;
  } catch {
    return null;
  }

  return {
    redirectUri: RECLAIM_LOOPBACK_REDIRECT_URI,
    tunnelCommand: RECLAIM_TUNNEL_COMMAND,
  };
}
