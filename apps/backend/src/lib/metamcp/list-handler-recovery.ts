import { ServerParameters } from "@repo/zod-types";

import logger from "@/utils/logger";

import { oauthSessionsRepository } from "../../db/repositories";
import { tryRefreshUpstreamTokens } from "../oauth-upstream/refresh-on-401";
import { ConnectedClient } from "./client";
import { isRecoverableBackendError } from "./session-error";

function isRejectedOAuthToken(error: unknown): boolean {
  return (
    error instanceof Error &&
    /Invalid or expired OAuth access token/i.test(error.message)
  );
}

/**
 * Minimal slice of McpServerPool the recovery wrapper needs. Structural
 * so tests can drive the wrapper with a fake pool.
 */
export interface RecoverySessionPool {
  invalidateServerConnection(
    sessionId: string,
    serverUuid: string,
    oauthUserId?: string,
  ): Promise<void>;
  getSession(
    sessionId: string,
    serverUuid: string,
    params: ServerParameters,
    namespaceUuid?: string,
  ): Promise<ConnectedClient | undefined>;
}

export interface RequestWithSessionRecoveryOptions<T> {
  pool: RecoverySessionPool;
  sessionId: string;
  serverUuid: string;
  params: ServerParameters;
  namespaceUuid?: string;
  /** Operation label for log lines, e.g. "tools/list". */
  operation: string;
  /** Human-readable server name for log lines. */
  serverName: string;
  /** The (possibly stale) pooled session the caller already holds. */
  session: ConnectedClient;
  /**
   * The actual backend request(s). Re-invoked exactly once on a fresh
   * session if the first invocation loses its backend connection or the
   * upstream rejects a refreshable OAuth access token.
   */
  attempt: (session: ConnectedClient) => Promise<T>;
  /**
   * Called when recovery swapped in a fresh session — lets the caller
   * repoint tool/prompt/resource maps to the new client.
   */
  onFreshSession?: (session: ConnectedClient) => void;
}

/**
 * Invalidate-and-retry-once recovery cascade for the per-server fetch
 * inside the aggregate list handlers (tools/list, prompts/list,
 * resources/list, resources/templates/list).
 *
 * The aggregate list handlers previously logged-and-continued in their
 * catch blocks, so a dead pooled session (e.g. after a restart of the
 * backend container) made the namespace return a "successful" 0-tool
 * response on every request, forever — the swallowed error meant the
 * zombie connection was never invalidated. A pooled OAuth connection can
 * likewise outlive an upstream access token despite its recorded expiry.
 * On the upstream's explicit invalid-token error, refresh credentials
 * before rebuilding the connection.
 *
 * Throws when the error is non-recoverable, when no fresh session could
 * be established, or when the retry on the fresh session fails — the
 * caller decides whether that excludes one server from an aggregate
 * response (and tracks it as degraded) or fails the request.
 */
export async function requestWithSessionRecovery<T>(
  opts: RequestWithSessionRecoveryOptions<T>,
): Promise<T> {
  try {
    return await opts.attempt(opts.session);
  } catch (error) {
    const backendConnectionLost = isRecoverableBackendError(error);
    if (!backendConnectionLost) {
      const oauthUserId = opts.params.oauth_user_id;
      if (
        (opts.params.type !== "SSE" &&
          opts.params.type !== "STREAMABLE_HTTP") ||
        !oauthUserId ||
        !opts.params.oauth_tokens?.refresh_token ||
        !isRejectedOAuthToken(error)
      ) {
        throw error;
      }

      const currentSession =
        await oauthSessionsRepository.findByMcpServerAndUser(
          opts.serverUuid,
          oauthUserId,
        );
      const storedTokens = currentSession?.tokens;
      let nextTokens = storedTokens;
      if (
        !storedTokens?.access_token ||
        storedTokens.access_token === opts.params.oauth_tokens?.access_token
      ) {
        const refresh = await tryRefreshUpstreamTokens(opts.params);
        if (refresh.status !== "refreshed" || !refresh.tokens) throw error;
        nextTokens = refresh.tokens;
      }
      if (!nextTokens) throw error;
      opts.params.oauth_tokens = {
        access_token: nextTokens.access_token,
        token_type: nextTokens.token_type,
        expires_in: nextTokens.expires_in,
        expires_at: nextTokens.expires_at,
        scope: nextTokens.scope,
        refresh_token: nextTokens.refresh_token,
      };
    }

    logger.warn(
      `${backendConnectionLost ? "Backend connection lost" : "Upstream OAuth token rejected"} for server ${opts.serverUuid} (${opts.serverName}) on ${opts.operation}; invalidating pool and retrying once.`,
    );

    if (backendConnectionLost) {
      await opts.pool.invalidateServerConnection(
        opts.sessionId,
        opts.serverUuid,
      );
    } else {
      await opts.pool.invalidateServerConnection(
        opts.sessionId,
        opts.serverUuid,
        opts.params.oauth_user_id,
      );
    }

    const fresh = await opts.pool.getSession(
      opts.sessionId,
      opts.serverUuid,
      opts.params,
      opts.namespaceUuid,
    );
    if (!fresh) {
      throw new Error(
        `Failed to re-initialize session for server ${opts.serverUuid} after recovery during ${opts.operation}`,
      );
    }

    opts.onFreshSession?.(fresh);
    return await opts.attempt(fresh);
  }
}
