import { ServerParameters } from "@repo/zod-types";

import logger from "@/utils/logger";

import { configService } from "../config.service";
import { ConnectedClient, connectMetaMcpClient } from "./client";
import { serverRequiresForwardedHeaders } from "./header-forwarding";
import { metamcpLogStore } from "./log-store";
import { serverErrorTracker } from "./server-error-tracker";

const CONNECTION_KEY_SEPARATOR = "\u0000";

function connectionKey(
  serverUuid: string,
  oauthUserId?: string | null,
): string {
  return `${serverUuid}${CONNECTION_KEY_SEPARATOR}${oauthUserId ?? ""}`;
}

function connectionKeyBelongsToServer(
  cacheKey: string,
  serverUuid: string,
): boolean {
  return cacheKey.startsWith(`${serverUuid}${CONNECTION_KEY_SEPARATOR}`);
}

function serverUuidFromConnectionKey(cacheKey: string): string {
  return cacheKey.split(CONNECTION_KEY_SEPARATOR, 1)[0];
}

export interface McpServerPoolStatus {
  idle: number;
  active: number;
  activeSessionIds: string[];
  idleServerUuids: string[];
  perServerCounts?: Record<string, number>;
  maxConnectionsPerServer?: number;
}

export class McpServerPool {
  // Singleton instance
  private static instance: McpServerPool | null = null;

  // Idle sessions: (serverUuid, OAuth principal) -> ConnectedClient.
  private idleSessions: Record<string, ConnectedClient> = {};

  // Active sessions: sessionId -> Record<(serverUuid, OAuth principal), client>
  private activeSessions: Record<string, Record<string, ConnectedClient>> = {};

  // Mapping: sessionId -> Set<(serverUuid, OAuth principal)> for cleanup tracking
  private sessionToServers: Record<string, Set<string>> = {};

  // Session creation timestamps: sessionId -> timestamp
  private sessionTimestamps: Record<string, number> = {};

  // Server parameters cache: (serverUuid, OAuth principal) -> parameters.
  private serverParamsCache: Record<string, ServerParameters> = {};

  // Track ongoing idle session creation to prevent duplicates
  private creatingIdleSessions: Set<string> = new Set();

  // Generation counter per server UUID: incremented by invalidateIdleSession() so
  // any in-flight createIdleSession / createIdleSessionAsync that resolves with a
  // stale generation knows to discard its result instead of storing it.
  private idleSessionGenerations: Record<string, number> = {};

  // Session cleanup timer
  private cleanupTimer: NodeJS.Timeout | null = null;

  // Health check timer for idle sessions
  private healthCheckTimer: NodeJS.Timeout | null = null;

  // Background idle sessions by namespace: namespaceUuid -> any
  private backgroundIdleSessionsByNamespace: Map<string, Map<string, unknown>> =
    new Map();

  // Default number of idle sessions per server UUID
  private readonly defaultIdleCount: number;

  // Maximum total connections (idle + active) to prevent runaway process spawning
  private readonly maxTotalConnections: number;

  // Maximum connections per individual server UUID (prevents per-server process explosion)
  private readonly maxConnectionsPerServer: number;

  private constructor(
    defaultIdleCount: number = 1,
    maxTotalConnections: number = parseInt(
      process.env.MAX_TOTAL_CONNECTIONS || "100",
      10,
    ),
    maxConnectionsPerServer: number = 5,
  ) {
    this.defaultIdleCount = defaultIdleCount;
    this.maxTotalConnections = maxTotalConnections;
    this.maxConnectionsPerServer = maxConnectionsPerServer;
    this.startCleanupTimer();
    this.startHealthCheckTimer();
  }

  /**
   * Get the singleton instance
   */
  static getInstance(
    defaultIdleCount: number = 1,
    maxConnectionsPerServer: number = 5,
  ): McpServerPool {
    if (!McpServerPool.instance) {
      const envMax = parseInt(process.env.MAX_TOTAL_CONNECTIONS || "", 10);
      const maxConn = Number.isFinite(envMax) && envMax > 0 ? envMax : 100;
      McpServerPool.instance = new McpServerPool(
        defaultIdleCount,
        maxConn,
        maxConnectionsPerServer,
      );
    }
    return McpServerPool.instance;
  }

  private getKnownConnectionKeysForServer(serverUuid: string): Set<string> {
    const keys = new Set<string>([
      ...Object.keys(this.idleSessions),
      ...Object.keys(this.serverParamsCache),
      ...Object.keys(this.idleSessionGenerations),
      ...this.creatingIdleSessions,
    ]);
    for (const sessionServers of Object.values(this.activeSessions)) {
      for (const cacheKey of Object.keys(sessionServers)) {
        keys.add(cacheKey);
      }
    }
    return new Set(
      [...keys].filter((cacheKey) =>
        connectionKeyBelongsToServer(cacheKey, serverUuid),
      ),
    );
  }

  /**
   * Count all connections (idle + active + pending) for a specific server UUID
   */
  private countConnectionsForServer(serverUuid: string): number {
    let count = 0;

    count += Object.keys(this.idleSessions).filter((cacheKey) =>
      connectionKeyBelongsToServer(cacheKey, serverUuid),
    ).length;

    // Count active sessions across all sessionIds
    for (const sessionServers of Object.values(this.activeSessions)) {
      count += Object.keys(sessionServers).filter((cacheKey) =>
        connectionKeyBelongsToServer(cacheKey, serverUuid),
      ).length;
    }

    // Count pending idle creation
    count += [...this.creatingIdleSessions].filter((cacheKey) =>
      connectionKeyBelongsToServer(cacheKey, serverUuid),
    ).length;

    return count;
  }

  /**
   * Check if we can create another connection for a specific server
   */
  private canCreateConnectionForServer(serverUuid: string): boolean {
    const count = this.countConnectionsForServer(serverUuid);
    if (count >= this.maxConnectionsPerServer) {
      logger.warn(
        `Per-server connection limit reached for ${serverUuid}: ${count}/${this.maxConnectionsPerServer}`,
      );
      return false;
    }
    return true;
  }

  /**
   * Find the oldest active connection for a server UUID (for reuse when at cap)
   */
  private findOldestActiveConnectionForKey(
    cacheKey: string,
  ): ConnectedClient | undefined {
    let oldestSessionId: string | undefined;
    let oldestTimestamp = Infinity;

    for (const [sessionId, sessionServers] of Object.entries(
      this.activeSessions,
    )) {
      if (sessionServers[cacheKey]) {
        const timestamp = this.sessionTimestamps[sessionId] || Infinity;
        if (timestamp < oldestTimestamp) {
          oldestTimestamp = timestamp;
          oldestSessionId = sessionId;
        }
      }
    }

    if (oldestSessionId) {
      return this.activeSessions[oldestSessionId]?.[cacheKey];
    }
    return undefined;
  }

  /**
   * Get or create a session for a specific MCP server
   */
  async getSession(
    sessionId: string,
    serverUuid: string,
    params: ServerParameters,
    namespaceUuid?: string,
  ): Promise<ConnectedClient | undefined> {
    const cacheKey = connectionKey(serverUuid, params.oauth_user_id);
    // Update server params cache
    this.serverParamsCache[cacheKey] = params;

    // Check if we already have an active session for this sessionId and server
    if (this.activeSessions[sessionId]?.[cacheKey]) {
      // Touch timestamp on every access so SESSION_LIFETIME acts as idle timeout, not hard TTL
      this.sessionTimestamps[sessionId] = Date.now();
      return this.activeSessions[sessionId][cacheKey];
    }

    // Initialize session if it doesn't exist
    if (!this.activeSessions[sessionId]) {
      this.activeSessions[sessionId] = {};
      this.sessionToServers[sessionId] = new Set();
      this.sessionTimestamps[sessionId] = Date.now();
    }

    // Check if we have an idle session for this server that we can convert.
    // Skip idle reuse for servers with forward_headers since each client may
    // need unique credentials forwarded to the backend MCP server.
    if (!serverRequiresForwardedHeaders(params)) {
      const idleClient = this.idleSessions[cacheKey];
      if (idleClient) {
        // Convert idle session to active session
        delete this.idleSessions[cacheKey];
        this.activeSessions[sessionId][cacheKey] = idleClient;
        this.sessionToServers[sessionId].add(cacheKey);

        logger.info(
          `Converted idle session to active for server ${serverUuid}, session ${sessionId}`,
        );

        // Create a new idle session to replace the one we just used (ASYNC - NON-BLOCKING)
        this.createIdleSessionAsync(serverUuid, params, namespaceUuid);

        return idleClient;
      }
    }

    // No idle session available — check per-server cap before spawning
    if (!this.canCreateConnectionForServer(serverUuid)) {
      // At cap: reuse the oldest active connection instead of spawning
      const reusable = this.findOldestActiveConnectionForKey(cacheKey);
      if (reusable) {
        logger.info(
          `Reusing existing connection for server ${serverUuid} (at per-server cap ${this.maxConnectionsPerServer})`,
        );
        this.activeSessions[sessionId][cacheKey] = reusable;
        this.sessionToServers[sessionId].add(cacheKey);
        return reusable;
      }
      logger.warn(
        `Per-server connection limit reached for ${serverUuid}, but no connection exists for the requested OAuth principal`,
      );
      return undefined;
    }

    const newClient = await this.createNewConnection(params, namespaceUuid);
    if (!newClient) {
      return undefined;
    }

    // Re-check after the async gap: a concurrent getSession() call for the same
    // (sessionId, serverUuid) pair may have stored a connection while we were awaiting
    // createNewConnection(). If so, discard ours to avoid leaking the spawned process.
    if (this.activeSessions[sessionId]?.[cacheKey]) {
      newClient.cleanup().catch((error) => {
        logger.error(
          `Error cleaning up duplicate connection for server ${params.uuid}:`,
          error,
        );
      });
      return this.activeSessions[sessionId][cacheKey];
    }

    this.activeSessions[sessionId][cacheKey] = newClient;
    this.sessionToServers[sessionId].add(cacheKey);

    logger.info(
      `Created new active session for server ${serverUuid}, session ${sessionId}`,
    );

    // Only pre-warm idle pool for servers that don't require forwarded headers.
    // Idle sessions are created without per-client headers, so they can't be
    // reused when per-client header forwarding is configured.
    if (!serverRequiresForwardedHeaders(params)) {
      this.createIdleSessionAsync(serverUuid, params, namespaceUuid);
    }

    return newClient;
  }

  /**
   * Create a new connection for a server
   */
  private async createNewConnection(
    params: ServerParameters,
    namespaceUuid?: string,
  ): Promise<ConnectedClient | undefined> {
    // Check connection limit before attempting to create
    if (!this.canCreateConnection()) {
      logger.warn(
        `Skipping connection for server ${params.name} (${params.uuid}) - connection limit reached`,
      );
      return undefined;
    }

    logger.info(
      `Creating new connection for server ${params.name} (${params.uuid}) with namespace: ${namespaceUuid || "none"}`,
    );
    metamcpLogStore.addLog(
      params.name,
      "info",
      `Creating new connection for namespace ${namespaceUuid || "none"}`,
    );

    const connectedClient = await connectMetaMcpClient(
      params,
      (exitCode, signal) => {
        logger.info(
          `Crash handler callback called for server ${params.name} (${params.uuid}) with namespace: ${namespaceUuid || "none"}`,
        );

        // Handle process crash - always set up crash handler
        if (namespaceUuid) {
          // If we have a namespace context, use it
          this.handleServerCrash(
            params.uuid,
            namespaceUuid,
            exitCode,
            signal,
          ).catch((error) => {
            logger.error(
              `Error handling server crash for ${params.uuid} in ${namespaceUuid}:`,
              error,
            );
          });
        } else {
          // If no namespace context, still track the crash globally
          this.handleServerCrashWithoutNamespace(
            params.uuid,
            exitCode,
            signal,
          ).catch((error) => {
            logger.error(
              `Error handling server crash for ${params.uuid} (no namespace):`,
              error,
            );
          });
        }
      },
    );
    if (!connectedClient) {
      return undefined;
    }

    return connectedClient;
  }

  /**
   * Create an idle session for a server (blocking version for initial setup)
   */
  private async createIdleSession(
    serverUuid: string,
    params: ServerParameters,
    namespaceUuid?: string,
  ): Promise<void> {
    const cacheKey = connectionKey(serverUuid, params.oauth_user_id);
    // Don't create if we already have an idle session or are already creating one.
    // Both checks are synchronous (before any await) so they act as a pre-await
    // mutex, matching the pattern used by createIdleSessionAsync.
    if (
      this.idleSessions[cacheKey] ||
      this.creatingIdleSessions.has(cacheKey)
    ) {
      return;
    }

    // Don't create if at per-server cap
    if (!this.canCreateConnectionForServer(serverUuid)) {
      return;
    }

    this.creatingIdleSessions.add(cacheKey);
    const generation = this.idleSessionGenerations[cacheKey] ?? 0;

    try {
      const newClient = await this.createNewConnection(params, namespaceUuid);
      if (newClient) {
        const currentGeneration = this.idleSessionGenerations[cacheKey] ?? 0;
        if (!this.idleSessions[cacheKey] && currentGeneration === generation) {
          this.idleSessions[cacheKey] = newClient;
          logger.info(`Created idle session for server ${serverUuid}`);
          metamcpLogStore.addLog(
            params.name,
            "info",
            `Created idle session for server ${serverUuid}`,
          );
        } else {
          // Either a concurrent call already stored an idle session, or
          // invalidateIdleSession() bumped the generation while we were awaiting,
          // meaning our result is stale. Discard it.
          newClient.cleanup().catch((error) => {
            logger.error(
              `Error cleaning up duplicate idle session for ${serverUuid}:`,
              error,
            );
          });
        }
      }
    } finally {
      // Only release the guard if we're still the current creation for this
      // server. If the generation was bumped while we were awaiting (e.g. by
      // invalidateIdleSession), the guard now belongs to the newer creation
      // and must not be removed here.
      if ((this.idleSessionGenerations[cacheKey] ?? 0) === generation) {
        this.creatingIdleSessions.delete(cacheKey);
      }
    }
  }

  /**
   * Create an idle session for a server asynchronously (non-blocking)
   */
  private createIdleSessionAsync(
    serverUuid: string,
    params: ServerParameters,
    namespaceUuid?: string,
  ): void {
    const cacheKey = connectionKey(serverUuid, params.oauth_user_id);
    // Don't create if we already have an idle session or are already creating one
    if (
      this.idleSessions[cacheKey] ||
      this.creatingIdleSessions.has(cacheKey)
    ) {
      return;
    }

    // Check per-server cap before spawning a background idle
    if (!this.canCreateConnectionForServer(serverUuid)) {
      return;
    }

    // Mark that we're creating an idle session for this server
    this.creatingIdleSessions.add(cacheKey);
    const generation = this.idleSessionGenerations[cacheKey] ?? 0;

    // Create the session in the background (fire and forget)
    this.createNewConnection(params, namespaceUuid)
      .then((newClient) => {
        const currentGeneration = this.idleSessionGenerations[cacheKey] ?? 0;
        if (
          newClient &&
          !this.idleSessions[cacheKey] &&
          currentGeneration === generation
        ) {
          this.idleSessions[cacheKey] = newClient;
          logger.info(
            `Created background idle session for server [${params.name}] ${serverUuid}`,
          );
          metamcpLogStore.addLog(
            params.name,
            "info",
            `Created background idle session for server ${serverUuid}`,
          );
          if (namespaceUuid) {
            this.setBackgroundIdleSessionsByNamespace(
              namespaceUuid,
              new Map().set("status", "created"),
            );
          }
        } else if (newClient) {
          // Either we already have an idle session, or invalidateIdleSession()
          // bumped the generation while we were awaiting (stale result). Discard it.
          newClient.cleanup().catch((error) => {
            logger.error(
              `Error cleaning up extra idle session for ${serverUuid}:`,
              error,
            );
          });
        }
      })
      .catch((error) => {
        logger.error(
          `Error creating background idle session for ${serverUuid}:`,
          error,
        );
      })
      .finally(() => {
        // Only release the guard if we're still the current creation for this
        // server. If the generation was bumped while we were awaiting (e.g. by
        // invalidateIdleSession), the guard now belongs to the newer creation
        // and must not be removed here.
        if ((this.idleSessionGenerations[cacheKey] ?? 0) === generation) {
          this.creatingIdleSessions.delete(cacheKey);
        }
      });
  }

  /**
   * Ensure idle sessions exist for all servers
   */
  async ensureIdleSessions(
    serverParams: Record<string, ServerParameters>,
    namespaceUuid?: string,
  ): Promise<void> {
    const promises = Object.entries(serverParams).map(
      async ([uuid, params]) => {
        const cacheKey = connectionKey(uuid, params.oauth_user_id);
        if (!this.idleSessions[cacheKey]) {
          await this.createIdleSession(uuid, params, namespaceUuid);
        }
      },
    );

    await Promise.allSettled(promises);
  }

  /**
   * Cleanup a session by sessionId.
   * Recycles healthy connections back to the idle pool instead of destroying them.
   */
  async cleanupSession(sessionId: string): Promise<void> {
    const activeSession = this.activeSessions[sessionId];
    if (!activeSession) {
      return;
    }

    let recycled = 0;
    let destroyed = 0;

    // Try to recycle each connection back to idle pool
    for (const [cacheKey, client] of Object.entries(activeSession)) {
      const serverUuid = serverUuidFromConnectionKey(cacheKey);
      if (!this.idleSessions[cacheKey]) {
        // No idle session for this server — recycle the connection
        this.idleSessions[cacheKey] = client;
        recycled++;
        logger.info(
          `Recycled active connection for server ${serverUuid} to idle pool (session ${sessionId})`,
        );
      } else {
        // Already have an idle session — destroy the extra
        try {
          await client.cleanup();
        } catch (error) {
          logger.error(
            `Error cleaning up extra connection for server ${serverUuid}:`,
            error,
          );
        }
        destroyed++;
      }
    }

    // Remove from active sessions
    delete this.activeSessions[sessionId];

    // Clean up session timestamp
    delete this.sessionTimestamps[sessionId];

    // Clean up session to servers mapping
    delete this.sessionToServers[sessionId];

    logger.info(
      `Cleaned up session ${sessionId} (recycled: ${recycled}, destroyed: ${destroyed})`,
    );
  }

  /**
   * Cleanup all sessions
   */
  async cleanupAll(): Promise<void> {
    // Cleanup all active sessions
    const activeSessionIds = Object.keys(this.activeSessions);
    await Promise.allSettled(
      activeSessionIds.map((sessionId) => this.cleanupSession(sessionId)),
    );

    // Cleanup all idle sessions
    await Promise.allSettled(
      Object.entries(this.idleSessions).map(async ([_uuid, client]) => {
        await client.cleanup();
      }),
    );

    // Clear all state
    this.idleSessions = {};
    this.activeSessions = {};
    this.sessionToServers = {};
    this.sessionTimestamps = {};
    this.serverParamsCache = {};

    // Bump all known generations (never reset to {}) so any in-flight idle
    // creation that started before cleanupAll() resolves with a stale value
    // and discards itself. Cover both tracked entries and UUIDs that are only
    // in creatingIdleSessions (which default to 0 and have no map entry yet).
    for (const uuid of new Set([
      ...Object.keys(this.idleSessionGenerations),
      ...this.creatingIdleSessions,
    ])) {
      this.idleSessionGenerations[uuid] =
        (this.idleSessionGenerations[uuid] ?? 0) + 1;
    }
    this.creatingIdleSessions.clear();

    // Clear cleanup timer
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }

    // Clear health check timer
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = null;
    }

    logger.info("Cleaned up all MCP server pool sessions");
  }

  /**
   * Get pool status for monitoring
   */
  getPoolStatus(): McpServerPoolStatus {
    const idle = Object.keys(this.idleSessions).length;
    const active = Object.keys(this.activeSessions).reduce(
      (total, sessionId) =>
        total + Object.keys(this.activeSessions[sessionId]).length,
      0,
    );

    // Calculate per-server breakdown
    const perServerCounts: Record<string, number> = {};
    const cachedServerUuids = new Set(
      Object.keys(this.serverParamsCache).map(serverUuidFromConnectionKey),
    );
    for (const serverUuid of cachedServerUuids) {
      perServerCounts[serverUuid] = this.countConnectionsForServer(serverUuid);
    }

    return {
      idle,
      active,
      activeSessionIds: Object.keys(this.activeSessions),
      idleServerUuids: [
        ...new Set(
          Object.keys(this.idleSessions).map(serverUuidFromConnectionKey),
        ),
      ],
      perServerCounts,
      maxConnectionsPerServer: this.maxConnectionsPerServer,
    };
  }

  /**
   * Get total connection count (idle + active + pending)
   */
  private getTotalConnectionCount(): number {
    const idle = Object.keys(this.idleSessions).length;
    const active = Object.keys(this.activeSessions).reduce(
      (total, sessionId) =>
        total + Object.keys(this.activeSessions[sessionId]).length,
      0,
    );
    const pending = this.creatingIdleSessions.size;
    return idle + active + pending;
  }

  /**
   * Check if we can create a new connection (respects maxTotalConnections limit)
   */
  private canCreateConnection(): boolean {
    const total = this.getTotalConnectionCount();
    if (total >= this.maxTotalConnections) {
      logger.warn(
        `Connection limit reached: ${total}/${this.maxTotalConnections}. Refusing to create new connection.`,
      );
      return false;
    }
    return true;
  }

  /**
   * Get active session connections for a specific session (for debugging/monitoring)
   */
  getSessionConnections(
    sessionId: string,
  ): Record<string, ConnectedClient> | undefined {
    return this.activeSessions[sessionId];
  }

  /**
   * Get all active session IDs (for debugging/monitoring)
   */
  getActiveSessionIds(): string[] {
    return Object.keys(this.activeSessions);
  }

  /**
   * Get background idle sessions by namespace
   */
  getBackgroundIdleSessionsByNamespace(): Map<string, Map<string, unknown>> {
    return this.backgroundIdleSessionsByNamespace;
  }

  /**
   * Set background idle sessions by namespace
   */
  setBackgroundIdleSessionsByNamespace(
    namespaceUuid: string,
    options: Map<string, unknown>,
  ): void {
    this.backgroundIdleSessionsByNamespace.set(namespaceUuid, options);
  }

  /**
   * Drop the pooled backend connection(s) for a given serverUuid.
   *
   * Used when a backend MCP server reports our Mcp-Session-Id is unknown
   * or our transport is dead (e.g. after the backend container restarts and
   * loses its in-memory session registry, or a Watchtower swap kills the
   * socket). No replacement is created here; the next `getSession` call
   * establishes a fresh connection (and therefore a fresh backend session)
   * on demand.
   *
   * The invalidation CASCADES across every session's slot for the affected
   * serverUuid, not just the triggering session's slot, plus the idle slot.
   * When a backend container restarts, EVERY cached ConnectedClient for that
   * serverUuid is dead — stale clients left in sibling sessions' slots for
   * the same backend would defeat a single-slot invalidation: a later
   * `getSession` for one of those siblings would hand back a dead client and
   * the retry would fail with the same envelope that triggered recovery. So
   * we drop them all.
   */
  async invalidateServerConnection(
    sessionId: string,
    serverUuid: string,
  ): Promise<void> {
    // Collect every doomed ConnectedClient across all active sessions plus
    // the idle slot, dropping the map entries as we go.
    const cleanupPromises: Promise<void>[] = [];

    for (const [sid, sessionServers] of Object.entries(this.activeSessions)) {
      for (const [cacheKey, cachedClient] of Object.entries(sessionServers)) {
        if (!connectionKeyBelongsToServer(cacheKey, serverUuid)) {
          continue;
        }
        // Each cleanup is wrapped so one failure can't strand the rest — we
        // WANT every stale slot dropped from the map regardless.
        cleanupPromises.push(
          (async () => {
            try {
              await cachedClient.cleanup();
            } catch (error) {
              logger.error(
                `Error cleaning up invalidated active session ${sid}/${serverUuid}:`,
                error,
              );
            }
          })(),
        );
        delete sessionServers[cacheKey];
        this.sessionToServers[sid]?.delete(cacheKey);
      }
    }

    for (const [cacheKey, idleClient] of Object.entries(this.idleSessions)) {
      if (!connectionKeyBelongsToServer(cacheKey, serverUuid)) {
        continue;
      }
      cleanupPromises.push(
        (async () => {
          try {
            await idleClient.cleanup();
          } catch (error) {
            logger.error(
              `Error cleaning up invalidated idle session for ${serverUuid}:`,
              error,
            );
          }
        })(),
      );
      delete this.idleSessions[cacheKey];
    }

    // Drop the in-flight idle-creation guard so the recovery's getSession
    // call isn't blocked from spawning a fresh connection.
    for (const cacheKey of this.getKnownConnectionKeysForServer(serverUuid)) {
      this.idleSessionGenerations[cacheKey] =
        (this.idleSessionGenerations[cacheKey] ?? 0) + 1;
      this.creatingIdleSessions.delete(cacheKey);
    }

    await Promise.all(cleanupPromises);

    if (cleanupPromises.length > 0) {
      logger.warn(
        `Invalidated ${cleanupPromises.length} pooled backend connection(s) for server ${serverUuid} ` +
          `(triggered by session ${sessionId}; cascaded across every active + idle slot for this serverUuid)`,
      );
    } else {
      logger.warn(
        `Invalidated pooled backend connection for server ${serverUuid} (session ${sessionId}) — no clients were cached`,
      );
    }
  }

  /**
   * Invalidate and refresh idle session for a specific server
   * This should be called when a server's parameters (command, args, etc.) change
   */
  async invalidateIdleSession(
    serverUuid: string,
    params: ServerParameters,
    namespaceUuid?: string,
  ): Promise<void> {
    logger.info(`Invalidating idle session for server ${serverUuid}`);

    // An administrative server update changes connection parameters for every
    // principal. This is deliberately separate from recovery invalidation so
    // its cleanup and logging retain administrative semantics.
    const activeClients = new Set<ConnectedClient>();
    for (const [sessionId, sessionServers] of Object.entries(
      this.activeSessions,
    )) {
      for (const [existingKey, client] of Object.entries(sessionServers)) {
        if (!connectionKeyBelongsToServer(existingKey, serverUuid)) {
          continue;
        }
        activeClients.add(client);
        delete sessionServers[existingKey];
        this.sessionToServers[sessionId]?.delete(existingKey);
      }
    }
    await Promise.all(
      [...activeClients].map(async (client) => {
        try {
          await client.cleanup();
        } catch (error) {
          logger.error(
            `Error cleaning up active connection during administrative update for ${serverUuid}:`,
            error,
          );
        }
      }),
    );

    const cacheKey = connectionKey(serverUuid, params.oauth_user_id);

    // Update server params cache
    this.serverParamsCache[cacheKey] = params;

    // A server configuration change invalidates every principal-scoped idle
    // connection for this server. A later namespace request repopulates its own
    // principal slot with freshly resolved parameters.
    for (const existingKey of this.getKnownConnectionKeysForServer(
      serverUuid,
    )) {
      const existingIdleSession = this.idleSessions[existingKey];
      if (existingKey !== cacheKey) {
        delete this.serverParamsCache[existingKey];
      }
      if (!existingIdleSession) {
        this.idleSessionGenerations[existingKey] =
          (this.idleSessionGenerations[existingKey] ?? 0) + 1;
        this.creatingIdleSessions.delete(existingKey);
        continue;
      }
      try {
        await existingIdleSession.cleanup();
        logger.info(
          `Cleaned up existing idle session for server ${serverUuid}`,
        );
      } catch (error) {
        logger.error(
          `Error cleaning up existing idle session for server ${serverUuid}:`,
          error,
        );
      }
      delete this.idleSessions[existingKey];
      this.idleSessionGenerations[existingKey] =
        (this.idleSessionGenerations[existingKey] ?? 0) + 1;
      this.creatingIdleSessions.delete(existingKey);
    }

    // Bump the generation before clearing the in-progress guard so any
    // in-flight createIdleSession / createIdleSessionAsync that resolves
    // after this point will see a stale generation and discard its result.
    this.idleSessionGenerations[cacheKey] =
      (this.idleSessionGenerations[cacheKey] ?? 0) + 1;
    this.creatingIdleSessions.delete(cacheKey);

    // Create a new idle session with updated parameters
    await this.createIdleSession(serverUuid, params, namespaceUuid);
  }

  /**
   * Invalidate and refresh idle sessions for multiple servers
   */
  async invalidateIdleSessions(
    serverParams: Record<string, ServerParameters>,
    namespaceUuid?: string,
  ): Promise<void> {
    const promises = Object.entries(serverParams).map(([serverUuid, params]) =>
      this.invalidateIdleSession(serverUuid, params, namespaceUuid),
    );

    await Promise.allSettled(promises);
  }

  /**
   * Clean up idle session for a specific server without creating a new one
   * This should be called when a server is being deleted
   */
  async cleanupIdleSession(serverUuid: string): Promise<void> {
    logger.info(`Cleaning up idle session for server ${serverUuid}`);

    for (const cacheKey of this.getKnownConnectionKeysForServer(serverUuid)) {
      const existingIdleSession = this.idleSessions[cacheKey];
      if (existingIdleSession) {
        try {
          await existingIdleSession.cleanup();
          logger.info(`Cleaned up idle session for server ${serverUuid}`);
        } catch (error) {
          logger.error(
            `Error cleaning up idle session for server ${serverUuid}:`,
            error,
          );
        }
        delete this.idleSessions[cacheKey];
      }

      // Bump rather than delete the generation entry. Deleting would reset the
      // effective value to 0 and could let an in-flight creation repopulate it.
      this.idleSessionGenerations[cacheKey] =
        (this.idleSessionGenerations[cacheKey] ?? 0) + 1;
      this.creatingIdleSessions.delete(cacheKey);

      delete this.serverParamsCache[cacheKey];
    }
  }

  /**
   * Ensure idle session exists for a newly created server
   * This should be called when a new server is created
   */
  async ensureIdleSessionForNewServer(
    serverUuid: string,
    params: ServerParameters,
    namespaceUuid?: string,
  ): Promise<void> {
    logger.info(`Ensuring idle session exists for new server ${serverUuid}`);

    const cacheKey = connectionKey(serverUuid, params.oauth_user_id);

    // Update server params cache
    this.serverParamsCache[cacheKey] = params;

    // Only create if we don't already have one
    if (
      !this.idleSessions[cacheKey] &&
      !this.creatingIdleSessions.has(cacheKey)
    ) {
      await this.createIdleSession(serverUuid, params, namespaceUuid);
    }
  }

  /**
   * Handle server process crash
   */
  async handleServerCrash(
    serverUuid: string,
    namespaceUuid: string,
    exitCode: number | null,
    signal: string | null,
  ): Promise<void> {
    logger.warn(
      `Handling server crash for ${serverUuid} in namespace ${namespaceUuid}`,
    );

    // Record the crash in the error tracker
    await serverErrorTracker.recordServerCrash(serverUuid, exitCode, signal);

    // Clean up any existing sessions for this server
    await this.cleanupServerSessions(serverUuid);
  }

  /**
   * Handle server process crash without namespace context
   * This is used when servers are created without a specific namespace
   */
  async handleServerCrashWithoutNamespace(
    serverUuid: string,
    exitCode: number | null,
    signal: string | null,
  ): Promise<void> {
    logger.warn(
      `Handling server crash for ${serverUuid} (no namespace context)`,
    );

    // Record the crash in the error tracker
    logger.info(`Recording crash for server ${serverUuid}`);
    await serverErrorTracker.recordServerCrash(serverUuid, exitCode, signal);

    // Clean up any existing sessions for this server
    await this.cleanupServerSessions(serverUuid);
  }

  /**
   * Clean up all sessions for a specific server
   */
  private async cleanupServerSessions(serverUuid: string): Promise<void> {
    // Bump generation and release the guard FIRST — before any await — so that
    // an in-flight idle creation that resolves during the cleanup loop below
    // (e.g. while we await an active-session cleanup) sees a stale generation
    // and discards its result instead of storing it into the now-empty slot.
    for (const cacheKey of this.getKnownConnectionKeysForServer(serverUuid)) {
      this.idleSessionGenerations[cacheKey] =
        (this.idleSessionGenerations[cacheKey] ?? 0) + 1;
      this.creatingIdleSessions.delete(cacheKey);

      const idleSession = this.idleSessions[cacheKey];
      if (idleSession) {
        try {
          await idleSession.cleanup();
          logger.info(
            `Cleaned up idle session for crashed server ${serverUuid}`,
          );
        } catch (error) {
          logger.error(
            `Error cleaning up idle session for crashed server ${serverUuid}:`,
            error,
          );
        }
        delete this.idleSessions[cacheKey];
      }
    }

    // Clean up active sessions that use this server
    for (const [sessionId, sessionServers] of Object.entries(
      this.activeSessions,
    )) {
      for (const [cacheKey, client] of Object.entries(sessionServers)) {
        if (!connectionKeyBelongsToServer(cacheKey, serverUuid)) {
          continue;
        }
        try {
          await client.cleanup();
          logger.info(
            `Cleaned up active session ${sessionId} for crashed server ${serverUuid}`,
          );
        } catch (error) {
          logger.error(
            `Error cleaning up active session ${sessionId} for crashed server ${serverUuid}:`,
            error,
          );
        }
        delete sessionServers[cacheKey];
        this.sessionToServers[sessionId]?.delete(cacheKey);
      }
    }
  }

  /**
   * Check if a server is in error state
   */
  async isServerInErrorState(serverUuid: string): Promise<boolean> {
    return await serverErrorTracker.isServerInErrorState(serverUuid);
  }

  /**
   * Reset error state for a server (e.g., after manual recovery)
   */
  async resetServerErrorState(serverUuid: string): Promise<void> {
    // Reset crash attempts and error status
    await serverErrorTracker.resetServerErrorState(serverUuid);

    logger.info(`Reset error state for server ${serverUuid}`);
  }

  /**
   * Start the automatic cleanup timer for expired sessions
   */
  private startCleanupTimer(): void {
    // Check for expired sessions every 5 minutes
    this.cleanupTimer = setInterval(
      async () => {
        await this.cleanupExpiredSessions();
      },
      5 * 60 * 1000,
    ); // 5 minutes
  }

  /**
   * Clean up expired sessions based on session lifetime setting
   */
  private async cleanupExpiredSessions(): Promise<void> {
    try {
      const sessionLifetime = await configService.getSessionLifetime();

      // If session lifetime is null, sessions are infinite - skip cleanup
      if (sessionLifetime === null) {
        return;
      }

      const now = Date.now();
      const expiredSessionIds: string[] = [];

      // Find expired sessions
      for (const [sessionId, timestamp] of Object.entries(
        this.sessionTimestamps,
      )) {
        if (now - timestamp > sessionLifetime) {
          expiredSessionIds.push(sessionId);
        }
      }

      // Clean up expired sessions
      if (expiredSessionIds.length > 0) {
        logger.info(
          `Cleaning up ${expiredSessionIds.length} expired MCP server pool sessions: ${expiredSessionIds.join(", ")}`,
        );

        await Promise.allSettled(
          expiredSessionIds.map((sessionId) => this.cleanupSession(sessionId)),
        );
      }
    } catch (error) {
      logger.error("Error during automatic session cleanup:", error);
    }
  }

  /**
   * Start the health check timer for idle sessions
   */
  private startHealthCheckTimer(): void {
    // Check idle session health every 60 seconds
    this.healthCheckTimer = setInterval(async () => {
      await this.checkIdleSessionHealth();
    }, 60 * 1000); // 60 seconds
  }

  /**
   * Check health of idle sessions by pinging them.
   * Dead sessions are cleaned up and recreated.
   * Servers in ERROR state whose crash counters have been reset are retried.
   */
  private async checkIdleSessionHealth(): Promise<void> {
    const cacheKeys = Object.keys(this.idleSessions);
    if (cacheKeys.length === 0) {
      return;
    }

    for (const cacheKey of cacheKeys) {
      const serverUuid = serverUuidFromConnectionKey(cacheKey);
      const client = this.idleSessions[cacheKey];
      if (!client) continue;

      try {
        // Ping with a 5-second timeout
        await client.client.ping({ timeout: 5000 });
      } catch {
        logger.warn(
          `Idle session health check failed for server ${serverUuid}, recreating...`,
        );

        // Clean up the dead session
        try {
          await client.cleanup();
        } catch {
          // Already dead, ignore cleanup errors
        }
        delete this.idleSessions[cacheKey];

        // Reset error state so we can retry
        await serverErrorTracker.resetServerErrorState(serverUuid);

        // Recreate if we have cached params
        const params = this.serverParamsCache[cacheKey];
        if (params) {
          this.createIdleSessionAsync(serverUuid, params);
        }
      }
    }

    // Also check for servers in ERROR state that have cached params but no idle session.
    // If they were reset (e.g., on startup), we should try to recreate them.
    for (const [cacheKey, params] of Object.entries(this.serverParamsCache)) {
      const serverUuid = serverUuidFromConnectionKey(cacheKey);
      if (
        !this.idleSessions[cacheKey] &&
        !this.creatingIdleSessions.has(cacheKey)
      ) {
        const isError =
          await serverErrorTracker.isServerInErrorState(serverUuid);
        if (!isError) {
          // Not in error and no idle session - try to create one
          this.createIdleSessionAsync(serverUuid, params);
        }
      }
    }
  }

  /**
   * Get session age in milliseconds
   */
  getSessionAge(sessionId: string): number | undefined {
    const timestamp = this.sessionTimestamps[sessionId];
    return timestamp ? Date.now() - timestamp : undefined;
  }

  /**
   * Check if a session is expired
   */
  async isSessionExpired(sessionId: string): Promise<boolean> {
    const age = this.getSessionAge(sessionId);
    if (age === undefined) return false;

    const sessionLifetime = await configService.getSessionLifetime();
    if (sessionLifetime === null) return false; // infinite sessions
    return age > sessionLifetime;
  }
}

// Create a singleton instance
export const mcpServerPool = McpServerPool.getInstance();
