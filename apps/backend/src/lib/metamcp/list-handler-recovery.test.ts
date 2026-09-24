import { DatabaseOAuthSession, ServerParameters } from "@repo/zod-types";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { oauthSessionsRepository } from "../../db/repositories";
import { tryRefreshUpstreamTokens } from "../oauth-upstream/refresh-on-401";
import { ConnectedClient } from "./client";
import {
  RecoverySessionPool,
  requestWithSessionRecovery,
} from "./list-handler-recovery";

vi.mock("../oauth-upstream/refresh-on-401", () => ({
  tryRefreshUpstreamTokens: vi.fn(),
}));
vi.mock("../../db/repositories", () => ({
  oauthSessionsRepository: {
    findByMcpServerAndUser: vi.fn(),
  },
}));

// The exact envelope shape the backend produces when its session died
// (matches session-error.test.ts fixtures). isRecoverableBackendError
// must classify it as recoverable.
const sessionLostError = () =>
  new Error(
    'Error POSTing to endpoint (HTTP 404): {"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,"message":"Session not found"}}',
  );

const transportLostError = () => new Error("Not connected");

const makeSession = (label: string): ConnectedClient =>
  ({ label }) as unknown as ConnectedClient;

const params = { uuid: "server-1", name: "test-server" } as ServerParameters;

const oauthSessionWithTokens = (
  accessToken: string,
  refreshToken: string,
): DatabaseOAuthSession => ({
  uuid: "oauth-session-1",
  mcp_server_uuid: "server-1",
  user_id: "user-1",
  client_information: null,
  tokens: {
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: "Bearer",
  },
  code_verifier: null,
  expected_state: null,
  discovery_state: null,
  created_at: new Date("2026-09-24T12:00:00Z"),
  updated_at: new Date("2026-09-24T12:00:00Z"),
});

const makePool = (freshSession: ConnectedClient | undefined) => {
  const pool: RecoverySessionPool = {
    invalidateServerConnection: vi.fn().mockResolvedValue(undefined),
    getSession: vi.fn().mockResolvedValue(freshSession),
  };
  return pool;
};

const baseOpts = (pool: RecoverySessionPool, session: ConnectedClient) => ({
  pool,
  sessionId: "session-abc",
  serverUuid: "server-1",
  params,
  namespaceUuid: "ns-1",
  operation: "tools/list",
  serverName: "test-server",
  session,
});

describe("requestWithSessionRecovery", () => {
  beforeEach(() => {
    vi.mocked(oauthSessionsRepository.findByMcpServerAndUser).mockReset();
    vi.mocked(tryRefreshUpstreamTokens).mockReset();
  });

  it("returns the first attempt's result without touching the pool", async () => {
    const session = makeSession("stale");
    const pool = makePool(undefined);
    const attempt = vi.fn().mockResolvedValue(["tool-a"]);

    const result = await requestWithSessionRecovery({
      ...baseOpts(pool, session),
      attempt,
    });

    expect(result).toEqual(["tool-a"]);
    expect(attempt).toHaveBeenCalledTimes(1);
    expect(attempt).toHaveBeenCalledWith(session);
    expect(pool.invalidateServerConnection).not.toHaveBeenCalled();
    expect(pool.getSession).not.toHaveBeenCalled();
  });

  it("invalidates, re-acquires, and retries once on a session-lost envelope", async () => {
    const stale = makeSession("stale");
    const fresh = makeSession("fresh");
    const pool = makePool(fresh);
    const attempt = vi
      .fn()
      .mockRejectedValueOnce(sessionLostError())
      .mockResolvedValueOnce(["tool-b"]);
    const onFreshSession = vi.fn();

    const result = await requestWithSessionRecovery({
      ...baseOpts(pool, stale),
      attempt,
      onFreshSession,
    });

    expect(result).toEqual(["tool-b"]);
    expect(pool.invalidateServerConnection).toHaveBeenCalledWith(
      "session-abc",
      "server-1",
    );
    expect(pool.getSession).toHaveBeenCalledWith(
      "session-abc",
      "server-1",
      params,
      "ns-1",
    );
    expect(onFreshSession).toHaveBeenCalledWith(fresh);
    expect(attempt).toHaveBeenNthCalledWith(1, stale);
    expect(attempt).toHaveBeenNthCalledWith(2, fresh);
  });

  it("recovers from the SDK transport-lost envelope too", async () => {
    const stale = makeSession("stale");
    const fresh = makeSession("fresh");
    const pool = makePool(fresh);
    const attempt = vi
      .fn()
      .mockRejectedValueOnce(transportLostError())
      .mockResolvedValueOnce("ok");

    await expect(
      requestWithSessionRecovery({ ...baseOpts(pool, stale), attempt }),
    ).resolves.toBe("ok");
    expect(pool.invalidateServerConnection).toHaveBeenCalledTimes(1);
  });

  it("refreshes an upstream rejected OAuth token before reconnecting tools/list", async () => {
    const stale = makeSession("stale");
    const fresh = makeSession("fresh");
    const pool = makePool(fresh);
    const oauthParams = {
      ...params,
      type: "STREAMABLE_HTTP",
      url: "https://api.example.test/mcp",
      oauth_user_id: "user-1",
      oauth_tokens: { access_token: "old", refresh_token: "refresh-1" },
    } as ServerParameters;
    vi.mocked(tryRefreshUpstreamTokens).mockResolvedValueOnce({
      status: "refreshed",
      tokens: {
        access_token: "new",
        refresh_token: "refresh-2",
        token_type: "Bearer",
        expires_at: Date.now() + 3600_000,
      },
    });
    const attempt = vi
      .fn()
      .mockRejectedValueOnce(new Error("Invalid or expired OAuth access token"))
      .mockResolvedValueOnce(["elevenlabs-tool"]);

    await expect(
      requestWithSessionRecovery({
        ...baseOpts(pool, stale),
        params: oauthParams,
        attempt,
      }),
    ).resolves.toEqual(["elevenlabs-tool"]);

    expect(tryRefreshUpstreamTokens).toHaveBeenCalledOnce();
    expect(pool.getSession).toHaveBeenCalledWith(
      "session-abc",
      "server-1",
      expect.objectContaining({
        oauth_tokens: expect.objectContaining({
          access_token: "new",
          refresh_token: "refresh-2",
        }),
      }),
      "ns-1",
    );
    expect(pool.invalidateServerConnection).toHaveBeenCalledOnce();
    expect(pool.invalidateServerConnection).toHaveBeenCalledWith(
      "session-abc",
      "server-1",
      "user-1",
    );
    expect(attempt).toHaveBeenCalledTimes(2);
  });

  it("does not reconnect when the upstream refuses the OAuth refresh", async () => {
    const session = makeSession("stale");
    const pool = makePool(makeSession("fresh"));
    const rejected = new Error("Invalid or expired OAuth access token");
    const attempt = vi.fn().mockRejectedValue(rejected);
    const oauthParams = {
      ...params,
      type: "STREAMABLE_HTTP",
      url: "https://api.example.test/mcp",
      oauth_user_id: "user-1",
      oauth_tokens: { access_token: "old", refresh_token: "refresh-1" },
    } as ServerParameters;
    vi.mocked(tryRefreshUpstreamTokens).mockResolvedValueOnce({
      status: "failed",
      error: "invalid_grant",
    });

    await expect(
      requestWithSessionRecovery({
        ...baseOpts(pool, session),
        params: oauthParams,
        attempt,
      }),
    ).rejects.toBe(rejected);

    expect(pool.invalidateServerConnection).not.toHaveBeenCalled();
    expect(attempt).toHaveBeenCalledTimes(1);
  });

  it("uses a token rotated by an earlier stale request without a second refresh", async () => {
    const pool = makePool(makeSession("fresh"));
    const firstParams = {
      ...params,
      type: "STREAMABLE_HTTP",
      url: "https://api.example.test/mcp",
      oauth_user_id: "user-1",
      oauth_tokens: { access_token: "old", refresh_token: "refresh-1" },
    } as ServerParameters;
    const secondParams = {
      ...firstParams,
      oauth_tokens: { access_token: "old", refresh_token: "refresh-1" },
    } as ServerParameters;
    vi.mocked(oauthSessionsRepository.findByMcpServerAndUser)
      .mockResolvedValueOnce(oauthSessionWithTokens("old", "refresh-1"))
      .mockResolvedValueOnce(oauthSessionWithTokens("new", "refresh-2"));
    vi.mocked(tryRefreshUpstreamTokens)
      .mockResolvedValueOnce({
        status: "refreshed",
        tokens: {
          access_token: "new",
          refresh_token: "refresh-2",
          token_type: "Bearer",
        },
      })
      .mockResolvedValueOnce({ status: "failed", error: "invalid_grant" });
    const staleTokenError = new Error("Invalid or expired OAuth access token");
    const firstAttempt = vi
      .fn()
      .mockRejectedValueOnce(staleTokenError)
      .mockResolvedValueOnce("first recovered");
    const secondAttempt = vi
      .fn()
      .mockRejectedValueOnce(staleTokenError)
      .mockResolvedValueOnce("second recovered");

    await expect(
      requestWithSessionRecovery({
        ...baseOpts(pool, makeSession("stale-1")),
        params: firstParams,
        attempt: firstAttempt,
      }),
    ).resolves.toBe("first recovered");
    await expect(
      requestWithSessionRecovery({
        ...baseOpts(pool, makeSession("stale-2")),
        params: secondParams,
        attempt: secondAttempt,
      }),
    ).resolves.toBe("second recovered");

    expect(tryRefreshUpstreamTokens).toHaveBeenCalledTimes(1);
    expect(secondParams.oauth_tokens?.access_token).toBe("new");
    expect(secondParams.oauth_tokens?.refresh_token).toBe("refresh-2");
    expect(pool.invalidateServerConnection).toHaveBeenCalledTimes(2);
    expect(pool.invalidateServerConnection).toHaveBeenCalledWith(
      "session-abc",
      "server-1",
      "user-1",
    );
  });

  it("rethrows non-recoverable errors without invalidating the pool", async () => {
    const session = makeSession("stale");
    const pool = makePool(undefined);
    const boom = new Error("schema validation failed");
    const attempt = vi.fn().mockRejectedValue(boom);

    await expect(
      requestWithSessionRecovery({ ...baseOpts(pool, session), attempt }),
    ).rejects.toBe(boom);
    expect(pool.invalidateServerConnection).not.toHaveBeenCalled();
    expect(attempt).toHaveBeenCalledTimes(1);
  });

  it("throws a re-init error when no fresh session can be established", async () => {
    const session = makeSession("stale");
    const pool = makePool(undefined);
    const attempt = vi.fn().mockRejectedValue(sessionLostError());

    await expect(
      requestWithSessionRecovery({ ...baseOpts(pool, session), attempt }),
    ).rejects.toThrow(
      /Failed to re-initialize session for server server-1 .* tools\/list/,
    );
    expect(attempt).toHaveBeenCalledTimes(1);
  });

  it("propagates the retry's failure when the fresh session also fails", async () => {
    const stale = makeSession("stale");
    const fresh = makeSession("fresh");
    const pool = makePool(fresh);
    const secondFailure = new Error("backend exploded after reconnect");
    const attempt = vi
      .fn()
      .mockRejectedValueOnce(sessionLostError())
      .mockRejectedValueOnce(secondFailure);

    await expect(
      requestWithSessionRecovery({ ...baseOpts(pool, stale), attempt }),
    ).rejects.toBe(secondFailure);
    expect(attempt).toHaveBeenCalledTimes(2);
  });
});
