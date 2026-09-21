import type { ServerParameters } from "@repo/zod-types";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// client.ts pulls in the DB-backed repositories transitively (directly,
// and via server-error-tracker.ts). None of that is exercised by
// refreshIfExpiringSoon or createMetaMcpClient (the two functions under
// test here never call connectMetaMcpClient's DB-touching branches), so a
// bare stub is enough to let the module graph load without a real
// DATABASE_URL.
vi.mock("../../db/index", () => ({ db: {}, pool: {} }));

const tryRefreshUpstreamTokens = vi.fn();
vi.mock("../oauth-upstream/refresh-on-401", () => ({
  tryRefreshUpstreamTokens: (...args: unknown[]) =>
    tryRefreshUpstreamTokens(...args),
}));

// Capture what createMetaMcpClient hands to the SDK transports so tests
// can assert on the Authorization header without depending on the real
// SDK transport's internal (unexported) state.
vi.mock("@modelcontextprotocol/sdk/client/streamableHttp.js", () => {
  class StreamableHTTPClientTransport {
    static instances: StreamableHTTPClientTransport[] = [];
    url: URL;
    opts?: Record<string, unknown>;
    constructor(url: URL, opts?: Record<string, unknown>) {
      this.url = url;
      this.opts = opts;
      StreamableHTTPClientTransport.instances.push(this);
    }
    async close() {}
  }
  return { StreamableHTTPClientTransport };
});

vi.mock("@modelcontextprotocol/sdk/client/sse.js", () => {
  class SSEClientTransport {
    static instances: SSEClientTransport[] = [];
    url: URL;
    opts?: Record<string, unknown>;
    constructor(url: URL, opts?: Record<string, unknown>) {
      this.url = url;
      this.opts = opts;
      SSEClientTransport.instances.push(this);
    }
    async close() {}
  }
  return { SSEClientTransport };
});

// Controls what `client.connect(transport)` does per attempt, so tests can
// drive connectMetaMcpClient's reactive 401-refresh cascade without a real
// SDK handshake.
const clientConnect = vi.fn();
vi.mock("@modelcontextprotocol/sdk/client/index.js", () => {
  class Client {
    connect(...args: unknown[]) {
      return clientConnect(...args);
    }
    async close() {}
  }
  return { Client };
});

import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import {
  connectMetaMcpClient,
  createMetaMcpClient,
  refreshIfExpiringSoon,
} from "./client";
import { McpServerPool } from "./mcp-server-pool";

// The import above resolves, at runtime, to the mock class defined in the
// vi.mock factory (same module instance createMetaMcpClient constructs
// against) — but its *type* still comes from the real SDK's .d.ts, which
// has neither `instances` nor `opts`. Cast to the shape our mock actually
// has instead of asserting against the real SDK type.
interface MockTransport {
  url: URL;
  opts?: Record<string, unknown>;
}
interface MockTransportClass {
  instances: MockTransport[];
}
const MockStreamableHTTPClientTransport =
  StreamableHTTPClientTransport as unknown as MockTransportClass;

function authHeaderOf(
  transport: MockTransport | undefined,
): string | undefined {
  const requestInit = transport?.opts?.requestInit as
    | { headers?: Record<string, string> }
    | undefined;
  return requestInit?.headers?.Authorization;
}

function makeServer(
  overrides: Partial<ServerParameters> = {},
): ServerParameters {
  return {
    uuid: "server-1",
    name: "reclaim",
    description: "",
    type: "STREAMABLE_HTTP",
    created_at: new Date().toISOString(),
    status: "active",
    stderr: "inherit" as const,
    url: "https://api.reclaim.ai/mcp",
    headers: {},
    ...overrides,
  };
}

function makePool(maxConnectionsPerServer = 5): McpServerPool {
  const PoolConstructor = McpServerPool as unknown as new (
    defaultIdleCount: number,
    maxTotalConnections: number,
    maxConnectionsPerServer: number,
  ) => McpServerPool;
  return new PoolConstructor(0, 100, maxConnectionsPerServer);
}

describe("refreshIfExpiringSoon", () => {
  beforeEach(() => {
    tryRefreshUpstreamTokens.mockReset();
    MockStreamableHTTPClientTransport.instances.length = 0;
  });

  it("refreshes exactly once when the token expires within the 60s buffer, and the next transport carries the new token", async () => {
    tryRefreshUpstreamTokens.mockResolvedValue({
      status: "refreshed",
      tokens: {
        access_token: "NEW_AT",
        token_type: "Bearer",
        refresh_token: "RT",
        expires_at: Date.now() + 3600_000,
      },
    });

    const serverParams = makeServer({
      oauth_user_id: "user-1",
      oauth_tokens: {
        access_token: "OLD_AT",
        token_type: "Bearer",
        refresh_token: "RT",
        expires_at: Date.now() + 10_000, // within the 60s buffer
      },
    });

    await refreshIfExpiringSoon(serverParams);

    expect(tryRefreshUpstreamTokens).toHaveBeenCalledTimes(1);
    expect(tryRefreshUpstreamTokens).toHaveBeenCalledWith(serverParams);
    expect(serverParams.oauth_tokens?.access_token).toBe("NEW_AT");
    expect(serverParams.oauth_user_id).toBe("user-1");

    createMetaMcpClient(serverParams);
    const built = MockStreamableHTTPClientTransport.instances.at(-1);
    expect(built).toBeDefined();
    expect(authHeaderOf(built)).toBe("Bearer NEW_AT");
  });

  it("does not refresh when the token is far from expiry", async () => {
    const serverParams = makeServer({
      oauth_user_id: "user-1",
      oauth_tokens: {
        access_token: "AT",
        token_type: "Bearer",
        refresh_token: "RT",
        expires_at: Date.now() + 3600_000,
      },
    });

    await refreshIfExpiringSoon(serverParams);

    expect(tryRefreshUpstreamTokens).not.toHaveBeenCalled();
    expect(serverParams.oauth_tokens?.access_token).toBe("AT");
  });

  it("does not refresh when there is no refresh_token", async () => {
    const serverParams = makeServer({
      oauth_tokens: {
        access_token: "AT",
        token_type: "Bearer",
        expires_at: Date.now() + 10_000,
      },
    });

    await refreshIfExpiringSoon(serverParams);

    expect(tryRefreshUpstreamTokens).not.toHaveBeenCalled();
  });

  it("does not refresh when expires_at is unknown", async () => {
    const serverParams = makeServer({
      oauth_tokens: {
        access_token: "AT",
        token_type: "Bearer",
        refresh_token: "RT",
      },
    });

    await refreshIfExpiringSoon(serverParams);

    expect(tryRefreshUpstreamTokens).not.toHaveBeenCalled();
  });

  it("never refreshes a STDIO server, even with an expiring token and refresh_token on file", async () => {
    const serverParams = makeServer({
      type: "STDIO",
      url: null,
      command: "node",
      oauth_tokens: {
        access_token: "AT",
        token_type: "Bearer",
        refresh_token: "RT",
        expires_at: Date.now() + 10_000,
      },
    });

    await refreshIfExpiringSoon(serverParams);

    expect(tryRefreshUpstreamTokens).not.toHaveBeenCalled();
  });

  it("does not refresh when OAuth tokens have no resolved principal", async () => {
    const serverParams = makeServer({
      oauth_tokens: {
        access_token: "AT",
        token_type: "Bearer",
        refresh_token: "RT",
        expires_at: Date.now() + 10_000,
      },
    });

    await refreshIfExpiringSoon(serverParams);

    expect(tryRefreshUpstreamTokens).not.toHaveBeenCalled();
  });

  it("swallows a refresh failure and leaves the connection attempt to proceed with the old token", async () => {
    tryRefreshUpstreamTokens.mockRejectedValue(new Error("upstream down"));

    const serverParams = makeServer({
      oauth_user_id: "user-1",
      oauth_tokens: {
        access_token: "OLD_AT",
        token_type: "Bearer",
        refresh_token: "RT",
        expires_at: Date.now() + 10_000,
      },
    });

    await expect(refreshIfExpiringSoon(serverParams)).resolves.toBeUndefined();
    expect(tryRefreshUpstreamTokens).toHaveBeenCalledTimes(1);
    expect(serverParams.oauth_tokens?.access_token).toBe("OLD_AT");

    createMetaMcpClient(serverParams);
    const built = MockStreamableHTTPClientTransport.instances.at(-1);
    expect(authHeaderOf(built)).toBe("Bearer OLD_AT");
  });

  it("does not swap tokens when the refresh helper reports a non-refreshed status", async () => {
    tryRefreshUpstreamTokens.mockResolvedValue({ status: "no_refresh_token" });

    const serverParams = makeServer({
      oauth_user_id: "user-1",
      oauth_tokens: {
        access_token: "OLD_AT",
        token_type: "Bearer",
        refresh_token: "RT",
        expires_at: Date.now() + 10_000,
      },
    });

    await refreshIfExpiringSoon(serverParams);

    expect(tryRefreshUpstreamTokens).toHaveBeenCalledTimes(1);
    expect(serverParams.oauth_tokens?.access_token).toBe("OLD_AT");
  });
});

describe("connectMetaMcpClient — reactive 401-refresh cascade", () => {
  beforeEach(() => {
    tryRefreshUpstreamTokens.mockReset();
    clientConnect.mockReset();
    MockStreamableHTTPClientTransport.instances.length = 0;
  });

  // Pins the fix for the fourth expires_at drop site: the pre-existing
  // reactive 401-refresh cascade rebuilds serverParams.oauth_tokens
  // field-by-field. McpServerPool.serverParamsCache holds a long-lived
  // reference to this exact object and mutates it in place, so if this
  // literal drops expires_at, the proactive gate goes dark for that
  // cached instance after the very first reactive refresh.
  it("carries expires_at from the refreshed tokens into serverParams.oauth_tokens", async () => {
    const NEW_EXPIRES_AT = Date.now() + 7200_000;
    tryRefreshUpstreamTokens.mockResolvedValue({
      status: "refreshed",
      tokens: {
        access_token: "NEW_AT",
        token_type: "Bearer",
        refresh_token: "RT2",
        expires_at: NEW_EXPIRES_AT,
      },
    });

    // First connect attempt fails with a 401 (isUpstreamUnauthorizedError
    // recognises this); second attempt (after the reactive refresh)
    // succeeds. expires_at is set far in the future so the PROACTIVE gate
    // (tested above) never fires here — only the reactive cascade should
    // call tryRefreshUpstreamTokens.
    clientConnect
      .mockRejectedValueOnce(new Error("HTTP 401: token expired"))
      .mockResolvedValueOnce(undefined);

    const serverParams = makeServer({
      oauth_user_id: "user-1",
      oauth_tokens: {
        access_token: "OLD_AT",
        token_type: "Bearer",
        refresh_token: "RT",
        expires_at: Date.now() + 3600_000, // far from expiry
      },
    });

    const connected = await connectMetaMcpClient(serverParams);

    expect(connected).toBeDefined();
    expect(clientConnect).toHaveBeenCalledTimes(2);
    expect(tryRefreshUpstreamTokens).toHaveBeenCalledTimes(1);
    expect(tryRefreshUpstreamTokens).toHaveBeenCalledWith(serverParams);
    expect(serverParams.oauth_tokens?.access_token).toBe("NEW_AT");
    expect(serverParams.oauth_tokens?.expires_at).toBe(NEW_EXPIRES_AT);
    expect(serverParams.oauth_user_id).toBe("user-1");
  });
});

describe("McpServerPool — OAuth principal cache identity", () => {
  it("does not exceed the per-server cap when existing connections belong to another principal", async () => {
    clientConnect.mockReset();
    clientConnect.mockResolvedValue(undefined);
    MockStreamableHTTPClientTransport.instances.length = 0;
    const pool = makePool(1);
    const userA = makeServer({
      oauth_user_id: "user-a",
      oauth_tokens: { access_token: "TOKEN_A", token_type: "Bearer" },
      forward_headers: { authorization: "x-forwarded-authorization" },
    });
    const userB = makeServer({
      oauth_user_id: "user-b",
      oauth_tokens: { access_token: "TOKEN_B", token_type: "Bearer" },
      forward_headers: { authorization: "x-forwarded-authorization" },
    });

    try {
      const first = await pool.getSession(
        "session-a",
        userA.uuid,
        userA,
        "namespace-a",
      );
      const blocked = await pool.getSession(
        "session-b",
        userB.uuid,
        userB,
        "namespace-b",
      );

      expect(first).toBeDefined();
      expect(blocked).toBeUndefined();
      expect(clientConnect).toHaveBeenCalledTimes(1);
      expect(MockStreamableHTTPClientTransport.instances).toHaveLength(1);
    } finally {
      await pool.cleanupAll();
    }
  });

  it("does not reuse a connection for another principal sharing the same session and server UUID", async () => {
    clientConnect.mockReset();
    clientConnect.mockResolvedValue(undefined);
    MockStreamableHTTPClientTransport.instances.length = 0;
    const pool = makePool();
    const userA = makeServer({
      oauth_user_id: "user-a",
      oauth_tokens: { access_token: "TOKEN_A", token_type: "Bearer" },
      forward_headers: { authorization: "x-forwarded-authorization" },
    });
    const userB = makeServer({
      oauth_user_id: "user-b",
      oauth_tokens: { access_token: "TOKEN_B", token_type: "Bearer" },
      forward_headers: { authorization: "x-forwarded-authorization" },
    });

    try {
      const first = await pool.getSession(
        "shared-session",
        userA.uuid,
        userA,
        "namespace-a",
      );
      const second = await pool.getSession(
        "shared-session",
        userB.uuid,
        userB,
        "namespace-b",
      );

      expect(first).toBeDefined();
      expect(second).toBeDefined();
      expect(second).not.toBe(first);
      expect(MockStreamableHTTPClientTransport.instances).toHaveLength(2);
      expect(authHeaderOf(MockStreamableHTTPClientTransport.instances[0])).toBe(
        "Bearer TOKEN_A",
      );
      expect(authHeaderOf(MockStreamableHTTPClientTransport.instances[1])).toBe(
        "Bearer TOKEN_B",
      );
    } finally {
      await pool.cleanupAll();
    }
  });

  it("administrative invalidation cleans active connections for every principal", async () => {
    clientConnect.mockReset();
    clientConnect.mockResolvedValue(undefined);
    MockStreamableHTTPClientTransport.instances.length = 0;
    const pool = makePool();
    const userA = makeServer({
      oauth_user_id: "user-a",
      oauth_tokens: { access_token: "TOKEN_A", token_type: "Bearer" },
      forward_headers: { authorization: "x-forwarded-authorization" },
    });
    const userB = makeServer({
      oauth_user_id: "user-b",
      oauth_tokens: { access_token: "TOKEN_B", token_type: "Bearer" },
      forward_headers: { authorization: "x-forwarded-authorization" },
    });

    try {
      const firstA = await pool.getSession(
        "session-a",
        userA.uuid,
        userA,
        "namespace-a",
      );
      const firstB = await pool.getSession(
        "session-b",
        userB.uuid,
        userB,
        "namespace-b",
      );
      expect(firstA).toBeDefined();
      expect(firstB).toBeDefined();
      if (!firstA || !firstB) {
        throw new Error("expected both principal-scoped connections");
      }
      const cleanupA = vi.spyOn(firstA, "cleanup");
      const cleanupB = vi.spyOn(firstB, "cleanup");

      await pool.invalidateIdleSession(userA.uuid, userA, "namespace-a");

      expect(cleanupA).toHaveBeenCalledTimes(1);
      expect(cleanupB).toHaveBeenCalledTimes(1);

      const nextA = await pool.getSession(
        "session-a",
        userA.uuid,
        userA,
        "namespace-a",
      );
      const nextB = await pool.getSession(
        "session-b",
        userB.uuid,
        userB,
        "namespace-b",
      );
      expect(nextA).toBeDefined();
      expect(nextB).toBeDefined();
      expect(nextA).not.toBe(firstA);
      expect(nextB).not.toBe(firstB);
    } finally {
      await pool.cleanupAll();
    }
  });
});
