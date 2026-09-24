import { afterEach, describe, expect, it, vi } from "vitest";

import { ConnectedClient } from "./client";
import { McpServerPool } from "./mcp-server-pool";

vi.mock("../config.service", () => ({
  configService: { getSessionLifetime: vi.fn().mockResolvedValue(null) },
}));
vi.mock("./client", () => ({ connectMetaMcpClient: vi.fn() }));
vi.mock("./server-error-tracker", () => ({ serverErrorTracker: {} }));

const makePool = () =>
  new (McpServerPool as unknown as new (
    idleCount: number,
    totalLimit: number,
    perServerLimit: number,
  ) => McpServerPool)(1, 2, 2);

const key = "server-1\u0000";

describe("McpServerPool shared connections", () => {
  const pools: McpServerPool[] = [];

  afterEach(async () => {
    await Promise.all(pools.map((pool) => pool.cleanupAll()));
    pools.length = 0;
  });

  it("counts one shared client once across sessions", () => {
    const pool = makePool();
    pools.push(pool);
    const client = {
      cleanup: vi.fn().mockResolvedValue(undefined),
    } as unknown as ConnectedClient;
    const state = pool as unknown as {
      activeSessions: Record<string, Record<string, ConnectedClient>>;
      serverParamsCache: Record<string, unknown>;
    };
    state.activeSessions = {
      first: { [key]: client },
      second: { [key]: client },
    };
    state.serverParamsCache = { [key]: { uuid: "server-1" } };

    expect(pool.getPoolStatus().perServerCounts?.["server-1"]).toBe(1);
  });

  it("does not recycle or close a client still used by another session", async () => {
    const pool = makePool();
    pools.push(pool);
    const cleanup = vi.fn().mockResolvedValue(undefined);
    const client = { cleanup } as unknown as ConnectedClient;
    const state = pool as unknown as {
      activeSessions: Record<string, Record<string, ConnectedClient>>;
      idleSessions: Record<string, ConnectedClient>;
    };
    state.activeSessions = {
      first: { [key]: client },
      second: { [key]: client },
    };

    await pool.cleanupSession("first");

    expect(cleanup).not.toHaveBeenCalled();
    expect(state.idleSessions[key]).toBeUndefined();
    expect(state.activeSessions.second[key]).toBe(client);
  });

  it("closes a shared client only once when clearing the pool", async () => {
    const pool = makePool();
    pools.push(pool);
    const cleanup = vi.fn().mockResolvedValue(undefined);
    const client = { cleanup } as unknown as ConnectedClient;
    const state = pool as unknown as {
      activeSessions: Record<string, Record<string, ConnectedClient>>;
    };
    state.activeSessions = {
      first: { [key]: client },
      second: { [key]: client },
    };

    await pool.cleanupAll();

    expect(cleanup).toHaveBeenCalledTimes(1);
  });

  it("closes a shared client only once when invalidating a server", async () => {
    const pool = makePool();
    pools.push(pool);
    const cleanup = vi.fn().mockResolvedValue(undefined);
    const client = { cleanup } as unknown as ConnectedClient;
    const state = pool as unknown as {
      activeSessions: Record<string, Record<string, ConnectedClient>>;
      idleSessions: Record<string, ConnectedClient>;
    };
    state.activeSessions = {
      first: { [key]: client },
      second: { [key]: client },
    };
    state.idleSessions = { [key]: client };

    await pool.invalidateServerConnection("first", "server-1");

    expect(cleanup).toHaveBeenCalledTimes(1);
    expect(state.activeSessions.first[key]).toBeUndefined();
    expect(state.activeSessions.second[key]).toBeUndefined();
    expect(state.idleSessions[key]).toBeUndefined();
  });

  it("retains a shared client when two sessions clean up concurrently", async () => {
    const pool = makePool();
    pools.push(pool);
    const shared = {
      cleanup: vi.fn().mockResolvedValue(undefined),
    } as unknown as ConnectedClient;
    const makeExtra = () =>
      ({
        cleanup: vi
          .fn()
          .mockImplementation(
            () => new Promise((resolve) => setTimeout(resolve, 0)),
          ),
      }) as unknown as ConnectedClient;
    const extraA = makeExtra();
    const extraB = makeExtra();
    const state = pool as unknown as {
      activeSessions: Record<string, Record<string, ConnectedClient>>;
      idleSessions: Record<string, ConnectedClient>;
    };
    state.activeSessions = {
      first: { [key]: shared, "extra-a\u0000": extraA },
      second: { [key]: shared, "extra-b\u0000": extraB },
    };
    state.idleSessions = {
      "extra-a\u0000": makeExtra(),
      "extra-b\u0000": makeExtra(),
    };

    await Promise.all([
      pool.cleanupSession("first"),
      pool.cleanupSession("second"),
    ]);

    expect(state.idleSessions[key]).toBe(shared);
  });

  it("keeps another OAuth principal connected when one token is rejected", async () => {
    const pool = makePool();
    pools.push(pool);
    const aliceKey = "server-1\u0000alice";
    const bobKey = "server-1\u0000bob";
    const aliceCleanup = vi.fn().mockResolvedValue(undefined);
    const bobCleanup = vi.fn().mockResolvedValue(undefined);
    const alice = { cleanup: aliceCleanup } as unknown as ConnectedClient;
    const bob = { cleanup: bobCleanup } as unknown as ConnectedClient;
    const state = pool as unknown as {
      activeSessions: Record<string, Record<string, ConnectedClient>>;
    };
    state.activeSessions = {
      first: { [aliceKey]: alice },
      second: { [bobKey]: bob },
    };

    await pool.invalidateServerConnection("first", "server-1", "alice");

    expect(aliceCleanup).toHaveBeenCalledTimes(1);
    expect(bobCleanup).not.toHaveBeenCalled();
    expect(state.activeSessions.first[aliceKey]).toBeUndefined();
    expect(state.activeSessions.second[bobKey]).toBe(bob);
  });
});
