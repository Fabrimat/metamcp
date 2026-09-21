import type {
  OAuthClientInformation,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { beforeEach, describe, expect, it, vi } from "vitest";

type Predicate =
  | { type: "eq"; field: string; value: unknown }
  | { type: "and"; predicates: Predicate[] };

const valuesCalls: any[] = [];
const onConflictSetCalls: any[] = [];
const onConflictTargetCalls: any[] = [];
const store = new Map<string, any>();

const keyFor = (mcpServerUuid: string, userId: string) =>
  `${mcpServerUuid}:${userId}`;

const matches = (
  row: Record<string, unknown>,
  predicate: Predicate,
): boolean =>
  predicate.type === "eq"
    ? row[predicate.field] === predicate.value
    : predicate.predicates.every((part) => matches(row, part));

vi.mock("drizzle-orm", () => ({
  and: (...predicates: Predicate[]): Predicate => ({ type: "and", predicates }),
  eq: (column: { name: string }, value: unknown): Predicate => ({
    type: "eq",
    field: column.name,
    value,
  }),
  sql: (strings: TemplateStringsArray) => ({ sql: strings.join("") }),
}));

vi.mock("../../index", () => ({
  db: {
    select: () => ({
      from: () => ({
        where: (predicate: Predicate) => ({
          limit: async (limit: number) =>
            [...store.values()]
              .filter((row) => matches(row, predicate))
              .slice(0, limit),
        }),
      }),
    }),
    insert: () => ({
      values: (values: any) => {
        valuesCalls.push(values);
        return {
          onConflictDoUpdate: ({
            target,
            set,
          }: {
            target: unknown;
            set: any;
          }) => {
            onConflictTargetCalls.push(target);
            onConflictSetCalls.push(set);
            return {
              returning: async () => {
                const key = keyFor(values.mcp_server_uuid, values.user_id);
                const now = new Date();
                const existing = store.get(key);
                if (existing) {
                  const { updated_at: _ignored, ...applicable } = set;
                  const updated = {
                    ...existing,
                    ...applicable,
                    updated_at: now,
                  };
                  store.set(key, updated);
                  return [updated];
                }
                const row = {
                  uuid: `uuid-${store.size}`,
                  mcp_server_uuid: values.mcp_server_uuid,
                  user_id: values.user_id,
                  client_information: values.client_information ?? {},
                  tokens: values.tokens ?? null,
                  code_verifier: values.code_verifier ?? null,
                  expected_state: values.expected_state ?? null,
                  discovery_state: values.discovery_state ?? null,
                  created_at: now,
                  updated_at: now,
                };
                store.set(key, row);
                return [row];
              },
            };
          },
          returning: async () => {
            const key = keyFor(values.mcp_server_uuid, values.user_id);
            const now = new Date();
            const row = {
              uuid: `uuid-${store.size}`,
              mcp_server_uuid: values.mcp_server_uuid,
              user_id: values.user_id,
              client_information: values.client_information ?? {},
              tokens: values.tokens ?? null,
              code_verifier: values.code_verifier ?? null,
              expected_state: values.expected_state ?? null,
              discovery_state: values.discovery_state ?? null,
              created_at: now,
              updated_at: now,
            };
            store.set(key, row);
            return [row];
          },
        };
      },
    }),
    update: () => ({
      set: (set: any) => ({
        where: (predicate: Predicate) => ({
          returning: async () => {
            const updated: any[] = [];
            for (const [key, row] of store) {
              if (!matches(row, predicate)) continue;
              const { updated_at: _ignored, ...applicable } = set;
              const next = { ...row, ...applicable, updated_at: new Date() };
              store.set(key, next);
              updated.push(next);
            }
            return updated;
          },
        }),
      }),
    }),
    delete: () => ({
      where: (predicate: Predicate) => ({
        returning: async () => {
          const deleted: any[] = [];
          for (const [key, row] of store) {
            if (!matches(row, predicate)) continue;
            store.delete(key);
            deleted.push(row);
          }
          return deleted;
        },
      }),
    }),
  },
}));

const { OAuthSessionsRepository } = await import("../oauth-sessions.repo");

describe("OAuthSessionsRepository", () => {
  const repo = new OAuthSessionsRepository();
  const serverId = "00000000-0000-0000-0000-000000000001";
  const userA = "user-a";
  const userB = "user-b";
  const tokensA = {
    access_token: "token-a",
    token_type: "Bearer",
  } as OAuthTokens;
  const tokensB = {
    access_token: "token-b",
    token_type: "Bearer",
  } as OAuthTokens;

  beforeEach(() => {
    store.clear();
    valuesCalls.length = 0;
    onConflictSetCalls.length = 0;
    onConflictTargetCalls.length = 0;
  });

  it("isolates sessions for two users of the same MCP server", async () => {
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userA,
      tokens: tokensA,
    });
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userB,
      tokens: tokensB,
    });

    expect(
      (await repo.findByMcpServerAndUser(serverId, userA))?.tokens,
    ).toEqual(tokensA);
    expect(
      (await repo.findByMcpServerAndUser(serverId, userB))?.tokens,
    ).toEqual(tokensB);
  });

  it("updates only the selected server and user pair", async () => {
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userA,
      tokens: tokensA,
    });
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userB,
      tokens: tokensB,
    });

    await repo.update({
      mcp_server_uuid: serverId,
      user_id: userA,
      code_verifier: "verifier-a",
    });

    expect(
      (await repo.findByMcpServerAndUser(serverId, userA))?.code_verifier,
    ).toBe("verifier-a");
    expect(
      (await repo.findByMcpServerAndUser(serverId, userB))?.code_verifier,
    ).toBeNull();
  });

  it("clears expected state only for the selected server and user pair", async () => {
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userA,
      expected_state: "state-a",
    });
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userB,
      expected_state: "state-b",
    });

    await repo.clearExpectedState(serverId, userA);

    expect(
      (await repo.findByMcpServerAndUser(serverId, userA))?.expected_state,
    ).toBeNull();
    expect(
      (await repo.findByMcpServerAndUser(serverId, userB))?.expected_state,
    ).toBe("state-b");
  });

  it("atomically claims an exact state once without touching another principal", async () => {
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userA,
      expected_state: "original",
    });
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userB,
      expected_state: "original",
    });
    const claims = await Promise.all([
      repo.compareAndSetExpectedState(serverId, userA, "original", "claim-a"),
      repo.compareAndSetExpectedState(serverId, userA, "original", "claim-b"),
    ]);
    expect(claims).toEqual([true, false]);
    expect(
      (await repo.findByMcpServerAndUser(serverId, userA))?.expected_state,
    ).toBe("claim-a");
    expect(
      (await repo.findByMcpServerAndUser(serverId, userB))?.expected_state,
    ).toBe("original");
  });

  it.each([null, "original"])(
    "only the current claim may transition to %s",
    async (nextState) => {
      await repo.upsert({
        mcp_server_uuid: serverId,
        user_id: userA,
        expected_state: "claim-a",
      });
      expect(
        await repo.compareAndSetExpectedState(
          serverId,
          userA,
          "claim-a",
          nextState,
        ),
      ).toBe(true);
      expect(
        (await repo.findByMcpServerAndUser(serverId, userA))?.expected_state,
      ).toBe(nextState);
      await repo.upsert({
        mcp_server_uuid: serverId,
        user_id: userA,
        expected_state: "new-attempt",
      });
      expect(
        await repo.compareAndSetExpectedState(
          serverId,
          userA,
          "claim-a",
          nextState,
        ),
      ).toBe(false);
      expect(
        (await repo.findByMcpServerAndUser(serverId, userA))?.expected_state,
      ).toBe("new-attempt");
    },
  );

  it("deletes only the selected server and user pair", async () => {
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userA,
      tokens: tokensA,
    });
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userB,
      tokens: tokensB,
    });

    await repo.deleteByMcpServerAndUser(serverId, userA);

    expect(await repo.findByMcpServerAndUser(serverId, userA)).toBeUndefined();
    expect(
      (await repo.findByMcpServerAndUser(serverId, userB))?.tokens,
    ).toEqual(tokensB);
  });

  it("uses one atomic upsert with the composite conflict target", async () => {
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userA,
      client_information: { client_id: "client-A" } as OAuthClientInformation,
    });
    const second = await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userA,
      client_information: { client_id: "client-B" } as OAuthClientInformation,
    });

    expect(store.size).toBe(1);
    expect(valuesCalls).toHaveLength(2);
    expect(onConflictTargetCalls[0]).toHaveLength(2);
    expect(second.client_information).toEqual({ client_id: "client-B" });
  });

  it("partial upsert writes only supplied fields and preserves the rest", async () => {
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userA,
      tokens: tokensA,
      expected_state: "state-A",
    });
    const second = await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userA,
      code_verifier: "the-verifier",
    });

    expect(onConflictSetCalls[1]).not.toHaveProperty("tokens");
    expect(onConflictSetCalls[1]).not.toHaveProperty("expected_state");
    expect(second.tokens).toEqual(tokensA);
    expect(second.expected_state).toBe("state-A");
    expect(second.code_verifier).toBe("the-verifier");
  });
});
