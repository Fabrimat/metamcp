import type {
  OAuthClientInformation,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { beforeEach, describe, expect, it, vi } from "vitest";

type Predicate =
  | { type: "eq"; field: string; value: unknown }
  | { type: "and"; predicates: Predicate[] }
  | { type: "sql"; text: string };

const valuesCalls: any[] = [];
const onConflictSetCalls: any[] = [];
const onConflictTargetCalls: any[] = [];
const store = new Map<string, any>();

const keyFor = (mcpServerUuid: string, userId: string) =>
  `${mcpServerUuid}:${userId}`;

const matches = (
  row: Record<string, unknown>,
  predicate: Predicate,
): boolean => {
  if (predicate.type === "eq") return row[predicate.field] === predicate.value;
  if (predicate.type === "and")
    return predicate.predicates.every((part) => matches(row, part));
  if (predicate.text.includes("_metamcp_registration")) {
    const client = row.client_information as Record<string, unknown> | null;
    return client?._metamcp_registration !== "legacy_unconfirmed";
  }
  return true;
};

vi.mock("drizzle-orm", () => ({
  and: (...predicates: Predicate[]): Predicate => ({ type: "and", predicates }),
  eq: (column: { name: string }, value: unknown): Predicate => ({
    type: "eq",
    field: column.name,
    value,
  }),
  sql: (strings: TemplateStringsArray) => ({
    type: "sql",
    text: strings.join(""),
  }),
}));

vi.mock("../../index", () => ({
  db: {
    select: () => ({
      from: () => ({
        where: (predicate: Predicate) => ({
          then: (resolve: (rows: unknown[]) => unknown) =>
            Promise.resolve(
              [...store.values()].filter((row) => matches(row, predicate)),
            ).then(resolve),
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
            setWhere,
          }: {
            target: unknown;
            set: any;
            setWhere?: Predicate;
          }) => {
            onConflictTargetCalls.push(target);
            onConflictSetCalls.push(set);
            return {
              returning: async () => {
                const key = keyFor(values.mcp_server_uuid, values.user_id);
                const now = new Date();
                const existing = store.get(key);
                if (existing) {
                  if (setWhere && !matches(existing, setWhere)) return [];
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
const { oauthSessionsTable } = await import("../../schema");

describe("OAuthSessionsRepository", () => {
  it("invalidates redirect material for both users of a public server preserving manual registration", async () => {
    const manual = {
      client_id: "manual",
      client_secret: "secret",
      _metamcp_registration: "manual",
      authorization_endpoint: "https://as.example/authorize",
      token_endpoint: "https://as.example/token",
    };
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userA,
      client_information: manual,
      tokens: tokensA,
      code_verifier: "A",
      expected_state: "state-A",
      discovery_state: { stale: true },
    });
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userB,
      client_information: {
        client_id: "dynamic",
        _metamcp_registration: "dynamic",
      },
      tokens: tokensB,
      code_verifier: "B",
      expected_state: "state-B",
      discovery_state: { stale: true },
    });
    await repo.upsert({
      mcp_server_uuid: "other-server",
      user_id: userA,
      tokens: tokensA,
    });
    await repo.invalidateRedirectDependentSessions(
      serverId,
      "http://localhost:4001/callback",
    );
    expect(await repo.findByMcpServerAndUser(serverId, userA)).toMatchObject({
      client_information: {
        ...manual,
        redirect_uris: ["http://localhost:4001/callback"],
      },
      tokens: null,
      code_verifier: null,
      expected_state: null,
      discovery_state: null,
    });
    expect(await repo.findByMcpServerAndUser(serverId, userB)).toMatchObject({
      client_information: {},
      tokens: null,
      code_verifier: null,
      expected_state: null,
      discovery_state: null,
    });
    expect(
      (await repo.findByMcpServerAndUser("other-server", userA))?.tokens,
    ).toEqual(tokensA);
  });

  it("quarantines ambiguous legacy client credentials instead of deleting them", async () => {
    const legacy = {
      client_id: "legacy-client",
      client_secret: "legacy-secret",
      token_endpoint_auth_method: "client_secret_post",
      redirect_uris: ["https://old.example/callback"],
    };
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userA,
      client_information: legacy,
      tokens: tokensA,
      code_verifier: "verifier",
      expected_state: "state",
      discovery_state: { authorizationServerUrl: "https://stale.example" },
    });
    const otherUsersLegacyClient = {
      client_id: "legacy-client-id-only",
      redirect_uris: ["https://old.example/callback"],
    };
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userB,
      client_information: otherUsersLegacyClient,
      tokens: tokensB,
      code_verifier: "other-verifier",
      expected_state: "other-state",
      discovery_state: {
        authorizationServerUrl: "https://other-stale.example",
      },
    });

    await repo.invalidateRedirectDependentSessions(
      serverId,
      "https://new.example/callback",
    );

    expect(await repo.findByMcpServerAndUser(serverId, userA)).toMatchObject({
      client_information: {
        ...legacy,
        _metamcp_registration: "legacy_unconfirmed",
      },
      tokens: null,
      code_verifier: null,
      expected_state: null,
      discovery_state: null,
    });
    expect(await repo.findByMcpServerAndUser(serverId, userB)).toMatchObject({
      client_information: {
        ...otherUsersLegacyClient,
        _metamcp_registration: "legacy_unconfirmed",
      },
      tokens: null,
      code_verifier: null,
      expected_state: null,
      discovery_state: null,
    });
  });

  it("deletes explicitly dynamic registration during redirect invalidation", async () => {
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userA,
      client_information: {
        client_id: "dynamic-client",
        client_secret: "dynamic-secret",
        _metamcp_registration: "dynamic",
      },
    });

    await repo.invalidateRedirectDependentSessions(
      serverId,
      "https://new.example/callback",
    );

    expect(
      (await repo.findByMcpServerAndUser(serverId, userA))?.client_information,
    ).toEqual({});
  });

  it("preserves an unmarked legacy client with explicit endpoints", async () => {
    const legacyManual = {
      client_id: "legacy-manual",
      client_secret: "secret",
      authorization_endpoint: "https://as.example/authorize",
      token_endpoint: "https://as.example/token",
      redirect_uris: ["https://old.example/callback"],
    };
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userA,
      client_information: legacyManual,
    });

    await repo.invalidateRedirectDependentSessions(
      serverId,
      "https://new.example/callback",
    );

    expect(
      (await repo.findByMcpServerAndUser(serverId, userA))?.client_information,
    ).toEqual({
      ...legacyManual,
      redirect_uris: ["https://new.example/callback"],
    });
  });
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
    expect(onConflictTargetCalls[0]).toEqual([
      oauthSessionsTable.mcp_server_uuid,
      oauthSessionsTable.user_id,
    ]);
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

  it("atomically refuses to overwrite quarantine with a late DCR result", async () => {
    const quarantined = {
      client_id: "legacy-client",
      client_secret: "legacy-secret",
      _metamcp_registration: "legacy_unconfirmed",
    };
    await repo.upsert({
      mcp_server_uuid: serverId,
      user_id: userA,
      client_information: quarantined,
    });

    const saved = await repo.saveDynamicClientInformation(serverId, userA, {
      client_id: "late-dcr-client",
      _metamcp_registration: "dynamic",
    } as unknown as OAuthClientInformation);

    expect(saved).toBe(false);
    expect(
      (await repo.findByMcpServerAndUser(serverId, userA))?.client_information,
    ).toEqual(quarantined);
  });
});
