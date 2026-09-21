import { describe, expect, it, vi } from "vitest";

// Mock logger to avoid path alias resolution issues in tests, and to keep
// the test output quiet.
vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// vi.mock factories are hoisted above all other top-level statements, so
// anything they reference must go through vi.hoisted() rather than a
// plain top-level const (see https://vitest.dev/api/vi.html#vi-hoisted).
const { findByMcpServerAndUser, SERVER_ROW } = vi.hoisted(() => ({
  findByMcpServerAndUser: vi.fn(),
  SERVER_ROW: {
    uuid: "11111111-1111-1111-1111-111111111111",
    name: "reclaim",
    description: "test server",
    type: "STREAMABLE_HTTP" as const,
    command: null,
    args: null,
    env: null,
    url: "https://api.reclaim.ai/mcp",
    created_at: new Date("2026-01-01T00:00:00Z"),
    bearerToken: null,
    headers: {},
    forward_headers: {},
    status: "ACTIVE",
    error_status: "NONE",
    oauth_user_id: "user-1",
  },
}));

// getMcpServers reaches the real oauth_sessions row through
// oauthSessionsRepository.findByMcpServerAndUser — mock it directly instead
// of the underlying `db` client so we can control what a session's
// persisted tokens look like per test.
vi.mock("../../db/repositories/index", () => ({
  oauthSessionsRepository: { findByMcpServerAndUser },
}));

// getMcpServers' own DB query (mcp_servers JOIN namespace_server_mappings)
// goes through this chainable `db` client — stub the chain to resolve to a
// single fixed row so we can assert on the ServerParameters produced.
vi.mock("../../db/index", () => ({
  db: {
    select: () => ({
      from: () => {
        const query = {
          innerJoin: () => query,
          where: async () => [SERVER_ROW],
        };
        return query;
      },
    }),
  },
}));

import { getMcpServers } from "./fetch-metamcp";

describe("getMcpServers — expires_at must survive into ServerParameters.oauth_tokens", () => {
  // This pins the specific trap called out in the proactive-refresh design:
  // getMcpServers copies oauth_sessions.tokens into ServerParameters.oauth_tokens
  // field-by-field (not a spread). A test that only checks the arithmetic
  // helper (withExpiresAt) would stay green even if this copy silently
  // dropped the new field — client.ts's proactive-refresh gate would then
  // never see an expires_at and would never fire.
  it("carries a persisted expires_at through into ServerParameters.oauth_tokens.expires_at", async () => {
    findByMcpServerAndUser.mockResolvedValue({
      tokens: {
        access_token: "AT_1",
        token_type: "Bearer",
        expires_in: 3600,
        expires_at: 1893456000000,
        refresh_token: "RT_1",
      },
    });

    const servers = await getMcpServers("namespace-uuid");
    const server = servers[SERVER_ROW.uuid];

    expect(server).toBeDefined();
    expect(server.oauth_tokens?.expires_at).toBe(1893456000000);
    expect(server.oauth_tokens?.access_token).toBe("AT_1");
    expect(server.oauth_tokens?.refresh_token).toBe("RT_1");
  });

  it("leaves oauth_tokens.expires_at undefined when the session has none", async () => {
    findByMcpServerAndUser.mockResolvedValue({
      tokens: {
        access_token: "AT_2",
        token_type: "Bearer",
        refresh_token: "RT_2",
      },
    });

    const servers = await getMcpServers("namespace-uuid");
    expect(servers[SERVER_ROW.uuid].oauth_tokens?.expires_at).toBeUndefined();
  });

  it("returns oauth_tokens: null when there is no oauth_sessions row", async () => {
    findByMcpServerAndUser.mockResolvedValue(undefined);

    const servers = await getMcpServers("namespace-uuid");
    expect(servers[SERVER_ROW.uuid].oauth_tokens).toBeNull();
  });
});
