import type { DatabaseMcpServer } from "@repo/zod-types";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// convertDbServerToParams imports oauthSessionsRepository directly from
// this file (not from db/repositories/index, unlike fetch-metamcp.ts) —
// mock it at that exact specifier. vi.mock factories are hoisted above
// all other top-level statements, so the mocked fn must come from
// vi.hoisted() rather than a plain top-level const (see
// https://vitest.dev/api/vi.html#vi-hoisted).
const { findByMcpServerAndUser } = vi.hoisted(() => ({
  findByMcpServerAndUser: vi.fn(),
}));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: { findByMcpServerAndUser },
}));

import { convertDbServerToParams } from "./utils";

const DB_SERVER: DatabaseMcpServer = {
  uuid: "22222222-2222-2222-2222-222222222222",
  name: "reclaim",
  description: "test server",
  type: "STREAMABLE_HTTP",
  command: null,
  args: [],
  env: {},
  url: "https://api.reclaim.ai/mcp",
  error_status: "NONE",
  created_at: new Date("2026-01-01T00:00:00Z"),
  bearerToken: null,
  headers: {},
  forward_headers: {},
  user_id: "user-1",
  redirect_uri: null,
};

describe("convertDbServerToParams — expires_at must survive into ServerParameters.oauth_tokens", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  // Same trap as getMcpServers (fetch-metamcp.test.ts), a second call site
  // used by startup.ts's idle-session warm-up and mcp-servers.impl.ts's
  // create/update paths. A test that only reverts fetch-metamcp.ts's copy
  // would stay green while this sibling copy regresses silently.
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

    const params = await convertDbServerToParams(DB_SERVER);

    expect(params).not.toBeNull();
    expect(params?.oauth_tokens?.expires_at).toBe(1893456000000);
    expect(params?.oauth_tokens?.access_token).toBe("AT_1");
  });

  it("leaves oauth_tokens.expires_at undefined when the session has none", async () => {
    findByMcpServerAndUser.mockResolvedValue({
      tokens: {
        access_token: "AT_2",
        token_type: "Bearer",
        refresh_token: "RT_2",
      },
    });

    const params = await convertDbServerToParams(DB_SERVER);
    expect(params?.oauth_tokens?.expires_at).toBeUndefined();
  });
});

describe("convertDbServerToParams — direct-server OAuth principal", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("uses a private server's owner to load and carry its OAuth session", async () => {
    findByMcpServerAndUser.mockResolvedValue({
      tokens: { access_token: "PRIVATE_TOKEN", token_type: "Bearer" },
    });

    const params = await convertDbServerToParams(DB_SERVER);

    expect(findByMcpServerAndUser).toHaveBeenCalledWith(
      DB_SERVER.uuid,
      "user-1",
    );
    expect(params?.oauth_user_id).toBe("user-1");
    expect(params?.oauth_tokens?.access_token).toBe("PRIVATE_TOKEN");
  });

  it("does not guess a principal or load OAuth tokens for a public server without a caller principal", async () => {
    const publicServer: DatabaseMcpServer = { ...DB_SERVER, user_id: null };

    const params = await convertDbServerToParams(publicServer);

    expect(findByMcpServerAndUser).not.toHaveBeenCalled();
    expect(params?.oauth_user_id).toBeUndefined();
    expect(params?.oauth_tokens).toBeNull();
  });
});
