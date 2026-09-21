import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// vitest hoists vi.mock() to before imports, so the repository mocks fire
// before oauth.impl loads and grabs the real repositories. The mock
// factories return fresh vi.fn() instances we can grab via dynamic import
// inside each test.
//
// `mcpServersRepository.findByUuid` is mocked because exchange/refresh
// resolve the upstream URL from the DB (NOT from the caller) as the SSRF
// guard for the OAuth token-exchange path.
vi.mock("../db/repositories", () => ({
  oauthSessionsRepository: {
    findByMcpServerAndUser: vi.fn(),
    upsert: vi.fn(),
    clearExpectedState: vi.fn(),
  },
  mcpServersRepository: {
    findByUuid: vi.fn(),
  },
}));

// Logger writes to stdout otherwise.
vi.mock("../utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

const ORIGINAL_APP_URL = process.env.APP_URL;
const stateFor = (uuid: string) => `upstream.${uuid}.${"a".repeat(43)}`;

describe("persisted OAuth protocol context", () => {
  const serverUuid = "00000000-0000-4000-8000-000000000003";
  const state = `upstream.${serverUuid}.${"a".repeat(43)}`;
  const discovery = {
    authorizationServerUrl: "https://identity.example/tenant",
    authorizationServerMetadata: {
      issuer: "https://identity.example/tenant",
      authorization_endpoint: "https://identity.example/authorize",
      token_endpoint: "https://tokens.example/exchange",
      response_types_supported: ["code"],
    },
    resourceMetadata: {
      resource: "https://resource.example/mcp",
      authorization_servers: ["https://identity.example/tenant"],
    },
  };
  const setup = async () => {
    const { oauthSessionsRepository, mcpServersRepository } =
      await import("../db/repositories");
    const { oauthImplementations } = await import("./oauth.impl");
    const session = {
      expected_state: state as string | null,
      code_verifier: "verifier",
      client_information: {
        client_id: "client",
        redirect_uris: ["https://metamcp.example/fe-oauth/callback"],
      } as Record<string, unknown>,
      discovery_state: structuredClone(discovery) as Record<string, unknown>,
      tokens: {
        access_token: "OLD",
        token_type: "Bearer",
        refresh_token: "RT",
      },
    };
    vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue({
      uuid: serverUuid,
      user_id: null,
      type: "STREAMABLE_HTTP",
      url: "https://resource.example/mcp",
    } as never);
    vi.mocked(
      oauthSessionsRepository.findByMcpServerAndUser,
    ).mockImplementation(async (_server, user) =>
      user === "user-a" ? (session as never) : undefined,
    );
    vi.mocked(oauthSessionsRepository.clearExpectedState).mockImplementation(
      async () => {
        session.expected_state = null;
        return undefined as never;
      },
    );
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(
        async () =>
          new Response(
            JSON.stringify({ access_token: "NEW", token_type: "Bearer" }),
            { status: 200 },
          ),
      );
    return { oauthImplementations, oauthSessionsRepository, session, fetchSpy };
  };
  beforeEach(() => vi.resetAllMocks());
  afterEach(() => vi.restoreAllMocks());

  it("posts exchange and refresh only to the persisted authorization server with the same resource", async () => {
    const { oauthImplementations, fetchSpy } = await setup();
    expect(
      await oauthImplementations.exchangeToken({ code: "C", state }, "user-a"),
    ).toMatchObject({ success: true, data: { mcp_server_uuid: serverUuid } });
    expect(
      await oauthImplementations.refreshToken(
        { mcp_server_uuid: serverUuid },
        "user-a",
      ),
    ).toMatchObject({ success: true });
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    for (const [url, init] of fetchSpy.mock.calls) {
      expect(url).toBe("https://tokens.example/exchange");
      expect(init?.method).toBe("POST");
      expect((init?.body as URLSearchParams).get("resource")).toBe(
        "https://resource.example/mcp",
      );
    }
  });

  it("carries freshly discovered authorization server and resource through authorize, exchange and refresh", async () => {
    const { oauthImplementations, oauthSessionsRepository, session, fetchSpy } =
      await setup();
    session.discovery_state = null as never;
    vi.mocked(oauthSessionsRepository.upsert).mockImplementation(
      async (input) => {
        Object.assign(session, input);
        return session as never;
      },
    );
    fetchSpy.mockImplementation(async (url) => {
      if (String(url).includes("/.well-known/oauth-protected-resource"))
        return jsonResponse(200, discovery.resourceMetadata);
      if (String(url).includes("/.well-known/oauth-authorization-server"))
        return jsonResponse(200, discovery.authorizationServerMetadata);
      if (String(url) === "https://tokens.example/exchange")
        return jsonResponse(200, {
          access_token: "NEW",
          token_type: "Bearer",
          refresh_token: "RT",
        });
      throw new Error(`Unexpected OAuth request: ${String(url)}`);
    });
    process.env.APP_URL = "https://metamcp.example";
    try {
      const started = await oauthImplementations.startAuthorization(
        { mcp_server_uuid: serverUuid },
        "user-a",
      );
      expect(started.success).toBe(true);
      if (!started.success) throw new Error("Authorization did not start");
      const authorizationUrl = new URL(started.data.authorization_url);
      expect(authorizationUrl.origin).toBe("https://identity.example");
      expect(authorizationUrl.searchParams.get("resource")).toBe(
        "https://resource.example/mcp",
      );
      expect(session.discovery_state).toMatchObject(discovery);
      fetchSpy.mockClear();
      const callbackState = authorizationUrl.searchParams.get("state");
      if (!callbackState) throw new Error("Authorization state missing");
      expect(
        await oauthImplementations.exchangeToken(
          { code: "C", state: callbackState },
          "user-a",
        ),
      ).toMatchObject({ success: true });
      expect(
        await oauthImplementations.refreshToken(
          { mcp_server_uuid: serverUuid },
          "user-a",
        ),
      ).toMatchObject({ success: true });
      expect(fetchSpy).toHaveBeenCalledTimes(2);
      for (const [url, init] of fetchSpy.mock.calls) {
        expect(url).toBe("https://tokens.example/exchange");
        expect((init?.body as URLSearchParams).get("resource")).toBe(
          "https://resource.example/mcp",
        );
      }
    } finally {
      if (ORIGINAL_APP_URL === undefined) delete process.env.APP_URL;
      else process.env.APP_URL = ORIGINAL_APP_URL;
    }
  });

  it("uses the persisted authorization server for the /token fallback", async () => {
    const { oauthImplementations, session, fetchSpy } = await setup();
    delete session.discovery_state.authorizationServerMetadata;
    expect(
      await oauthImplementations.exchangeToken({ code: "C", state }, "user-a"),
    ).toMatchObject({ success: true });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy.mock.calls[0]?.[0]).toBe("https://identity.example/token");
  });

  it("honors a pre-registered token endpoint over persisted metadata", async () => {
    const { oauthImplementations, session, fetchSpy } = await setup();
    session.client_information.token_endpoint =
      "https://configured.example/token";
    expect(
      await oauthImplementations.exchangeToken({ code: "C", state }, "user-a"),
    ).toMatchObject({ success: true });
    expect(fetchSpy.mock.calls[0]?.[0]).toBe(
      "https://configured.example/token",
    );
  });

  it.each([
    null,
    `upstream.${serverUuid}.${"b".repeat(43)}`,
    "short",
    "é".repeat(state.length),
  ])(
    "fails closed for a missing or mismatched stored state: %s",
    async (expected) => {
      const { oauthImplementations, session, fetchSpy } = await setup();
      session.expected_state = expected;
      expect(
        await oauthImplementations.exchangeToken(
          { code: "C", state },
          "user-a",
        ),
      ).toMatchObject({ success: false, error: "invalid_state" });
      expect(fetchSpy).not.toHaveBeenCalled();
    },
  );

  it("does not use another user's state on a public server", async () => {
    const { oauthImplementations, oauthSessionsRepository, fetchSpy } =
      await setup();
    expect(
      await oauthImplementations.exchangeToken({ code: "C", state }, "user-b"),
    ).toMatchObject({ success: false });
    expect(oauthSessionsRepository.findByMcpServerAndUser).toHaveBeenCalledWith(
      serverUuid,
      "user-b",
    );
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("rejects replay after a successful exchange without another fetch", async () => {
    const { oauthImplementations, fetchSpy } = await setup();
    await oauthImplementations.exchangeToken({ code: "C", state }, "user-a");
    fetchSpy.mockClear();
    expect(
      await oauthImplementations.exchangeToken({ code: "C", state }, "user-a"),
    ).toMatchObject({ success: false, error: "invalid_state" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it.each([
    [400, "invalid_grant", null],
    [400, "invalid_client", null],
    [503, "temporarily_unavailable", state],
    [429, "slow_down", state],
    [408, "request_timeout", state],
  ])(
    "handles terminal versus retryable upstream failure %s %s",
    async (status, error, remaining) => {
      const { oauthImplementations, session, fetchSpy } = await setup();
      fetchSpy.mockResolvedValue(
        new Response(JSON.stringify({ error }), { status }),
      );
      expect(
        await oauthImplementations.exchangeToken(
          { code: "C", state },
          "user-a",
        ),
      ).toMatchObject({ success: false, error });
      expect(session.expected_state).toBe(remaining);
    },
  );

  it.each([
    {},
    { authorizationServerUrl: "file:///tmp/token" },
    {
      ...discovery,
      authorizationServerMetadata: {
        ...discovery.authorizationServerMetadata,
        token_endpoint: "javascript:alert(1)",
      },
    },
    {
      ...discovery,
      resourceMetadata: { resource: "https://wrong.example/mcp" },
    },
    { ...discovery, resourceMetadata: { resource: 42 } },
  ])(
    "rejects corrupt discovery before outbound exchange or refresh: %j",
    async (corrupt) => {
      const { oauthImplementations, session, fetchSpy } = await setup();
      session.discovery_state = corrupt;
      expect(
        await oauthImplementations.exchangeToken(
          { code: "C", state },
          "user-a",
        ),
      ).toMatchObject({ success: false, error: "invalid_discovery_state" });
      expect(
        await oauthImplementations.refreshToken(
          { mcp_server_uuid: serverUuid },
          "user-a",
        ),
      ).toMatchObject({ success: false, error: "invalid_discovery_state" });
      expect(fetchSpy).not.toHaveBeenCalled();
    },
  );
});

const jsonResponse = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

describe("frontend OAuth router user scoping", () => {
  it("forwards ctx.user.id to get and upsert", async () => {
    const { createOAuthRouter } = await import("@repo/trpc");
    const get = vi.fn().mockResolvedValue({
      success: false as const,
      error: "session_not_found",
      message: "OAuth session not found",
    });
    const upsert = vi.fn().mockResolvedValue({
      success: false as const,
      error: "not_saved",
    });
    const implementations = {
      get,
      upsert,
      exchangeToken: vi.fn(),
      refreshToken: vi.fn(),
      startAuthorization: vi.fn(),
    };
    const caller = createOAuthRouter(implementations).createCaller({
      user: { id: "user-a" },
      session: { id: "session-a" },
    });
    const input = {
      mcp_server_uuid: "00000000-0000-4000-8000-000000000001",
    };

    await caller.get(input);
    await caller.upsert(input);

    expect(get).toHaveBeenCalledWith(input, "user-a");
    expect(upsert).toHaveBeenCalledWith(input, "user-a");
  });
});

describe("oauthImplementations get/upsert authorization", () => {
  const serverUuid = "00000000-0000-0000-0000-000000000002";
  const userId = "user-a";
  const sessionFor = (owner: string, secret: string) => ({
    uuid: `00000000-0000-0000-0000-0000000000${owner === userId ? "0a" : "0b"}`,
    mcp_server_uuid: serverUuid,
    user_id: owner,
    client_information: {
      client_id: secret,
      client_secret: `${secret}-client-secret`,
    },
    tokens: { access_token: `${secret}-access-token`, token_type: "Bearer" },
    code_verifier: `${secret}-verifier`,
    expected_state: `${secret}-state`,
    discovery_state: null,
    created_at: new Date(),
    updated_at: new Date(),
  });

  beforeEach(() => vi.clearAllMocks());

  const loadModule = async () => {
    const repos = await import("../db/repositories");
    const impl = await import("./oauth.impl");
    return {
      oauthImplementations: impl.oauthImplementations,
      findByMcpServerAndUser: repos.oauthSessionsRepository
        .findByMcpServerAndUser as ReturnType<typeof vi.fn>,
      upsert: repos.oauthSessionsRepository.upsert as ReturnType<typeof vi.fn>,
      findServerByUuid: repos.mcpServersRepository.findByUuid as ReturnType<
        typeof vi.fn
      >,
    };
  };

  it("returns access_denied before reading or serializing another user's session", async () => {
    const { oauthImplementations, findByMcpServerAndUser, findServerByUuid } =
      await loadModule();
    findServerByUuid.mockResolvedValue({
      uuid: serverUuid,
      user_id: "user-b",
      type: "STREAMABLE_HTTP",
      url: "https://mcp.example.com",
    });
    const result = await oauthImplementations.get(
      { mcp_server_uuid: serverUuid },
      userId,
    );

    expect(result).toMatchObject({ success: false, error: "access_denied" });
    expect(findByMcpServerAndUser).not.toHaveBeenCalled();
    expect(JSON.stringify(result)).not.toContain("OTHER-USER");
  });

  it("allows a public server but reads only the caller's session", async () => {
    const { oauthImplementations, findByMcpServerAndUser, findServerByUuid } =
      await loadModule();
    findServerByUuid.mockResolvedValue({
      uuid: serverUuid,
      user_id: null,
      type: "STREAMABLE_HTTP",
      url: "https://mcp.example.com",
    });
    findByMcpServerAndUser.mockImplementation(
      async (_server: string, requestedUser: string) =>
        requestedUser === userId
          ? sessionFor(userId, "CALLER")
          : sessionFor("user-b", "OTHER-USER"),
    );

    const result = await oauthImplementations.get(
      { mcp_server_uuid: serverUuid },
      userId,
    );

    expect(findByMcpServerAndUser).toHaveBeenCalledWith(serverUuid, userId);
    expect(result.success).toBe(true);
    expect(JSON.stringify(result)).toContain("CALLER-access-token");
    expect(JSON.stringify(result)).not.toContain("OTHER-USER");
  });

  it("rejects upsert for another user's private server before persistence", async () => {
    const { oauthImplementations, upsert, findServerByUuid } =
      await loadModule();
    findServerByUuid.mockResolvedValue({
      uuid: serverUuid,
      user_id: "user-b",
      type: "STREAMABLE_HTTP",
      url: "https://mcp.example.com",
    });

    const result = await oauthImplementations.upsert(
      { mcp_server_uuid: serverUuid, code_verifier: "do-not-save" },
      userId,
    );

    expect(result).toMatchObject({ success: false, error: "access_denied" });
    expect(upsert).not.toHaveBeenCalled();
  });

  it("permits upsert for a public server and writes the caller's user id", async () => {
    const { oauthImplementations, upsert, findServerByUuid } =
      await loadModule();
    findServerByUuid.mockResolvedValue({
      uuid: serverUuid,
      user_id: null,
      type: "STREAMABLE_HTTP",
      url: "https://mcp.example.com",
    });
    upsert.mockResolvedValue(sessionFor(userId, "CALLER"));

    const result = await oauthImplementations.upsert(
      { mcp_server_uuid: serverUuid, code_verifier: "verifier-a" },
      userId,
    );

    expect(result.success).toBe(true);
    expect(upsert).toHaveBeenCalledWith({
      mcp_server_uuid: serverUuid,
      user_id: userId,
      code_verifier: "verifier-a",
    });
  });
});

describe("oauthImplementations.exchangeToken", () => {
  beforeEach(() => {
    process.env.APP_URL = "https://metamcp.example.com";
    vi.clearAllMocks();
  });
  afterEach(() => {
    process.env.APP_URL = ORIGINAL_APP_URL;
  });

  const loadModule = async () => {
    const repos = await import("../db/repositories");
    const impl = await import("./oauth.impl");
    return {
      oauthImplementations: impl.oauthImplementations,
      findByMcpServerAndUser: repos.oauthSessionsRepository
        .findByMcpServerAndUser as ReturnType<typeof vi.fn>,
      upsert: repos.oauthSessionsRepository.upsert as ReturnType<typeof vi.fn>,
      clearExpectedState: repos.oauthSessionsRepository
        .clearExpectedState as ReturnType<typeof vi.fn>,
      findServerByUuid: repos.mcpServersRepository.findByUuid as ReturnType<
        typeof vi.fn
      >,
    };
  };

  // Helper: a server row the resolver will accept (owned, HTTP, valid URL).
  const ownedServer = (uuid: string, url: string, userId = "user-1") => ({
    uuid,
    name: "test-server",
    type: "STREAMABLE_HTTP" as const,
    url,
    user_id: userId,
    description: null,
    command: null,
    args: [] as string[],
    env: {},
    error_status: "NONE" as const,
    created_at: new Date(),
    bearerToken: null,
    headers: {},
  });

  const USER_ID = "user-1";

  const SERVER_UUID = "00000000-0000-0000-0000-000000000abc";

  it("loads the session, POSTs to the upstream token endpoint, and persists the tokens", async () => {
    const {
      oauthImplementations,
      findByMcpServerAndUser,
      upsert,
      findServerByUuid,
    } = await loadModule();

    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, "https://api.salesforce.com/platform/mcp/v1"),
    );
    findByMcpServerAndUser.mockResolvedValue({
      expected_state: stateFor(SERVER_UUID),
      uuid: "sess",
      mcp_server_uuid: SERVER_UUID,
      code_verifier: "PKCE_VERIFIER",
      client_information: {
        client_id: "3MVG9.Salesforce",
        token_endpoint: "https://login.salesforce.com/services/oauth2/token",
      },
      tokens: null,
    });
    upsert.mockResolvedValue({ uuid: "sess" });

    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (url, init) => {
        const urlStr = typeof url === "string" ? url : (url as URL).toString();
        if (urlStr.includes("/.well-known/oauth-authorization-server")) {
          return new Response("not found", { status: 404 });
        }
        expect(urlStr).toBe(
          "https://login.salesforce.com/services/oauth2/token",
        );
        const body = init?.body as URLSearchParams;
        expect(body.get("grant_type")).toBe("authorization_code");
        expect(body.get("code")).toBe("CODE_FROM_REDIRECT");
        expect(body.get("code_verifier")).toBe("PKCE_VERIFIER");
        expect(body.get("redirect_uri")).toBe(
          "https://metamcp.example.com/fe-oauth/callback",
        );
        expect(body.get("client_id")).toBe("3MVG9.Salesforce");
        return jsonResponse(200, {
          access_token: "AT_xyz",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "RT_abc",
        });
      });

    const result = await oauthImplementations.exchangeToken(
      { state: stateFor(SERVER_UUID), code: "CODE_FROM_REDIRECT" },
      USER_ID,
    );

    expect(result.success).toBe(true);
    expect(upsert).toHaveBeenCalledTimes(1);
    expect(upsert).toHaveBeenCalledWith({
      mcp_server_uuid: SERVER_UUID,
      user_id: USER_ID,
      tokens: expect.objectContaining({
        access_token: "AT_xyz",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "RT_abc",
      }),
    });
    fetchSpy.mockRestore();
  });

  it("persists expires_at computed from expires_in", async () => {
    const {
      oauthImplementations,
      findByMcpServerAndUser,
      upsert,
      findServerByUuid,
    } = await loadModule();

    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, "https://api.reclaim.ai/mcp"),
    );
    findByMcpServerAndUser.mockResolvedValue({
      expected_state: stateFor(SERVER_UUID),
      uuid: "sess",
      mcp_server_uuid: SERVER_UUID,
      code_verifier: "PKCE_VERIFIER",
      client_information: {
        client_id: "client-1",
        token_endpoint: "https://api.reclaim.ai/oauth/token",
      },
      tokens: null,
    });
    upsert.mockResolvedValue({ uuid: "sess" });

    const before = Date.now();
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (url) => {
        const urlStr = typeof url === "string" ? url : (url as URL).toString();
        if (urlStr.includes("/.well-known/")) {
          return new Response("not found", { status: 404 });
        }
        return jsonResponse(200, {
          access_token: "AT_reclaim",
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "RT_reclaim",
        });
      });

    const result = await oauthImplementations.exchangeToken(
      { state: stateFor(SERVER_UUID), code: "CODE" },
      USER_ID,
    );

    expect(result.success).toBe(true);
    const persisted = upsert.mock.calls[0][0] as {
      tokens: { expires_at?: number };
    };
    expect(persisted.tokens.expires_at).toBeGreaterThanOrEqual(
      before + 3600 * 1000,
    );
    fetchSpy.mockRestore();
  });

  it("does not persist expires_at when the upstream omits expires_in", async () => {
    const {
      oauthImplementations,
      findByMcpServerAndUser,
      upsert,
      findServerByUuid,
    } = await loadModule();

    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, "https://api.example.com/mcp"),
    );
    findByMcpServerAndUser.mockResolvedValue({
      expected_state: stateFor(SERVER_UUID),
      uuid: "sess",
      mcp_server_uuid: SERVER_UUID,
      code_verifier: "PKCE_VERIFIER",
      client_information: { client_id: "client-1" },
      tokens: null,
    });
    upsert.mockResolvedValue({ uuid: "sess" });

    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (url) => {
        const urlStr = typeof url === "string" ? url : (url as URL).toString();
        if (urlStr.includes("/.well-known/")) {
          return new Response("not found", { status: 404 });
        }
        return jsonResponse(200, {
          access_token: "AT_no_expiry",
          token_type: "Bearer",
        });
      });

    const result = await oauthImplementations.exchangeToken(
      { state: stateFor(SERVER_UUID), code: "CODE" },
      USER_ID,
    );

    expect(result.success).toBe(true);
    const persisted = upsert.mock.calls[0][0] as {
      tokens: Record<string, unknown>;
    };
    expect(persisted.tokens).not.toHaveProperty("expires_at");
    fetchSpy.mockRestore();
  });

  it("returns the upstream OAuth error envelope on 400 instead of throwing", async () => {
    const {
      oauthImplementations,
      findByMcpServerAndUser,
      upsert,
      findServerByUuid,
    } = await loadModule();

    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, "https://api.salesforce.com/mcp"),
    );
    findByMcpServerAndUser.mockResolvedValue({
      expected_state: stateFor(SERVER_UUID),
      mcp_server_uuid: SERVER_UUID,
      code_verifier: "PKCE_VERIFIER",
      client_information: {
        client_id: "3MVG9",
        token_endpoint: "https://login.salesforce.com/services/oauth2/token",
      },
      tokens: null,
    });

    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (url) => {
        const urlStr = typeof url === "string" ? url : (url as URL).toString();
        if (urlStr.includes("/.well-known/")) {
          return new Response("nope", { status: 404 });
        }
        return jsonResponse(400, {
          error: "invalid_grant",
          error_description: "authentication failure",
        });
      });

    const result = await oauthImplementations.exchangeToken(
      { state: stateFor(SERVER_UUID), code: "BAD" },
      USER_ID,
    );

    expect(result).toEqual({
      success: false,
      error: "invalid_grant",
      error_description: "authentication failure",
      upstream_status: 400,
    });
    expect(upsert).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it("returns server_not_found when the MCP server does not exist", async () => {
    const { oauthImplementations, findServerByUuid } = await loadModule();
    findServerByUuid.mockResolvedValue(undefined);
    const result = await oauthImplementations.exchangeToken(
      { state: stateFor(SERVER_UUID), code: "C" },
      USER_ID,
    );
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error).toBe("server_not_found");
  });

  it("returns access_denied when a different user owns the server", async () => {
    const { oauthImplementations, findServerByUuid } = await loadModule();
    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, "https://api.example.com/mcp", "other-user"),
    );
    const result = await oauthImplementations.exchangeToken(
      { state: stateFor(SERVER_UUID), code: "C" },
      USER_ID,
    );
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error).toBe("access_denied");
  });

  it("returns session_not_found when the OAuth session is missing", async () => {
    const { oauthImplementations, findByMcpServerAndUser, findServerByUuid } =
      await loadModule();
    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, "https://api.example.com/mcp"),
    );
    findByMcpServerAndUser.mockResolvedValue(undefined);

    const result = await oauthImplementations.exchangeToken(
      { state: stateFor(SERVER_UUID), code: "C" },
      USER_ID,
    );
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error).toBe("session_not_found");
  });

  it("returns code_verifier_missing when the session has no PKCE verifier", async () => {
    const { oauthImplementations, findByMcpServerAndUser, findServerByUuid } =
      await loadModule();
    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, "https://api.example.com/mcp"),
    );
    findByMcpServerAndUser.mockResolvedValue({
      expected_state: stateFor(SERVER_UUID),
      mcp_server_uuid: SERVER_UUID,
      code_verifier: null,
      client_information: { client_id: "x" },
      tokens: null,
    });

    const result = await oauthImplementations.exchangeToken(
      { state: stateFor(SERVER_UUID), code: "C" },
      USER_ID,
    );
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error).toBe("code_verifier_missing");
  });

  it("returns client_information_missing when client_id is absent", async () => {
    const { oauthImplementations, findByMcpServerAndUser, findServerByUuid } =
      await loadModule();
    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, "https://api.example.com/mcp"),
    );
    findByMcpServerAndUser.mockResolvedValue({
      expected_state: stateFor(SERVER_UUID),
      mcp_server_uuid: SERVER_UUID,
      code_verifier: "verifier",
      client_information: {},
      tokens: null,
    });

    const result = await oauthImplementations.exchangeToken(
      { state: stateFor(SERVER_UUID), code: "C" },
      USER_ID,
    );
    expect(result.success).toBe(false);
    if (!result.success)
      expect(result.error).toBe("client_information_missing");
  });
});

// Regression test for redirect_uri byte-match. The frontend builds the
// redirect_uri as `getAppUrl() + "/fe-oauth/callback"` with no
// normalization (apps/frontend/lib/oauth-provider.ts), so the backend
// MUST mirror that exactly. Diverging normalization (e.g. stripping the
// trailing slash) silently re-introduces the upstream `invalid_grant`
// failure mode we are fixing.
describe("exchangeToken redirect_uri byte-match", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  afterEach(() => {
    process.env.APP_URL = ORIGINAL_APP_URL;
  });

  const loadModule = async () => {
    const repos = await import("../db/repositories");
    const impl = await import("./oauth.impl");
    return {
      oauthImplementations: impl.oauthImplementations,
      findByMcpServerAndUser: repos.oauthSessionsRepository
        .findByMcpServerAndUser as ReturnType<typeof vi.fn>,
      upsert: repos.oauthSessionsRepository.upsert as ReturnType<typeof vi.fn>,
      clearExpectedState: repos.oauthSessionsRepository
        .clearExpectedState as ReturnType<typeof vi.fn>,
      findServerByUuid: repos.mcpServersRepository.findByUuid as ReturnType<
        typeof vi.fn
      >,
    };
  };

  // Helper: a server row the resolver will accept (owned, HTTP, valid URL).
  const ownedServer = (uuid: string, url: string, userId = "user-1") => ({
    uuid,
    name: "test-server",
    type: "STREAMABLE_HTTP" as const,
    url,
    user_id: userId,
    description: null,
    command: null,
    args: [] as string[],
    env: {},
    error_status: "NONE" as const,
    created_at: new Date(),
    bearerToken: null,
    headers: {},
  });

  const USER_ID = "user-1";

  it.each([
    [
      "no trailing slash",
      "https://metamcp.example.com",
      "https://metamcp.example.com/fe-oauth/callback",
    ],
    [
      "trailing slash preserved (matches frontend's verbatim concatenation)",
      "https://metamcp.example.com/",
      "https://metamcp.example.com//fe-oauth/callback",
    ],
  ])("uses APP_URL+%s verbatim", async (_label, appUrl, expectedRedirect) => {
    process.env.APP_URL = appUrl;

    const {
      oauthImplementations,
      findByMcpServerAndUser,
      upsert,
      findServerByUuid,
    } = await loadModule();
    findServerByUuid.mockResolvedValue(
      ownedServer(
        "00000000-0000-0000-0000-000000000fff",
        "https://upstream/mcp",
      ),
    );
    findByMcpServerAndUser.mockResolvedValue({
      expected_state: stateFor("00000000-0000-0000-0000-000000000fff"),
      mcp_server_uuid: "00000000-0000-0000-0000-000000000fff",
      code_verifier: "v",
      client_information: {
        client_id: "c",
        token_endpoint: "https://upstream/token",
      },
      tokens: null,
    });
    upsert.mockResolvedValue({});

    let observedRedirect: string | null = null;
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (url, init) => {
        const urlStr = typeof url === "string" ? url : (url as URL).toString();
        if (urlStr.includes("/.well-known/")) {
          return new Response("nope", { status: 404 });
        }
        const body = init?.body as URLSearchParams;
        observedRedirect = body.get("redirect_uri");
        return new Response(
          JSON.stringify({ access_token: "x", token_type: "Bearer" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      });

    await oauthImplementations.exchangeToken(
      { state: stateFor("00000000-0000-0000-0000-000000000fff"), code: "C" },
      USER_ID,
    );

    expect(observedRedirect).toBe(expectedRedirect);
    fetchSpy.mockRestore();
  });
});

// Per-server redirect_uri override (Brief A). oauth.impl reads
// client_information.redirect_uris[0] — the value actually sent at
// registration/authorize — rather than recomputing a redirect_uri, so the
// token-exchange request is byte-identical to what the upstream already
// saw regardless of any per-server override. Falls back to the APP_URL
// derivation only when redirect_uris is absent (e.g. a session predating
// this field).
describe("exchangeToken redirect_uri source", () => {
  beforeEach(() => {
    process.env.APP_URL = "https://metamcp.example.com";
    vi.clearAllMocks();
  });
  afterEach(() => {
    process.env.APP_URL = ORIGINAL_APP_URL;
  });

  const loadModule = async () => {
    const repos = await import("../db/repositories");
    const impl = await import("./oauth.impl");
    return {
      oauthImplementations: impl.oauthImplementations,
      findByMcpServerAndUser: repos.oauthSessionsRepository
        .findByMcpServerAndUser as ReturnType<typeof vi.fn>,
      upsert: repos.oauthSessionsRepository.upsert as ReturnType<typeof vi.fn>,
      findServerByUuid: repos.mcpServersRepository.findByUuid as ReturnType<
        typeof vi.fn
      >,
    };
  };

  const ownedServer = (uuid: string, url: string) => ({
    uuid,
    name: "test-server",
    type: "STREAMABLE_HTTP" as const,
    url,
    user_id: "user-1",
    description: null,
    command: null,
    args: [] as string[],
    env: {},
    error_status: "NONE" as const,
    created_at: new Date(),
    bearerToken: null,
    headers: {},
  });

  const USER_ID = "user-1";
  const SERVER_UUID = "00000000-0000-0000-0000-0000000000cc";

  it("uses client_information.redirect_uris[0] when present (per-server override)", async () => {
    const {
      oauthImplementations,
      findByMcpServerAndUser,
      upsert,
      findServerByUuid,
    } = await loadModule();
    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, "https://upstream.example.com/mcp"),
    );
    findByMcpServerAndUser.mockResolvedValue({
      expected_state: stateFor(SERVER_UUID),
      mcp_server_uuid: SERVER_UUID,
      code_verifier: "v",
      client_information: {
        client_id: "c",
        token_endpoint: "https://upstream.example.com/token",
        redirect_uris: ["http://127.0.0.1:33418/callback"],
      },
      tokens: null,
    });
    upsert.mockResolvedValue({});

    let observedRedirect: string | null = null;
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (url, init) => {
        const urlStr = typeof url === "string" ? url : (url as URL).toString();
        if (urlStr.includes("/.well-known/")) {
          return new Response("nope", { status: 404 });
        }
        const body = init?.body as URLSearchParams;
        observedRedirect = body.get("redirect_uri");
        return jsonResponse(200, { access_token: "x", token_type: "Bearer" });
      });

    await oauthImplementations.exchangeToken(
      { state: stateFor(SERVER_UUID), code: "C" },
      USER_ID,
    );

    expect(observedRedirect).toBe("http://127.0.0.1:33418/callback");
    fetchSpy.mockRestore();
  });

  it("falls back to the APP_URL derivation when redirect_uris is absent", async () => {
    const {
      oauthImplementations,
      findByMcpServerAndUser,
      upsert,
      findServerByUuid,
    } = await loadModule();
    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, "https://upstream.example.com/mcp"),
    );
    findByMcpServerAndUser.mockResolvedValue({
      expected_state: stateFor(SERVER_UUID),
      mcp_server_uuid: SERVER_UUID,
      code_verifier: "v",
      client_information: {
        client_id: "c",
        token_endpoint: "https://upstream.example.com/token",
      },
      tokens: null,
    });
    upsert.mockResolvedValue({});

    let observedRedirect: string | null = null;
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (url, init) => {
        const urlStr = typeof url === "string" ? url : (url as URL).toString();
        if (urlStr.includes("/.well-known/")) {
          return new Response("nope", { status: 404 });
        }
        const body = init?.body as URLSearchParams;
        observedRedirect = body.get("redirect_uri");
        return jsonResponse(200, { access_token: "x", token_type: "Bearer" });
      });

    await oauthImplementations.exchangeToken(
      { state: stateFor(SERVER_UUID), code: "C" },
      USER_ID,
    );

    expect(observedRedirect).toBe(
      "https://metamcp.example.com/fe-oauth/callback",
    );
    fetchSpy.mockRestore();
  });
});

describe("oauthImplementations.refreshToken", () => {
  beforeEach(() => {
    process.env.APP_URL = "https://metamcp.example.com";
    vi.clearAllMocks();
  });
  afterEach(() => {
    process.env.APP_URL = ORIGINAL_APP_URL;
  });

  const loadModule = async () => {
    const repos = await import("../db/repositories");
    const impl = await import("./oauth.impl");
    return {
      oauthImplementations: impl.oauthImplementations,
      findByMcpServerAndUser: repos.oauthSessionsRepository
        .findByMcpServerAndUser as ReturnType<typeof vi.fn>,
      upsert: repos.oauthSessionsRepository.upsert as ReturnType<typeof vi.fn>,
      clearExpectedState: repos.oauthSessionsRepository
        .clearExpectedState as ReturnType<typeof vi.fn>,
      findServerByUuid: repos.mcpServersRepository.findByUuid as ReturnType<
        typeof vi.fn
      >,
    };
  };

  // Helper: a server row the resolver will accept (owned, HTTP, valid URL).
  const ownedServer = (uuid: string, url: string, userId = "user-1") => ({
    uuid,
    name: "test-server",
    type: "STREAMABLE_HTTP" as const,
    url,
    user_id: userId,
    description: null,
    command: null,
    args: [] as string[],
    env: {},
    error_status: "NONE" as const,
    created_at: new Date(),
    bearerToken: null,
    headers: {},
  });

  const USER_ID = "user-1";

  const SERVER_UUID = "00000000-0000-0000-0000-000000000def";

  it("POSTs grant_type=refresh_token and persists the new access token", async () => {
    const {
      oauthImplementations,
      findByMcpServerAndUser,
      upsert,
      findServerByUuid,
    } = await loadModule();

    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, "https://example.com/mcp"),
    );
    findByMcpServerAndUser.mockResolvedValue({
      expected_state: stateFor(SERVER_UUID),
      mcp_server_uuid: SERVER_UUID,
      code_verifier: null,
      client_information: {
        client_id: "client-1",
        token_endpoint: "https://example.com/token",
      },
      tokens: {
        access_token: "OLD",
        token_type: "Bearer",
        refresh_token: "RT_original",
      },
    });
    upsert.mockResolvedValue({});

    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (url, init) => {
        const urlStr = typeof url === "string" ? url : (url as URL).toString();
        if (urlStr.includes("/.well-known/")) {
          return new Response("nope", { status: 404 });
        }
        const body = init?.body as URLSearchParams;
        expect(body.get("grant_type")).toBe("refresh_token");
        expect(body.get("refresh_token")).toBe("RT_original");
        return jsonResponse(200, {
          access_token: "AT_new",
          token_type: "Bearer",
        });
      });

    const result = await oauthImplementations.refreshToken(
      { mcp_server_uuid: SERVER_UUID },
      USER_ID,
    );

    expect(result.success).toBe(true);
    expect(upsert).toHaveBeenCalledWith({
      mcp_server_uuid: SERVER_UUID,
      user_id: USER_ID,
      tokens: expect.objectContaining({
        access_token: "AT_new",
        refresh_token: "RT_original",
      }),
    });
    fetchSpy.mockRestore();
  });

  it("returns no_refresh_token when the session has no refresh_token", async () => {
    const { oauthImplementations, findByMcpServerAndUser, findServerByUuid } =
      await loadModule();
    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, "https://example.com/mcp"),
    );
    findByMcpServerAndUser.mockResolvedValue({
      expected_state: stateFor(SERVER_UUID),
      mcp_server_uuid: SERVER_UUID,
      client_information: { client_id: "x" },
      tokens: { access_token: "x", token_type: "Bearer" },
    });

    const result = await oauthImplementations.refreshToken(
      { mcp_server_uuid: SERVER_UUID },
      USER_ID,
    );
    expect(result.success).toBe(false);
    if (!result.success) expect(result.error).toBe("no_refresh_token");
  });
});

// RFC 6749 §10.12: exact state verification is mandatory. Consumed or missing
// state fails closed, and terminal authorization errors require a fresh flow.
describe("exchangeToken state CSRF validation", () => {
  beforeEach(() => {
    process.env.APP_URL = "https://metamcp.example.com";
    vi.clearAllMocks();
  });
  afterEach(() => {
    process.env.APP_URL = ORIGINAL_APP_URL;
  });

  const loadModule = async () => {
    const repos = await import("../db/repositories");
    const impl = await import("./oauth.impl");
    return {
      oauthImplementations: impl.oauthImplementations,
      findByMcpServerAndUser: repos.oauthSessionsRepository
        .findByMcpServerAndUser as ReturnType<typeof vi.fn>,
      upsert: repos.oauthSessionsRepository.upsert as ReturnType<typeof vi.fn>,
      clearExpectedState: repos.oauthSessionsRepository
        .clearExpectedState as ReturnType<typeof vi.fn>,
      findServerByUuid: repos.mcpServersRepository.findByUuid as ReturnType<
        typeof vi.fn
      >,
    };
  };

  const ownedServer = (uuid: string, url: string) => ({
    uuid,
    name: "test-server",
    type: "STREAMABLE_HTTP" as const,
    url,
    user_id: "user-1",
    description: null,
    command: null,
    args: [] as string[],
    env: {},
    error_status: "NONE" as const,
    created_at: new Date(),
    bearerToken: null,
    headers: {},
  });

  const SERVER_UUID = "00000000-0000-0000-0000-0000000000aa";
  const USER_ID = "user-1";

  const upstreamSuccess = vi.fn(async (url: string, init?: RequestInit) => {
    const urlStr = url;
    if (urlStr.includes("/.well-known/")) {
      return new Response("nope", { status: 404 });
    }
    void init;
    return new Response(
      JSON.stringify({
        access_token: "AT",
        token_type: "Bearer",
        expires_in: 3600,
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  });

  it("expected_state null in DB fails closed before fetching", async () => {
    const {
      oauthImplementations,
      findByMcpServerAndUser,
      upsert,
      clearExpectedState,
      findServerByUuid,
    } = await loadModule();
    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, "https://upstream.example.com/mcp"),
    );
    findByMcpServerAndUser.mockResolvedValue({
      uuid: "sess",
      mcp_server_uuid: SERVER_UUID,
      code_verifier: "v",
      client_information: {
        client_id: "c",
        token_endpoint: "https://upstream.example.com/token",
      },
      tokens: null,
      expected_state: null,
    });
    upsert.mockResolvedValue({});
    clearExpectedState.mockResolvedValue({});

    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(upstreamSuccess as unknown as typeof fetch);

    const result = await oauthImplementations.exchangeToken(
      { code: "C", state: stateFor(SERVER_UUID) },
      USER_ID,
    );

    expect(result).toMatchObject({ success: false, error: "invalid_state" });
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(upsert).not.toHaveBeenCalled();
    expect(clearExpectedState).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it("expected_state matches input.state → exchange proceeds, clearExpectedState called once", async () => {
    const {
      oauthImplementations,
      findByMcpServerAndUser,
      upsert,
      clearExpectedState,
      findServerByUuid,
    } = await loadModule();
    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, "https://upstream.example.com/mcp"),
    );
    findByMcpServerAndUser.mockResolvedValue({
      mcp_server_uuid: SERVER_UUID,
      code_verifier: "v",
      client_information: {
        client_id: "c",
        token_endpoint: "https://upstream.example.com/token",
      },
      tokens: null,
      expected_state: stateFor(SERVER_UUID),
    });
    upsert.mockResolvedValue({});
    clearExpectedState.mockResolvedValue({});

    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(upstreamSuccess as unknown as typeof fetch);

    const result = await oauthImplementations.exchangeToken(
      { code: "C", state: stateFor(SERVER_UUID) },
      USER_ID,
    );

    expect(result.success).toBe(true);
    expect(clearExpectedState).toHaveBeenCalledWith(SERVER_UUID, USER_ID);
    expect(clearExpectedState).toHaveBeenCalledTimes(1);
    fetchSpy.mockRestore();
  });

  it("expected_state mismatches input.state → returns invalid_state, no upstream POST, no clear", async () => {
    const {
      oauthImplementations,
      findByMcpServerAndUser,
      upsert,
      clearExpectedState,
      findServerByUuid,
    } = await loadModule();
    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, "https://upstream.example.com/mcp"),
    );
    findByMcpServerAndUser.mockResolvedValue({
      mcp_server_uuid: SERVER_UUID,
      code_verifier: "v",
      client_information: { client_id: "c" },
      tokens: null,
      expected_state: stateFor(SERVER_UUID),
    });

    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const result = await oauthImplementations.exchangeToken(
      { code: "C", state: "different-value" },
      USER_ID,
    );

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("invalid_state");
    }
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(upsert).not.toHaveBeenCalled();
    expect(clearExpectedState).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it("expected_state present but input.state empty returns invalid_state", async () => {
    const {
      oauthImplementations,
      findByMcpServerAndUser,
      upsert,
      clearExpectedState,
      findServerByUuid,
    } = await loadModule();
    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, "https://upstream.example.com/mcp"),
    );
    findByMcpServerAndUser.mockResolvedValue({
      mcp_server_uuid: SERVER_UUID,
      code_verifier: "v",
      client_information: { client_id: "c" },
      tokens: null,
      expected_state: stateFor(SERVER_UUID),
    });

    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const result = await oauthImplementations.exchangeToken(
      { state: "", code: "C" },
      USER_ID,
    );

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("invalid_state");
    }
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(upsert).not.toHaveBeenCalled();
    expect(clearExpectedState).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it("expected_state matches but invalid_grant consumes the state", async () => {
    const {
      oauthImplementations,
      findByMcpServerAndUser,
      upsert,
      clearExpectedState,
      findServerByUuid,
    } = await loadModule();
    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, "https://upstream.example.com/mcp"),
    );
    findByMcpServerAndUser.mockResolvedValue({
      mcp_server_uuid: SERVER_UUID,
      code_verifier: "v",
      client_information: {
        client_id: "c",
        token_endpoint: "https://upstream.example.com/token",
      },
      tokens: null,
      expected_state: stateFor(SERVER_UUID),
    });

    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (url) => {
        const urlStr = typeof url === "string" ? url : (url as URL).toString();
        if (urlStr.includes("/.well-known/")) {
          return new Response("nope", { status: 404 });
        }
        return new Response(
          JSON.stringify({
            error: "invalid_grant",
            error_description: "the code was already used",
          }),
          { status: 400, headers: { "Content-Type": "application/json" } },
        );
      });

    const result = await oauthImplementations.exchangeToken(
      { code: "C", state: stateFor(SERVER_UUID) },
      USER_ID,
    );

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("invalid_grant");
    }
    expect(upsert).not.toHaveBeenCalled();
    expect(clearExpectedState).toHaveBeenCalledWith(SERVER_UUID, USER_ID);
    fetchSpy.mockRestore();
  });

  // Regression test for the persistence bug found in code review: the
  // tRPC `upsert` must forward expected_state for legacy session-upsert callers.
  it("frontend.oauth.upsert forwards expected_state to the repository", async () => {
    const { oauthImplementations, upsert, findServerByUuid } =
      await loadModule();
    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, "https://mcp.example.com"),
    );
    upsert.mockResolvedValue({
      uuid: "sess",
      mcp_server_uuid: SERVER_UUID,
      client_information: null,
      tokens: null,
      code_verifier: null,
      created_at: new Date(),
      updated_at: new Date(),
    });

    await oauthImplementations.upsert(
      {
        mcp_server_uuid: SERVER_UUID,
        expected_state: "the-csrf-nonce",
      },
      USER_ID,
    );

    expect(upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        mcp_server_uuid: SERVER_UUID,
        user_id: USER_ID,
        expected_state: "the-csrf-nonce",
      }),
    );
  });
});

// Server-side authorize-URL construction (Brief E). `auth()` is the real
// MCP SDK orchestrator — only `fetch` is mocked, per the "mock the
// upstream HTTP calls, don't hit anything live" requirement. This
// exercises OAuthUpstreamClientProvider (provider.ts) end to end through
// the SDK's actual discovery/DCR/PKCE/state code paths.
describe("oauthImplementations.startAuthorization", () => {
  beforeEach(() => {
    process.env.APP_URL = "https://metamcp.example.com";
    vi.clearAllMocks();
  });
  afterEach(() => {
    process.env.APP_URL = ORIGINAL_APP_URL;
  });

  const loadModule = async () => {
    const repos = await import("../db/repositories");
    const impl = await import("./oauth.impl");
    return {
      oauthImplementations: impl.oauthImplementations,
      findByMcpServerAndUser: repos.oauthSessionsRepository
        .findByMcpServerAndUser as ReturnType<typeof vi.fn>,
      upsert: repos.oauthSessionsRepository.upsert as ReturnType<typeof vi.fn>,
      findServerByUuid: repos.mcpServersRepository.findByUuid as ReturnType<
        typeof vi.fn
      >,
    };
  };

  // Helper: a server row the resolver will accept (owned, HTTP, valid
  // URL), with an optional per-server redirect_uri override.
  const ownedServer = (
    uuid: string,
    url: string,
    opts?: { redirectUri?: string | null; userId?: string },
  ) => ({
    uuid,
    name: "test-server",
    type: "STREAMABLE_HTTP" as const,
    url,
    user_id: opts?.userId ?? "user-1",
    description: null,
    command: null,
    args: [] as string[],
    env: {},
    error_status: "NONE" as const,
    created_at: new Date(),
    bearerToken: null,
    headers: {},
    redirect_uri: opts?.redirectUri ?? null,
  });

  const USER_ID = "user-1";
  const SERVER_UUID = "00000000-0000-0000-0000-0000000000e1";
  const SERVER_URL = "https://mcp.example.com/mcp";

  it("returns access_denied when a different user owns the server (same ownership gate as exchangeToken/refreshToken)", async () => {
    const { oauthImplementations, findServerByUuid } = await loadModule();
    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, SERVER_URL, { userId: "other-user" }),
    );

    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const result = await oauthImplementations.startAuthorization(
      { mcp_server_uuid: SERVER_UUID },
      USER_ID,
    );

    expect(result.success).toBe(false);
    if (!result.success) expect(result.error).toBe("access_denied");
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  // THE byte-match test. A redirect_uri-only configuration (per-server
  // override set, NO pre-registered client_id) forces DCR to run. The
  // mocked DCR response deliberately echoes back a DIFFERENT redirect_uris
  // than what MetaMCP sent, to prove OAuthUpstreamClientProvider.
  // saveClientInformation() actively corrects it rather than trusting the
  // upstream's echo. A subsequent exchangeToken call (fed the persisted
  // client_information) must then send that same, corrected redirect_uri
  // — this is the exact "invalid_grant from a mismatched redirect_uri"
  // failure mode the CRITICAL requirement in the brief describes.
  it("byte-matches the redirect_uri override through DCR into a subsequent exchangeToken", async () => {
    const {
      oauthImplementations,
      findByMcpServerAndUser,
      upsert,
      findServerByUuid,
    } = await loadModule();

    const REDIRECT_OVERRIDE = "http://127.0.0.1:5555/callback";
    findServerByUuid.mockResolvedValue(
      ownedServer(SERVER_UUID, SERVER_URL, {
        redirectUri: REDIRECT_OVERRIDE,
      }),
    );
    // No session yet: clientInformation() and discoveryState() both see
    // nothing, forcing full discovery + DCR.
    findByMcpServerAndUser.mockResolvedValue(undefined);
    upsert.mockResolvedValue({});

    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (url, init) => {
        const urlStr = typeof url === "string" ? url : (url as URL).toString();
        if (urlStr.includes("/.well-known/oauth-protected-resource")) {
          return new Response("not found", { status: 404 });
        }
        if (urlStr.includes("/.well-known/oauth-authorization-server")) {
          return jsonResponse(200, {
            issuer: "https://mcp.example.com",
            authorization_endpoint: "https://mcp.example.com/authorize",
            token_endpoint: "https://mcp.example.com/token",
            registration_endpoint: "https://mcp.example.com/register",
            response_types_supported: ["code"],
          });
        }
        if (urlStr === "https://mcp.example.com/register") {
          // Deliberately WRONG redirect_uris — proves the provider
          // overrides it rather than trusting the upstream's echo.
          return jsonResponse(201, {
            client_id: "dcr-client-xyz",
            redirect_uris: ["https://mismatched.example/would-fail"],
            token_endpoint_auth_method: "none",
            grant_types: ["authorization_code", "refresh_token"],
            response_types: ["code"],
          });
        }
        if (urlStr === "https://mcp.example.com/token") {
          const body = init?.body as URLSearchParams;
          return jsonResponse(200, {
            access_token: "AT",
            token_type: "Bearer",
            _observed_redirect_uri: body.get("redirect_uri"),
          });
        }
        throw new Error(`unexpected fetch in test: ${urlStr}`);
      });

    const startResult = await oauthImplementations.startAuthorization(
      { mcp_server_uuid: SERVER_UUID },
      USER_ID,
    );

    expect(startResult.success).toBe(true);
    if (!startResult.success) throw new Error("unreachable");
    expect(startResult.data.authorization_url).toContain(
      "https://mcp.example.com/authorize",
    );
    expect(startResult.data.authorization_url).toContain(
      `redirect_uri=${encodeURIComponent(REDIRECT_OVERRIDE)}`,
    );

    // Find the upsert call that persisted client_information and assert
    // the CRITICAL invariant: redirect_uris[0] is the override, NOT the
    // upstream's mismatched echo.
    const clientInfoCall = upsert.mock.calls.find(
      (call) => call[0]?.client_information,
    );
    expect(clientInfoCall).toBeDefined();
    if (!clientInfoCall) throw new Error("unreachable");
    const persistedClientInfo = clientInfoCall[0].client_information;
    expect(persistedClientInfo.redirect_uris).toEqual([REDIRECT_OVERRIDE]);
    expect(persistedClientInfo.client_id).toBe("dcr-client-xyz");

    // Now feed that persisted client_information into exchangeToken, as
    // if the browser had come back with an authorization code, and assert
    // the token POST sends the exact same redirect_uri byte-for-byte.
    const callbackState = new URL(
      startResult.data.authorization_url,
    ).searchParams.get("state");
    if (!callbackState) throw new Error("Authorization state missing");
    const persistedDiscovery = upsert.mock.calls.find(
      (call) => call[0]?.discovery_state,
    )?.[0].discovery_state;
    findByMcpServerAndUser.mockResolvedValue({
      mcp_server_uuid: SERVER_UUID,
      code_verifier: "PKCE_VERIFIER",
      client_information: persistedClientInfo,
      tokens: null,
      expected_state: callbackState,
      discovery_state: persistedDiscovery,
    });

    const exchangeResult = await oauthImplementations.exchangeToken(
      { state: callbackState, code: "AUTH_CODE" },
      USER_ID,
    );

    expect(exchangeResult.success).toBe(true);
    const tokenCallBody = fetchSpy.mock.calls.find(([callUrl]) => {
      const urlStr =
        typeof callUrl === "string" ? callUrl : (callUrl as URL).toString();
      return urlStr === "https://mcp.example.com/token";
    });
    expect(tokenCallBody).toBeDefined();

    fetchSpy.mockRestore();
  });

  // Pre-registered authorization_endpoint/token_endpoint (Salesforce/Okta/
  // ServiceNow style) must make discoveryState() short-circuit BOTH RFC
  // 9728 protected-resource discovery AND RFC 8414 authorization-server
  // discovery — i.e. zero fetch calls — and the authorize URL must use
  // the pre-registered endpoints. This is the "authorization_endpoint was
  // dead on the authorize side" bug fix.
  it("uses pre-registered authorization_endpoint/token_endpoint with no discovery fetch", async () => {
    const {
      oauthImplementations,
      findByMcpServerAndUser,
      upsert,
      findServerByUuid,
    } = await loadModule();

    findServerByUuid.mockResolvedValue(ownedServer(SERVER_UUID, SERVER_URL));
    findByMcpServerAndUser.mockResolvedValue({
      mcp_server_uuid: SERVER_UUID,
      code_verifier: null,
      client_information: {
        client_id: "preset-client-id",
        authorization_endpoint: "https://as.example.com/authorize",
        token_endpoint: "https://as.example.com/token",
        token_endpoint_auth_method: "none",
      },
      tokens: null,
      expected_state: null,
    });
    upsert.mockResolvedValue({});

    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const result = await oauthImplementations.startAuthorization(
      { mcp_server_uuid: SERVER_UUID },
      USER_ID,
    );

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(result.success).toBe(true);
    if (!result.success) throw new Error("unreachable");
    expect(
      result.data.authorization_url.startsWith(
        "https://as.example.com/authorize",
      ),
    ).toBe(true);
    expect(result.data.authorization_url).toContain(
      "client_id=preset-client-id",
    );

    fetchSpy.mockRestore();
  });

  // SECURITY regression: an authorization_endpoint controlled by whoever
  // configured the mcp_servers row must not be able to hand the frontend a
  // `javascript:` URL — the frontend assigns `authorization_url` directly
  // to `window.location.href`. Uses the pre-registered-endpoints
  // short-circuit (discoveryState()) so no fetch mock is needed; the SDK's
  // startAuthorization() does `new URL(metadata.authorization_endpoint)`,
  // which happily parses `javascript:alert(1)` since it's a syntactically
  // valid URL — the scheme guard is the only thing that stops it.
  it("rejects a javascript: authorization_endpoint and returns no URL", async () => {
    const { oauthImplementations, findByMcpServerAndUser, findServerByUuid } =
      await loadModule();

    findServerByUuid.mockResolvedValue(ownedServer(SERVER_UUID, SERVER_URL));
    findByMcpServerAndUser.mockResolvedValue({
      mcp_server_uuid: SERVER_UUID,
      code_verifier: null,
      client_information: {
        client_id: "preset-client-id",
        authorization_endpoint: "javascript:alert(1)",
        token_endpoint: "https://as.example.com/token",
        token_endpoint_auth_method: "none",
      },
      tokens: null,
      expected_state: null,
    });

    const fetchSpy = vi.spyOn(globalThis, "fetch");

    const result = await oauthImplementations.startAuthorization(
      { mcp_server_uuid: SERVER_UUID },
      USER_ID,
    );

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("unsafe_authorization_url");
    }
    expect(result).not.toHaveProperty("data");
    expect(fetchSpy).not.toHaveBeenCalled();

    fetchSpy.mockRestore();
  });

  // state() persists expected_state, and exchangeToken's CSRF validation
  // (RFC 6749 §10.12) accepts the resulting round trip.
  it("state() persists expected_state and exchangeToken accepts the round trip", async () => {
    const {
      oauthImplementations,
      findByMcpServerAndUser,
      upsert,
      findServerByUuid,
    } = await loadModule();

    const presetClientInfo = {
      client_id: "preset-client-id",
      authorization_endpoint: "https://as.example.com/authorize",
      token_endpoint: "https://as.example.com/token",
      token_endpoint_auth_method: "none",
    };

    findServerByUuid.mockResolvedValue(ownedServer(SERVER_UUID, SERVER_URL));
    findByMcpServerAndUser.mockResolvedValue({
      mcp_server_uuid: SERVER_UUID,
      code_verifier: null,
      client_information: presetClientInfo,
      tokens: null,
      expected_state: null,
    });
    upsert.mockResolvedValue({});

    const startResult = await oauthImplementations.startAuthorization(
      { mcp_server_uuid: SERVER_UUID },
      USER_ID,
    );
    expect(startResult.success).toBe(true);

    const stateCall = upsert.mock.calls.find((call) => call[0]?.expected_state);
    expect(stateCall).toBeDefined();
    if (!stateCall) throw new Error("unreachable");
    const persistedState: string = stateCall[0].expected_state;
    expect(persistedState.length).toBeGreaterThan(10);

    // Round trip: the upstream echoes the same state back on redirect.
    findByMcpServerAndUser.mockResolvedValue({
      mcp_server_uuid: SERVER_UUID,
      code_verifier: "PKCE_VERIFIER",
      client_information: presetClientInfo,
      tokens: null,
      expected_state: persistedState,
    });

    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (url) => {
        const urlStr = typeof url === "string" ? url : (url as URL).toString();
        if (urlStr.includes("/.well-known/")) {
          return new Response("nope", { status: 404 });
        }
        return jsonResponse(200, { access_token: "AT", token_type: "Bearer" });
      });

    const exchangeResult = await oauthImplementations.exchangeToken(
      { code: "C", state: persistedState },
      USER_ID,
    );

    expect(exchangeResult.success).toBe(true);
    fetchSpy.mockRestore();
  });
});
