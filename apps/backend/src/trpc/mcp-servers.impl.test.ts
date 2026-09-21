import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { OAuthSessionsRepository } from "../db/repositories/oauth-sessions.repo";
import {
  buildPreRegisteredClientInformation,
  persistPreRegisteredOAuthClient,
  resolveRedirectUri,
} from "./pre-registered-oauth";

const REDIRECT_URI = "https://metamcp.example.com/fe-oauth/callback";

describe("buildPreRegisteredClientInformation", () => {
  it("returns null when client_id is missing", () => {
    expect(
      buildPreRegisteredClientInformation(
        {
          client_secret: "secret",
          scope: "api",
          authorization_endpoint: "https://example.com/authorize",
        },
        REDIRECT_URI,
      ),
    ).toBeNull();
  });

  it("returns null when client_id is whitespace-only", () => {
    expect(
      buildPreRegisteredClientInformation({ client_id: "   " }, REDIRECT_URI),
    ).toBeNull();
  });

  it("builds a minimal public client when only client_id is provided", () => {
    const result = buildPreRegisteredClientInformation(
      { client_id: "3MVG9.Salesforce" },
      REDIRECT_URI,
    );

    expect(result).toEqual({
      _metamcp_registration: "manual",
      client_id: "3MVG9.Salesforce",
      redirect_uris: [REDIRECT_URI],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    });
  });

  it("includes the secret, endpoints, and scope when supplied", () => {
    const result = buildPreRegisteredClientInformation(
      {
        client_id: "3MVG9.Salesforce",
        client_secret: "shhh",
        scope: "api refresh_token",
        authorization_endpoint:
          "https://login.salesforce.com/services/oauth2/authorize",
        token_endpoint: "https://login.salesforce.com/services/oauth2/token",
        token_endpoint_auth_method: "client_secret_post",
      },
      REDIRECT_URI,
    );

    expect(result).toEqual({
      _metamcp_registration: "manual",
      client_id: "3MVG9.Salesforce",
      client_secret: "shhh",
      redirect_uris: [REDIRECT_URI],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post",
      scope: "api refresh_token",
      authorization_endpoint:
        "https://login.salesforce.com/services/oauth2/authorize",
      token_endpoint: "https://login.salesforce.com/services/oauth2/token",
    });
  });

  it("trims whitespace from inputs", () => {
    const result = buildPreRegisteredClientInformation(
      {
        client_id: "  trimmed-id  ",
        scope: "  api  ",
        authorization_endpoint: "  https://example.com/authorize  ",
        token_endpoint: "  https://example.com/token  ",
      },
      REDIRECT_URI,
    );

    expect(result).toMatchObject({
      client_id: "trimmed-id",
      scope: "api",
      authorization_endpoint: "https://example.com/authorize",
      token_endpoint: "https://example.com/token",
    });
  });

  it("never reflects the user's redirect_uri input — it is always MetaMCP's callback", () => {
    const result = buildPreRegisteredClientInformation(
      {
        client_id: "3MVG9.Salesforce",
      },
      "https://different.metamcp.example.com/fe-oauth/callback",
    );

    expect(result?.redirect_uris).toEqual([
      "https://different.metamcp.example.com/fe-oauth/callback",
    ]);
  });

  it("omits client_secret when blank", () => {
    const result = buildPreRegisteredClientInformation(
      { client_id: "3MVG9", client_secret: "" },
      REDIRECT_URI,
    );

    expect(result).not.toHaveProperty("client_secret");
  });
});

describe("resolveRedirectUri", () => {
  const original = process.env.APP_URL;
  afterEach(() => {
    process.env.APP_URL = original;
  });

  it("composes APP_URL + /fe-oauth/callback", () => {
    process.env.APP_URL = "https://metamcp.example.com";
    expect(resolveRedirectUri()).toBe(
      "https://metamcp.example.com/fe-oauth/callback",
    );
  });

  it("strips a trailing slash from APP_URL", () => {
    process.env.APP_URL = "https://metamcp.example.com/";
    expect(resolveRedirectUri()).toBe(
      "https://metamcp.example.com/fe-oauth/callback",
    );
  });

  it("throws when APP_URL is not set", () => {
    delete process.env.APP_URL;
    expect(() => resolveRedirectUri()).toThrow(/APP_URL/);
  });
});

describe("persistPreRegisteredOAuthClient", () => {
  it("preserves explicit manual client credentials on a redirect edit", async () => {
    let stored: Record<string, unknown> | undefined = {
      client_information: {
        client_id: "manual",
        client_secret: "secret",
        _metamcp_registration: "manual",
      },
      tokens: { access_token: "old" },
      code_verifier: "old",
      expected_state: "old",
    };
    const repo = {
      findByMcpServerAndUser: async () => stored,
      upsert: async (input: Record<string, unknown>) => {
        stored = { ...stored, ...input };
      },
      deleteByMcpServerAndUser: async () => {
        stored = undefined;
      },
      invalidateRedirectDependentSessions: async () => {
        stored = {
          ...stored,
          tokens: null,
          code_verifier: null,
          expected_state: null,
          discovery_state: null,
        };
      },
    } as unknown as OAuthSessionsRepository;
    process.env.APP_URL = "https://metamcp.example.com";
    await persistPreRegisteredOAuthClient(
      "server",
      "user",
      {
        client_id: "manual",
        client_secret: "secret",
        authorization_endpoint: "https://as.example/authorize",
        token_endpoint: "https://as.example/token",
        redirect_uri: "http://localhost:4001/callback",
      },
      repo,
      "http://localhost:4000/callback",
    );
    expect(stored).toMatchObject({
      client_information: {
        client_id: "manual",
        client_secret: "secret",
        authorization_endpoint: "https://as.example/authorize",
        token_endpoint: "https://as.example/token",
        redirect_uris: ["http://localhost:4001/callback"],
      },
      tokens: null,
      code_verifier: null,
      expected_state: null,
    });
  });
  const SERVER_UUID = "00000000-0000-0000-0000-000000000001";
  const USER_ID = "user-1";
  const mockRepo = {
    findByMcpServerAndUser: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    upsert: vi.fn(),
    deleteByMcpServerAndUser: vi.fn(),
    invalidateRedirectDependentSessions: vi.fn(),
  } as unknown as OAuthSessionsRepository & {
    findByMcpServerAndUser: ReturnType<typeof vi.fn>;
    upsert: ReturnType<typeof vi.fn>;
    deleteByMcpServerAndUser: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    process.env.APP_URL = "https://metamcp.example.com";
    vi.clearAllMocks();
  });

  it("upserts oauth_sessions.client_information with the server-derived redirect_uri", async () => {
    await persistPreRegisteredOAuthClient(
      SERVER_UUID,
      USER_ID,
      {
        client_id: "3MVG9",
        client_secret: "shh",
        scope: "api refresh_token",
        authorization_endpoint: "https://login.salesforce.com/oauth2/authorize",
        token_endpoint: "https://login.salesforce.com/oauth2/token",
        token_endpoint_auth_method: "client_secret_post",
      },
      mockRepo,
    );

    expect(mockRepo.upsert).toHaveBeenCalledTimes(1);
    expect(mockRepo.upsert).toHaveBeenCalledWith({
      mcp_server_uuid: SERVER_UUID,
      user_id: USER_ID,
      client_information: expect.objectContaining({
        client_id: "3MVG9",
        client_secret: "shh",
        redirect_uris: ["https://metamcp.example.com/fe-oauth/callback"],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_post",
        scope: "api refresh_token",
        authorization_endpoint: "https://login.salesforce.com/oauth2/authorize",
        token_endpoint: "https://login.salesforce.com/oauth2/token",
      }),
    });
  });

  it("does not write to the repo when client_id is blank and no prior session exists", async () => {
    (
      mockRepo.findByMcpServerAndUser as ReturnType<typeof vi.fn>
    ).mockResolvedValue(undefined);

    await persistPreRegisteredOAuthClient(
      SERVER_UUID,
      USER_ID,
      { client_id: "" },
      mockRepo,
    );

    expect(mockRepo.findByMcpServerAndUser).toHaveBeenCalledWith(
      SERVER_UUID,
      USER_ID,
    );
    expect(mockRepo.upsert).not.toHaveBeenCalled();
    expect(mockRepo.deleteByMcpServerAndUser).not.toHaveBeenCalled();
  });

  it("deletes the prior oauth_sessions row when the user clears the section", async () => {
    (
      mockRepo.findByMcpServerAndUser as ReturnType<typeof vi.fn>
    ).mockResolvedValue({
      uuid: "session-uuid",
      mcp_server_uuid: SERVER_UUID,
    });

    await persistPreRegisteredOAuthClient(
      SERVER_UUID,
      USER_ID,
      { client_id: "" },
      mockRepo,
    );

    expect(mockRepo.deleteByMcpServerAndUser).toHaveBeenCalledWith(
      SERVER_UUID,
      USER_ID,
    );
    expect(mockRepo.upsert).not.toHaveBeenCalled();
  });

  // Per-server redirect_uri override precedence (Brief A). Unlike the
  // "never reflects the user's redirect_uri input" test above — which pins
  // buildPreRegisteredClientInformation's own contract of using its
  // redirectUri argument verbatim, with no user input in scope — this pins
  // persistPreRegisteredOAuthClient's resolution of THAT argument: the
  // per-server override wins when set, else the APP_URL derivation.
  it("uses the per-server redirect_uri override when set", async () => {
    await persistPreRegisteredOAuthClient(
      SERVER_UUID,
      USER_ID,
      { client_id: "3MVG9", redirect_uri: "http://127.0.0.1:33418/callback" },
      mockRepo,
    );

    expect(mockRepo.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        client_information: expect.objectContaining({
          redirect_uris: ["http://127.0.0.1:33418/callback"],
        }),
      }),
    );
  });

  it("falls back to the APP_URL derivation when no override is set", async () => {
    await persistPreRegisteredOAuthClient(
      SERVER_UUID,
      USER_ID,
      { client_id: "3MVG9" },
      mockRepo,
    );

    expect(mockRepo.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        client_information: expect.objectContaining({
          redirect_uris: ["https://metamcp.example.com/fe-oauth/callback"],
        }),
      }),
    );
  });

  // Brief G: invalidate a persisted upstream OAuth registration when a
  // server's redirect_uri override actually changes. The 4th argument is
  // the override as stored on mcp_servers.redirect_uri BEFORE this call —
  // mcp-servers.impl.ts's `update` passes the value it fetched prior to
  // applying the update.
  it("invalidates the persisted session when the override changes from one loopback value to another", async () => {
    (
      mockRepo.findByMcpServerAndUser as ReturnType<typeof vi.fn>
    ).mockResolvedValue({ uuid: "session-uuid", mcp_server_uuid: SERVER_UUID });

    await persistPreRegisteredOAuthClient(
      SERVER_UUID,
      USER_ID,
      { client_id: "3MVG9", redirect_uri: "http://127.0.0.1:5000/callback" },
      mockRepo,
      "http://127.0.0.1:4000/callback",
    );

    expect(mockRepo.invalidateRedirectDependentSessions).toHaveBeenCalledWith(
      SERVER_UUID,
      "http://127.0.0.1:5000/callback",
    );
  });

  it("invalidates the persisted session when an override is set where none existed", async () => {
    (
      mockRepo.findByMcpServerAndUser as ReturnType<typeof vi.fn>
    ).mockResolvedValue({ uuid: "session-uuid", mcp_server_uuid: SERVER_UUID });

    await persistPreRegisteredOAuthClient(
      SERVER_UUID,
      USER_ID,
      { client_id: "3MVG9", redirect_uri: "http://127.0.0.1:5000/callback" },
      mockRepo,
      null,
    );

    expect(mockRepo.invalidateRedirectDependentSessions).toHaveBeenCalledWith(
      SERVER_UUID,
      "http://127.0.0.1:5000/callback",
    );
  });

  it("invalidates the persisted session when an existing override is cleared", async () => {
    (
      mockRepo.findByMcpServerAndUser as ReturnType<typeof vi.fn>
    ).mockResolvedValue({ uuid: "session-uuid", mcp_server_uuid: SERVER_UUID });

    await persistPreRegisteredOAuthClient(
      SERVER_UUID,
      USER_ID,
      { client_id: "3MVG9", redirect_uri: "" },
      mockRepo,
      "http://127.0.0.1:4000/callback",
    );

    expect(mockRepo.invalidateRedirectDependentSessions).toHaveBeenCalledWith(
      SERVER_UUID,
      REDIRECT_URI,
    );
  });

  it("does not invalidate when the same override value is resubmitted", async () => {
    (
      mockRepo.findByMcpServerAndUser as ReturnType<typeof vi.fn>
    ).mockResolvedValue({ uuid: "session-uuid", mcp_server_uuid: SERVER_UUID });

    await persistPreRegisteredOAuthClient(
      SERVER_UUID,
      USER_ID,
      { client_id: "3MVG9", redirect_uri: "http://127.0.0.1:4000/callback" },
      mockRepo,
      "http://127.0.0.1:4000/callback",
    );

    expect(mockRepo.deleteByMcpServerAndUser).not.toHaveBeenCalled();
  });

  // Not one of the five named acceptance cases, but a direct consequence
  // of how the fix is implemented: a brand-new client_id + redirect_uri
  // pair entered for the very first time (no `previous` and no prior
  // session) must survive — there is nothing stale to invalidate, and a
  // naive "override changed" check with no existing-session guard would
  // wipe out the row this same call just wrote.
  it("does not invalidate a first-ever registration even though the override 'changed' from null", async () => {
    (
      mockRepo.findByMcpServerAndUser as ReturnType<typeof vi.fn>
    ).mockResolvedValue(undefined);

    await persistPreRegisteredOAuthClient(
      SERVER_UUID,
      USER_ID,
      { client_id: "3MVG9", redirect_uri: "http://127.0.0.1:4000/callback" },
      mockRepo,
      null,
    );

    expect(mockRepo.deleteByMcpServerAndUser).not.toHaveBeenCalled();
    expect(mockRepo.upsert).toHaveBeenCalledTimes(1);
  });

  // Ordering regression pin. apps/frontend's edit form prefills
  // oauth_client_info.client_id from whatever is already in
  // client_information — including a client_id the SDK dynamically
  // registered, not one the user typed in — so a redirect_uri-only edit
  // still resubmits that (now-stale) client_id alongside the new
  // redirect_uri. If invalidation ran BEFORE the upsert above instead of
  // after, that upsert would immediately recreate a row pairing the stale
  // client_id with the new redirect_uri, silently undoing the
  // invalidation. A stateful fake is used (rather than mockRepo's bare
  // vi.fn()s) so the assertion is on the actual END STATE — no row at all
  // — not just that deleteByMcpServerAndUser was called at some point.
  it("ends with no persisted session when a stale, form-prefilled client_id is resubmitted alongside a changed redirect_uri", async () => {
    let stored: Record<string, unknown> | undefined = {
      mcp_server_uuid: SERVER_UUID,
      client_information: {
        client_id: "dynamically-registered-id",
        redirect_uris: ["http://127.0.0.1:4000/callback"],
      },
      tokens: { access_token: "old-token" },
    };

    const statefulRepo = {
      findByMcpServerAndUser: vi.fn(async () => stored),
      create: vi.fn(),
      update: vi.fn(),
      upsert: vi.fn(async (input: Record<string, unknown>) => {
        stored = { ...stored, ...input };
        return stored;
      }),
      deleteByMcpServerAndUser: vi.fn(async () => {
        const deleted = stored;
        stored = undefined;
        return deleted;
      }),
      invalidateRedirectDependentSessions: vi.fn(async () => {
        stored = undefined;
      }),
    } as unknown as OAuthSessionsRepository;

    await persistPreRegisteredOAuthClient(
      SERVER_UUID,
      USER_ID,
      {
        // Form-prefilled from the existing (dynamically registered)
        // client_information, not user-typed — the realistic shape.
        client_id: "dynamically-registered-id",
        redirect_uri: "http://127.0.0.1:5000/callback",
      },
      statefulRepo,
      "http://127.0.0.1:4000/callback",
    );

    expect(stored).toBeUndefined();
  });
});
