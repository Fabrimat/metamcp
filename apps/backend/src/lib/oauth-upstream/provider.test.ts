import {
  auth,
  type OAuthDiscoveryState,
} from "@modelcontextprotocol/sdk/client/auth.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../db/repositories", () => ({
  oauthSessionsRepository: {
    findByMcpServerAndUser: vi.fn(),
    upsert: vi.fn(),
    saveDynamicClientInformation: vi.fn(),
  },
}));

vi.mock("../../utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

const SERVER = "00000000-0000-4000-8000-000000000003";
const USER = "user-a";
const ORIGINAL_METADATA_URL = process.env.OAUTH_CLIENT_METADATA_URL;

describe("OAuthUpstreamClientProvider user-scoped persistence", () => {
  beforeEach(() => {
    delete process.env.OAUTH_CLIENT_METADATA_URL;
    vi.clearAllMocks();
    vi.spyOn(globalThis, "fetch").mockImplementation(
      async () => new Response("No resource metadata", { status: 404 }),
    );
  });
  afterEach(() => {
    if (ORIGINAL_METADATA_URL === undefined)
      delete process.env.OAUTH_CLIENT_METADATA_URL;
    else process.env.OAUTH_CLIENT_METADATA_URL = ORIGINAL_METADATA_URL;
    vi.restoreAllMocks();
  });

  const load = async (
    redirectUriOverride: string | null = "http://127.0.0.1:3456/callback",
    serverUrl = "https://mcp.example.com/mcp",
  ) => {
    const repositories = await import("../../db/repositories");
    const { OAuthUpstreamClientProvider } = await import("./provider");
    const saveDynamicClientInformation = repositories.oauthSessionsRepository
      .saveDynamicClientInformation as ReturnType<typeof vi.fn>;
    saveDynamicClientInformation.mockResolvedValue(true);
    return {
      provider: new OAuthUpstreamClientProvider({
        mcpServerUuid: SERVER,
        userId: USER,
        serverUrl,
        redirectUriOverride,
      }),
      findByMcpServerAndUser: repositories.oauthSessionsRepository
        .findByMcpServerAndUser as ReturnType<typeof vi.fn>,
      upsert: repositories.oauthSessionsRepository.upsert as ReturnType<
        typeof vi.fn
      >,
      saveDynamicClientInformation,
    };
  };

  it("exposes CIMD as both client metadata URL and redirect URL", async () => {
    process.env.OAUTH_CLIENT_METADATA_URL =
      "https://oauth.example/oauth/client-metadata";
    const { provider } = await load(null);

    expect(provider.clientMetadataUrl).toBe(
      "https://oauth.example/oauth/client-metadata",
    );
    expect(provider.redirectUrl).toBe(
      "https://oauth.example/oauth/client-metadata",
    );
    expect(provider.clientMetadata.redirect_uris).toEqual([
      "https://oauth.example/oauth/client-metadata",
    ]);
  });

  it("disables CIMD when the server has a redirect override", async () => {
    process.env.OAUTH_CLIENT_METADATA_URL =
      "https://oauth.example/oauth/client-metadata";
    const { provider } = await load("http://127.0.0.1:4567/callback");

    expect(provider.clientMetadataUrl).toBeUndefined();
    expect(provider.redirectUrl).toBe("http://127.0.0.1:4567/callback");
  });

  it("persists URL-based client information with byte-identical identifiers", async () => {
    const metadataUrl = "https://oauth.example/oauth/client-metadata";
    process.env.OAUTH_CLIENT_METADATA_URL = metadataUrl;
    const { provider, saveDynamicClientInformation } = await load(null);

    await provider.saveClientInformation({ client_id: metadataUrl });

    expect(saveDynamicClientInformation).toHaveBeenCalledWith(SERVER, USER, {
      client_id: metadataUrl,
      _metamcp_registration: "url_based",
      redirect_uris: [metadataUrl],
      token_endpoint_auth_method: "none",
    });
  });

  it("treats a URL-based registration for an old metadata URL as stale", async () => {
    process.env.OAUTH_CLIENT_METADATA_URL =
      "https://new.example/oauth/client-metadata";
    const { provider, findByMcpServerAndUser } = await load(null);
    findByMcpServerAndUser.mockResolvedValue({
      client_information: {
        client_id: "https://old.example/oauth/client-metadata",
        _metamcp_registration: "url_based",
      },
    });

    await expect(provider.clientInformation()).resolves.toBeUndefined();
  });

  it("keeps existing manual client information authoritative over CIMD", async () => {
    process.env.OAUTH_CLIENT_METADATA_URL =
      "https://oauth.example/oauth/client-metadata";
    const { provider, findByMcpServerAndUser } = await load(null);
    findByMcpServerAndUser.mockResolvedValue({
      client_information: {
        client_id: "manual-client",
        _metamcp_registration: "manual",
        redirect_uris: ["https://manual.example/callback"],
      },
    });

    await expect(provider.clientInformation()).resolves.toMatchObject({
      client_id: "manual-client",
      _metamcp_registration: "manual",
    });
  });

  it("loads client information with the composite server and user key", async () => {
    const { provider, findByMcpServerAndUser } = await load();
    findByMcpServerAndUser.mockResolvedValueOnce({
      client_information: { client_id: "caller-client" },
    });
    await expect(provider.clientInformation()).resolves.toMatchObject({
      client_id: "caller-client",
    });
    expect(findByMcpServerAndUser).toHaveBeenCalledWith(SERVER, USER);
  });

  it("does not expose quarantined legacy client information to the SDK", async () => {
    const { provider, findByMcpServerAndUser } = await load();
    findByMcpServerAndUser.mockResolvedValueOnce({
      client_information: {
        client_id: "legacy-client",
        client_secret: "legacy-secret",
        _metamcp_registration: "legacy_unconfirmed",
      },
    });

    await expect(provider.clientInformation()).resolves.toBeUndefined();
  });

  it("does not derive or reuse discovery for quarantined legacy clients", async () => {
    const { provider, findByMcpServerAndUser } = await load();
    findByMcpServerAndUser.mockResolvedValue({
      client_information: {
        client_id: "legacy-client",
        authorization_endpoint: "https://configured.example/authorize",
        token_endpoint: "https://configured.example/token",
        _metamcp_registration: "legacy_unconfirmed",
      },
      discovery_state: { authorizationServerUrl: "https://stale.example" },
    });

    await expect(provider.discoveryState()).resolves.toBeUndefined();
  });

  it("fails closed when redirect invalidation quarantines during DCR", async () => {
    const { provider, saveDynamicClientInformation, upsert } = await load();
    saveDynamicClientInformation.mockResolvedValue(false);

    await expect(
      provider.saveClientInformation({ client_id: "late-dcr-client" }),
    ).rejects.toMatchObject({
      code: "oauth_client_confirmation_required",
    });
    expect(upsert).not.toHaveBeenCalled();
  });

  it("writes verifier state with the caller user id", async () => {
    const { provider, upsert } = await load();
    const state = await provider.state();
    await provider.saveCodeVerifier("pkce-verifier");

    expect(upsert).toHaveBeenCalledWith({
      mcp_server_uuid: SERVER,
      user_id: USER,
      code_verifier: "pkce-verifier",
      expected_state: state,
    });
  });

  it("persists a self-identifying state for the current server", async () => {
    const { provider, upsert } = await load();
    const state = await provider.state();
    expect(state).toMatch(
      new RegExp(`^upstream\\.${SERVER}\\.[0-9]{13}\\.[A-Za-z0-9_-]{43}$`),
    );
    expect(upsert).not.toHaveBeenCalled();
  });

  it("interleaved starts publish each state only with its own verifier", async () => {
    const { provider: first, upsert } = await load();
    const { provider: second } = await load();
    const writes: Record<string, unknown>[] = [];
    upsert.mockImplementation(async (input) => {
      writes.push(input);
      return input;
    });
    const stateA = await first.state();
    const stateB = await second.state();
    await second.saveCodeVerifier("verifier-B");
    await first.saveCodeVerifier("verifier-A");
    expect(writes.filter((row) => row.expected_state)).toEqual([
      {
        mcp_server_uuid: SERVER,
        user_id: USER,
        expected_state: stateB,
        code_verifier: "verifier-B",
      },
      {
        mcp_server_uuid: SERVER,
        user_id: USER,
        expected_state: stateA,
        code_verifier: "verifier-A",
      },
    ]);
  });

  it("prefers complete pre-registered endpoints over stale discovery", async () => {
    const { provider, findByMcpServerAndUser } = await load();
    findByMcpServerAndUser.mockResolvedValue({
      client_information: {
        client_id: "client",
        authorization_endpoint: "https://configured.example/authorize",
        token_endpoint: "https://configured.example/token",
      },
      discovery_state: { authorizationServerUrl: "https://stale.example" },
    });
    expect(await provider.discoveryState()).toMatchObject({
      authorizationServerUrl: "https://configured.example",
      authorizationServerMetadata: {
        token_endpoint: "https://configured.example/token",
      },
    });
    expect((await provider.discoveryState())?.resourceMetadata).toBeUndefined();
  });

  it("persists pre-registered discovery when preparing an authorization redirect", async () => {
    const { provider, findByMcpServerAndUser, upsert } = await load();
    findByMcpServerAndUser.mockResolvedValue({
      client_information: {
        client_id: "client",
        authorization_endpoint: "https://configured.example/authorize",
        token_endpoint: "https://configured.example/token",
      },
    });
    await auth(provider, { serverUrl: "https://mcp.example.com/mcp" });
    expect(provider.authorizationUrl?.searchParams.get("resource")).toBe(null);
    expect(upsert).toHaveBeenCalledWith({
      mcp_server_uuid: SERVER,
      user_id: USER,
      discovery_state: expect.objectContaining({
        authorizationServerUrl: "https://configured.example",
      }),
    });
    const persisted = upsert.mock.calls.find(
      ([input]) => input.discovery_state,
    )?.[0].discovery_state;
    expect(persisted.resourceMetadata).toBeUndefined();
  });

  it("preserves genuine persisted resource metadata when overriding authorization endpoints", async () => {
    const { provider, findByMcpServerAndUser, upsert } = await load();
    const resourceMetadata = {
      resource: "https://mcp.example.com/",
      scopes_supported: ["read"],
    };
    findByMcpServerAndUser.mockResolvedValue({
      client_information: {
        client_id: "client",
        authorization_endpoint: "https://configured.example/authorize",
        token_endpoint: "https://configured.example/token",
      },
      discovery_state: {
        authorizationServerUrl: "https://stale.example",
        resourceMetadata,
        resourceMetadataUrl:
          "https://mcp.example.com/.well-known/oauth-protected-resource",
      },
    });
    await auth(provider, { serverUrl: "https://mcp.example.com/mcp" });
    expect(provider.authorizationUrl?.searchParams.get("resource")).toBe(
      "https://mcp.example.com/",
    );
    expect(upsert).toHaveBeenCalledWith({
      mcp_server_uuid: SERVER,
      user_id: USER,
      discovery_state: expect.objectContaining({
        authorizationServerUrl: "https://configured.example",
        resourceMetadata,
        resourceMetadataUrl:
          "https://mcp.example.com/.well-known/oauth-protected-resource",
      }),
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("fails SDK authorization when cached protected resource metadata is incompatible", async () => {
    const { provider, findByMcpServerAndUser } = await load();
    findByMcpServerAndUser.mockResolvedValue({
      client_information: { client_id: "client" },
      discovery_state: {
        authorizationServerUrl: "https://auth.example.com",
        authorizationServerMetadata: {
          issuer: "https://auth.example.com",
          authorization_endpoint: "https://auth.example.com/authorize",
          token_endpoint: "https://auth.example.com/token",
          response_types_supported: ["code"],
        },
        resourceMetadata: { resource: "https://wrong.example.com/mcp" },
      },
    });
    await expect(
      auth(provider, { serverUrl: "https://mcp.example.com/mcp" }),
    ).rejects.toThrow(/Protected resource/);
  });

  it("rediscovers OAuth metadata after the MCP URL changes from /mcp to root", async () => {
    const { provider, findByMcpServerAndUser } = await load(
      "http://127.0.0.1:3456/callback",
      "https://mcp.example.com",
    );
    findByMcpServerAndUser.mockResolvedValue({
      discovery_state: {
        authorizationServerUrl: "https://auth.example.com",
        authorizationServerMetadata: {
          issuer: "https://auth.example.com",
          authorization_endpoint: "https://auth.example.com/authorize",
          token_endpoint: "https://auth.example.com/token",
          response_types_supported: ["code"],
        },
        resourceMetadata: { resource: "https://mcp.example.com/mcp" },
      },
      client_information: null,
    });

    await expect(provider.discoveryState()).resolves.toBeUndefined();
  });

  it("persists and reloads serializable OAuth discovery state", async () => {
    const { provider, findByMcpServerAndUser, upsert } = await load();
    const discoveryState: OAuthDiscoveryState = {
      authorizationServerUrl: "https://auth.example.com",
      resourceMetadataUrl:
        "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
      authorizationServerMetadata: {
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://auth.example.com/authorize",
        token_endpoint: "https://auth.example.com/token",
        response_types_supported: ["code"],
      },
      resourceMetadata: {
        resource: "https://mcp.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        scopes_supported: ["tools:read"],
      },
    };

    await provider.saveDiscoveryState(discoveryState);
    expect(upsert).toHaveBeenCalledWith({
      mcp_server_uuid: SERVER,
      user_id: USER,
      discovery_state: discoveryState,
    });

    findByMcpServerAndUser.mockResolvedValue({
      discovery_state: discoveryState,
      client_information: null,
    });
    await expect(provider.discoveryState()).resolves.toEqual(discoveryState);
  });
});
