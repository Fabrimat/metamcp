import {
  auth,
  type OAuthDiscoveryState,
} from "@modelcontextprotocol/sdk/client/auth.js";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../db/repositories", () => ({
  oauthSessionsRepository: {
    findByMcpServerAndUser: vi.fn(),
    upsert: vi.fn(),
  },
}));

vi.mock("../../utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

const SERVER = "00000000-0000-4000-8000-000000000003";
const USER = "user-a";

describe("OAuthUpstreamClientProvider user-scoped persistence", () => {
  beforeEach(() => vi.clearAllMocks());

  const load = async () => {
    const repositories = await import("../../db/repositories");
    const { OAuthUpstreamClientProvider } = await import("./provider");
    return {
      provider: new OAuthUpstreamClientProvider({
        mcpServerUuid: SERVER,
        userId: USER,
        serverUrl: "https://mcp.example.com/mcp",
        redirectUriOverride: "http://127.0.0.1:3456/callback",
      }),
      findByMcpServerAndUser: repositories.oauthSessionsRepository
        .findByMcpServerAndUser as ReturnType<typeof vi.fn>,
      upsert: repositories.oauthSessionsRepository.upsert as ReturnType<
        typeof vi.fn
      >,
    };
  };

  it("loads client information with the composite server and user key", async () => {
    const { provider, findByMcpServerAndUser } = await load();
    findByMcpServerAndUser.mockResolvedValue({
      client_information: { client_id: "caller-client" },
    });
    await expect(provider.clientInformation()).resolves.toMatchObject({
      client_id: "caller-client",
    });
    expect(findByMcpServerAndUser).toHaveBeenCalledWith(SERVER, USER);
  });

  it("writes verifier state with the caller user id", async () => {
    const { provider, upsert } = await load();

    await provider.saveCodeVerifier("pkce-verifier");

    expect(upsert).toHaveBeenCalledWith({
      mcp_server_uuid: SERVER,
      user_id: USER,
      code_verifier: "pkce-verifier",
    });
  });

  it("persists a self-identifying state for the current server", async () => {
    const { provider, upsert } = await load();
    const state = await provider.state();
    expect(state).toMatch(
      new RegExp(`^upstream\\.${SERVER}\\.[A-Za-z0-9_-]{43}$`),
    );
    expect(upsert).toHaveBeenCalledWith({
      mcp_server_uuid: SERVER,
      user_id: USER,
      expected_state: state,
    });
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
      resourceMetadata: { resource: "https://mcp.example.com/mcp" },
    });
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
    expect(provider.authorizationUrl?.searchParams.get("resource")).toBe(
      "https://mcp.example.com/mcp",
    );
    expect(upsert).toHaveBeenCalledWith({
      mcp_server_uuid: SERVER,
      user_id: USER,
      discovery_state: expect.objectContaining({
        authorizationServerUrl: "https://configured.example",
        resourceMetadata: { resource: "https://mcp.example.com/mcp" },
      }),
    });
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
