import {
  ExchangeOAuthTokenRequestSchema,
  ExchangeOAuthTokenResponseSchema,
  OAuthClientInfoRequestSchema,
  OAuthClientInformationSchema,
  OAuthSessionUpdateInputSchema,
} from "@repo/zod-types";
import { describe, expect, it } from "vitest";

describe("upstream callback contract", () => {
  it("requires state and routes using state only", () => {
    expect(
      ExchangeOAuthTokenRequestSchema.parse({ code: "C", state: "S" }),
    ).toEqual({ code: "C", state: "S" });
    expect(
      ExchangeOAuthTokenRequestSchema.safeParse({
        code: "C",
        mcp_server_uuid: "00000000-0000-4000-8000-000000000003",
      }).success,
    ).toBe(false);
    expect(
      ExchangeOAuthTokenRequestSchema.safeParse({ code: "C", state: "" })
        .success,
    ).toBe(false);
  });
  it("accepts a valid optional RFC 9207 issuer", () => {
    expect(
      ExchangeOAuthTokenRequestSchema.parse({
        code: "C",
        state: "S",
        iss: "https://identity.example/tenant",
      }),
    ).toEqual({
      code: "C",
      state: "S",
      iss: "https://identity.example/tenant",
    });
  });
  it.each([
    "",
    "http://identity.example",
    "https://user@identity.example",
    "https://identity.example/?query=1",
    "https://identity.example/#fragment",
    "relative-issuer",
    "https:identity.example",
    `https://${"a".repeat(2048)}.example`,
  ])("rejects invalid RFC 9207 issuer %s", (iss) => {
    expect(
      ExchangeOAuthTokenRequestSchema.safeParse({ code: "C", state: "S", iss })
        .success,
    ).toBe(false);
  });
  it("returns the server UUID in the successful response", () => {
    const result = {
      success: true,
      data: { mcp_server_uuid: "00000000-0000-4000-8000-000000000003" },
      message: "OK",
    };
    expect(ExchangeOAuthTokenResponseSchema.parse(result)).toEqual(result);
  });
  it("rejects null discovery updates instead of silently ignoring them", () => {
    expect(
      OAuthSessionUpdateInputSchema.safeParse({
        mcp_server_uuid: "00000000-0000-4000-8000-000000000003",
        user_id: "user-a",
        discovery_state: null,
      }).success,
    ).toBe(false);
  });
});

describe("OAuthClientInfoRequestSchema", () => {
  it("accepts an entirely empty payload (the section was untouched)", () => {
    expect(OAuthClientInfoRequestSchema.safeParse({}).success).toBe(true);
  });

  it("rejects payload missing client_id when any other field is set", () => {
    const result = OAuthClientInfoRequestSchema.safeParse({
      client_secret: "shh",
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.path).toContain("client_id");
    }
  });

  it("rejects payload missing client_id when authorization_endpoint is set", () => {
    const result = OAuthClientInfoRequestSchema.safeParse({
      authorization_endpoint: "https://example.com/authorize",
    });
    expect(result.success).toBe(false);
  });

  it("accepts a minimal pre-registered client", () => {
    const result = OAuthClientInfoRequestSchema.safeParse({
      client_id: "3MVG9",
    });
    expect(result.success).toBe(true);
  });

  it("rejects an invalid authorization_endpoint URL", () => {
    const result = OAuthClientInfoRequestSchema.safeParse({
      client_id: "3MVG9",
      authorization_endpoint: "not a url",
    });
    expect(result.success).toBe(false);
  });

  it("rejects an invalid token_endpoint URL", () => {
    const result = OAuthClientInfoRequestSchema.safeParse({
      client_id: "3MVG9",
      token_endpoint: "definitely-not-a-url",
    });
    expect(result.success).toBe(false);
  });

  it("rejects unknown token_endpoint_auth_method values", () => {
    const result = OAuthClientInfoRequestSchema.safeParse({
      client_id: "3MVG9",
      token_endpoint_auth_method: "private_key_jwt",
    });
    expect(result.success).toBe(false);
  });

  it("accepts the full RFC 7591 shape we collect from the UI", () => {
    const result = OAuthClientInfoRequestSchema.safeParse({
      client_id: "3MVG9",
      client_secret: "shh",
      scope: "api refresh_token",
      authorization_endpoint:
        "https://login.salesforce.com/services/oauth2/authorize",
      token_endpoint: "https://login.salesforce.com/services/oauth2/token",
      token_endpoint_auth_method: "client_secret_post",
    });
    expect(result.success).toBe(true);
  });
});

// Table-driven pin for the per-server redirect_uri override's loopback-only
// validation (Brief A). Verified live against Reclaim.ai's RFC 7591 DCR
// endpoint (https://api.app.reclaim.ai/oauth2/register) for the base
// accept/reject cases; `http://[::1]:...` is accepted here even though
// Reclaim itself rejects it (RFC 8252 §8.3 loopback, upstream's choice to
// reject it), and any fragment is rejected regardless of host.
describe("OAuthClientInfoRequestSchema redirect_uri (loopback validation)", () => {
  it.each([
    ["http://127.0.0.1:33418/callback"],
    ["http://localhost:12008/fe-oauth/callback"],
    ["http://127.0.0.1/cb"],
    ["http://[::1]:33418/cb"],
  ])("accepts %s", (redirect_uri) => {
    const result = OAuthClientInfoRequestSchema.safeParse({ redirect_uri });
    expect(result.success).toBe(true);
  });

  it.each([
    ["https://example.com/cb"],
    ["https://127.0.0.1:33418/cb"],
    ["http://127.0.0.2:33418/cb"],
    ["urn:ietf:wg:oauth:2.0:oob"],
    ["http://evil.com/cb"],
    ["http://127.0.0.1:33418/cb#frag"],
    ["http://127.0.0.1:33418/cb#"],
  ])("rejects %s", (redirect_uri) => {
    const result = OAuthClientInfoRequestSchema.safeParse({ redirect_uri });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.path).toContain("redirect_uri");
    }
  });

  it("accepts an unset redirect_uri (blank is allowed)", () => {
    expect(OAuthClientInfoRequestSchema.safeParse({}).success).toBe(true);
    expect(
      OAuthClientInfoRequestSchema.safeParse({ redirect_uri: "" }).success,
    ).toBe(true);
  });

  // Design decision: redirect_uri must NOT trip the "client_id becomes
  // required" refinement, because an upstream that only accepts loopback
  // redirect URIs (Reclaim.ai) can still support RFC 7591 dynamic client
  // registration — the user only needs to override redirect_uri, not
  // pre-register a client.
  it("accepts redirect_uri set alone, with no client_id", () => {
    const result = OAuthClientInfoRequestSchema.safeParse({
      redirect_uri: "http://127.0.0.1:33418/callback",
    });
    expect(result.success).toBe(true);
  });
});

describe("OAuthClientInformationSchema", () => {
  // The schema is the read-side validator on the tRPC oauth.get output.
  // Without passthrough, zod's default strip mode silently drops the extra
  // RFC 7591 fields, causing the edit form to lose values on round-trip.
  it("round-trips the extra RFC 7591 fields needed by the pre-registered UI", () => {
    const payload = {
      client_id: "3MVG9.Salesforce",
      client_secret: "shh",
      redirect_uris: ["https://metamcp.example.com/fe-oauth/callback"],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post",
      scope: "api refresh_token",
      authorization_endpoint:
        "https://login.salesforce.com/services/oauth2/authorize",
      token_endpoint: "https://login.salesforce.com/services/oauth2/token",
    };

    const parsed = OAuthClientInformationSchema.parse(payload);
    expect(parsed).toEqual(payload);
  });
});

// Cross-cut: the value the frontend's `provider.clientInformation()` reads
// from `oauth.get` is parsed by the MCP SDK's own
// `OAuthClientInformationSchema` (apps/frontend/lib/oauth-provider.ts:68).
// PR A added `.passthrough()` to the zod-types schema; this test asserts
// that the resulting object also satisfies the SDK schema. If the SDK ever
// adds new required fields, this test breaks loudly instead of breaking
// the OAuth flow silently in production.
describe("SDK OAuthClientInformationSchema cross-cut", () => {
  it("accepts the shape that the backend writes to oauth_sessions.client_information", async () => {
    const { OAuthClientInformationSchema: SdkSchema } =
      await import("@modelcontextprotocol/sdk/shared/auth.js");

    // Minimum shape MetaMCP persists for a pre-registered client.
    const persisted = {
      client_id: "3MVG9.Salesforce",
      client_secret: "shh",
      redirect_uris: ["https://metamcp.example.com/fe-oauth/callback"],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post",
      scope: "api refresh_token",
      authorization_endpoint: "https://login.salesforce.com/oauth2/authorize",
      token_endpoint: "https://login.salesforce.com/oauth2/token",
    };

    const parsed = await SdkSchema.parseAsync(persisted);
    // SDK schema only declares the 4 client-id fields; the rest are
    // stripped (it does NOT use .passthrough()). That is OK: the SDK only
    // needs client_id/client_secret to skip dynamic registration; the
    // server-side token exchange reads the rest directly from the DB row.
    expect(parsed.client_id).toBe("3MVG9.Salesforce");
    expect(parsed.client_secret).toBe("shh");
  });
});
