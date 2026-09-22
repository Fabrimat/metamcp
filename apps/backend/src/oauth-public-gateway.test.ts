import type { AddressInfo } from "node:net";

import { afterEach, describe, expect, it, vi } from "vitest";

import { createOAuthPublicGateway } from "./oauth-public-gateway";

const METADATA_URL = "https://oauth.example/oauth/client-metadata";

async function withGateway(
  env: NodeJS.ProcessEnv,
  test: (baseUrl: string, logger: TestLogger) => Promise<void>,
) {
  const logger = {
    info: vi.fn(),
    error: vi.fn(),
  };
  const server = createOAuthPublicGateway({ env, logger });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address() as AddressInfo;
  try {
    await test(`http://127.0.0.1:${address.port}`, logger);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}

type TestLogger = {
  info: ReturnType<typeof vi.fn>;
  error: ReturnType<typeof vi.fn>;
};

afterEach(() => vi.restoreAllMocks());

describe("OAuth public gateway metadata", () => {
  it("returns the exact SEP-991 document with public cache and security headers", async () => {
    await withGateway(
      {
        OAUTH_CLIENT_METADATA_URL: METADATA_URL,
        APP_URL: "http://metamcp-app:12008",
      },
      async (baseUrl) => {
        const response = await fetch(`${baseUrl}/oauth/client-metadata`);
        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({
          client_id: METADATA_URL,
          client_name: "MetaMCP",
          redirect_uris: [METADATA_URL],
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
          token_endpoint_auth_method: "none",
        });
        expect(response.headers.get("access-control-allow-origin")).toBe("*");
        expect(response.headers.get("cache-control")).toBe(
          "public, max-age=300",
        );
        expect(response.headers.get("x-content-type-options")).toBe("nosniff");
        expect(response.headers.get("x-frame-options")).toBe("DENY");
        expect(response.headers.get("referrer-policy")).toBe("no-referrer");
        expect(response.headers.get("content-security-policy")).toBe(
          "default-src 'none'; frame-ancestors 'none'",
        );
      },
    );
  });

  it("serves HEAD with metadata headers and no body", async () => {
    await withGateway(
      { OAUTH_CLIENT_METADATA_URL: METADATA_URL },
      async (baseUrl) => {
        const response = await fetch(`${baseUrl}/oauth/client-metadata`, {
          method: "HEAD",
        });
        expect(response.status).toBe(200);
        expect(await response.text()).toBe("");
        expect(response.headers.get("content-type")).toContain(
          "application/json",
        );
      },
    );
  });

  it("returns 404 when metadata is disabled", async () => {
    await withGateway({}, async (baseUrl) => {
      expect((await fetch(`${baseUrl}/oauth/client-metadata`)).status).toBe(
        404,
      );
    });
  });

  it("does not cache callback-like requests when metadata is disabled", async () => {
    await withGateway({}, async (baseUrl) => {
      const response = await fetch(
        `${baseUrl}/oauth/client-metadata?code=secret&state=state`,
        { redirect: "manual" },
      );
      expect(response.status).toBe(404);
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    });
  });

  it.each([
    "/",
    "/health",
    "/trpc",
    "/fe-oauth/callback",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/oauth/client-metadata/",
  ])("keeps %s isolated behind 404", async (path) => {
    await withGateway(
      { OAUTH_CLIENT_METADATA_URL: METADATA_URL },
      async (baseUrl) => {
        expect((await fetch(baseUrl + path)).status).toBe(404);
      },
    );
  });
});

describe("OAuth public gateway callback relay", () => {
  it("relays a code with 303 to fixed APP_URL despite hostile proxy headers", async () => {
    await withGateway(
      {
        OAUTH_CLIENT_METADATA_URL: METADATA_URL,
        APP_URL: "http://metamcp-app:12008",
      },
      async (baseUrl) => {
        const response = await fetch(
          `${baseUrl}/oauth/client-metadata?code=auth-code&state=trusted-state`,
          {
            redirect: "manual",
            headers: {
              Host: "evil.example",
              "X-Forwarded-Host": "evil.example",
              "X-Forwarded-Proto": "https",
            },
          },
        );
        expect(response.status).toBe(303);
        expect(response.headers.get("location")).toBe(
          "http://metamcp-app:12008/fe-oauth/callback?code=auth-code&state=trusted-state",
        );
        expect(response.headers.get("cache-control")).toBe("no-store");
        expect(response.headers.get("referrer-policy")).toBe("no-referrer");
        expect(response.headers.get("x-content-type-options")).toBe("nosniff");
        expect(response.headers.get("x-frame-options")).toBe("DENY");
        expect(response.headers.get("content-security-policy")).toBe(
          "default-src 'none'; frame-ancestors 'none'",
        );
      },
    );
  });

  it("relays only the allowlisted OAuth error values", async () => {
    await withGateway(
      {
        OAUTH_CLIENT_METADATA_URL: METADATA_URL,
        APP_URL: "https://private.example/base",
      },
      async (baseUrl) => {
        const response = await fetch(
          `${baseUrl}/oauth/client-metadata?error=access_denied&error_description=User+declined&state=s1`,
          { redirect: "manual" },
        );
        expect(response.status).toBe(303);
        expect(response.headers.get("location")).toBe(
          "https://private.example/base/fe-oauth/callback?error=access_denied&error_description=User+declined&state=s1",
        );
      },
    );
  });

  it.each([
    "?state=s1",
    "?code=c1",
    "?code=c1&error=access_denied&state=s1",
    "?code=c1&code=c2&state=s1",
    "?code=c1&state=s1&state=s2",
    "?error=access_denied&error_description=x&error_description=y&state=s1",
    "?code=c1&state=s1&return_url=https%3A%2F%2Fevil.example",
    "?foo=bar",
    "?code=&state=s1",
    "?code=c1&state=",
    "?error=bad%00value&state=s1",
    "?code=%ZZ&state=s1",
  ])("rejects malformed callback query %s", async (query) => {
    await withGateway(
      {
        OAUTH_CLIENT_METADATA_URL: METADATA_URL,
        APP_URL: "http://metamcp-app:12008",
      },
      async (baseUrl) => {
        const response = await fetch(
          `${baseUrl}/oauth/client-metadata${query}`,
          { redirect: "manual" },
        );
        expect(response.status).toBe(400);
        expect(response.headers.get("cache-control")).toBe("no-store");
      },
    );
  });

  it("rejects oversized callback values", async () => {
    await withGateway(
      {
        OAUTH_CLIENT_METADATA_URL: METADATA_URL,
        APP_URL: "http://metamcp-app:12008",
      },
      async (baseUrl) => {
        const response = await fetch(
          `${baseUrl}/oauth/client-metadata?code=${"a".repeat(8193)}&state=s1`,
          { redirect: "manual" },
        );
        expect(response.status).toBe(400);
      },
    );
  });

  it("never logs query parameters, codes, or states", async () => {
    await withGateway(
      {
        OAUTH_CLIENT_METADATA_URL: METADATA_URL,
        APP_URL: "http://metamcp-app:12008",
      },
      async (baseUrl, logger) => {
        await fetch(
          `${baseUrl}/oauth/client-metadata?code=super-secret-code&state=super-secret-state`,
          { redirect: "manual" },
        );
        const logs = JSON.stringify([
          logger.info.mock.calls,
          logger.error.mock.calls,
        ]);
        expect(logs).not.toContain("super-secret-code");
        expect(logs).not.toContain("super-secret-state");
        expect(logs).not.toContain("?");
      },
    );
  });
});
