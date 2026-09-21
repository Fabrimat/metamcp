import { afterEach, describe, expect, it, vi } from "vitest";

import {
  beginUpstreamAuthorization,
  OAuthAuthorizationError,
  shouldStartUpstreamOAuth,
} from "./oauth-authorization";

const SERVER = "11111111-1111-4111-8111-111111111111";

describe("beginUpstreamAuthorization", () => {
  afterEach(() => {
    Reflect.deleteProperty(globalThis, "sessionStorage");
  });

  it("starts backend authorization and navigates to its validated URL", async () => {
    const start = vi.fn().mockResolvedValue({
      success: true,
      data: { authorization_url: "https://auth.example/authorize" },
      message: "ready",
    });
    const navigate = vi.fn();

    await beginUpstreamAuthorization(SERVER, start, navigate);

    expect(start).toHaveBeenCalledWith({ mcp_server_uuid: SERVER });
    expect(navigate).toHaveBeenCalledWith("https://auth.example/authorize");
  });

  it("throws a typed, sanitized backend failure and does not navigate", async () => {
    const start = vi.fn().mockResolvedValue({
      success: false,
      error: "access_denied",
      error_description: "The user denied access",
      raw_secret: "must not escape",
    });
    const navigate = vi.fn();

    const failure = await beginUpstreamAuthorization(
      SERVER,
      start,
      navigate,
    ).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(OAuthAuthorizationError);
    expect(failure).toMatchObject({
      code: "access_denied",
      description: "The user denied access",
      message: "access_denied: The user denied access",
    });
    expect(JSON.stringify(failure)).not.toContain("must not escape");
    expect(navigate).not.toHaveBeenCalled();
  });

  it("rejects malformed or unsafe success responses before navigation", async () => {
    const start = vi.fn().mockResolvedValue({
      success: true,
      data: { authorization_url: "javascript:alert(1)" },
      message: "ready",
    });
    const navigate = vi.fn();

    await expect(
      beginUpstreamAuthorization(SERVER, start, navigate),
    ).rejects.toMatchObject({
      name: "OAuthAuthorizationError",
      code: "invalid_authorization_response",
    });
    expect(navigate).not.toHaveBeenCalled();
  });

  it("does not use sessionStorage as authorization authority", async () => {
    Object.defineProperty(globalThis, "sessionStorage", {
      configurable: true,
      get() {
        throw new Error("sessionStorage was accessed");
      },
    });
    const navigate = vi.fn();

    await beginUpstreamAuthorization(
      SERVER,
      async () => ({
        success: true,
        data: { authorization_url: "https://auth.example/authorize" },
        message: "ready",
      }),
      navigate,
    );

    expect(navigate).toHaveBeenCalledOnce();
  });
});

describe("shouldStartUpstreamOAuth", () => {
  it.each([
    [{ is401: true, isMetaMCP: false }, true],
    [{ is401: true, isMetaMCP: true }, false],
    [{ is401: false, isMetaMCP: false }, false],
  ])("returns %s for %o", (input, expected) => {
    expect(shouldStartUpstreamOAuth(input)).toBe(expected);
  });
});
