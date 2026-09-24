import { afterEach, describe, expect, it, vi } from "vitest";

import { validateRedirectUri } from "./utils";

describe("validateRedirectUri in production", () => {
  afterEach(() => vi.unstubAllEnvs());

  it.each([
    "http://localhost:45697/callback",
    "http://127.0.0.1:45697/callback",
    "http://[::1]:45697/callback",
  ])("accepts desktop loopback callback %s", (uri) => {
    vi.stubEnv("NODE_ENV", "production");

    expect(validateRedirectUri(uri)).toBe(true);
  });

  it.each([
    "http://example.com/callback",
    "http://localhost.evil.example/callback",
    "http://192.168.1.1/callback",
  ])("rejects non-loopback HTTP callback %s", (uri) => {
    vi.stubEnv("NODE_ENV", "production");

    expect(validateRedirectUri(uri)).toBe(false);
  });

  it("continues to accept public HTTPS callbacks", () => {
    vi.stubEnv("NODE_ENV", "production");

    expect(validateRedirectUri("https://client.example/callback")).toBe(true);
  });
});
