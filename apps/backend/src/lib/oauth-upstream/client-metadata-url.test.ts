import { afterEach, describe, expect, it } from "vitest";

import { resolveOAuthClientMetadataUrl } from "./client-metadata-url";

const ORIGINAL_URL = process.env.OAUTH_CLIENT_METADATA_URL;

afterEach(() => {
  if (ORIGINAL_URL === undefined) delete process.env.OAUTH_CLIENT_METADATA_URL;
  else process.env.OAUTH_CLIENT_METADATA_URL = ORIGINAL_URL;
});

describe("resolveOAuthClientMetadataUrl", () => {
  it("keeps OAuth behavior disabled when the environment variable is absent", () => {
    delete process.env.OAUTH_CLIENT_METADATA_URL;
    expect(resolveOAuthClientMetadataUrl()).toBeUndefined();
  });

  it("returns a valid HTTPS metadata URL byte-for-byte", () => {
    const value = "https://oauth.example:443/oauth/client-metadata";
    process.env.OAUTH_CLIENT_METADATA_URL = value;
    expect(resolveOAuthClientMetadataUrl()).toBe(value);
  });

  it("rejects a metadata URL whose pathname is not the gateway route", () => {
    process.env.OAUTH_CLIENT_METADATA_URL =
      "https://oauth.example/other/client-metadata";
    expect(() => resolveOAuthClientMetadataUrl()).toThrow(
      /OAUTH_CLIENT_METADATA_URL/,
    );
  });

  it.each([
    "",
    "not-a-url",
    "http://oauth.example/oauth/client-metadata",
    "https://oauth.example/",
    "https://oauth.example/oauth/../oauth/client-metadata",
    "https://oauth.example/oauth/%2e%2e/oauth/client-metadata",
    "https://user:password@oauth.example/oauth/client-metadata",
    "https://oauth.example/oauth/client-metadata?",
    "https://oauth.example/oauth/client-metadata?return=https://evil.example",
    "https://oauth.example/oauth/client-metadata#",
    "https://oauth.example/oauth/client-metadata#fragment",
  ])("rejects unsafe metadata URL %j", (value) => {
    process.env.OAUTH_CLIENT_METADATA_URL = value;
    expect(() => resolveOAuthClientMetadataUrl()).toThrow(
      /OAUTH_CLIENT_METADATA_URL/,
    );
  });
});
