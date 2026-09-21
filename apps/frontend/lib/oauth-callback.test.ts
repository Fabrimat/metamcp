import { readFileSync } from "node:fs";

import { afterEach, describe, expect, it } from "vitest";

import { parseOAuthCallback } from "./oauth-callback";

const STATE =
  "upstream.11111111-1111-4111-8111-111111111111.abcdefghijklmnopqrstuvwxyzABCDEFGH_1234567";

describe("parseOAuthCallback", () => {
  afterEach(() => {
    Reflect.deleteProperty(globalThis, "sessionStorage");
  });

  it("returns only the required authorization code and upstream state", () => {
    expect(
      parseOAuthCallback(`?code=code-123&state=${STATE}&ignored=not-authority`),
    ).toEqual({ kind: "success", code: "code-123", state: STATE });
  });

  it("surfaces OAuth provider errors and ignores unrelated parameters", () => {
    expect(
      parseOAuthCallback(
        "?error=access_denied&error_description=Nope&server_uuid=attacker",
      ),
    ).toEqual({
      kind: "error",
      error: "access_denied",
      errorDescription: "Nope",
    });
  });

  it.each([
    [`?state=${STATE}`, "missing_callback_parameters"],
    ["?code=code-123&state=downstream.state", "invalid_callback_state"],
  ])(
    "rejects an invalid callback without storage fallback",
    (search, error) => {
      expect(parseOAuthCallback(search)).toMatchObject({
        kind: "error",
        error,
      });
    },
  );

  it("never reads sessionStorage", () => {
    Object.defineProperty(globalThis, "sessionStorage", {
      configurable: true,
      get() {
        throw new Error("sessionStorage was accessed");
      },
    });

    expect(parseOAuthCallback(`?code=code-123&state=${STATE}`)).toMatchObject({
      kind: "success",
    });
  });
});

type JsonObject = Record<string, unknown>;

function readLocale(locale: string, namespace: string): JsonObject {
  return JSON.parse(
    readFileSync(
      new URL(`../public/locales/${locale}/${namespace}.json`, import.meta.url),
      "utf8",
    ),
  ) as JsonObject;
}

function recursiveKeys(value: unknown, prefix = ""): string[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return [prefix];
  }

  return Object.entries(value as JsonObject).flatMap(([key, child]) =>
    recursiveKeys(child, prefix ? `${prefix}.${key}` : key),
  );
}

describe("OAuth locale parity", () => {
  const translatedLocales = ["es", "ko", "pt", "zh"];

  it.each(translatedLocales)(
    "%s has the English common.oauth and advancedOauth key trees",
    (locale) => {
      const englishCommon = readLocale("en", "common");
      const translatedCommon = readLocale(locale, "common");
      const englishServers = readLocale("en", "mcp-servers");
      const translatedServers = readLocale(locale, "mcp-servers");

      expect(recursiveKeys(translatedCommon.oauth).sort()).toEqual(
        recursiveKeys(englishCommon.oauth).sort(),
      );
      expect(recursiveKeys(translatedServers.advancedOauth).sort()).toEqual(
        recursiveKeys(englishServers.advancedOauth).sort(),
      );
    },
  );

  it.each(translatedLocales)(
    "%s translates detail authorization states and OAuth validation keys",
    (locale) => {
      const servers = readLocale(locale, "mcp-servers");
      const validation = readLocale(locale, "validation");
      const detail = servers.detail as JsonObject;

      expect([
        detail.authorize,
        detail.authorizing,
        detail.authorizeFailed,
      ]).toEqual(expect.not.arrayContaining([undefined]));
      expect(
        recursiveKeys({
          oauthClientId: validation.oauthClientId,
          oauthAuthorizationEndpoint: validation.oauthAuthorizationEndpoint,
          oauthTokenEndpoint: validation.oauthTokenEndpoint,
          oauthRedirectUri: validation.oauthRedirectUri,
        }).sort(),
      ).toEqual([
        "oauthAuthorizationEndpoint.invalid",
        "oauthClientId.required",
        "oauthRedirectUri.invalid",
        "oauthTokenEndpoint.invalid",
      ]);
    },
  );
});
