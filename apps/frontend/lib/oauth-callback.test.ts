import { readFileSync } from "node:fs";

import { afterEach, describe, expect, it, vi } from "vitest";

import { getServerSpecificKey, SESSION_KEYS } from "./constants";
import { completeOAuthCallback, parseOAuthCallback } from "./oauth-callback";

const STATE =
  "upstream.11111111-1111-4111-8111-111111111111.abcdefghijklmnopqrstuvwxyzABCDEFGH_1234567";
const SERVER = "11111111-1111-4111-8111-111111111111";

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

function createStorage(entries: Record<string, string>) {
  const values = new Map(Object.entries(entries));
  return {
    values,
    storage: {
      getItem: vi.fn((key: string) => values.get(key) ?? null),
      removeItem: vi.fn((key: string) => {
        values.delete(key);
      }),
    },
  };
}

describe("completeOAuthCallback", () => {
  const NAMESPACE = "22222222-2222-4222-8222-222222222222";
  const SERVER_URL =
    "/mcp-proxy/metamcp/22222222-2222-4222-8222-222222222222/sse";

  it("completes a downstream consent return and returns to its namespace", async () => {
    const verifierKey = getServerSpecificKey(
      SESSION_KEYS.CODE_VERIFIER,
      SERVER_URL,
    );
    const tokenKey = getServerSpecificKey(SESSION_KEYS.TOKENS, SERVER_URL);
    const { storage, values } = createStorage({
      [SESSION_KEYS.SERVER_URL]: SERVER_URL,
      [SESSION_KEYS.MCP_SERVER_UUID]: NAMESPACE,
      [verifierKey]: "verifier",
      [tokenKey]: JSON.stringify({ access_token: "downstream-token" }),
    });
    const exchangeUpstream = vi.fn();
    const completeDownstream = vi.fn().mockResolvedValue({
      result: "AUTHORIZED",
      tokens: { access_token: "downstream-token" },
    });
    const navigate = vi.fn();

    const result = await completeOAuthCallback(
      "?code=downstream-code&state=downstream-state",
      { storage, exchangeUpstream, completeDownstream, navigate },
    );

    expect(result).toEqual({ kind: "redirected", flow: "downstream" });
    expect(completeDownstream).toHaveBeenCalledWith({
      authorizationCode: "downstream-code",
      returnUuid: NAMESPACE,
      serverUrl: SERVER_URL,
    });
    expect(exchangeUpstream).not.toHaveBeenCalled();
    expect(navigate).toHaveBeenCalledWith(`/namespaces/${NAMESPACE}`);
    expect(values.has(SESSION_KEYS.SERVER_URL)).toBe(false);
    expect(values.has(SESSION_KEYS.MCP_SERVER_UUID)).toBe(false);
    expect(values.has(verifierKey)).toBe(false);
    expect(values.has(tokenKey)).toBe(true);
  });

  it("always chooses backend exchange for upstream state even when downstream storage exists", async () => {
    const { storage } = createStorage({
      [SESSION_KEYS.SERVER_URL]: SERVER_URL,
      [SESSION_KEYS.MCP_SERVER_UUID]: NAMESPACE,
    });
    const exchangeUpstream = vi.fn().mockResolvedValue({
      success: true,
      data: { mcp_server_uuid: SERVER },
      message: "authorized",
    });
    const completeDownstream = vi.fn();
    const navigate = vi.fn();

    const result = await completeOAuthCallback(
      `?code=upstream-code&state=${STATE}`,
      { storage, exchangeUpstream, completeDownstream, navigate },
    );

    expect(result).toEqual({ kind: "redirected", flow: "upstream" });
    expect(exchangeUpstream).toHaveBeenCalledWith({
      code: "upstream-code",
      state: STATE,
    });
    expect(completeDownstream).not.toHaveBeenCalled();
    expect(storage.getItem).not.toHaveBeenCalled();
    expect(storage.removeItem).not.toHaveBeenCalled();
    expect(navigate).toHaveBeenCalledWith(`/mcp-servers/${SERVER}`);
  });

  it("cleans downstream callback context after a terminal provider error", async () => {
    const verifierKey = getServerSpecificKey(
      SESSION_KEYS.CODE_VERIFIER,
      SERVER_URL,
    );
    const { storage, values } = createStorage({
      [SESSION_KEYS.SERVER_URL]: SERVER_URL,
      [SESSION_KEYS.MCP_SERVER_UUID]: NAMESPACE,
      [verifierKey]: "verifier",
    });

    const result = await completeOAuthCallback(
      "?error=access_denied&error_description=Denied&state=downstream-state",
      {
        storage,
        exchangeUpstream: vi.fn(),
        completeDownstream: vi.fn(),
        navigate: vi.fn(),
      },
    );

    expect(result).toEqual({
      kind: "error",
      error: "access_denied",
      errorDescription: "Denied",
    });
    expect(values.has(SESSION_KEYS.SERVER_URL)).toBe(false);
    expect(values.has(SESSION_KEYS.MCP_SERVER_UUID)).toBe(false);
    expect(values.has(verifierKey)).toBe(false);
  });

  it("rejects a downstream AUTHORIZED result when no tokens were persisted", async () => {
    const { storage, values } = createStorage({
      [SESSION_KEYS.SERVER_URL]: SERVER_URL,
      [SESSION_KEYS.MCP_SERVER_UUID]: NAMESPACE,
    });
    const navigate = vi.fn();

    const result = await completeOAuthCallback(
      "?code=downstream-code&state=downstream-state",
      {
        storage,
        exchangeUpstream: vi.fn(),
        completeDownstream: vi.fn().mockResolvedValue({
          result: "AUTHORIZED",
          tokens: undefined,
        }),
        navigate,
      },
    );

    expect(result).toMatchObject({
      kind: "error",
      error: "downstream_authorization_failed",
    });
    expect(navigate).not.toHaveBeenCalled();
    expect(values.has(SESSION_KEYS.SERVER_URL)).toBe(false);
    expect(values.has(SESSION_KEYS.MCP_SERVER_UUID)).toBe(false);
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

  function oauthValidationTree(locale: string): JsonObject {
    return Object.fromEntries(
      Object.entries(readLocale(locale, "validation")).filter(([key]) =>
        key.startsWith("oauth"),
      ),
    );
  }

  it.each(translatedLocales)(
    "%s has recursive parity for every OAuth locale subtree",
    (locale) => {
      const englishCommon = readLocale("en", "common");
      const translatedCommon = readLocale(locale, "common");
      const englishServers = readLocale("en", "mcp-servers");
      const translatedServers = readLocale(locale, "mcp-servers");

      expect(recursiveKeys(translatedCommon.oauth).sort()).toEqual(
        recursiveKeys(englishCommon.oauth).sort(),
      );
      expect(recursiveKeys(translatedServers.detail).sort()).toEqual(
        recursiveKeys(englishServers.detail).sort(),
      );
      expect(recursiveKeys(translatedServers.advancedOauth).sort()).toEqual(
        recursiveKeys(englishServers.advancedOauth).sort(),
      );
      expect(recursiveKeys(oauthValidationTree(locale)).sort()).toEqual(
        recursiveKeys(oauthValidationTree("en")).sort(),
      );
    },
  );
});
