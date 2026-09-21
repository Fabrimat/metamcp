import { describe, expect, it } from "vitest";

import { createUpstreamState, parseUpstreamState } from "./state";

const UUID = "00000000-0000-4000-8000-000000000003";

describe("upstream OAuth state", () => {
  it("round trips a UUID with a fresh 32-byte nonce", () => {
    const state = createUpstreamState(UUID);
    expect(state).toMatch(
      new RegExp(`^upstream\\.${UUID}\\.[A-Za-z0-9_-]{43}$`),
    );
    expect(parseUpstreamState(state)).toBe(UUID);
    expect(createUpstreamState(UUID)).not.toBe(state);
  });

  it.each([
    "",
    `wrong.${UUID}.${"a".repeat(43)}`,
    `UPSTREAM.${UUID}.${"a".repeat(43)}`,
    `upstream.not-a-uuid.${"a".repeat(43)}`,
    `upstream.${UUID}`,
    `upstream.${UUID}.`,
    `upstream.${UUID}.short`,
    `upstream.${UUID}.${"a".repeat(43)}.extra`,
    `upstream.${UUID}.${"!".repeat(43)}`,
  ])("rejects malformed state %s", (state) => {
    expect(parseUpstreamState(state)).toBeNull();
  });
});
