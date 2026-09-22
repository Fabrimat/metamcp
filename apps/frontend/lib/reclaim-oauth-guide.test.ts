import { describe, expect, it } from "vitest";

import { getReclaimOAuthGuide } from "./reclaim-oauth-guide";

describe("getReclaimOAuthGuide", () => {
  it("guides a Reclaim DCR server error through the local callback tunnel", () => {
    expect(
      getReclaimOAuthGuide({
        serverUrl: "https://mcp.reclaim.ai/mcp",
        errorCode: "server_error",
      }),
    ).toEqual({
      redirectUri: "http://127.0.0.1:33418/oauth/client-metadata",
      tunnelCommand: "ssh -N -L 33418:127.0.0.1:12010 mimir",
    });
  });

  it("does not replace errors from other OAuth providers", () => {
    expect(
      getReclaimOAuthGuide({
        serverUrl: "https://api.us.elevenlabs.io/v1/mcp",
        errorCode: "server_error",
      }),
    ).toBeNull();
  });
});
