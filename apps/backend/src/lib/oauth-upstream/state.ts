import { randomBytes } from "node:crypto";

// The UUID is only routing information. Callers must still compare the full
// state with the authenticated user's persisted nonce before exchanging a code.
export function createUpstreamState(mcpServerUuid: string): string {
  return `upstream.${mcpServerUuid}.${randomBytes(32).toString("base64url")}`;
}

export function parseUpstreamState(state: string): string | null {
  if (typeof state !== "string" || !state.startsWith("upstream.")) return null;
  const match =
    /^upstream\.([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.([A-Za-z0-9_-]{43})$/i.exec(
      state,
    );
  return match?.[1] ?? null;
}
