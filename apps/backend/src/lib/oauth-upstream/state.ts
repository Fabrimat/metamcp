import { randomBytes } from "node:crypto";

// The UUID is only routing information. Callers must still compare the full
// state with the authenticated user's persisted nonce before exchanging a code.
export function createUpstreamState(mcpServerUuid: string): string {
  // The timestamp is stored verbatim with the nonce; unrelated row updates
  // cannot extend this ten-minute authorization attempt. Exact-state CAS
  // authenticates the timestamp along with the random nonce.
  return `upstream.${mcpServerUuid}.${Date.now()}.${randomBytes(32).toString("base64url")}`;
}

export function parseUpstreamState(state: string): string | null {
  if (typeof state !== "string" || !state.startsWith("upstream.")) return null;
  const match =
    /^upstream\.([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.(\d{13})\.([A-Za-z0-9_-]{43})$/i.exec(
      state,
    );
  if (!match) return null;
  const age = Date.now() - Number(match[2]);
  return age >= 0 && age < 10 * 60 * 1000 ? match[1] : null;
}
