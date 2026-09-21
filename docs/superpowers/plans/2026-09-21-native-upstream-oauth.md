# Native Upstream OAuth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete secure, user-scoped native OAuth for upstream MCP servers and prepare an immutable, reversible release to Mimir.

**Architecture:** Persist OAuth client state by `(mcp_server_uuid, user_id)`, propagate the namespace owner as the OAuth principal when proxying public server definitions, and keep discovery/registration/exchange/refresh on the backend. Persist the MCP SDK discovery state so authorize, exchange, and refresh use the same authorization server and RFC 8707 resource, and make the callback identify its flow from a single-use backend state rather than browser storage.

**Tech Stack:** TypeScript 5, Node.js, Express 5, Next.js 15, tRPC 11, Zod 4, Drizzle/PostgreSQL, MCP SDK 1.29, Vitest 4, pnpm/Turborepo, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-09-21-native-upstream-oauth-design.md`

## Global Constraints

- Preserve the existing uncommitted OAuth implementation and extend it through failing tests; do not replace unrelated working code.
- Every OAuth database read or mutation is scoped by both MCP server UUID and authenticated application user ID.
- Public MCP server definitions may be reused, but credentials, PKCE, discovery state, and tokens remain per user.
- The browser never supplies a server URL, token endpoint, client secret, verifier, or resource indicator to exchange or refresh procedures.
- Only `http:` and `https:` upstream endpoints are accepted; loopback redirect overrides remain limited to `http://127.0.0.1`, `http://localhost`, or `http://[::1]` without fragments.
- Private-network and Tailscale MCP endpoints remain supported intentionally.
- Authorization state is high-entropy, single-use, user-bound, and server-bound.
- Do not log authorization codes, tokens, client secrets, PKCE verifiers, or complete callback query strings.
- Use the namespace owner as the OAuth principal for namespace proxy connections. If neither namespace nor server has a user owner, do not attach OAuth credentials.
- Implementation follows red-green-refactor. Each production change must be preceded by a focused test that fails for the expected missing behavior.
- Run focused tests after every red/green step and the complete verification matrix before release.

---

## File Responsibility Map

- `packages/zod-types/src/oauth.zod.ts`: shared persistence and tRPC OAuth contracts.
- `packages/zod-types/src/metamcp.zod.ts`: runtime server parameters, including the resolved OAuth principal.
- `apps/backend/src/db/schema.ts` and Drizzle migration files: user-scoped OAuth persistence.
- `apps/backend/src/db/repositories/oauth-sessions.repo.ts`: all keyed OAuth session operations.
- `apps/backend/src/trpc/oauth.impl.ts`: authorization access checks, state resolution, exchange, refresh, and authorization start.
- `apps/backend/src/lib/oauth-upstream/provider.ts`: MCP SDK provider used for backend discovery, DCR, PKCE, state, and discovery persistence.
- `apps/backend/src/lib/oauth-upstream/token-exchange.ts`: RFC-compliant exchange and refresh form construction.
- `apps/backend/src/lib/oauth-upstream/refresh-on-401.ts`: per-principal refresh synchronization.
- `apps/backend/src/lib/metamcp/fetch-metamcp.ts`, `utils.ts`, and `client.ts`: choose and consume per-user tokens at runtime.
- `apps/frontend/lib/oauth-authorization.ts`: shared browser navigation helper for starting backend OAuth.
- `apps/frontend/hooks/useConnection.ts`: upstream-only automatic authorization recovery.
- `apps/frontend/components/OAuthCallback.tsx`: storage-independent callback processing.
- `apps/frontend/public/locales/*`: complete localized OAuth UI strings.
- `README-oauth.md`: operational behavior and trust assumptions.

---

### Task 1: User-Scoped OAuth Persistence and Procedure Authorization

**Files:**
- Modify: `packages/zod-types/src/oauth.zod.ts`
- Modify: `apps/backend/src/db/schema.ts`
- Create: `apps/backend/drizzle/0020_user_scoped_oauth.sql`
- Create: `apps/backend/drizzle/meta/0020_snapshot.json`
- Modify: `apps/backend/drizzle/meta/_journal.json`
- Modify: `apps/backend/src/db/repositories/oauth-sessions.repo.ts`
- Modify: `apps/backend/src/db/repositories/__tests__/oauth-sessions.repo.test.ts`
- Modify: `packages/trpc/src/routers/frontend/oauth.ts`
- Modify: `apps/backend/src/trpc/oauth.impl.ts`
- Modify: `apps/backend/src/trpc/oauth.impl.test.ts`
- Modify: `apps/backend/src/lib/oauth-upstream/provider.ts`
- Create: `apps/backend/src/lib/oauth-upstream/provider.test.ts`

**Interfaces:**
- Produces `OAuthSessionKey = { mcp_server_uuid: string; user_id: string }`.
- Produces `findByMcpServerAndUser(mcpServerUuid: string, userId: string)` and user-scoped clear/delete methods.
- Changes every `oauthImplementations` method to accept `(input, userId)`.
- Changes `OAuthUpstreamClientProviderOptions` to include `userId: string`.
- Later tasks rely on a nullable JSON `discovery_state` column and the composite unique key.

- [ ] **Step 1: Write failing repository isolation tests**

Add cases proving that two users can store distinct rows for one server and that update, state clearing, and deletion affect only the selected pair:

```ts
it("isolates sessions for two users of the same MCP server", async () => {
  await repo.upsert({ mcp_server_uuid: SERVER, user_id: "user-a", tokens: TOKENS_A });
  await repo.upsert({ mcp_server_uuid: SERVER, user_id: "user-b", tokens: TOKENS_B });

  expect((await repo.findByMcpServerAndUser(SERVER, "user-a"))?.tokens).toEqual(TOKENS_A);
  expect((await repo.findByMcpServerAndUser(SERVER, "user-b"))?.tokens).toEqual(TOKENS_B);
});
```

- [ ] **Step 2: Run the repository tests and confirm the missing API fails**

Run: `corepack pnpm --filter backend exec vitest run src/db/repositories/__tests__/oauth-sessions.repo.test.ts`

Expected: FAIL because `findByMcpServerAndUser` and `user_id` do not exist and the current unique constraint permits only one row per server.

- [ ] **Step 3: Extend shared schemas and the Drizzle table**

Add `user_id` to create/update/database schemas and add serializable discovery state:

```ts
export const OAuthDiscoveryStateSchema = z.record(z.string(), z.unknown());

export const OAuthSessionKeySchema = z.object({
  mcp_server_uuid: z.string().uuid(),
  user_id: z.string().min(1),
});
```

In `oauthSessionsTable`, add a non-null foreign key to `usersTable.id`, nullable `jsonb("discovery_state")`, a user index, and a unique constraint on `(mcp_server_uuid, user_id)`.

- [ ] **Step 4: Generate and normalize migration 0020**

Run: `corepack pnpm --filter backend db:generate:dev`

Ensure the generated SQL performs this order atomically:

```sql
ALTER TABLE "oauth_sessions" ADD COLUMN "user_id" text;
ALTER TABLE "oauth_sessions" ADD COLUMN "discovery_state" jsonb;
UPDATE "oauth_sessions" AS os
SET "user_id" = ms."user_id"
FROM "mcp_servers" AS ms
WHERE ms."uuid" = os."mcp_server_uuid" AND ms."user_id" IS NOT NULL;
DELETE FROM "oauth_sessions" WHERE "user_id" IS NULL;
ALTER TABLE "oauth_sessions" ALTER COLUMN "user_id" SET NOT NULL;
```

Then replace the per-server unique constraint with the composite constraint, add the user foreign key with cascade, and add `oauth_sessions_user_id_idx`. Do not alter migration `0019`.

- [ ] **Step 5: Implement composite repository operations**

Use `and(eq(server), eq(user))` for reads, updates, clears, and deletes. Use both columns as the upsert conflict target:

```ts
async findByMcpServerAndUser(mcpServerUuid: string, userId: string) { /* composite WHERE */ }
async clearExpectedState(mcpServerUuid: string, userId: string) { /* composite WHERE */ }
async deleteByMcpServerAndUser(mcpServerUuid: string, userId: string) { /* composite WHERE */ }
```

Remove production use of `findByMcpServerUuid`. Do not retain an unscoped fallback.

- [ ] **Step 6: Run repository tests green**

Run: `corepack pnpm --filter backend exec vitest run src/db/repositories/__tests__/oauth-sessions.repo.test.ts`

Expected: PASS for isolation, scoped update, scoped clear, scoped delete, and atomic composite upsert.

- [ ] **Step 7: Write failing router and implementation ownership tests**

Add tests verifying `get` and `upsert` forward `ctx.user.id`, reject another user's private server, permit a public server while using the caller's own session, and never return another user's secrets.

```ts
expect(implementations.get).toHaveBeenCalledWith(input, "user-a");
expect(implementations.upsert).toHaveBeenCalledWith(input, "user-a");
```

- [ ] **Step 8: Run focused procedure tests red**

Run: `corepack pnpm --filter backend exec vitest run src/trpc/oauth.impl.test.ts src/trpc/oauth-request-schema.test.ts`

Expected: FAIL because `get/upsert` are currently unscoped and the provider lacks `userId`.

- [ ] **Step 9: Scope every procedure and provider operation**

Pass `ctx.user.id` through all five router procedures. Make `get`, `upsert`, `exchangeToken`, `refreshToken`, and `startAuthorization` resolve server access first and use only the composite session key. Add `userId` to `OAuthUpstreamClientProviderOptions` and use it in every provider repository call.

- [ ] **Step 10: Prevent secret-bearing session serialization where not required**

Keep compatibility for the legacy frontend provider during this task, but ensure failed access returns a typed `access_denied` response before serialization. Add a test that a caller cannot fetch `client_information`, tokens, verifier, or expected state from another user's session.

- [ ] **Step 11: Run Task 1 tests and type checks**

Run:

```powershell
corepack pnpm --filter backend exec vitest run src/db/repositories/__tests__/oauth-sessions.repo.test.ts src/trpc/oauth.impl.test.ts src/trpc/oauth-request-schema.test.ts src/lib/oauth-upstream/provider.test.ts
corepack pnpm --filter @repo/zod-types check-types
corepack pnpm --filter backend exec tsc --noEmit
```

Expected: all commands exit 0.

- [ ] **Step 12: Commit Task 1**

```powershell
git add packages/zod-types/src/oauth.zod.ts apps/backend/src/db/schema.ts apps/backend/drizzle apps/backend/src/db/repositories/oauth-sessions.repo.ts apps/backend/src/db/repositories/__tests__/oauth-sessions.repo.test.ts packages/trpc/src/routers/frontend/oauth.ts apps/backend/src/trpc/oauth.impl.ts apps/backend/src/trpc/oauth.impl.test.ts apps/backend/src/lib/oauth-upstream/provider.ts apps/backend/src/lib/oauth-upstream/provider.test.ts
git commit -m "feat: isolate upstream OAuth sessions by user"
```

---

### Task 2: Propagate the OAuth Principal Through Runtime Connections

**Files:**
- Modify: `packages/zod-types/src/metamcp.zod.ts`
- Modify: `apps/backend/src/lib/metamcp/fetch-metamcp.ts`
- Modify: `apps/backend/src/lib/metamcp/fetch-metamcp.test.ts`
- Modify: `apps/backend/src/lib/metamcp/utils.ts`
- Modify: `apps/backend/src/lib/metamcp/utils.test.ts`
- Modify: `apps/backend/src/lib/metamcp/client.ts`
- Modify: `apps/backend/src/lib/metamcp/client.test.ts`
- Modify: `apps/backend/src/lib/oauth-upstream/refresh-on-401.ts`
- Modify: `apps/backend/src/lib/oauth-upstream/refresh-on-401.test.ts`
- Modify: `apps/backend/src/lib/metamcp/mcp-server-pool.ts`

**Interfaces:**
- Adds `oauth_user_id?: string` to `ServerParameters`.
- `getMcpServers(namespaceUuid)` selects `oauth_user_id = namespace.user_id ?? server.user_id` and loads only that principal's tokens.
- `tryRefreshUpstreamTokens(serverParams)` keys repository access and its mutex by `serverParams.oauth_user_id` plus server UUID.
- A server without an OAuth principal has `oauth_tokens: null` and cannot refresh.

- [ ] **Step 1: Write failing namespace-principal tests**

Extend `fetch-metamcp.test.ts` with a public server mapped into two user-owned namespaces. Mock joined rows so each namespace has a different `namespace_user_id`; assert each call loads only that user's session.

```ts
expect(findByMcpServerAndUser).toHaveBeenCalledWith(SERVER_UUID, "namespace-owner-a");
expect(result[SERVER_UUID].oauth_user_id).toBe("namespace-owner-a");
```

Also test that a public namespace plus public server yields no OAuth lookup and `oauth_tokens: null`.

- [ ] **Step 2: Run fetch tests red**

Run: `corepack pnpm --filter backend exec vitest run src/lib/metamcp/fetch-metamcp.test.ts`

Expected: FAIL because the namespace owner is not joined and token lookup is server-only.

- [ ] **Step 3: Resolve and carry the principal in `getMcpServers`**

Join `namespacesTable`, select both namespace and server owners, and resolve:

```ts
const oauthUserId = server.namespace_user_id ?? server.server_user_id ?? undefined;
const oauthSession = oauthUserId
  ? await oauthSessionsRepository.findByMcpServerAndUser(server.uuid, oauthUserId)
  : undefined;
```

Store `oauth_user_id: oauthUserId` on `ServerParameters`.

- [ ] **Step 4: Define direct-server conversion behavior**

Write failing `utils.test.ts` cases asserting `convertDbServerToParams(privateServer)` uses `server.user_id`, while a public server with no caller principal receives no OAuth tokens. Update the function accordingly; do not guess the current logged-in user from global state.

- [ ] **Step 5: Write failing per-principal refresh tests**

Add tests that two users refreshing the same server use separate repository rows and separate in-flight promises, while duplicate refreshes for the same pair coalesce.

```ts
await Promise.all([
  tryRefreshUpstreamTokens({ ...SERVER, oauth_user_id: "user-a" }),
  tryRefreshUpstreamTokens({ ...SERVER, oauth_user_id: "user-b" }),
]);
expect(fetchImpl).toHaveBeenCalledTimes(2);
```

- [ ] **Step 6: Run refresh and client tests red**

Run: `corepack pnpm --filter backend exec vitest run src/lib/oauth-upstream/refresh-on-401.test.ts src/lib/metamcp/client.test.ts src/lib/metamcp/utils.test.ts`

Expected: FAIL because refresh lookup and mutex currently use only server UUID.

- [ ] **Step 7: Scope refresh and pool cache behavior**

Require `oauth_user_id` before token refresh, use `${serverParams.uuid}:${serverParams.oauth_user_id}` as the mutex key, and use the composite repository key. Ensure cached parameters retain `oauth_user_id` whenever the pool updates tokens in place.

- [ ] **Step 8: Run Task 2 verification**

Run:

```powershell
corepack pnpm --filter backend exec vitest run src/lib/metamcp/fetch-metamcp.test.ts src/lib/metamcp/utils.test.ts src/lib/metamcp/client.test.ts src/lib/oauth-upstream/refresh-on-401.test.ts
corepack pnpm --filter @repo/zod-types check-types
corepack pnpm --filter backend exec tsc --noEmit
```

Expected: all commands exit 0, including two-user public-server coverage.

- [ ] **Step 9: Commit Task 2**

```powershell
git add packages/zod-types/src/metamcp.zod.ts apps/backend/src/lib/metamcp/fetch-metamcp.ts apps/backend/src/lib/metamcp/fetch-metamcp.test.ts apps/backend/src/lib/metamcp/utils.ts apps/backend/src/lib/metamcp/utils.test.ts apps/backend/src/lib/metamcp/client.ts apps/backend/src/lib/metamcp/client.test.ts apps/backend/src/lib/oauth-upstream/refresh-on-401.ts apps/backend/src/lib/oauth-upstream/refresh-on-401.test.ts apps/backend/src/lib/metamcp/mcp-server-pool.ts
git commit -m "feat: scope upstream OAuth runtime tokens by principal"
```

---

### Task 3: Persist Discovery, Propagate RFC 8707 Resource, and Make State Self-Identifying

**Files:**
- Modify: `packages/zod-types/src/oauth.zod.ts`
- Modify: `apps/backend/src/lib/oauth-upstream/provider.ts`
- Modify: `apps/backend/src/lib/oauth-upstream/provider.test.ts`
- Create: `apps/backend/src/lib/oauth-upstream/state.ts`
- Create: `apps/backend/src/lib/oauth-upstream/state.test.ts`
- Modify: `apps/backend/src/lib/oauth-upstream/token-exchange.ts`
- Modify: `apps/backend/src/lib/oauth-upstream/token-exchange.test.ts`
- Modify: `apps/backend/src/lib/oauth-upstream/refresh-on-401.ts`
- Modify: `apps/backend/src/lib/oauth-upstream/refresh-on-401.test.ts`
- Modify: `apps/backend/src/trpc/oauth.impl.ts`
- Modify: `apps/backend/src/trpc/oauth.impl.test.ts`
- Modify: `apps/backend/src/trpc/oauth-request-schema.test.ts`

**Interfaces:**
- Produces `createUpstreamState(mcpServerUuid: string): string` and `parseUpstreamState(state: string): string | null` using `upstream.{uuid}.{base64url-nonce}`.
- Changes exchange input to `{ code: string; state: string }`; UUID is derived server-side only after exact expected-state verification.
- Successful exchange returns `{ success: true, data: { mcp_server_uuid: string }, message: string }`.
- Adds `resource?: string | URL` to exchange and refresh helpers.
- Provider implements `saveDiscoveryState(state)` and returns persisted state from `discoveryState()`.

- [ ] **Step 1: Write failing opaque-state tests**

Test valid creation/parsing, malformed prefix, invalid UUID, missing nonce, short nonce, and exact round trip. The candidate UUID is routing information only; tests in `oauth.impl.test.ts` must prove no fetch occurs until the full state matches the stored value for the authenticated user.

- [ ] **Step 2: Run state and request-schema tests red**

Run: `corepack pnpm --filter backend exec vitest run src/lib/oauth-upstream/state.test.ts src/trpc/oauth-request-schema.test.ts`

Expected: FAIL because the helper does not exist and exchange still requires `mcp_server_uuid` while allowing optional state.

- [ ] **Step 3: Implement self-identifying state and contracts**

Generate 32 random bytes and encode base64url:

```ts
export function createUpstreamState(mcpServerUuid: string): string {
  return `upstream.${mcpServerUuid}.${randomBytes(32).toString("base64url")}`;
}
```

Make `state` required, remove `mcp_server_uuid` from `ExchangeOAuthTokenRequestSchema`, and add the success data UUID.

- [ ] **Step 4: Write failing discovery persistence tests**

Test that `saveDiscoveryState` persists the full SDK object under the composite key, `discoveryState` reloads it, and complete pre-registered endpoints take precedence. Remove the custom `validateResourceURL(): undefined` and test that incompatible protected-resource metadata causes the SDK flow to fail.

- [ ] **Step 5: Implement provider discovery persistence**

Add:

```ts
async saveDiscoveryState(state: OAuthDiscoveryState): Promise<void> {
  await repo.upsert({
    mcp_server_uuid: this.mcpServerUuid,
    user_id: this.userId,
    discovery_state: state as unknown as Record<string, unknown>,
  });
}
```

Return complete pre-registered metadata first, then persisted discovery state, then `undefined`. Let the MCP SDK's default `selectResourceURL` validation run by omitting `validateResourceURL`.

- [ ] **Step 6: Write failing resource form tests**

Add one exchange test and one refresh test asserting `resource=https%3A%2F%2Fresource.example%2Fmcp` is present when supplied and absent when omitted.

- [ ] **Step 7: Extend token exchange and refresh inputs**

Add `resource?: string | URL` and set it on `URLSearchParams` for both grant types:

```ts
if (resource) params.set("resource", String(resource));
```

- [ ] **Step 8: Write failing separate-authorization-server integration tests**

In `oauth.impl.test.ts`, persist discovery state containing a resource server, a distinct `authorizationServerUrl`, metadata with a distinct HTTPS `token_endpoint`, and protected-resource metadata. Assert exchange and refresh post only to that token endpoint and send the persisted resource. Add corrupted-state and non-HTTP endpoint cases that fail before any outbound fetch.

- [ ] **Step 9: Implement discovery-consistent exchange and refresh**

Resolve token endpoint in this order: pre-registered endpoint; persisted `authorizationServerMetadata.token_endpoint`; fallback `/token` relative to persisted `authorizationServerUrl`. Use the persisted protected-resource metadata with MCP SDK `selectResourceURL`. Do not rediscover from the resource origin during exchange or refresh when persisted discovery is present.

- [ ] **Step 10: Implement state-derived exchange and replay prevention**

Parse the candidate UUID, verify access, load the caller's composite session, compare exact state in constant time where lengths match, and only then exchange. Clear `expected_state` on success. Preserve it for retryable upstream failures; clear it for invalid-grant or another terminal authorization error. Replay after a successful exchange must return `invalid_state` without a token request.

- [ ] **Step 11: Run Task 3 verification**

Run:

```powershell
corepack pnpm --filter backend exec vitest run src/lib/oauth-upstream/state.test.ts src/lib/oauth-upstream/provider.test.ts src/lib/oauth-upstream/token-exchange.test.ts src/lib/oauth-upstream/refresh-on-401.test.ts src/trpc/oauth.impl.test.ts src/trpc/oauth-request-schema.test.ts
corepack pnpm --filter backend exec tsc --noEmit
```

Expected: all commands exit 0; authorize, exchange, and refresh use one persisted authorization server and resource.

- [ ] **Step 12: Commit Task 3**

```powershell
git add packages/zod-types/src/oauth.zod.ts apps/backend/src/lib/oauth-upstream/provider.ts apps/backend/src/lib/oauth-upstream/provider.test.ts apps/backend/src/lib/oauth-upstream/state.ts apps/backend/src/lib/oauth-upstream/state.test.ts apps/backend/src/lib/oauth-upstream/token-exchange.ts apps/backend/src/lib/oauth-upstream/token-exchange.test.ts apps/backend/src/lib/oauth-upstream/refresh-on-401.ts apps/backend/src/lib/oauth-upstream/refresh-on-401.test.ts apps/backend/src/trpc/oauth.impl.ts apps/backend/src/trpc/oauth.impl.test.ts apps/backend/src/trpc/oauth-request-schema.test.ts
git commit -m "feat: persist upstream OAuth discovery state"
```

---

### Task 4: Unify Frontend Authorization and Remove Callback Storage Authority

**Files:**
- Create: `apps/frontend/lib/oauth-authorization.ts`
- Create: `apps/frontend/lib/oauth-authorization.test.ts`
- Create: `apps/frontend/lib/oauth-callback.ts`
- Create: `apps/frontend/lib/oauth-callback.test.ts`
- Modify: `apps/frontend/hooks/useConnection.ts`
- Modify: `apps/frontend/app/[locale]/(sidebar)/mcp-servers/[uuid]/page.tsx`
- Modify: `apps/frontend/components/OAuthCallback.tsx`
- Modify: `apps/frontend/lib/oauth-provider.ts`
- Modify: `apps/frontend/package.json`
- Modify: `apps/frontend/public/locales/es/common.json`
- Modify: `apps/frontend/public/locales/es/mcp-servers.json`
- Modify: `apps/frontend/public/locales/ko/common.json`
- Modify: `apps/frontend/public/locales/ko/mcp-servers.json`
- Modify: `apps/frontend/public/locales/pt/common.json`
- Modify: `apps/frontend/public/locales/pt/mcp-servers.json`
- Modify: `apps/frontend/public/locales/zh/common.json`
- Modify: `apps/frontend/public/locales/zh/mcp-servers.json`
- Modify: `README-oauth.md`

**Interfaces:**
- Produces `beginUpstreamAuthorization(mcpServerUuid, start, navigate): Promise<void>`.
- Produces `parseOAuthCallback(search: string)` returning either an upstream error or required `{ code, state }`.
- Callback calls `exchangeToken({ code, state })` and redirects using the returned `data.mcp_server_uuid`.
- `useConnection` uses backend authorization only when `!isMetaMCP`; namespace/downstream authentication behavior remains separate.

- [ ] **Step 1: Add the frontend Vitest script and failing pure-helper tests**

Add `"test": "vitest run"` to `apps/frontend/package.json`. Reuse workspace Vitest; pure helpers require no DOM environment. Test successful navigation, typed failure, no navigation on failure, and no `sessionStorage` access.

```ts
await beginUpstreamAuthorization(SERVER, start, navigate);
expect(start).toHaveBeenCalledWith({ mcp_server_uuid: SERVER });
expect(navigate).toHaveBeenCalledWith("https://auth.example/authorize");
```

- [ ] **Step 2: Run helper tests red**

Run: `corepack pnpm --filter frontend test -- lib/oauth-authorization.test.ts lib/oauth-callback.test.ts`

Expected: FAIL because the helper modules do not exist.

- [ ] **Step 3: Implement authorization and callback helpers**

`beginUpstreamAuthorization` accepts injected mutation/navigation functions, validates the result, and throws a sanitized error using `error` plus `error_description`. `parseOAuthCallback` requires both code and an `upstream.` state, surfaces upstream error fields, and ignores unrelated query parameters.

- [ ] **Step 4: Replace duplicate manual authorization logic**

In the detail page, call the shared helper with `startAuthorization.mutateAsync` and `window.location.assign`. Remove writes of `SERVER_URL` and `MCP_SERVER_UUID` from this flow.

- [ ] **Step 5: Write and verify an automatic-401 regression test**

Extract the upstream decision into a pure function if needed and test:

```ts
expect(shouldStartUpstreamOAuth({ is401: true, isMetaMCP: false })).toBe(true);
expect(shouldStartUpstreamOAuth({ is401: true, isMetaMCP: true })).toBe(false);
expect(shouldStartUpstreamOAuth({ is401: false, isMetaMCP: false })).toBe(false);
```

Run the test before updating `useConnection` and confirm the old browser SDK path does not satisfy it.

- [ ] **Step 6: Route upstream 401 recovery through the backend**

For upstream connections only, invoke the shared start helper and stop reconnecting after navigation begins. Preserve the existing MetaMCP/namespace branch because its UUID is a namespace UUID, not an MCP server UUID. Prevent concurrent 401 handlers from launching multiple authorization flows.

- [ ] **Step 7: Make the callback storage-independent**

Parse only `code`, `state`, and provider error fields. Call:

```ts
const result = await vanillaTrpcClient.frontend.oauth.exchangeToken.mutate({ code, state });
window.location.assign(`/mcp-servers/${result.data.mcp_server_uuid}`);
```

Do not read or require server UUID, server URL, tokens, client information, or verifier from storage. Retain loopback origin bounce with the complete query string. Keep the Strict Mode one-shot guard.

- [ ] **Step 8: Retire browser-side upstream discovery responsibilities**

Remove active upstream calls to MCP SDK `auth()` and remove tRPC `get/upsert` use from the browser provider wherever no downstream compatibility path needs them. Do not delete downstream OAuth support. Verify that no new callback code logs secrets or raw URLs.

- [ ] **Step 9: Complete locale parity**

Add translated equivalents of `common.oauth.callbackFailedTitle`, `common.oauth.backToMcpServers`, detail authorize states, validation messages, and `advancedOAuth` labels/help to Spanish, Korean, Portuguese, and Chinese. Add a pure recursive-key parity test for these three subtrees against English.

- [ ] **Step 10: Update OAuth documentation**

Document per-user sessions, backend discovery/DCR, separate authorization servers, resource indicators, storage-independent callbacks, public-server behavior, private-network trust, loopback workflow, and reauthorization behavior. Remove claims that merely loading an URL from the database prevents SSRF.

- [ ] **Step 11: Run Task 4 verification**

Run:

```powershell
corepack pnpm --filter frontend test
corepack pnpm --filter frontend check-types
corepack pnpm --filter frontend build
```

Expected: all commands exit 0; callback tests pass with empty storage and namespace connections do not call upstream authorization.

- [ ] **Step 12: Commit Task 4**

```powershell
git add apps/frontend/lib/oauth-authorization.ts apps/frontend/lib/oauth-authorization.test.ts apps/frontend/lib/oauth-callback.ts apps/frontend/lib/oauth-callback.test.ts apps/frontend/hooks/useConnection.ts 'apps/frontend/app/[locale]/(sidebar)/mcp-servers/[uuid]/page.tsx' apps/frontend/components/OAuthCallback.tsx apps/frontend/lib/oauth-provider.ts apps/frontend/package.json apps/frontend/public/locales README-oauth.md
git commit -m "feat: unify upstream OAuth browser flow"
```

---

### Task 5: Integration Verification and Release Artifact

**Files:**
- Modify only files required to repair failures exposed by the complete verification matrix.
- Do not add unrelated refactors or dependencies.

**Interfaces:**
- Consumes all contracts from Tasks 1-4.
- Produces a clean verified commit suitable for immutable Docker tagging.

- [ ] **Step 1: Run the complete backend suite**

Run: `corepack pnpm --filter backend test`

Expected: all backend test files pass with zero failures.

- [ ] **Step 2: Run workspace static verification**

Run:

```powershell
corepack pnpm check-types
corepack pnpm lint
git diff --check HEAD~4..HEAD
```

Expected: all commands exit 0 and lint emits no warnings.

- [ ] **Step 3: Run the production build**

Run: `corepack pnpm build`

Expected: Turbo reports successful backend, frontend, shared-contract, and package builds.

- [ ] **Step 4: Validate migration artifacts**

Run:

```powershell
corepack pnpm --filter backend exec drizzle-kit check
rg -n 'user_id|discovery_state|oauth_sessions_unique_per_server_user_idx' apps/backend/drizzle/0020_user_scoped_oauth.sql apps/backend/drizzle/meta/0020_snapshot.json
```

Expected: Drizzle check exits 0 and the generated migration/snapshot contain the composite key and new fields.

- [ ] **Step 5: Build the immutable local image**

Run:

```powershell
$releaseSha = git rev-parse HEAD
docker build --label "org.opencontainers.image.revision=$releaseSha" -t "metamcp-oauth:$releaseSha" .
docker image inspect "metamcp-oauth:$releaseSha" --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}}'
```

Expected: build exits 0 and the image label exactly matches the full commit SHA.

- [ ] **Step 6: Run the container smoke test**

Use `docker-compose.test.yml` or an isolated Compose project with a disposable PostgreSQL volume. Start the image, wait for health, confirm migration success in logs, call `http://127.0.0.1:12008/health`, and stop only the disposable project. Never point this smoke test at Mimir's volume.

- [ ] **Step 7: Fix failures through TDD and rerun the entire matrix**

For every functional failure, first add or tighten a focused failing regression test, make the smallest repair, and rerun Steps 1-6. Do not call the branch verified until every command has fresh exit-0 evidence.

- [ ] **Step 8: Commit verification repairs if any**

```powershell
git add apps/backend apps/frontend packages README-oauth.md pnpm-lock.yaml
git commit -m "fix: complete upstream OAuth integration"
```

Skip this commit only when Steps 1-6 required no file changes.

---

## Post-Implementation Release Operations

These operations happen only after independent whole-branch review and fresh verification.

1. Push branch `ai-dev` to `origin` and confirm the remote SHA equals local `HEAD`.
2. Connect using `ssh -p 2222 fabrimat@mimir.larosa.work`.
3. Inspect user, architecture, Docker/Compose versions, active MetaMCP container, Compose working directory/config files, image ID/digest, and disk usage. Do not print the expanded Compose configuration or environment values.
4. From the discovered Compose directory, create a timestamped PostgreSQL custom-format dump with `docker compose exec -T postgres ... pg_dump ... -Fc`, verify it is non-empty, and record its SHA-256.
5. Tag the current application image `metamcp-rollback:{UTC-timestamp}` and verify the tag resolves to the recorded image ID.
6. Build `metamcp-oauth:{full-release-SHA}` from a clean checkout on Mimir when architecture/resources permit. Otherwise transfer an image archive built for Mimir's architecture using the approved SCP/SSH channel.
7. Inspect any existing `docker-compose.override.yml`. Merge only the application image override and `pull_policy: never`; do not overwrite unrelated settings.
8. Validate image selection with `docker compose ... config --images`, recreate only `app` using `--no-deps --force-recreate --pull never --wait --wait-timeout 180`, and inspect migration/application logs.
9. Verify container health, `curl -fsS http://127.0.0.1:12008/health`, the new schema columns, login, MCP server listing, and a real upstream OAuth authorize/callback/token-use flow.
10. On application failure, point the override to the rollback tag and recreate only `app`. Leave additive columns in place; restore the database dump only for demonstrated data damage.
