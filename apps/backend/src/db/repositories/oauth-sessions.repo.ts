import {
  DatabaseOAuthSession,
  OAuthSessionCreateInput,
  OAuthSessionUpdateInput,
} from "@repo/zod-types";
import { and, eq, sql } from "drizzle-orm";

import { isManualOAuthClient } from "../../lib/oauth-upstream/client-registration";
import { db } from "../index";
import { oauthSessionsTable } from "../schema";

export class OAuthSessionsRepository {
  async invalidateRedirectDependentSessions(
    mcpServerUuid: string,
    redirectUri: string,
  ): Promise<void> {
    const sessions = await db
      .select()
      .from(oauthSessionsTable)
      .where(eq(oauthSessionsTable.mcp_server_uuid, mcpServerUuid));
    for (const session of sessions) {
      const client = session.client_information as Record<
        string,
        unknown
      > | null;
      await db
        .update(oauthSessionsTable)
        .set({
          client_information: isManualOAuthClient(client)
            ? ({
                ...client,
                redirect_uris: [redirectUri],
              } as unknown as typeof session.client_information)
            : ({} as typeof session.client_information),
          tokens: null,
          code_verifier: null,
          expected_state: null,
          discovery_state: null,
          updated_at: sql`NOW()`,
        })
        .where(
          and(
            eq(oauthSessionsTable.mcp_server_uuid, mcpServerUuid),
            eq(oauthSessionsTable.user_id, session.user_id),
          ),
        )
        .returning();
    }
  }

  async findByMcpServerAndUser(
    mcpServerUuid: string,
    userId: string,
  ): Promise<DatabaseOAuthSession | undefined> {
    const [session] = await db
      .select()
      .from(oauthSessionsTable)
      .where(
        and(
          eq(oauthSessionsTable.mcp_server_uuid, mcpServerUuid),
          eq(oauthSessionsTable.user_id, userId),
        ),
      )
      .limit(1);

    return session;
  }

  async create(input: OAuthSessionCreateInput): Promise<DatabaseOAuthSession> {
    const [createdSession] = await db
      .insert(oauthSessionsTable)
      .values({
        mcp_server_uuid: input.mcp_server_uuid,
        user_id: input.user_id,
        ...(input.client_information && {
          client_information: input.client_information,
        }),
        ...(input.tokens && { tokens: input.tokens }),
        ...(input.code_verifier && { code_verifier: input.code_verifier }),
        ...(input.expected_state && {
          expected_state: input.expected_state,
        }),
        ...(input.discovery_state && {
          discovery_state: input.discovery_state,
        }),
      })
      .returning();

    return createdSession;
  }

  async update(
    input: OAuthSessionUpdateInput,
  ): Promise<DatabaseOAuthSession | undefined> {
    const [updatedSession] = await db
      .update(oauthSessionsTable)
      .set({
        ...(input.client_information && {
          client_information: input.client_information,
        }),
        ...(input.tokens && { tokens: input.tokens }),
        ...(input.code_verifier && { code_verifier: input.code_verifier }),
        ...(input.expected_state && {
          expected_state: input.expected_state,
        }),
        ...(input.discovery_state && {
          discovery_state: input.discovery_state,
        }),
        updated_at: sql`NOW()`,
      })
      .where(
        and(
          eq(oauthSessionsTable.mcp_server_uuid, input.mcp_server_uuid),
          eq(oauthSessionsTable.user_id, input.user_id),
        ),
      )
      .returning();

    return updatedSession;
  }

  // Explicit unconditional reset for session maintenance. Callback exchange
  // must use compareAndSetExpectedState so it cannot clear a newer attempt.
  async clearExpectedState(
    mcpServerUuid: string,
    userId: string,
  ): Promise<DatabaseOAuthSession | undefined> {
    const [updatedSession] = await db
      .update(oauthSessionsTable)
      .set({
        expected_state: null,
        updated_at: sql`NOW()`,
      })
      .where(
        and(
          eq(oauthSessionsTable.mcp_server_uuid, mcpServerUuid),
          eq(oauthSessionsTable.user_id, userId),
        ),
      )
      .returning();

    return updatedSession;
  }

  // Atomic claim/consume/restore for one authorization attempt. Matching the
  // previous value prevents competing callbacks or a newer authorize flow
  // from being overwritten by a stale request.
  async compareAndSetExpectedState(
    mcpServerUuid: string,
    userId: string,
    expectedState: string,
    nextState: string | null,
  ): Promise<boolean> {
    const [updatedSession] = await db
      .update(oauthSessionsTable)
      .set({ expected_state: nextState, updated_at: sql`NOW()` })
      .where(
        and(
          eq(oauthSessionsTable.mcp_server_uuid, mcpServerUuid),
          eq(oauthSessionsTable.user_id, userId),
          eq(oauthSessionsTable.expected_state, expectedState),
        ),
      )
      .returning();
    return Boolean(updatedSession);
  }

  async upsert(input: OAuthSessionUpdateInput): Promise<DatabaseOAuthSession> {
    // Single-statement atomic upsert. Concurrent callers for the same
    // mcp_server_uuid resolve via ON CONFLICT instead of racing a
    // SELECT-then-INSERT, which previously crashed the loser with a
    // unique-constraint violation. Only fields present on `input` are written
    // so a partial update (e.g. tokens only) does not clear unrelated columns
    // such as code_verifier.
    const [row] = await db
      .insert(oauthSessionsTable)
      .values({
        mcp_server_uuid: input.mcp_server_uuid,
        user_id: input.user_id,
        ...(input.client_information && {
          client_information: input.client_information,
        }),
        ...(input.tokens && { tokens: input.tokens }),
        ...(input.code_verifier && { code_verifier: input.code_verifier }),
        ...(input.expected_state && {
          expected_state: input.expected_state,
        }),
        ...(input.discovery_state && {
          discovery_state: input.discovery_state,
        }),
      })
      .onConflictDoUpdate({
        target: [
          oauthSessionsTable.mcp_server_uuid,
          oauthSessionsTable.user_id,
        ],
        set: {
          ...(input.client_information && {
            client_information: input.client_information,
          }),
          ...(input.tokens && { tokens: input.tokens }),
          ...(input.code_verifier && { code_verifier: input.code_verifier }),
          ...(input.expected_state && {
            expected_state: input.expected_state,
          }),
          ...(input.discovery_state && {
            discovery_state: input.discovery_state,
          }),
          updated_at: sql`NOW()`,
        },
      })
      .returning();

    if (!row) {
      throw new Error("Failed to upsert OAuth session");
    }

    return row;
  }

  async deleteByMcpServerAndUser(
    mcpServerUuid: string,
    userId: string,
  ): Promise<DatabaseOAuthSession | undefined> {
    const [deletedSession] = await db
      .delete(oauthSessionsTable)
      .where(
        and(
          eq(oauthSessionsTable.mcp_server_uuid, mcpServerUuid),
          eq(oauthSessionsTable.user_id, userId),
        ),
      )
      .returning();

    return deletedSession;
  }
}

export const oauthSessionsRepository = new OAuthSessionsRepository();
