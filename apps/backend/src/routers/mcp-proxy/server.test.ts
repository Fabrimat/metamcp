import type { Request } from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../db/index", () => ({ db: {}, pool: {} }));
vi.mock("../../db/repositories", () => ({
  mcpServersRepository: { findByUuid: vi.fn(), findAll: vi.fn() },
  oauthSessionsRepository: {
    findByMcpServerAndUser: vi.fn(),
    upsert: vi.fn(),
    compareAndSetExpectedState: vi.fn(),
  },
}));
vi.mock("../../middleware/better-auth-mcp.middleware", () => ({
  betterAuthMcpMiddleware: vi.fn(),
}));
vi.mock("../../lib/metamcp/mcp-server-pool", () => ({ mcpServerPool: {} }));
vi.mock("../../utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import {
  mcpServersRepository,
  oauthSessionsRepository,
} from "../../db/repositories";
import { oauthImplementations } from "../../trpc/oauth.impl";
import { createTransport } from "./server";

const uuid = "00000000-0000-4000-8000-000000000003";

describe("direct Inspector proxy persisted OAuth", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    process.env.APP_URL = "https://metamcp.example";
  });
  afterEach(() => vi.restoreAllMocks());

  it.each(["SSE", "STREAMABLE_HTTP"] as const)(
    "connects %s after authorize/callback with only the authenticated user's persisted token",
    async (type) => {
      const server = {
        uuid,
        name: "public",
        type,
        user_id: null,
        url: "https://mcp.example/mcp",
        headers: {},
        redirect_uri: null,
      };
      const session: Record<string, unknown> = {
        client_information: {
          client_id: "manual",
          authorization_endpoint: "https://as.example/authorize",
          token_endpoint: "https://as.example/token",
          redirect_uris: ["https://metamcp.example/fe-oauth/callback"],
        },
      };
      vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(
        server as never,
      );
      vi.mocked(mcpServersRepository.findAll).mockResolvedValue([
        server,
      ] as never);
      vi.mocked(
        oauthSessionsRepository.findByMcpServerAndUser,
      ).mockImplementation(
        async (_server, user) =>
          (user === "user-a"
            ? { ...session }
            : {
                tokens: { access_token: "OTHER_USER", token_type: "Bearer" },
              }) as never,
      );
      vi.mocked(oauthSessionsRepository.upsert).mockImplementation(
        async (input) => {
          Object.assign(session, input);
          return session as never;
        },
      );
      vi.mocked(
        oauthSessionsRepository.compareAndSetExpectedState,
      ).mockImplementation(async (_server, user, expected, next) => {
        if (user !== "user-a" || session.expected_state !== expected)
          return false;
        session.expected_state = next;
        return true;
      });
      const observed: string[] = [];
      const resourceUrls: string[] = [];
      let rejectNext = false;
      let refreshCount = 0;
      vi.spyOn(globalThis, "fetch").mockImplementation(async (url, init) => {
        if (String(url).includes(".well-known"))
          return new Response("missing", { status: 404 });
        if (String(url) === "https://as.example/token") {
          const refreshing =
            (init?.body as URLSearchParams).get("grant_type") ===
            "refresh_token";
          if (refreshing) refreshCount++;
          return Response.json({
            access_token: refreshing ? "ROTATED" : "PERSISTED",
            refresh_token: "RT",
            token_type: "Bearer",
          });
        }
        observed.push(
          new Headers(init?.headers).get("authorization") ?? "missing",
        );
        resourceUrls.push(String(url));
        if (rejectNext) {
          rejectNext = false;
          return new Response(null, { status: 401 });
        }
        if (type === "SSE" && (!init?.method || init.method === "GET"))
          return new Response(
            new ReadableStream({
              start(controller) {
                controller.enqueue(
                  new TextEncoder().encode(
                    "event: endpoint\ndata: /messages\n\n",
                  ),
                );
              },
            }),
            { headers: { "content-type": "text/event-stream" } },
          );
        return new Response(null, { status: 202 });
      });
      const started = await oauthImplementations.startAuthorization(
        { mcp_server_uuid: uuid },
        "user-a",
      );
      if (!started.success) throw new Error("authorize failed");
      const state = new URL(started.data.authorization_url).searchParams.get(
        "state",
      );
      if (!state) throw new Error("Authorization state missing");
      expect(
        await oauthImplementations.exchangeToken(
          { code: "CODE", state },
          "user-a",
        ),
      ).toMatchObject({ success: true });
      const transport = await createTransport({
        user: { id: "user-a" },
        query: {
          transportType: type,
          mcp_server_uuid: uuid,
          url: "https://attacker.example/mcp",
        },
        headers: { authorization: "Bearer BROWSER_TOKEN" },
      } as unknown as Request);
      try {
        await transport.send({
          jsonrpc: "2.0",
          method: "notifications/tools/list_changed",
        });
        expect(observed.length).toBeGreaterThan(0);
        expect(observed.every((header) => header === "Bearer PERSISTED")).toBe(
          true,
        );
        rejectNext = true;
        await transport.send({
          jsonrpc: "2.0",
          method: "notifications/tools/list_changed",
        });
        expect(observed.at(-1)).toBe("Bearer ROTATED");
        expect(refreshCount).toBe(1);
        expect(
          resourceUrls.every(
            (value) => new URL(value).origin === "https://mcp.example",
          ),
        ).toBe(true);
      } finally {
        await transport.close();
      }
    },
  );

  it.each([undefined, "other-user"])(
    "denies missing/wrong authenticated identity %s before loading credentials",
    async (userId) => {
      vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue({
        uuid,
        user_id: "owner",
        type: "SSE",
        url: "https://mcp.example/sse",
      } as never);
      await expect(
        createTransport({
          user: userId ? { id: userId } : undefined,
          query: { transportType: "SSE", mcp_server_uuid: uuid },
        } as unknown as Request),
      ).rejects.toThrow();
      expect(
        oauthSessionsRepository.findByMcpServerAndUser,
      ).not.toHaveBeenCalled();
    },
  );
});
