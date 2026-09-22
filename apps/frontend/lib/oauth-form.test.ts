import { createServerFormSchema, EditServerFormSchema } from "@repo/zod-types";
import { describe, expect, it } from "vitest";

import { oauthCreatePayload, oauthEditPayload } from "./oauth-form";

describe("OAuth form submissions", () => {
  it("submits only the redirect when editing a prefilled client", () => {
    expect(
      oauthEditPayload(
        {
          type: "SSE",
          oauth_client_id: "dynamic-client",
          oauth_redirect_uri: "http://localhost:4001/callback",
        },
        { oauth_redirect_uri: true },
      ),
    ).toEqual({ redirect_uri: "http://localhost:4001/callback" });
  });
  it("represents clearing the redirect explicitly without clearing manual configuration", () => {
    expect(
      oauthEditPayload(
        {
          type: "STREAMABLE_HTTP",
          oauth_client_id: "manual",
          oauth_client_secret: "secret",
          oauth_redirect_uri: "",
        },
        { oauth_redirect_uri: true },
      ),
    ).toEqual({ redirect_uri: "" });
  });
  it("preserves manually configured credentials and endpoints when editing the client", () => {
    expect(
      oauthEditPayload(
        {
          type: "SSE",
          oauth_client_id: "manual",
          oauth_client_secret: "secret",
          oauth_authorization_endpoint: "https://as.example/authorize",
          oauth_token_endpoint: "https://as.example/token",
          oauth_redirect_uri: "http://localhost/callback",
        },
        { oauth_scope: true },
      ),
    ).toMatchObject({
      confirm_client_information: true,
      client_id: "manual",
      client_secret: "secret",
      authorization_endpoint: "https://as.example/authorize",
      token_endpoint: "https://as.example/token",
      redirect_uri: "http://localhost/callback",
    });
  });
  it("preserves explicit client clearing", () => {
    expect(
      oauthEditPayload(
        { type: "SSE", oauth_client_id: "" },
        { oauth_client_id: true },
      ),
    ).toMatchObject({ client_id: "", confirm_client_information: true });
  });
  it("confirms a client id entered while creating an HTTP server", () => {
    expect(
      oauthCreatePayload({
        type: "SSE",
        oauth_client_id: " manual-client ",
      }),
    ).toMatchObject({
      client_id: "manual-client",
      confirm_client_information: true,
    });
  });
  it("does not claim confirmation for a redirect-only create", () => {
    expect(
      oauthCreatePayload({
        type: "STREAMABLE_HTTP",
        oauth_redirect_uri: "http://localhost/callback",
      }),
    ).toEqual({
      redirect_uri: "http://localhost/callback",
    });
  });
  it.each([createServerFormSchema, EditServerFormSchema])(
    "accepts redirect-only HTTP form data",
    (schema) => {
      expect(
        schema.safeParse({
          name: "server",
          type: "SSE",
          url: "https://mcp.example/sse",
          oauth_redirect_uri: "http://localhost/callback",
        }).success,
      ).toBe(true);
    },
  );
});
