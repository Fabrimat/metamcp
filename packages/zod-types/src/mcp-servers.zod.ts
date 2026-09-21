import { z } from "zod";

export const McpServerTypeEnum = z.enum(["STDIO", "SSE", "STREAMABLE_HTTP"]);
export const McpServerStatusEnum = z.enum(["ACTIVE", "INACTIVE"]);

export const McpServerErrorStatusEnum = z.enum(["NONE", "ERROR"]);

/**
 * RFC 7230 token characters for HTTP header field names.
 * Valid: letters, digits, and !#$%&'*+-.^_`|~
 */
const HTTP_HEADER_NAME_REGEX = /^[a-zA-Z0-9!#$%&'*+\-.^_`|~]+$/;

/**
 * Headers that must never be forwarded to backend servers.
 * Shared between Zod validation (reject at save time) and runtime filtering.
 */
export const DENIED_FORWARD_HEADERS = new Set([
  "host",
  "cookie",
  "set-cookie",
  "connection",
  "transfer-encoding",
  "content-length",
  "content-encoding",
  "te",
  "trailer",
  "upgrade",
  "keep-alive",
  "proxy-authorization",
  "proxy-authenticate",
  "proxy-connection",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-real-ip",
  "mcp-session-id",
]);

/**
 * Header name prefixes that are always denied.
 * - `proxy-` covers all proxy-related headers
 * - `sec-` covers browser-controlled Fetch Metadata headers
 */
export const DENIED_HEADER_PREFIXES = ["proxy-", "sec-"];

/** Check whether a header name is denied (exact or prefix match) */
function isDeniedHeader(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    DENIED_FORWARD_HEADERS.has(lower) ||
    DENIED_HEADER_PREFIXES.some((p) => lower.startsWith(p))
  );
}

/** Reusable Zod schema for a single HTTP header name */
const httpHeaderName = z
  .string()
  .min(1, "Header name cannot be empty")
  .regex(HTTP_HEADER_NAME_REGEX, "Invalid HTTP header name");

/**
 * Validated Record mapping client header names to server header names.
 * Keys are validated against the deny-list; values are free-form header names.
 */
export const ForwardHeadersRecordSchema = z
  .record(httpHeaderName, httpHeaderName)
  .refine(
    (rec) => Object.keys(rec).length <= 50,
    "Too many forward headers (max 50)",
  )
  .refine(
    (rec) => Object.keys(rec).every((k) => !isDeniedHeader(k)),
    "Forbidden header name in keys",
  )
  .optional();

/**
 * Validated forward_headers from a form textarea (newline-separated string).
 * Each line is either:
 *  - `HeaderName` (1:1 mapping, shorthand for HeaderName=HeaderName)
 *  - `ClientHeader=ServerHeader` (rename mapping)
 */
export const ForwardHeadersFormSchema = z
  .string()
  .optional()
  .refine(
    (val) => {
      if (!val || val.trim() === "") return true;
      const lines = val
        .trim()
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
      return lines.every((line) => {
        const eqIdx = line.indexOf("=");
        if (eqIdx === -1) {
          // Bare name: must be valid header and not denied
          return HTTP_HEADER_NAME_REGEX.test(line) && !isDeniedHeader(line);
        }
        const clientName = line.slice(0, eqIdx).trim();
        const serverName = line.slice(eqIdx + 1).trim();
        return (
          HTTP_HEADER_NAME_REGEX.test(clientName) &&
          !isDeniedHeader(clientName) &&
          HTTP_HEADER_NAME_REGEX.test(serverName)
        );
      });
    },
    { message: "validation:forwardHeaders.invalidHeaderName" },
  );

// Supported token_endpoint_auth_method values exposed in the UI for
// pre-registered upstream OAuth clients. The MCP SDK accepts any string,
// but we constrain the UI to the three values commonly required by
// enterprise SaaS providers that do not implement RFC 7591.
export const OAuthClientAuthMethodEnum = z.enum([
  "none",
  "client_secret_basic",
  "client_secret_post",
]);

// Optional pre-registered upstream OAuth client. Used to unblock providers
// (Salesforce, Zendesk, ServiceNow, Microsoft Graph, ...) that require the
// caller to register a client out-of-band instead of supporting RFC 7591
// Dynamic Client Registration.
//
// When `client_id` is provided, the backend will populate
// `oauth_sessions.client_information` for the MCP server so the SDK skips
// dynamic registration and goes straight to the authorization-code-with-PKCE
// flow against the provider's authorization endpoint.
const oauthClientInfoBaseSchema = z.object({
  client_id: z.string().optional(),
  client_secret: z.string().optional(),
  authorization_endpoint: z.string().optional(),
  token_endpoint: z.string().optional(),
  scope: z.string().optional(),
  token_endpoint_auth_method: OAuthClientAuthMethodEnum.optional(),
  // Per-server override for the redirect_uri MetaMCP registers/authorizes
  // with the upstream (see isValidLoopbackRedirectUri below). Deliberately
  // NOT included in oauthClientInfoIsBlank / the client_id-required
  // refinement below: an upstream that only accepts loopback redirect URIs
  // (e.g. Reclaim.ai) still supports RFC 7591 dynamic client registration,
  // so a user may need to set ONLY this field with no client_id.
  redirect_uri: z.string().optional(),
});

const isEmptyString = (value: string | undefined) =>
  value === undefined || value.trim() === "";

const oauthClientInfoIsBlank = (
  data: z.infer<typeof oauthClientInfoBaseSchema> | undefined,
) =>
  !data ||
  (isEmptyString(data.client_id) &&
    isEmptyString(data.client_secret) &&
    isEmptyString(data.authorization_endpoint) &&
    isEmptyString(data.token_endpoint) &&
    isEmptyString(data.scope) &&
    (data.token_endpoint_auth_method === undefined ||
      data.token_endpoint_auth_method === "none"));

const isValidOptionalUrl = (value: string | undefined) => {
  if (isEmptyString(value)) return true;
  try {
    new URL(value as string);
    return true;
  } catch {
    return false;
  }
};

// Hostnames accepted for the per-server redirect_uri override. Verified
// live against Reclaim.ai's RFC 7591 dynamic client registration endpoint
// (https://api.app.reclaim.ai/oauth2/register): `http://127.0.0.1` and
// `http://localhost` (any port/path) are ACCEPTED; https on loopback is
// REJECTED, as are any non-loopback hosts over http or https. `[::1]` is
// also accepted here even though Reclaim itself rejects it — it is a
// legitimate RFC 8252 §8.3 loopback address, and whether a given upstream
// accepts it is that upstream's business, not ours to pre-empt.
const LOOPBACK_REDIRECT_HOSTNAMES = new Set([
  "127.0.0.1",
  "localhost",
  "[::1]",
]);

// Validates the per-server OAuth redirect_uri override. Deliberately
// narrower than a generic URL check: this override's only purpose is
// unblocking upstreams that only accept loopback redirect URIs, and this
// value is later used verbatim as the browser authorize redirect and the
// token-exchange redirect_uri. Allowing arbitrary hosts (https included)
// would turn a per-server setting into an auth-code exfiltration vector.
const isValidLoopbackRedirectUri = (value: string | undefined) => {
  if (isEmptyString(value)) return true;
  try {
    const url = new URL(value as string);
    return (
      url.protocol === "http:" &&
      LOOPBACK_REDIRECT_HOSTNAMES.has(url.hostname) &&
      url.hash === ""
    );
  } catch {
    return false;
  }
};

// Validation rules applied to the request schemas: if ANY field in the
// section is populated, client_id becomes required; URL fields must parse.
export const OAuthClientInfoRequestSchema = oauthClientInfoBaseSchema
  .refine(
    (data) => oauthClientInfoIsBlank(data) || !isEmptyString(data.client_id),
    {
      message:
        "client_id is required when any pre-registered OAuth field is set",
      path: ["client_id"],
    },
  )
  .refine((data) => isValidOptionalUrl(data.authorization_endpoint), {
    message: "authorization_endpoint must be a valid URL",
    path: ["authorization_endpoint"],
  })
  .refine((data) => isValidOptionalUrl(data.token_endpoint), {
    message: "token_endpoint must be a valid URL",
    path: ["token_endpoint"],
  })
  .refine((data) => isValidLoopbackRedirectUri(data.redirect_uri), {
    message:
      "redirect_uri must be a loopback URL: scheme http with hostname 127.0.0.1, localhost, or [::1] (any port/path allowed), no fragment",
    path: ["redirect_uri"],
  });

export type OAuthClientInfoRequest = z.infer<
  typeof OAuthClientInfoRequestSchema
>;
export type OAuthClientAuthMethod = z.infer<typeof OAuthClientAuthMethodEnum>;

// Form-level shape for the Advanced OAuth section. Fields are plain optional
// strings here so that empty inputs from the form do not trigger zod errors;
// presence-based validation (client_id required when any field is set) is
// applied via .refine() on the parent form schema.
const oauthClientInfoFormShape = {
  oauth_client_id: z.string().optional(),
  oauth_client_secret: z.string().optional(),
  oauth_authorization_endpoint: z.string().optional(),
  oauth_token_endpoint: z.string().optional(),
  oauth_scope: z.string().optional(),
  oauth_token_endpoint_auth_method: OAuthClientAuthMethodEnum.optional(),
  // Not included in formOauthIsBlank below — see oauthClientInfoBaseSchema's
  // redirect_uri field comment for why it must not require oauth_client_id.
  oauth_redirect_uri: z.string().optional(),
} as const;

const formOauthIsBlank = (data: {
  oauth_client_id?: string;
  oauth_client_secret?: string;
  oauth_authorization_endpoint?: string;
  oauth_token_endpoint?: string;
  oauth_scope?: string;
  oauth_token_endpoint_auth_method?: OAuthClientAuthMethod;
}) =>
  isEmptyString(data.oauth_client_id) &&
  isEmptyString(data.oauth_client_secret) &&
  isEmptyString(data.oauth_authorization_endpoint) &&
  isEmptyString(data.oauth_token_endpoint) &&
  isEmptyString(data.oauth_scope) &&
  (data.oauth_token_endpoint_auth_method === undefined ||
    data.oauth_token_endpoint_auth_method === "none");

// Define the form schema (includes UI-specific fields)
export const createServerFormSchema = z
  .object({
    name: z
      .string()
      .min(1, "validation:serverName.required")
      .regex(/^[a-zA-Z0-9_-]+$/, "validation:serverName.invalidCharacters")
      .refine(
        (value) => !/_{2,}/.test(value),
        "validation:serverName.consecutiveUnderscores",
      ),
    description: z.string().optional(),
    type: McpServerTypeEnum,
    command: z.string().optional(),
    args: z.string().optional(),
    url: z.string().optional(),
    bearerToken: z.string().optional(),
    headers: z.string().optional(),
    forward_headers: ForwardHeadersFormSchema,
    env: z.string().optional(),
    user_id: z.string().nullable().optional(),
    ...oauthClientInfoFormShape,
  })
  .refine(
    (data) => {
      // Command is required for stdio type
      if (data.type === McpServerTypeEnum.enum.STDIO) {
        return data.command && data.command.trim() !== "";
      }
      return true;
    },
    {
      message: "validation:command.required",
      path: ["command"],
    },
  )
  .refine(
    (data) => {
      // URL is required for SSE and Streamable HTTP types
      if (
        data.type === McpServerTypeEnum.enum.SSE ||
        data.type === McpServerTypeEnum.enum.STREAMABLE_HTTP
      ) {
        if (!data.url || data.url.trim() === "") {
          return false;
        }
        // Validate URL format
        try {
          new URL(data.url);
          return true;
        } catch {
          return false;
        }
      }
      return true;
    },
    {
      message: "validation:url.required",
      path: ["url"],
    },
  )
  .refine(
    (data) => formOauthIsBlank(data) || !isEmptyString(data.oauth_client_id),
    {
      message: "validation:oauthClientId.required",
      path: ["oauth_client_id"],
    },
  )
  .refine((data) => isValidOptionalUrl(data.oauth_authorization_endpoint), {
    message: "validation:oauthAuthorizationEndpoint.invalid",
    path: ["oauth_authorization_endpoint"],
  })
  .refine((data) => isValidOptionalUrl(data.oauth_token_endpoint), {
    message: "validation:oauthTokenEndpoint.invalid",
    path: ["oauth_token_endpoint"],
  })
  .refine((data) => isValidLoopbackRedirectUri(data.oauth_redirect_uri), {
    message: "validation:oauthRedirectUri.invalid",
    path: ["oauth_redirect_uri"],
  });

export type CreateServerFormData = z.infer<typeof createServerFormSchema>;

// Form schema for editing servers
export const EditServerFormSchema = z
  .object({
    name: z
      .string()
      .min(1, "validation:serverName.required")
      .regex(/^[a-zA-Z0-9_-]+$/, "validation:serverName.invalidCharacters")
      .refine(
        (value) => !/_{2,}/.test(value),
        "validation:serverName.consecutiveUnderscores",
      ),
    description: z.string().optional(),
    type: McpServerTypeEnum,
    command: z.string().optional(),
    args: z.string().optional(),
    url: z.string().optional(),
    bearerToken: z.string().optional(),
    headers: z.string().optional(),
    forward_headers: ForwardHeadersFormSchema,
    env: z.string().optional(),
    user_id: z.string().nullable().optional(),
    ...oauthClientInfoFormShape,
  })
  .refine(
    (data) => {
      // Command is required for stdio type
      if (data.type === McpServerTypeEnum.enum.STDIO) {
        return data.command && data.command.trim() !== "";
      }
      return true;
    },
    {
      message: "validation:command.required",
      path: ["command"],
    },
  )
  .refine(
    (data) => {
      // URL is required for SSE and Streamable HTTP types
      if (
        data.type === McpServerTypeEnum.enum.SSE ||
        data.type === McpServerTypeEnum.enum.STREAMABLE_HTTP
      ) {
        if (!data.url || data.url.trim() === "") {
          return false;
        }
        // Validate URL format
        try {
          new URL(data.url);
          return true;
        } catch {
          return false;
        }
      }
      return true;
    },
    {
      message: "validation:url.required",
      path: ["url"],
    },
  )
  .refine(
    (data) => formOauthIsBlank(data) || !isEmptyString(data.oauth_client_id),
    {
      message: "validation:oauthClientId.required",
      path: ["oauth_client_id"],
    },
  )
  .refine((data) => isValidOptionalUrl(data.oauth_authorization_endpoint), {
    message: "validation:oauthAuthorizationEndpoint.invalid",
    path: ["oauth_authorization_endpoint"],
  })
  .refine((data) => isValidOptionalUrl(data.oauth_token_endpoint), {
    message: "validation:oauthTokenEndpoint.invalid",
    path: ["oauth_token_endpoint"],
  })
  .refine((data) => isValidLoopbackRedirectUri(data.oauth_redirect_uri), {
    message: "validation:oauthRedirectUri.invalid",
    path: ["oauth_redirect_uri"],
  });

export type EditServerFormData = z.infer<typeof EditServerFormSchema>;

export const CreateMcpServerRequestSchema = z
  .object({
    name: z
      .string()
      .min(1, "Name is required")
      .regex(
        /^[a-zA-Z0-9_-]+$/,
        "Server name must only contain letters, numbers, underscores, and hyphens",
      )
      .refine(
        (value) => !/_{2,}/.test(value),
        "Server name cannot contain consecutive underscores",
      ),
    description: z.string().optional(),
    type: McpServerTypeEnum,
    command: z.string().optional(),
    args: z.array(z.string()).optional(),
    env: z.record(z.string(), z.string()).optional(),
    url: z.string().optional(),
    bearerToken: z.string().optional(),
    headers: z.record(z.string(), z.string()).optional(),
    forward_headers: ForwardHeadersRecordSchema,
    user_id: z.string().nullable().optional(),
    oauth_client_info: OAuthClientInfoRequestSchema.optional(),
  })
  .refine(
    (data) => {
      // For stdio type, command is required and URL should be empty
      if (data.type === "STDIO") {
        return data.command && data.command.trim() !== "";
      }

      // For other types, URL should be provided and valid
      if (!data.url || data.url.trim() === "") {
        return false;
      }

      try {
        new URL(data.url);
        return true;
      } catch {
        return false;
      }
    },
    {
      message:
        "Command is required for stdio servers. URL is required and must be valid for sse and streamable_http server types",
    },
  );

export const McpServerSchema = z.object({
  uuid: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  type: McpServerTypeEnum,
  command: z.string().nullable(),
  args: z.array(z.string()),
  env: z.record(z.string(), z.string()),
  url: z.string().nullable(),
  created_at: z.string(),
  bearerToken: z.string().nullable(),
  headers: z.record(z.string(), z.string()),
  forward_headers: z.record(z.string(), z.string()),
  user_id: z.string().nullable(),
  error_status: McpServerErrorStatusEnum.optional(),
  // Per-server loopback-only redirect_uri override for upstream OAuth. See
  // isValidLoopbackRedirectUri above. Null when unset (falls back to the
  // APP_URL-derived MetaMCP callback).
  redirect_uri: z.string().nullable(),
});

export const CreateMcpServerResponseSchema = z.object({
  success: z.boolean(),
  data: McpServerSchema.optional(),
  message: z.string().optional(),
});

export const ListMcpServersResponseSchema = z.object({
  success: z.boolean(),
  data: z.array(McpServerSchema),
  message: z.string().optional(),
});

export const GetMcpServerResponseSchema = z.object({
  success: z.boolean(),
  data: McpServerSchema.optional(),
  message: z.string().optional(),
});

// Bulk import schemas
export const BulkImportMcpServerSchema = z
  .object({
    command: z.string().optional(),
    args: z.array(z.string()).optional(),
    env: z.record(z.string(), z.string()).optional(),
    url: z.string().optional(),
    headers: z.record(z.string(), z.string()).optional(),
    forward_headers: ForwardHeadersRecordSchema,
    description: z.string().optional(),
    type: z
      .string()
      .optional()
      .transform((val) => {
        if (!val) return undefined;
        // Convert to uppercase for case-insensitive matching
        const upperVal = val.toUpperCase();
        // Map common variations to the correct enum values
        if (upperVal === "STDIO" || upperVal === "STD") return "STDIO";
        if (upperVal === "SSE") return "SSE";
        if (
          upperVal === "STREAMABLE_HTTP" ||
          upperVal === "STREAMABLEHTTP" ||
          upperVal === "HTTP"
        )
          return "STREAMABLE_HTTP";
        return upperVal; // Return as-is if it doesn't match known patterns
      })
      .pipe(McpServerTypeEnum.optional()),
  })
  .refine(
    (data) => {
      const serverType = data.type || McpServerTypeEnum.enum.STDIO;

      // For STDIO type, URL can be empty
      if (serverType === McpServerTypeEnum.enum.STDIO) {
        return true;
      }

      // For other types, URL should be provided and valid
      if (!data.url || data.url.trim() === "") {
        return false;
      }

      try {
        new URL(data.url);
        return true;
      } catch {
        return false;
      }
    },
    {
      message:
        "URL is required and must be valid for sse and streamable_http server types",
      path: ["url"],
    },
  );

export const BulkImportMcpServersRequestSchema = z.object({
  mcpServers: z.record(z.string(), BulkImportMcpServerSchema),
});

export const BulkImportMcpServersResponseSchema = z.object({
  success: z.boolean(),
  imported: z.number(),
  errors: z.array(z.string()).optional(),
  message: z.string().optional(),
});

// MCP Server types
export type McpServerType = z.infer<typeof McpServerTypeEnum>;
export type CreateMcpServerRequest = z.infer<
  typeof CreateMcpServerRequestSchema
>;
export type McpServer = z.infer<typeof McpServerSchema>;
export type CreateMcpServerResponse = z.infer<
  typeof CreateMcpServerResponseSchema
>;
export type ListMcpServersResponse = z.infer<
  typeof ListMcpServersResponseSchema
>;
export type GetMcpServerResponse = z.infer<typeof GetMcpServerResponseSchema>;
export type BulkImportMcpServer = z.infer<typeof BulkImportMcpServerSchema>;
export type BulkImportMcpServersRequest = z.infer<
  typeof BulkImportMcpServersRequestSchema
>;
export type BulkImportMcpServersResponse = z.infer<
  typeof BulkImportMcpServersResponseSchema
>;

export const DeleteMcpServerRequestSchema = z.object({
  uuid: z.string().uuid(),
});

export const DeleteMcpServerResponseSchema = z.object({
  success: z.boolean(),
  message: z.string().optional(),
  error: z.string().optional(),
});

export const UpdateMcpServerRequestSchema = z
  .object({
    uuid: z.string().uuid(),
    name: z
      .string()
      .min(1, "Name is required")
      .regex(
        /^[a-zA-Z0-9_-]+$/,
        "Server name must only contain letters, numbers, underscores, and hyphens",
      )
      .refine(
        (value) => !/_{2,}/.test(value),
        "Server name cannot contain consecutive underscores",
      ),
    description: z.string().optional(),
    type: McpServerTypeEnum,
    command: z.string().optional(),
    args: z.array(z.string()).optional(),
    env: z.record(z.string(), z.string()).optional(),
    url: z.string().optional(),
    bearerToken: z.string().optional(),
    headers: z.record(z.string(), z.string()).optional(),
    forward_headers: ForwardHeadersRecordSchema,
    user_id: z.string().nullable().optional(),
    oauth_client_info: OAuthClientInfoRequestSchema.optional(),
  })
  .refine(
    (data) => {
      // For stdio type, command is required and URL should be empty
      if (data.type === "STDIO") {
        return data.command && data.command.trim() !== "";
      }

      // For other types, URL should be provided and valid
      if (!data.url || data.url.trim() === "") {
        return false;
      }

      try {
        new URL(data.url);
        return true;
      } catch {
        return false;
      }
    },
    {
      message:
        "Command is required for stdio servers. URL is required and must be valid for sse and streamable_http server types",
    },
  );

export const UpdateMcpServerResponseSchema = z.object({
  success: z.boolean(),
  data: McpServerSchema.optional(),
  message: z.string().optional(),
  error: z.string().optional(),
});

export type DeleteMcpServerRequest = z.infer<
  typeof DeleteMcpServerRequestSchema
>;

export type DeleteMcpServerResponse = z.infer<
  typeof DeleteMcpServerResponseSchema
>;

export type UpdateMcpServerRequest = z.infer<
  typeof UpdateMcpServerRequestSchema
>;

export type UpdateMcpServerResponse = z.infer<
  typeof UpdateMcpServerResponseSchema
>;

// Repository-specific schemas
export const McpServerCreateInputSchema = z.object({
  name: z
    .string()
    .regex(
      /^[a-zA-Z0-9_-]+$/,
      "Server name must only contain letters, numbers, underscores, and hyphens",
    )
    .refine(
      (value) => !/_{2,}/.test(value),
      "Server name cannot contain consecutive underscores",
    ),
  description: z.string().nullable().optional(),
  type: McpServerTypeEnum,
  command: z.string().nullable().optional(),
  args: z.array(z.string()).optional(),
  env: z.record(z.string(), z.string()).optional(),
  url: z.string().nullable().optional(),
  bearerToken: z.string().nullable().optional(),
  headers: z.record(z.string(), z.string()).optional(),
  forward_headers: ForwardHeadersRecordSchema,
  user_id: z.string().nullable().optional(),
  redirect_uri: z.string().nullable().optional(),
});

export const McpServerUpdateInputSchema = z.object({
  uuid: z.string(),
  name: z
    .string()
    .regex(
      /^[a-zA-Z0-9_-]+$/,
      "Server name must only contain letters, numbers, underscores, and hyphens",
    )
    .refine(
      (value) => !/_{2,}/.test(value),
      "Server name cannot contain consecutive underscores",
    )
    .optional(),
  description: z.string().nullable().optional(),
  type: McpServerTypeEnum.optional(),
  command: z.string().nullable().optional(),
  args: z.array(z.string()).optional(),
  env: z.record(z.string(), z.string()).optional(),
  url: z.string().nullable().optional(),
  bearerToken: z.string().nullable().optional(),
  headers: z.record(z.string(), z.string()).optional(),
  forward_headers: ForwardHeadersRecordSchema,
  user_id: z.string().nullable().optional(),
  redirect_uri: z.string().nullable().optional(),
});

export type McpServerCreateInput = z.infer<typeof McpServerCreateInputSchema>;
export type McpServerUpdateInput = z.infer<typeof McpServerUpdateInputSchema>;

// Database-specific schemas (raw database results with Date objects)
export const DatabaseMcpServerSchema = z.object({
  uuid: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  type: McpServerTypeEnum,
  command: z.string().nullable(),
  args: z.array(z.string()),
  env: z.record(z.string(), z.string()),
  url: z.string().nullable(),
  error_status: McpServerErrorStatusEnum,
  created_at: z.date(),
  bearerToken: z.string().nullable(),
  headers: z.record(z.string(), z.string()),
  forward_headers: z.record(z.string(), z.string()),
  user_id: z.string().nullable(),
  redirect_uri: z.string().nullable(),
});

export type DatabaseMcpServer = z.infer<typeof DatabaseMcpServerSchema>;
