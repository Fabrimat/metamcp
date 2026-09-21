"use client";

import { auth } from "@modelcontextprotocol/sdk/client/auth.js";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { useTranslations } from "@/hooks/useTranslations";

import { getAppUrl } from "../lib/env";
import { completeOAuthCallback } from "../lib/oauth-callback";
import { createAuthProvider } from "../lib/oauth-provider";
import { vanillaTrpcClient } from "../lib/trpc";

type CallbackStatus =
  | { kind: "pending" }
  | { kind: "error"; error: string; description?: string };

const OAuthCallback = () => {
  const { t } = useTranslations();
  const hasProcessedRef = useRef(false);
  const [status, setStatus] = useState<CallbackStatus>({ kind: "pending" });

  useEffect(() => {
    const handleCallback = async () => {
      // Skip if we've already processed this callback (e.g. React strict mode)
      if (hasProcessedRef.current) {
        return;
      }
      hasProcessedRef.current = true;

      // A loopback redirect_uri override (see mcp-servers.zod.ts
      // isValidLoopbackRedirectUri) points the upstream back at
      // http://127.0.0.1:<port> / http://localhost:<port>. When the user
      // reaches MetaMCP itself through an SSH tunnel bound to that same
      // loopback port, the upstream's redirect lands on the *tunnel*
      // origin — which serves this same app — instead of MetaMCP's own
      // configured origin (getAppUrl()). Bounce to the configured origin so
      // the exchangeToken call runs against the configured application
      // origin. The complete query string carries all callback inputs.
      // Guarded on an actual origin mismatch so this can't loop.
      const configuredOrigin = new URL(getAppUrl()).origin;
      if (window.location.origin !== configuredOrigin) {
        window.location.replace(
          configuredOrigin + "/fe-oauth/callback" + window.location.search,
        );
        return;
      }

      const completion = await completeOAuthCallback(window.location.search, {
        storage: sessionStorage,
        exchangeUpstream: (input) =>
          vanillaTrpcClient.frontend.oauth.exchangeToken.mutate(input),
        completeDownstream: async ({
          authorizationCode,
          returnUuid,
          serverUrl,
        }) => {
          const provider = createAuthProvider(returnUuid, serverUrl);
          const result = await auth(provider, {
            serverUrl,
            authorizationCode,
          });
          return { result, tokens: await provider.tokens() };
        },
        navigate: (path) => window.location.assign(path),
      });

      if (completion.kind === "error") {
        setStatus({
          kind: "error",
          error: completion.error,
          description: completion.errorDescription,
        });
      }
    };

    void handleCallback();
  }, []);

  if (status.kind === "error") {
    return (
      <div className="flex flex-col items-center justify-center h-screen gap-4 px-6 text-center">
        <h1 className="text-2xl font-semibold">
          {t("common:oauth.callbackFailedTitle")}
        </h1>
        <p className="text-red-600 font-medium">{status.error}</p>
        {status.description && (
          <p className="max-w-2xl text-sm text-muted-foreground whitespace-pre-wrap">
            {status.description}
          </p>
        )}
        <Link
          href="/mcp-servers"
          className="text-sm underline text-muted-foreground"
        >
          {t("common:oauth.backToMcpServers")}
        </Link>
      </div>
    );
  }

  return (
    <div className="flex items-center justify-center h-screen">
      <p className="text-lg text-gray-500">
        {t("common:oauth.processingCallback")}
      </p>
    </div>
  );
};

export default OAuthCallback;
