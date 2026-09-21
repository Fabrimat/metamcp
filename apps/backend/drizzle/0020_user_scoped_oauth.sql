ALTER TABLE "oauth_sessions" ADD COLUMN "user_id" text;--> statement-breakpoint
ALTER TABLE "oauth_sessions" ADD COLUMN "discovery_state" jsonb;--> statement-breakpoint
UPDATE "oauth_sessions" AS os
SET "user_id" = ms."user_id"
FROM "mcp_servers" AS ms
WHERE ms."uuid" = os."mcp_server_uuid" AND ms."user_id" IS NOT NULL;--> statement-breakpoint
DELETE FROM "oauth_sessions" WHERE "user_id" IS NULL;--> statement-breakpoint
ALTER TABLE "oauth_sessions" ALTER COLUMN "user_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "oauth_sessions" DROP CONSTRAINT "oauth_sessions_unique_per_server_idx";--> statement-breakpoint
ALTER TABLE "oauth_sessions" ADD CONSTRAINT "oauth_sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "oauth_sessions_user_id_idx" ON "oauth_sessions" USING btree ("user_id");--> statement-breakpoint
ALTER TABLE "oauth_sessions" ADD CONSTRAINT "oauth_sessions_unique_per_server_user_idx" UNIQUE("mcp_server_uuid","user_id");
