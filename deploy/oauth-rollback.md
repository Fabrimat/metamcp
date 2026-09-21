# Native upstream OAuth rollback

Migration `0020_user_scoped_oauth.sql` requires `oauth_sessions.user_id` and replaces the server-only unique constraint. A pre-feature image cannot write this schema. **App-only rollback after 0020 is forbidden. Restore the complete pre-deploy PostgreSQL dump before starting the old image.**

## Before deployment

Record the exact Compose project/files, database service/name/role, current image ID and rollback tag. Stop every application writer before the backup and keep them stopped until the new release starts. Create a custom-format `pg_dump` of the entire application database (no table/schema filters; include the `drizzle` journal). Retain its SHA-256 checksum, row counts for users/servers/namespaces/OAuth sessions, and previous app configuration. Check `pg_restore --list` succeeds and lists both public and migration-journal objects. Restore into a disposable database and run the guard below before deployment: an untested dump is not a verified rollback artifact.

## Required rollback sequence

**Destructive:** full restoration discards every write after the backup, including users, configuration, tokens, and audit entries. Retain a forensic dump first. A schema-only down migration cannot recover the legacy public sessions deleted by 0020.

1. Stop `app` and every other writer using the recorded Compose project/files. Verify no app container or app database connection remains; leave PostgreSQL running. Record the failed image ID.
2. Create a forensic dump. Verify the pre-deploy dump checksum matches the manifest and inspect its TOC again. Abort on any mismatch.
3. Replace only the recorded application database, using native PostgreSQL tools on the deployment host. Variables below must match the recorded targets. Supply credentials through the existing protected connection mechanism; never print them. Run as the database owner (or use the recorded owner via `--role` during restore):

   ```sh
   pg_dump --format=custom --no-owner --no-privileges --dbname="$DB_NAME" --file="$FORENSIC_DUMP"
   dropdb --if-exists -- "$DB_NAME"
   createdb --owner="$DB_ROLE" -- "$DB_NAME"
   pg_restore --exit-on-error --no-owner --no-privileges --dbname="$DB_NAME" "$PREDEPLOY_DUMP"
   psql --dbname="$DB_NAME" --set=ON_ERROR_STOP=1 --file=deploy/oauth-rollback-guard.sql
   ```

   Every nonzero exit is a stop condition. Do not run either application or its migration entrypoint during restore. Restore the journal with the schema/data; never manually mark 0020 unapplied on a migrated schema.
4. Compare restored row counts with the manifest. The read-only guard verifies absence of user-scoped OAuth columns, presence of the real server-only unique constraint, and absence of migration 0020-or-later journal entries.
5. Point the Compose override/configuration at the recorded old image, verify its image ID against the rollback tag, then start `app`. Verify `/health`, login, server listing and a server-only OAuth session write. Retain backup, forensic dump, restore log, guard exit status and image ID as evidence.

## Repository verification

`apps/backend/scripts/verify-oauth-migration.mjs` applies migrations 0000–0020 to disposable embedded PostgreSQL, proves the guard rejects 0020, restores the complete pre-deploy snapshot (including legacy public OAuth rows), and executes the old `ON CONFLICT (mcp_server_uuid)` write successfully:

```sh
node apps/backend/scripts/verify-oauth-migration.mjs /absolute/path/to/@electric-sql/pglite/dist/index.js
```

The rehearsal uses `@electric-sql/pglite@0.3.14` installed separately in a temporary directory; project dependencies are unchanged. The snapshot verifies PostgreSQL schema/data compatibility. Native `pg_dump`/`pg_restore`, image startup and health checks still require rehearsal with the deployment PostgreSQL/image versions.
