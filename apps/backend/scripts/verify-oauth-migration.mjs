// Run with a separately installed @electric-sql/pglite module path. Uses only
// disposable embedded PostgreSQL instances; never connects to deployment data.
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const { PGlite } = await import(pathToFileURL(resolve(process.argv[2])).href);
const migrationDir = new URL("../drizzle/", import.meta.url);
const guard = await readFile(
  new URL("../../../deploy/oauth-rollback-guard.sql", import.meta.url),
  "utf8",
);
const database = new PGlite();
let restored;
try {
  for (const name of (await readdir(migrationDir))
    .filter((name) => /^00[01][0-9]_.*\.sql$/.test(name))
    .sort()) {
    await database.exec(await readFile(new URL(name, migrationDir), "utf8"));
  }
  await database.exec(`INSERT INTO users (id, name, email) VALUES ('owner', 'Owner', 'owner@example.test');
    INSERT INTO mcp_servers (uuid, name, user_id) VALUES
      ('00000000-0000-4000-8000-000000000001', 'owned', 'owner'),
      ('00000000-0000-4000-8000-000000000002', 'public', NULL);
    INSERT INTO oauth_sessions (mcp_server_uuid, client_information) VALUES
      ('00000000-0000-4000-8000-000000000001', '{"client_id":"owned"}'),
      ('00000000-0000-4000-8000-000000000002', '{"client_id":"legacy-public"}');`);
  const backup = await database.dumpDataDir();
  await database.exec(
    await readFile(new URL("0020_user_scoped_oauth.sql", migrationDir), "utf8"),
  );
  assert.deepEqual(
    (await database.query("SELECT user_id FROM oauth_sessions")).rows,
    [{ user_id: "owner" }],
  );
  await assert.rejects(
    database.exec(guard),
    /restore|incompatible/i,
    "the old binary must be blocked on schema 0020",
  );
  // A complete PostgreSQL snapshot restoration models pg_dump/pg_restore's
  // schema+data result; native pg_restore remains a deployment smoke check.
  restored = new PGlite({ loadDataDir: backup });
  await restored.exec(guard);
  assert.equal(
    (await restored.query("SELECT count(*)::int AS n FROM oauth_sessions"))
      .rows[0].n,
    2,
  );
  await restored.exec(`INSERT INTO oauth_sessions (mcp_server_uuid, code_verifier)
    VALUES ('00000000-0000-4000-8000-000000000001', 'legacy-client-write')
    ON CONFLICT (mcp_server_uuid) DO UPDATE SET code_verifier = EXCLUDED.code_verifier;`);
  assert.equal(
    (
      await restored.query(
        "SELECT code_verifier FROM oauth_sessions WHERE mcp_server_uuid = '00000000-0000-4000-8000-000000000001'",
      )
    ).rows[0].code_verifier,
    "legacy-client-write",
  );
  console.log(
    "PASS: 0000-0020 migration; migrated-schema rollback guard; full pre-deploy restoration; legacy ON CONFLICT write.",
  );
} finally {
  await database.close();
  await restored?.close();
}
