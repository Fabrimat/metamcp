-- Read-only gate: psql -v ON_ERROR_STOP=1 -f deploy/oauth-rollback-guard.sql
DO $$
DECLARE migrated_journal boolean;
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'oauth_sessions' AND column_name = 'user_id'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'public.oauth_sessions'::regclass AND contype = 'u'
      AND pg_get_constraintdef(oid) = 'UNIQUE (mcp_server_uuid)'
  ) THEN
    RAISE EXCEPTION 'Incompatible OAuth schema: restore the complete pre-deploy PostgreSQL dump before starting the old image';
  END IF;
  IF to_regclass('drizzle.__drizzle_migrations') IS NOT NULL THEN
    EXECUTE 'SELECT EXISTS (SELECT 1 FROM drizzle.__drizzle_migrations WHERE created_at >= 1790007606248)'
      INTO migrated_journal;
    IF migrated_journal THEN
      RAISE EXCEPTION 'Incompatible migration journal: restore the complete pre-deploy PostgreSQL dump';
    END IF;
  END IF;
END $$;
