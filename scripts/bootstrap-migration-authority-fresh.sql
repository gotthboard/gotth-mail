-- Run twice as one distinct trusted superuser installer inside an exclusive administration window.
-- Invocation 1 creates passwordless NOLOGIN principals and a database/OID-bound phase marker.
-- Provision app and migrator SCRAM verifiers externally, then invocation 2 activates only the migrator.
BEGIN;
DO $bootstrap$
DECLARE
  db_oid oid := (SELECT oid FROM pg_database WHERE datname=current_database());
  installer_is_superuser boolean;
  named_count integer;
BEGIN
  SELECT rolsuper INTO installer_is_superuser FROM pg_roles WHERE rolname=session_user;
  IF NOT installer_is_superuser OR session_user IN ('gotth_mail','gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim') THEN
    RAISE EXCEPTION 'fresh authority bootstrap requires a distinct trusted superuser installer' USING ERRCODE='42501';
  END IF;
  SELECT count(*) INTO named_count FROM pg_roles
   WHERE rolname IN ('gotth_mail','gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim');
  IF named_count = 0 THEN
    CREATE ROLE gotth_mail_schema_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1;
    CREATE ROLE gotth_mail_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1;
    CREATE ROLE gotth_mail_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1;
    CREATE ROLE gotth_mail_gate NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1;
    CREATE ROLE gotth_mail_jobs NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1;
    CREATE ROLE gotth_mail_import NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1;
    CREATE ROLE gotth_mail_scim NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1;
    EXECUTE format('ALTER ROLE gotth_mail_schema_owner IN DATABASE %I SET gotth_mail.bootstrap_phase TO %L', current_database(), 'fresh-v1-principals-created');
    RETURN;
  END IF;
  IF named_count <> 7 OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname='gotth_mail') OR EXISTS (
    SELECT 1 FROM (VALUES
      ('gotth_mail_schema_owner'),('gotth_mail_migrator'),('gotth_mail_app'),('gotth_mail_gate'),('gotth_mail_jobs'),('gotth_mail_import'),('gotth_mail_scim')
    ) e(name) LEFT JOIN pg_authid a ON a.rolname=e.name
    WHERE a.oid IS NULL OR a.rolcanlogin OR a.rolsuper OR a.rolcreatedb OR a.rolcreaterole OR a.rolinherit OR a.rolreplication OR a.rolbypassrls
       OR a.rolconnlimit <> -1 OR a.rolvaliduntil IS NOT NULL
       OR (e.name IN ('gotth_mail_app','gotth_mail_migrator') AND (a.rolpassword IS NULL OR a.rolpassword !~ '^SCRAM-SHA-256\$[0-9]+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$'))
  ) THEN
    RAISE EXCEPTION 'fresh activation requires exact transitional roles and SCRAM app/migrator verifiers' USING ERRCODE='55000';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_auth_members m JOIN pg_roles g ON g.oid=m.roleid JOIN pg_roles u ON u.oid=m.member
    WHERE g.rolname IN ('gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim')
       OR u.rolname IN ('gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim')
  ) THEN
    RAISE EXCEPTION 'fresh activation requires no product role memberships' USING ERRCODE='55000';
  END IF;
  IF (SELECT count(*) FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole
       WHERE r.rolname IN ('gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim')) <> 1
     OR NOT EXISTS (
       SELECT 1 FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole
       WHERE r.rolname='gotth_mail_schema_owner' AND s.setdatabase=db_oid
         AND s.setconfig=ARRAY['gotth_mail.bootstrap_phase=fresh-v1-principals-created']::text[]
     ) THEN
    RAISE EXCEPTION 'fresh activation phase marker/settings mismatch' USING ERRCODE='55000';
  END IF;
  ALTER ROLE gotth_mail_migrator LOGIN;
  GRANT gotth_mail_schema_owner TO gotth_mail_migrator WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
  EXECUTE format('ALTER ROLE gotth_mail_migrator IN DATABASE %I SET role TO gotth_mail_schema_owner', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO gotth_mail_migrator', current_database());
  GRANT USAGE,CREATE ON SCHEMA public TO gotth_mail_schema_owner;
  REVOKE CREATE ON SCHEMA public FROM gotth_mail_app,PUBLIC;
  EXECUTE format('ALTER ROLE gotth_mail_schema_owner IN DATABASE %I SET gotth_mail.bootstrap_phase TO %L', current_database(), 'fresh-v1-prefix-ready');
END $bootstrap$;
COMMIT;
