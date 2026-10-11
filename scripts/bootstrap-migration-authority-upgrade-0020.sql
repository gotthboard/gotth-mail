BEGIN;
DO $ledger$
BEGIN
  IF EXISTS (
    WITH expected(version, checksum) AS (VALUES
      ('schema_migrations','413687179f8e273fb76c98d3e22798130dddd35e0856d6e6a0892824c5cab4e5'),
      ('domains','240be515a722f64555a47a847073cc5b018990d507bf439a82cd604411257895'),
      ('mailboxes','d4f2b3e862baec674d5e996102cbedc2361d6bee55675aa79819b46ce11085b9'),
      ('aliases','3cc0c4263826f159c42c5e65c4bb2283d5a09ad344b42fadf8b18dea0cd09521'),
      ('relays','54a2156cbc7265f9980af794ec35f91abb7bd12318ed9b665d010db27d917b7f'),
      ('tokens','b3b36866d9fefde39b62902778b0d59ae39965ea870263e7f0a3f7c351f0a902'),
      ('oidc_login_states','a66c85bc9d82371c4fed89b5253f4f267b3492a68bf8e02754a529356cab762d'),
      ('sessions','badbbe90775ecd01ff7ea681535acfab5fc5b5af2c343646a8509c48c4b3b8ff'),
      ('identity_refs','1c375ba15e044417abf37167c43f0e251440faff1710ae01b2d8eb42ed8d5783'),
      ('role_bindings','bfe321d34a28fb3ce4d92f56742226c2f3f2242a78ad75fcc8c89761d3cf9419'),
      ('audit_events','d82cfe3c025c66a2a55998b7fabbb951f781d2b73482d9998d291d0cead933a4'),
      ('generated_config_sets','0c5f4518b4d3a5f65d8014975471c309eb07bd3326dc8f190028358f6e1f0dd2'),
      ('backup_artifacts','9529cdc1a0e7ba853bd0bdf49bd8704f832b9829e4e31b661ccb787643904b46'),
      ('backup_verifications','c65a854038b9e0990f95469300b8bbf63d4d13993db8bbe57502af863d7d6550'),
      ('snapshots','e8e9a93b84e219e27c457f69671bd1fd88fc1c8c8c6cd5dea156ab7ffcb2ef8b'),
      ('webmail_drafts','4272f75c54e2319e545f55c9ed248dbd300ad0ba512dfcaed426b4ac62461a7f'),
      ('notification_deliveries','271354b05f1a6f9ce50f51960e988353145e313a83249b855ed3268ae7551c15'),
      ('notification_actor_mappings','4304c7e219445dcff670286c366dd90d8dce3910ebcc898acef10b3b2f1dcf0f'),
      ('notification_approvals','783aa96eee2814bfed9a008a73acd8d1165a4d071ff1c413b71ccd46bddcfd1f'),
      ('plugin_registrations','bbfe82dc6851f92df26e1d678346d292ddee6fc5354f6ee16bf629baecc46954'),
      ('0002_notification_delivery_evidence','8248f32695e8a4b9d4c4e40d5381a46b7fa95c0edb6fcce068fc18b5cefd2db9'),
      ('0003_oidc_protected_attempts','5d84747cd9e46fe07f38a65047a2ae7250a2331b719677e5f7e90856c702bb5a'),
      ('0004_scim_resources','31fd23ebd1f93743b8b584f207fa987363ccfd1ff44354eec5bcf9bf248382f4'),
      ('0005_app_password_contract','024875d66aa098296b5a9f88d0d6dd5bccb412d7089ce5b8e2009f7ebdb1f9bc'),
      ('0006_oidc_scim_identity_binding','70d4e2cb255cc8ca707ba1fe626ec1805557cec2fbcf928163730be3de479097'),
      ('0007_scim_group_members','c78113960f1f2e896e50118a7bccf05b16156ff832dd2652517c20d040706939'),
      ('0008_outbound_policy','cfae1dcd0a170056db82dd1f4b6687d77b31f45ba012fa2d3210bf94310b844b'),
      ('0009_outbound_queue','0876940b3329cdb4399cf3d92da1d54a8d1352a01b62cff2b5e522b5cb4884b2'),
      ('0010_outbound_queue_release','a97d5351da09f8281e48be91094582d85259a323d6777e8b5af46425e6c012eb'),
      ('0011_webmail_cc_bcc','968b058395486742c1f74b5aa179cda9bcea9278d9b14f3e03c2170abff1586c'),
      ('0012_webmail_delivery_uncertain','b08487355adf0274cbe8e0714ae7f4913e5de5f158d73ff99f8fa1974611d83a'),
      ('0013_notification_approval_binding','262bae80c2eef041b0574707423e253efd2997fc6a043c15f577f8f7610ddcc3'),
      ('0014_notification_approval_execution','a41fa7fc66a24d13ce94230f7a30d5e34e12bbf67e9f5c2800fdc9f389463343'),
      ('0015_notification_telegram_updates','9d800c9f3842173edc4225cb5cfc17cd698252345abcdbbc8aa4669f66c59faf'),
      ('0016_notification_event_states','2fb6d62845ea7f6016713d2538e62f3144e51b1ed6ea75a116a703b62ec91b55'),
      ('0017_extension_administrator','2ff880161f031f3b646592b87284e379497a32725a3c6cb57bc00c425971e9c1'),
      ('0018_role_binding_authority','d5b8856fb53f2cbd0e4fea0f1e90c4d62c6d28e3123e359beb800edfd32d444b'),
      ('0019_group_role_projection','a205965b60b94d5c6403b11e551478de1a50eea131f3161a9c606331ea9695e0'),
      ('0020_final_queue_artifact_binding','70ba885e190d0e0907f6d93e6256d36998964c9acc50b88829bfd8a3a5ed823b')
    )
    SELECT 1
      FROM expected e
      FULL JOIN public.schema_migrations l USING (version)
     WHERE e.version IS NULL OR l.version IS NULL
        OR l.checksum IS DISTINCT FROM e.checksum
        OR l.dirty IS DISTINCT FROM false
  ) THEN
    RAISE EXCEPTION '0020 migration ledger mismatch' USING ERRCODE = '55000';
  END IF;
END $ledger$;
-- Run with services stopped by one distinct trusted superuser in an exclusive administration window.
-- The legacy branch requires a dedicated cluster and exact <=0020 owner/ACL provenance.
DO $bootstrap$
DECLARE
  rec record;
  actual text[];
  db_oid oid := (SELECT oid FROM pg_database WHERE datname=current_database());
  role_oid oid;
  legacy_password text;
  legacy_branch boolean := EXISTS (SELECT 1 FROM pg_roles WHERE rolname='gotth_mail');
  expected constant text[] := ARRAY[
    'r:aliases','r:audit_events','r:backup_artifacts','r:backup_verifications','r:domains',
    'r:extension_instances','r:extension_operation_previews','r:extension_secrets',
    'r:final_queue_artifacts','r:final_queue_bindings','r:final_queue_recipients','r:final_queue_sources',
    'r:generated_config_sets','r:identity_group_role_mappings','r:identity_refs','r:mailboxes',
    'r:notification_actor_mappings','r:notification_approvals','r:notification_deliveries',
    'r:notification_event_states','r:notification_telegram_updates','r:oidc_login_states',
    'r:outbound_queue_messages','r:outbound_queue_recipients','r:outbound_queue_sources',
    'r:outbound_system_senders','r:plugin_registrations','r:relays','r:role_binding_group_sources',
    'r:role_bindings','r:schema_migrations','r:scim_group_members','r:scim_index_contracts',
    'r:scim_resource_indexes','r:scim_resources','r:scim_tombstones','r:sessions','r:snapshots',
    'r:tokens','r:webmail_drafts'
  ];
BEGIN
  IF session_user IN ('gotth_mail','gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim')
     OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=session_user AND rolsuper) THEN
    RAISE EXCEPTION 'upgrade requires a distinct trusted superuser installer' USING ERRCODE='42501';
  END IF;
  SELECT array_agg(c.relkind::text || ':' || c.relname ORDER BY c.relkind,c.relname) INTO actual
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f');
  IF actual IS DISTINCT FROM expected OR EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public'
  ) OR EXISTS (
    SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
     WHERE n.nspname='public' AND t.typtype IN ('c','d','e','r','m')
       AND NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.oid=t.typrelid)
  ) THEN
    RAISE EXCEPTION '0020 structural inventory mismatch' USING ERRCODE='55000';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_database d WHERE NOT d.datistemplate AND d.oid<>db_oid AND d.datname<>'postgres') THEN
    RAISE EXCEPTION 'upgrade requires dedicated current database plus clean postgres maintenance database' USING ERRCODE='55000';
  END IF;
  IF legacy_branch THEN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim')) THEN
      RAISE EXCEPTION 'legacy transition requires all seven target names absent' USING ERRCODE='55000';
    END IF;
    SELECT oid,rolpassword INTO role_oid,legacy_password FROM pg_authid
     WHERE rolname='gotth_mail' AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
       AND NOT rolinherit AND NOT rolreplication AND NOT rolbypassrls AND rolconnlimit=-1 AND rolvaliduntil IS NULL;
    IF role_oid IS NULL OR (legacy_password IS NOT NULL AND legacy_password !~ '^SCRAM-SHA-256\$[0-9]+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$') THEN
      RAISE EXCEPTION 'legacy role attributes/verifier provenance mismatch' USING ERRCODE='55000';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_auth_members WHERE roleid=role_oid OR member=role_oid)
       OR EXISTS (SELECT 1 FROM pg_db_role_setting WHERE setrole=role_oid)
       OR (SELECT datdba FROM pg_database WHERE oid=db_oid) <> role_oid
       OR EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                  WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')
                    AND (c.relowner<>role_oid OR c.relacl IS NOT NULL))
       OR EXISTS (SELECT 1 FROM pg_default_acl)
       OR EXISTS (SELECT 1 FROM pg_database WHERE oid=db_oid AND datacl IS NOT NULL)
       OR EXISTS (
         SELECT 1 FROM pg_namespace n WHERE n.nspname='public' AND (
           n.nspowner<>'pg_database_owner'::regrole
           OR EXISTS (SELECT 1 FROM aclexplode(n.nspacl) x WHERE NOT (
                (x.grantee=0 AND x.privilege_type='USAGE' AND NOT x.is_grantable)
             OR (x.grantee='pg_database_owner'::regrole AND x.privilege_type IN ('USAGE','CREATE'))))
           OR (SELECT count(*) FROM aclexplode(n.nspacl) x WHERE x.grantee=0 AND x.privilege_type='USAGE')<>1
           OR (SELECT count(*) FROM aclexplode(n.nspacl) x WHERE x.grantee='pg_database_owner'::regrole AND x.privilege_type IN ('USAGE','CREATE'))<>2
         )
       ) THEN
      RAISE EXCEPTION 'legacy owner/ACL provenance mismatch' USING ERRCODE='55000';
    END IF;
    IF EXISTS (
      SELECT 1 FROM pg_shdepend s WHERE s.refclassid='pg_authid'::regclass AND s.refobjid=role_oid
       AND (s.dbid NOT IN (0,db_oid) OR (s.dbid=0 AND NOT (s.classid='pg_database'::regclass AND s.objid=db_oid AND s.deptype='o')))
    ) OR EXISTS (
      SELECT 1 FROM pg_database d WHERE d.datname='postgres' AND NOT d.datistemplate
       AND (d.datdba=role_oid OR EXISTS (SELECT 1 FROM aclexplode(d.datacl) x WHERE x.grantee=role_oid))
    ) OR EXISTS (SELECT 1 FROM pg_stat_activity WHERE usesysid=role_oid)
      OR EXISTS (SELECT 1 FROM pg_prepared_xacts WHERE owner='gotth_mail') THEN
      RAISE EXCEPTION 'legacy role has remote dependency/session/prepared-transaction provenance' USING ERRCODE='55000';
    END IF;
    ALTER ROLE gotth_mail RENAME TO gotth_mail_app;
    CREATE ROLE gotth_mail_schema_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1;
    CREATE ROLE gotth_mail_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1;
    CREATE ROLE gotth_mail_gate NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1;
    CREATE ROLE gotth_mail_jobs NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1;
    CREATE ROLE gotth_mail_import NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1;
    CREATE ROLE gotth_mail_scim NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1;
    GRANT gotth_mail_schema_owner TO gotth_mail_migrator WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
    EXECUTE format('ALTER ROLE gotth_mail_migrator IN DATABASE %I SET role TO gotth_mail_schema_owner',current_database());
    EXECUTE format('ALTER DATABASE %I OWNER TO gotth_mail_schema_owner',current_database());
    EXECUTE format('REVOKE ALL PRIVILEGES ON DATABASE %I FROM PUBLIC,gotth_mail_schema_owner,gotth_mail_migrator,gotth_mail_app,gotth_mail_gate,gotth_mail_jobs,gotth_mail_import,gotth_mail_scim',current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO gotth_mail_migrator,gotth_mail_app',current_database());
    REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC,gotth_mail_schema_owner,gotth_mail_migrator,gotth_mail_app,gotth_mail_gate,gotth_mail_jobs,gotth_mail_import,gotth_mail_scim;
    GRANT USAGE ON SCHEMA public TO PUBLIC;
    GRANT USAGE,CREATE ON SCHEMA public TO gotth_mail_schema_owner;
    FOR rec IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='public' AND c.relkind='r' ORDER BY c.relname LOOP
      EXECUTE format('ALTER TABLE public.%I OWNER TO gotth_mail_schema_owner',rec.relname);
      EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.%I FROM PUBLIC,gotth_mail_migrator,gotth_mail_app,gotth_mail_gate,gotth_mail_jobs,gotth_mail_import,gotth_mail_scim',rec.relname);
      IF rec.relname='schema_migrations' THEN
        EXECUTE 'GRANT SELECT,INSERT,UPDATE ON public.schema_migrations TO gotth_mail_migrator';
        EXECUTE 'GRANT SELECT ON public.schema_migrations TO gotth_mail_app';
      ELSE
        EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.%I TO gotth_mail_app',rec.relname);
      END IF;
    END LOOP;
    IF (SELECT rolpassword FROM pg_authid WHERE rolname='gotth_mail_app') IS DISTINCT FROM legacy_password THEN
      RAISE EXCEPTION 'legacy verifier changed during rename' USING ERRCODE='55000';
    END IF;
    RETURN;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='gotth_mail') OR EXISTS (
    SELECT 1 FROM (VALUES
      ('gotth_mail_schema_owner',false),('gotth_mail_migrator',true),('gotth_mail_app',true),
      ('gotth_mail_gate',false),('gotth_mail_jobs',false),('gotth_mail_import',false),('gotth_mail_scim',false)
    ) e(name,canlogin) LEFT JOIN pg_authid a ON a.rolname=e.name
    WHERE a.oid IS NULL OR a.rolcanlogin IS DISTINCT FROM e.canlogin OR a.rolsuper OR a.rolcreatedb OR a.rolcreaterole
       OR a.rolinherit OR a.rolreplication OR a.rolbypassrls OR a.rolconnlimit<>-1 OR a.rolvaliduntil IS NOT NULL
       OR (e.name IN ('gotth_mail_app','gotth_mail_migrator') AND a.rolpassword IS NOT NULL AND a.rolpassword !~ '^SCRAM-SHA-256\$[0-9]+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$')
       OR (e.name NOT IN ('gotth_mail_app','gotth_mail_migrator') AND a.rolpassword IS NOT NULL)
  ) THEN
    RAISE EXCEPTION 'already-app exact role/verifier model mismatch' USING ERRCODE='55000';
  END IF;
  SELECT oid INTO role_oid FROM pg_roles WHERE rolname='gotth_mail_app';
  IF role_oid IS NULL OR (SELECT datdba FROM pg_database WHERE oid=db_oid) <> 'gotth_mail_schema_owner'::regrole
     OR EXISTS (SELECT 1 FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole
                WHERE r.rolname='gotth_mail_schema_owner' AND array_to_string(s.setconfig,',') LIKE '%gotth_mail.bootstrap_phase=%')
     OR (SELECT count(*) FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole
         WHERE r.rolname IN ('gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim')) <> 1
     OR NOT EXISTS (SELECT 1 FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole
                    WHERE r.rolname='gotth_mail_migrator' AND s.setdatabase=db_oid
                      AND s.setconfig=ARRAY['role=gotth_mail_schema_owner']::text[])
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles g ON g.oid=m.roleid JOIN pg_roles u ON u.oid=m.member
                WHERE (g.rolname IN ('gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim')
                    OR u.rolname IN ('gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim'))
                  AND NOT (g.rolname='gotth_mail_schema_owner' AND u.rolname='gotth_mail_migrator' AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option))
     OR (SELECT count(*) FROM pg_auth_members m JOIN pg_roles g ON g.oid=m.roleid JOIN pg_roles u ON u.oid=m.member
         WHERE g.rolname='gotth_mail_schema_owner' AND u.rolname='gotth_mail_migrator')<>1
     OR EXISTS (SELECT 1 FROM pg_default_acl) THEN
    RAISE EXCEPTION 'already-app completed settings/default ACL mismatch' USING ERRCODE='55000';
  END IF;
  IF EXISTS (
    WITH actual(owner_oid,grantor,grantee,privilege_type,is_grantable) AS (
      SELECT d.datdba,x.grantor,x.grantee,x.privilege_type,x.is_grantable
      FROM pg_database d CROSS JOIN LATERAL aclexplode(d.datacl) x WHERE d.oid=db_oid
    ), expected(owner_oid,grantor,grantee,privilege_type,is_grantable) AS (
      SELECT 'gotth_mail_schema_owner'::regrole::oid,'gotth_mail_schema_owner'::regrole::oid,
             v.grantee,'CONNECT'::text,false
      FROM (VALUES ('gotth_mail_app'::regrole::oid),('gotth_mail_migrator'::regrole::oid)) v(grantee)
    ), delta AS (
      (SELECT * FROM actual EXCEPT ALL SELECT * FROM expected)
      UNION ALL
      (SELECT * FROM expected EXCEPT ALL SELECT * FROM actual)
    ) SELECT 1 FROM delta
  ) OR EXISTS (
    WITH actual(owner_oid,grantor,grantee,privilege_type,is_grantable) AS (
      SELECT n.nspowner,x.grantor,x.grantee,x.privilege_type,x.is_grantable
      FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) x WHERE n.nspname='public'
    ), expected(owner_oid,grantor,grantee,privilege_type,is_grantable) AS (
      SELECT 'pg_database_owner'::regrole::oid,'pg_database_owner'::regrole::oid,v.grantee,v.privilege_type,false
      FROM (VALUES
        (0::oid,'USAGE'::text),
        ('pg_database_owner'::regrole::oid,'USAGE'::text),('pg_database_owner'::regrole::oid,'CREATE'::text),
        ('gotth_mail_schema_owner'::regrole::oid,'USAGE'::text),('gotth_mail_schema_owner'::regrole::oid,'CREATE'::text)
      ) v(grantee,privilege_type)
    ), delta AS (
      (SELECT * FROM actual EXCEPT ALL SELECT * FROM expected)
      UNION ALL
      (SELECT * FROM expected EXCEPT ALL SELECT * FROM actual)
    ) SELECT 1 FROM delta
  ) THEN
    RAISE EXCEPTION 'already-app completed database/schema ACL manifest mismatch' USING ERRCODE='55000';
  END IF;
  IF EXISTS (
    WITH objects AS (
      SELECT c.oid,c.relname,c.relowner,c.relacl
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relkind='r'
    ), actual(relname,owner_oid,grantor,grantee,privilege_type,is_grantable) AS (
      SELECT o.relname,o.relowner,x.grantor,x.grantee,x.privilege_type,x.is_grantable
      FROM objects o CROSS JOIN LATERAL aclexplode(o.relacl) x
    ), expected(relname,owner_oid,grantor,grantee,privilege_type,is_grantable) AS (
      SELECT o.relname,'gotth_mail_schema_owner'::regrole::oid,'gotth_mail_schema_owner'::regrole::oid,
             'gotth_mail_schema_owner'::regrole::oid,p.privilege_type,false
      FROM objects o CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),('REFERENCES'),('TRIGGER'),('MAINTAIN')) p(privilege_type)
      UNION ALL
      SELECT o.relname,'gotth_mail_schema_owner'::regrole::oid,'gotth_mail_schema_owner'::regrole::oid,
             'gotth_mail_app'::regrole::oid,p.privilege_type,false
      FROM objects o CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE')) p(privilege_type)
      WHERE o.relname<>'schema_migrations'
      UNION ALL
      SELECT 'schema_migrations','gotth_mail_schema_owner'::regrole::oid,'gotth_mail_schema_owner'::regrole::oid,
             'gotth_mail_app'::regrole::oid,'SELECT',false
      UNION ALL
      SELECT 'schema_migrations','gotth_mail_schema_owner'::regrole::oid,'gotth_mail_schema_owner'::regrole::oid,
             'gotth_mail_migrator'::regrole::oid,p.privilege_type,false
      FROM (VALUES ('SELECT'),('INSERT'),('UPDATE')) p(privilege_type)
    ), delta AS (
      (SELECT * FROM actual EXCEPT ALL SELECT * FROM expected)
      UNION ALL
      (SELECT * FROM expected EXCEPT ALL SELECT * FROM actual)
    ) SELECT 1 FROM delta
  ) THEN
    RAISE EXCEPTION 'already-app object owner/ACL manifest mismatch' USING ERRCODE='55000';
  END IF;
  IF EXISTS (
    WITH product_roles(oid) AS (
      SELECT oid FROM pg_roles WHERE rolname IN ('gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim')
    ), objects AS (
      SELECT c.oid,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relkind='r'
    ), actual(dbid,classid,objid,objsubid,refobjid,deptype) AS (
      SELECT s.dbid,s.classid,s.objid,s.objsubid,s.refobjid,s.deptype::text
      FROM pg_shdepend s WHERE s.refclassid='pg_authid'::regclass AND s.refobjid IN (SELECT oid FROM product_roles)
    ), expected(dbid,classid,objid,objsubid,refobjid,deptype) AS (
      SELECT 0::oid,'pg_database'::regclass::oid,db_oid,0,'gotth_mail_schema_owner'::regrole::oid,'o'::text
      UNION ALL SELECT 0::oid,'pg_database'::regclass::oid,db_oid,0,'gotth_mail_app'::regrole::oid,'a'::text
      UNION ALL SELECT 0::oid,'pg_database'::regclass::oid,db_oid,0,'gotth_mail_migrator'::regrole::oid,'a'::text
      UNION ALL SELECT db_oid,'pg_namespace'::regclass::oid,n.oid,0,'gotth_mail_schema_owner'::regrole::oid,'a'::text FROM pg_namespace n WHERE n.nspname='public'
      UNION ALL SELECT db_oid,'pg_class'::regclass::oid,o.oid,0,'gotth_mail_schema_owner'::regrole::oid,'o'::text FROM objects o
      UNION ALL SELECT db_oid,'pg_class'::regclass::oid,o.oid,0,'gotth_mail_app'::regrole::oid,'a'::text FROM objects o
      UNION ALL SELECT db_oid,'pg_class'::regclass::oid,o.oid,0,'gotth_mail_migrator'::regrole::oid,'a'::text FROM objects o WHERE o.relname='schema_migrations'
    ), delta AS (
      (SELECT * FROM actual EXCEPT ALL SELECT * FROM expected)
      UNION ALL
      (SELECT * FROM expected EXCEPT ALL SELECT * FROM actual)
    ) SELECT 1 FROM delta
  ) THEN
    RAISE EXCEPTION 'already-app shared/current-database dependency manifest mismatch' USING ERRCODE='55000';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_database d WHERE d.datname='postgres' AND NOT d.datistemplate
             AND (d.datdba IN (SELECT oid FROM pg_roles WHERE rolname IN ('gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim'))
               OR EXISTS (SELECT 1 FROM aclexplode(d.datacl) x WHERE x.grantee IN (SELECT oid FROM pg_roles WHERE rolname IN ('gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim')))))
     OR EXISTS (SELECT 1 FROM pg_stat_activity WHERE usesysid IN (SELECT oid FROM pg_roles WHERE rolname IN ('gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim')))
     OR EXISTS (SELECT 1 FROM pg_prepared_xacts WHERE owner IN ('gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim')) THEN
    RAISE EXCEPTION 'already-app remote dependency/session topology mismatch' USING ERRCODE='55000';
  END IF;
  -- exact completed <=0020 rerun: deliberately no mutation.
END $bootstrap$;
COMMIT;
