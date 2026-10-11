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
-- Run after an exact <=0020 fresh foundation was created under the schema-owner default role.
-- This sealed inventory grants the runtime data plane and ledger ACL before 0021.
-- Any inventory mismatch aborts; regenerate and review a new explicit-inventory script.
DO $bootstrap$
DECLARE
  actual text[];
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
  SELECT array_agg(c.relkind::text || ':' || c.relname ORDER BY c.relkind, c.relname)
    INTO actual
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind IN ('r','p','v','m','S','f');
  IF actual IS DISTINCT FROM expected THEN
    RAISE EXCEPTION '0020 ownership inventory mismatch' USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='public'
  ) OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
     WHERE n.nspname='public' AND t.typtype IN ('c','d','e','r','m')
       AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=t.typrelid)
  ) THEN
    RAISE EXCEPTION '0020 callable/type ownership inventory mismatch' USING ERRCODE = '55000';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='gotth_mail') OR EXISTS (
    SELECT 1 FROM (VALUES
      ('gotth_mail_schema_owner',false),('gotth_mail_migrator',true),('gotth_mail_app',false),
      ('gotth_mail_gate',false),('gotth_mail_jobs',false),('gotth_mail_import',false),('gotth_mail_scim',false)
    ) e(name,canlogin) LEFT JOIN pg_authid a ON a.rolname=e.name
    WHERE a.oid IS NULL OR a.rolcanlogin IS DISTINCT FROM e.canlogin
       OR a.rolsuper OR a.rolcreatedb OR a.rolcreaterole OR a.rolinherit OR a.rolreplication OR a.rolbypassrls
       OR a.rolconnlimit <> -1 OR a.rolvaliduntil IS NOT NULL
       OR (e.name IN ('gotth_mail_app','gotth_mail_migrator') AND (a.rolpassword IS NULL OR a.rolpassword !~ '^SCRAM-SHA-256\$[0-9]+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$'))
  ) THEN
    RAISE EXCEPTION 'fresh-0020 roles/verifiers do not match prefix-ready model' USING ERRCODE='55000';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_auth_members m JOIN pg_roles g ON g.oid=m.roleid JOIN pg_roles u ON u.oid=m.member
    WHERE (g.rolname IN ('gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim')
        OR u.rolname IN ('gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim'))
      AND NOT (g.rolname='gotth_mail_schema_owner' AND u.rolname='gotth_mail_migrator'
               AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)
  ) OR (SELECT count(*) FROM pg_auth_members m JOIN pg_roles g ON g.oid=m.roleid JOIN pg_roles u ON u.oid=m.member
         WHERE g.rolname='gotth_mail_schema_owner' AND u.rolname='gotth_mail_migrator') <> 1 THEN
    RAISE EXCEPTION 'fresh-0020 membership mismatch' USING ERRCODE='55000';
  END IF;
  IF (SELECT count(*) FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole
       WHERE r.rolname IN ('gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim')) <> 2
     OR NOT EXISTS (
       SELECT 1 FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole
       WHERE r.rolname='gotth_mail_schema_owner' AND s.setdatabase=(SELECT oid FROM pg_database WHERE datname=current_database())
         AND s.setconfig=ARRAY['gotth_mail.bootstrap_phase=fresh-v1-prefix-ready']::text[]
     ) OR NOT EXISTS (
       SELECT 1 FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole
       WHERE r.rolname='gotth_mail_migrator' AND s.setdatabase=(SELECT oid FROM pg_database WHERE datname=current_database())
         AND s.setconfig=ARRAY['role=gotth_mail_schema_owner']::text[]
     ) THEN
    RAISE EXCEPTION 'fresh-0020 phase/settings mismatch' USING ERRCODE='55000';
  END IF;
  IF EXISTS (
    WITH owner_role(oid) AS (SELECT oid FROM pg_roles WHERE rolname=session_user),
    actual(owner_oid,grantor,grantee,privilege_type,is_grantable) AS (
      SELECT d.datdba,x.grantor,x.grantee,x.privilege_type,x.is_grantable
      FROM pg_database d CROSS JOIN LATERAL aclexplode(d.datacl) x
      WHERE d.datname=current_database()
    ), expected(owner_oid,grantor,grantee,privilege_type,is_grantable) AS (
      SELECT o.oid,o.oid,
             CASE v.grantee_kind WHEN 'public' THEN 0::oid WHEN 'owner' THEN o.oid ELSE 'gotth_mail_migrator'::regrole::oid END,
             v.privilege_type,false
      FROM owner_role o CROSS JOIN (VALUES
        ('public','CONNECT'::text),('public','TEMPORARY'::text),
        ('owner','CONNECT'::text),('owner','CREATE'::text),('owner','TEMPORARY'::text),
        ('migrator','CONNECT'::text)
      ) v(grantee_kind,privilege_type)
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
    RAISE EXCEPTION 'fresh-0020 transitional database/schema ACL provenance mismatch' USING ERRCODE='55000';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_default_acl d JOIN pg_roles r ON r.oid=d.defaclrole
             WHERE r.rolname IN ('gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim')) THEN
    RAISE EXCEPTION 'fresh-0020 unexpected product default ACL' USING ERRCODE='55000';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner
    WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')
      AND (r.rolname<>'gotth_mail_schema_owner' OR c.relacl IS NOT NULL)
  ) THEN
    RAISE EXCEPTION 'fresh-0020 prefix owner/ACL provenance mismatch' USING ERRCODE='55000';
  END IF;
END $bootstrap$;
DO $cutover$
DECLARE r record;
BEGIN
  EXECUTE format('ALTER DATABASE %I OWNER TO gotth_mail_schema_owner', current_database());
  EXECUTE format('REVOKE ALL PRIVILEGES ON DATABASE %I FROM PUBLIC,gotth_mail_schema_owner,gotth_mail_migrator,gotth_mail_app,gotth_mail_gate,gotth_mail_jobs,gotth_mail_import,gotth_mail_scim', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO gotth_mail_migrator,gotth_mail_app', current_database());
  REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC,gotth_mail_schema_owner,gotth_mail_migrator,gotth_mail_app,gotth_mail_gate,gotth_mail_jobs,gotth_mail_import,gotth_mail_scim;
  GRANT USAGE ON SCHEMA public TO PUBLIC;
  GRANT USAGE,CREATE ON SCHEMA public TO gotth_mail_schema_owner;
  FOR r IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relkind='r' ORDER BY c.relname LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO gotth_mail_schema_owner',r.relname);
    EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.%I FROM PUBLIC,gotth_mail_migrator,gotth_mail_app,gotth_mail_gate,gotth_mail_jobs,gotth_mail_import,gotth_mail_scim',r.relname);
  END LOOP;
END $cutover$;
-- restore the app data-plane subset of former ownership; deliberately no DDL/TRIGGER/TRUNCATE/REFERENCES
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.aliases TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.audit_events TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.backup_artifacts TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.backup_verifications TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.domains TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.extension_instances TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.extension_operation_previews TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.extension_secrets TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.final_queue_artifacts TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.final_queue_bindings TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.final_queue_recipients TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.final_queue_sources TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.generated_config_sets TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.identity_group_role_mappings TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.identity_refs TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.mailboxes TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.notification_actor_mappings TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.notification_approvals TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.notification_deliveries TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.notification_event_states TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.notification_telegram_updates TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.oidc_login_states TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.outbound_queue_messages TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.outbound_queue_recipients TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.outbound_queue_sources TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.outbound_system_senders TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.plugin_registrations TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.relays TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.role_binding_group_sources TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.role_bindings TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.scim_group_members TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.scim_index_contracts TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.scim_resource_indexes TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.scim_resources TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.scim_tombstones TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.sessions TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.snapshots TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.tokens TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE public.webmail_drafts TO gotth_mail_app;
GRANT SELECT,INSERT,UPDATE ON public.schema_migrations TO gotth_mail_migrator;
REVOKE ALL ON public.schema_migrations FROM gotth_mail_app,gotth_mail_gate,gotth_mail_jobs,gotth_mail_import,gotth_mail_scim;
GRANT SELECT ON public.schema_migrations TO gotth_mail_app;

ALTER ROLE gotth_mail_app LOGIN;
DO $phase$ BEGIN EXECUTE format('ALTER ROLE gotth_mail_schema_owner IN DATABASE %I RESET gotth_mail.bootstrap_phase', current_database()); END $phase$;
COMMIT;
