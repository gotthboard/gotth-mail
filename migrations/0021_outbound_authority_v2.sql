SELECT pg_advisory_xact_lock(0x474d4131::int, 21);

DO $p$
DECLARE n text;
BEGIN
  IF session_user <> 'gotth_mail_migrator' OR current_user <> 'gotth_mail_schema_owner' THEN
    RAISE EXCEPTION '0021_migrator_principal_required' USING ERRCODE='42501';
  END IF;
  FOREACH n IN ARRAY ARRAY['gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=n) THEN RAISE EXCEPTION '0021_role_preflight_missing:%',n USING ERRCODE='55000'; END IF;
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='gotth_mail_schema_owner' AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolcanlogin OR rolreplication OR rolbypassrls)) THEN
    RAISE EXCEPTION '0021_schema_owner_attributes' USING ERRCODE='55000';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='gotth_mail_migrator' AND (NOT rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
    RAISE EXCEPTION '0021_migrator_attributes' USING ERRCODE='55000';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles g ON g.oid=m.roleid JOIN pg_roles u ON u.oid=m.member WHERE g.rolname='gotth_mail_schema_owner' AND u.rolname='gotth_mail_migrator' AND m.set_option) THEN
    RAISE EXCEPTION '0021_migrator_membership' USING ERRCODE='55000';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles g ON g.oid=m.roleid JOIN pg_roles u ON u.oid=m.member WHERE g.rolname IN ('gotth_mail_schema_owner','gotth_mail_migrator') AND u.rolname IN ('gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim')) THEN
    RAISE EXCEPTION '0021_runtime_role_membership' USING ERRCODE='55000';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.pid<>pg_backend_pid() AND a.datname=current_database() AND a.usename IN ('gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim')) THEN
    RAISE EXCEPTION '0021_outage_runtime_sessions' USING ERRCODE='55000';
  END IF;
END $p$;
LOCK TABLE public.outbound_queue_messages IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.final_queue_bindings IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.final_queue_artifacts IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.final_queue_recipients IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.final_queue_sources IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.domains IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.scim_resources IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.scim_tombstones IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.mailboxes IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.aliases IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.outbound_system_senders IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.audit_events IN ACCESS EXCLUSIVE MODE;

CREATE FUNCTION public.gotth_is_canonical_domain(v text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog
AS $$ SELECT octet_length(v) BETWEEN 1 AND 253 AND v=lower(v COLLATE "C") AND v ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$' $$;
CREATE FUNCTION public.gotth_is_authority_local_part(v text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path=pg_catalog
AS $$ SELECT octet_length(v) BETWEEN 1 AND 64 AND v=lower(v COLLATE "C") AND v ~ $re$^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$re$ $$;

DO $p$
DECLARE detail text;
BEGIN
 SELECT string_agg(x,'; ' ORDER BY x) INTO detail FROM (
   SELECT 'domain:'||id||':'||name x FROM public.domains WHERE NOT public.gotth_is_canonical_domain(name)
   UNION ALL SELECT 'mailbox:'||id||':'||local_part FROM public.mailboxes WHERE NOT public.gotth_is_authority_local_part(local_part)
   UNION ALL SELECT 'alias:'||id||':'||local_part FROM public.aliases WHERE NOT public.gotth_is_authority_local_part(local_part)
   UNION ALL SELECT 'mailbox_address_too_long:'||m.id FROM public.mailboxes m JOIN public.domains d ON d.id=m.domain_id WHERE octet_length(m.local_part||'@'||d.name)>254
   UNION ALL SELECT 'alias_address_too_long:'||a.id FROM public.aliases a JOIN public.domains d ON d.id=a.domain_id WHERE octet_length(a.local_part||'@'||d.name)>254
   UNION ALL SELECT 'mailbox_casefold_collision:'||domain_id||':'||lower(local_part COLLATE "C") FROM public.mailboxes GROUP BY domain_id,lower(local_part COLLATE "C") HAVING count(*)>1
   UNION ALL SELECT 'alias_casefold_collision:'||domain_id||':'||lower(local_part COLLATE "C") FROM public.aliases GROUP BY domain_id,lower(local_part COLLATE "C") HAVING count(*)>1
   UNION ALL SELECT 'enabled_mailbox_alias_collision:'||m.domain_id||':'||lower(m.local_part COLLATE "C") FROM public.mailboxes m JOIN public.aliases a ON a.domain_id=m.domain_id AND lower(a.local_part COLLATE "C")=lower(m.local_part COLLATE "C") WHERE m.enabled AND a.enabled
   UNION ALL SELECT 'system_sender_domain_mismatch:'||s.id FROM public.outbound_system_senders s JOIN public.domains d ON d.id=s.domain_id WHERE s.enabled AND (s.address<>lower(s.address COLLATE "C") OR split_part(s.address,'@',2)<>d.name OR octet_length(s.address)>254)
 ) q;
 IF detail IS NOT NULL THEN RAISE EXCEPTION '0021_canonical_preflight:%',detail USING ERRCODE='23514'; END IF;
END $p$;

ALTER TABLE public.domains ADD CONSTRAINT domains_authority_name_check CHECK(public.gotth_is_canonical_domain(name));
ALTER TABLE public.mailboxes ADD CONSTRAINT mailboxes_authority_local_check CHECK(public.gotth_is_authority_local_part(local_part));
ALTER TABLE public.aliases ADD CONSTRAINT aliases_authority_local_check CHECK(public.gotth_is_authority_local_part(local_part));
CREATE UNIQUE INDEX mailboxes_domain_local_ci_uq ON public.mailboxes(domain_id,lower(local_part COLLATE "C"));
CREATE UNIQUE INDEX aliases_domain_local_ci_uq ON public.aliases(domain_id,lower(local_part COLLATE "C"));

CREATE TABLE public.outbound_authority_epoch(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),epoch char(64) NOT NULL UNIQUE CHECK(epoch ~ '^[0-9a-f]{64}$'));
INSERT INTO public.outbound_authority_epoch(singleton,epoch) VALUES(true,lower(replace(gen_random_uuid()::text,'-','')||replace(gen_random_uuid()::text,'-','')));
CREATE SEQUENCE public.outbound_authority_generation_seq AS bigint MINVALUE 1 MAXVALUE 9223372036854775807 NO CYCLE;
ALTER TABLE public.domains ADD COLUMN authority_generation bigint, ADD COLUMN authority_revision bigint;
ALTER TABLE public.mailboxes ADD COLUMN authority_generation bigint, ADD COLUMN revision bigint;
ALTER TABLE public.aliases ADD COLUMN authority_generation bigint, ADD COLUMN revision bigint;
ALTER TABLE public.outbound_system_senders ADD COLUMN authority_generation bigint, ALTER COLUMN revision DROP DEFAULT;
DO $p$ DECLARE r record; BEGIN
 FOR r IN SELECT id FROM public.domains ORDER BY id LOOP UPDATE public.domains SET authority_generation=nextval('public.outbound_authority_generation_seq'),authority_revision=1 WHERE id=r.id; END LOOP;
 FOR r IN SELECT id FROM public.mailboxes ORDER BY id LOOP UPDATE public.mailboxes SET authority_generation=nextval('public.outbound_authority_generation_seq'),revision=1 WHERE id=r.id; END LOOP;
 FOR r IN SELECT id FROM public.aliases ORDER BY id LOOP UPDATE public.aliases SET authority_generation=nextval('public.outbound_authority_generation_seq'),revision=1 WHERE id=r.id; END LOOP;
 FOR r IN SELECT id FROM public.outbound_system_senders ORDER BY id LOOP UPDATE public.outbound_system_senders SET authority_generation=nextval('public.outbound_authority_generation_seq') WHERE id=r.id; END LOOP;
END $p$;
ALTER TABLE public.domains ALTER COLUMN authority_generation SET NOT NULL,ALTER COLUMN authority_revision SET NOT NULL,ADD CONSTRAINT domains_authority_generation_check CHECK(authority_generation>0),ADD CONSTRAINT domains_authority_revision_check CHECK(authority_revision>0);
ALTER TABLE public.mailboxes ALTER COLUMN authority_generation SET NOT NULL,ALTER COLUMN revision SET NOT NULL,ADD CONSTRAINT mailboxes_authority_generation_check CHECK(authority_generation>0),ADD CONSTRAINT mailboxes_revision_check CHECK(revision>0);
ALTER TABLE public.aliases ALTER COLUMN authority_generation SET NOT NULL,ALTER COLUMN revision SET NOT NULL,ADD CONSTRAINT aliases_authority_generation_check CHECK(authority_generation>0),ADD CONSTRAINT aliases_revision_check CHECK(revision>0);
ALTER TABLE public.outbound_system_senders ALTER COLUMN authority_generation SET NOT NULL,ADD CONSTRAINT outbound_system_senders_generation_check CHECK(authority_generation>0);

CREATE TABLE public.signing_identities(
 id uuid PRIMARY KEY,mailbox_id uuid NOT NULL REFERENCES public.mailboxes(id) ON DELETE RESTRICT,address text NOT NULL,
 fingerprint text NOT NULL CHECK(fingerprint ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),key_ref text NOT NULL CHECK(length(key_ref) BETWEEN 1 AND 1024 AND key_ref !~ '[[:cntrl:]]'),
 context text NOT NULL CHECK(context='forward'),enabled boolean NOT NULL DEFAULT false,authority_generation bigint NOT NULL CHECK(authority_generation>0),revision bigint NOT NULL CHECK(revision>0),
 created_at timestamp(6) NOT NULL,updated_at timestamp(6) NOT NULL CHECK(updated_at>=created_at),CHECK(length(address) BETWEEN 3 AND 254 AND address=lower(address COLLATE "C") AND address !~ '[[:cntrl:]]'));
CREATE UNIQUE INDEX signing_identities_enabled_fingerprint_uq ON public.signing_identities(fingerprint) WHERE enabled;
CREATE UNIQUE INDEX signing_identities_enabled_mailbox_context_uq ON public.signing_identities(mailbox_id,context) WHERE enabled;
CREATE INDEX signing_identities_mailbox_idx ON public.signing_identities(mailbox_id,id);
CREATE TABLE public.forward_signers(
 id uuid PRIMARY KEY,source_kind text NOT NULL CHECK(source_kind IN ('alias','forward','list','catch_all')),alias_id uuid NOT NULL REFERENCES public.aliases(id) ON DELETE RESTRICT,
 local_mailbox_id uuid NOT NULL REFERENCES public.mailboxes(id) ON DELETE RESTRICT,signing_identity_id uuid NOT NULL REFERENCES public.signing_identities(id) ON DELETE RESTRICT,
 context text NOT NULL CHECK(context='forward'),enabled boolean NOT NULL DEFAULT false,authority_generation bigint NOT NULL CHECK(authority_generation>0),revision bigint NOT NULL CHECK(revision>0),
 created_at timestamp(6) NOT NULL,updated_at timestamp(6) NOT NULL CHECK(updated_at>=created_at));
CREATE UNIQUE INDEX forward_signers_enabled_source_uq ON public.forward_signers(alias_id,source_kind,context) WHERE enabled;
CREATE INDEX forward_signers_mailbox_idx ON public.forward_signers(local_mailbox_id,id);
CREATE INDEX forward_signers_signer_idx ON public.forward_signers(signing_identity_id,id);

ALTER TABLE public.final_queue_artifacts ADD COLUMN authority_version smallint NOT NULL DEFAULT 1,ADD COLUMN authority_epoch char(64) NULL,ADD COLUMN local_identity_address text NULL,
 ADD COLUMN local_mailbox_revision bigint NULL,ADD COLUMN local_mailbox_generation bigint NULL,ADD COLUMN local_domain_id uuid NULL,ADD COLUMN local_domain_generation bigint NULL,
 ADD COLUMN local_domain_authority_revision bigint NULL,ADD COLUMN local_scim_resource_id text NULL,ADD COLUMN signing_identity_ref_id uuid NULL,ADD COLUMN signer_address text NULL,
 ADD COLUMN signer_context text NULL,ADD COLUMN signer_revision bigint NULL,ADD COLUMN signer_generation bigint NULL,
 ADD CONSTRAINT final_queue_artifacts_authority_v1_only CHECK(authority_version=1),ADD CONSTRAINT final_queue_artifacts_authority_version_check CHECK(authority_version IN(1,2));
ALTER TABLE public.final_queue_sources ADD COLUMN source_generation bigint NULL,ADD COLUMN source_domain_id uuid NULL,ADD COLUMN source_domain_generation bigint NULL,
 ADD COLUMN source_domain_authority_revision bigint NULL,ADD COLUMN source_address text NULL,ADD COLUMN alias_targets_sha256 text NULL;
CREATE TABLE public.final_queue_forward_signers(
 artifact_id text NOT NULL REFERENCES public.final_queue_artifacts(artifact_id) ON DELETE CASCADE,source_kind text NOT NULL CHECK(source_kind IN ('alias','forward','list','catch_all')),
 source_id uuid NOT NULL REFERENCES public.aliases(id) ON DELETE RESTRICT,mapping_id uuid NOT NULL REFERENCES public.forward_signers(id) ON DELETE RESTRICT,
 mapping_revision bigint NOT NULL CHECK(mapping_revision>0),mapping_generation bigint NOT NULL CHECK(mapping_generation>0),alias_id uuid NOT NULL REFERENCES public.aliases(id) ON DELETE RESTRICT,
 local_mailbox_id uuid NOT NULL REFERENCES public.mailboxes(id) ON DELETE RESTRICT,signing_identity_id uuid NOT NULL REFERENCES public.signing_identities(id) ON DELETE RESTRICT,
 context text NOT NULL CHECK(context='forward'),ordinal integer NOT NULL CHECK(ordinal>=0),PRIMARY KEY(artifact_id,source_kind,source_id),UNIQUE(artifact_id,ordinal));

CREATE FUNCTION public.set_domain_authority() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN
 IF TG_OP='INSERT' THEN IF NEW.authority_generation IS NOT NULL OR NEW.authority_revision IS NOT NULL THEN RAISE EXCEPTION 'manual domain authority insert' USING ERRCODE='42501';END IF;NEW.authority_generation:=nextval('public.outbound_authority_generation_seq');NEW.authority_revision:=1;
 ELSE IF NEW.authority_generation IS DISTINCT FROM OLD.authority_generation OR NEW.authority_revision IS DISTINCT FROM OLD.authority_revision THEN RAISE EXCEPTION 'manual domain authority edit' USING ERRCODE='42501';END IF;IF ROW(NEW.name,NEW.enabled) IS DISTINCT FROM ROW(OLD.name,OLD.enabled) THEN IF OLD.authority_revision=9223372036854775807 THEN RAISE EXCEPTION 'domain revision overflow' USING ERRCODE='22003';END IF;NEW.authority_revision:=OLD.authority_revision+1;END IF;END IF;RETURN NEW;
END $f$;
CREATE FUNCTION public.set_mailbox_authority() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN
 IF TG_OP='INSERT' THEN IF NEW.authority_generation IS NOT NULL OR NEW.revision IS NOT NULL THEN RAISE EXCEPTION 'manual mailbox authority insert' USING ERRCODE='42501';END IF;NEW.authority_generation:=nextval('public.outbound_authority_generation_seq');NEW.revision:=1;
 ELSE IF NEW.authority_generation IS DISTINCT FROM OLD.authority_generation OR NEW.revision IS DISTINCT FROM OLD.revision THEN RAISE EXCEPTION 'manual mailbox authority edit' USING ERRCODE='42501';END IF;IF ROW(NEW.domain_id,NEW.local_part,NEW.enabled,NEW.scim_resource_id) IS DISTINCT FROM ROW(OLD.domain_id,OLD.local_part,OLD.enabled,OLD.scim_resource_id) THEN IF OLD.revision=9223372036854775807 THEN RAISE EXCEPTION 'mailbox revision overflow' USING ERRCODE='22003';END IF;NEW.revision:=OLD.revision+1;END IF;END IF;RETURN NEW;
END $f$;
CREATE FUNCTION public.set_alias_authority() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN
 IF TG_OP='INSERT' THEN IF NEW.authority_generation IS NOT NULL OR NEW.revision IS NOT NULL THEN RAISE EXCEPTION 'manual alias authority insert' USING ERRCODE='42501';END IF;NEW.authority_generation:=nextval('public.outbound_authority_generation_seq');NEW.revision:=1;
 ELSE IF NEW.authority_generation IS DISTINCT FROM OLD.authority_generation OR NEW.revision IS DISTINCT FROM OLD.revision THEN RAISE EXCEPTION 'manual alias authority edit' USING ERRCODE='42501';END IF;IF ROW(NEW.domain_id,NEW.local_part,NEW.targets_json,NEW.enabled) IS DISTINCT FROM ROW(OLD.domain_id,OLD.local_part,OLD.targets_json,OLD.enabled) THEN IF OLD.revision=9223372036854775807 THEN RAISE EXCEPTION 'alias revision overflow' USING ERRCODE='22003';END IF;NEW.revision:=OLD.revision+1;END IF;END IF;RETURN NEW;
END $f$;
CREATE FUNCTION public.set_system_sender_authority() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN
 IF TG_OP='INSERT' THEN IF NEW.authority_generation IS NOT NULL THEN RAISE EXCEPTION 'manual system authority insert' USING ERRCODE='42501';END IF;NEW.authority_generation:=nextval('public.outbound_authority_generation_seq');NEW.revision:=coalesce(NEW.revision,1);
 ELSE IF NEW.authority_generation IS DISTINCT FROM OLD.authority_generation OR NEW.revision IS DISTINCT FROM OLD.revision THEN RAISE EXCEPTION 'manual system authority edit' USING ERRCODE='42501';END IF;IF ROW(NEW.domain_id,NEW.address,NEW.enabled) IS DISTINCT FROM ROW(OLD.domain_id,OLD.address,OLD.enabled) THEN IF OLD.revision=9223372036854775807 THEN RAISE EXCEPTION 'system revision overflow' USING ERRCODE='22003';END IF;NEW.revision:=OLD.revision+1;END IF;END IF;RETURN NEW;
END $f$;
CREATE FUNCTION public.set_signing_identity_authority() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN
 IF TG_OP='INSERT' THEN IF NEW.authority_generation IS NOT NULL OR NEW.revision IS NOT NULL THEN RAISE EXCEPTION 'manual signer authority insert' USING ERRCODE='42501';END IF;NEW.authority_generation:=nextval('public.outbound_authority_generation_seq');NEW.revision:=1;
 ELSE IF NEW.authority_generation IS DISTINCT FROM OLD.authority_generation OR NEW.revision IS DISTINCT FROM OLD.revision THEN RAISE EXCEPTION 'manual signer authority edit' USING ERRCODE='42501';END IF;IF ROW(NEW.mailbox_id,NEW.address,NEW.fingerprint,NEW.key_ref,NEW.context,NEW.enabled) IS DISTINCT FROM ROW(OLD.mailbox_id,OLD.address,OLD.fingerprint,OLD.key_ref,OLD.context,OLD.enabled) THEN IF OLD.revision=9223372036854775807 THEN RAISE EXCEPTION 'signer revision overflow' USING ERRCODE='22003';END IF;NEW.revision:=OLD.revision+1;END IF;END IF;RETURN NEW;
END $f$;
CREATE FUNCTION public.set_forward_signer_authority() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $f$
BEGIN
 IF TG_OP='INSERT' THEN IF NEW.authority_generation IS NOT NULL OR NEW.revision IS NOT NULL THEN RAISE EXCEPTION 'manual mapping authority insert' USING ERRCODE='42501';END IF;NEW.authority_generation:=nextval('public.outbound_authority_generation_seq');NEW.revision:=1;
 ELSE IF NEW.authority_generation IS DISTINCT FROM OLD.authority_generation OR NEW.revision IS DISTINCT FROM OLD.revision THEN RAISE EXCEPTION 'manual mapping authority edit' USING ERRCODE='42501';END IF;IF ROW(NEW.source_kind,NEW.alias_id,NEW.local_mailbox_id,NEW.signing_identity_id,NEW.context,NEW.enabled) IS DISTINCT FROM ROW(OLD.source_kind,OLD.alias_id,OLD.local_mailbox_id,OLD.signing_identity_id,OLD.context,OLD.enabled) THEN IF OLD.revision=9223372036854775807 THEN RAISE EXCEPTION 'mapping revision overflow' USING ERRCODE='22003';END IF;NEW.revision:=OLD.revision+1;END IF;END IF;RETURN NEW;
END $f$;
CREATE TRIGGER domains_authority_biu BEFORE INSERT OR UPDATE ON public.domains FOR EACH ROW EXECUTE FUNCTION public.set_domain_authority();
CREATE TRIGGER mailboxes_authority_biu BEFORE INSERT OR UPDATE ON public.mailboxes FOR EACH ROW EXECUTE FUNCTION public.set_mailbox_authority();
CREATE TRIGGER aliases_authority_biu BEFORE INSERT OR UPDATE ON public.aliases FOR EACH ROW EXECUTE FUNCTION public.set_alias_authority();
CREATE TRIGGER outbound_system_senders_authority_biu BEFORE INSERT OR UPDATE ON public.outbound_system_senders FOR EACH ROW EXECUTE FUNCTION public.set_system_sender_authority();
CREATE TRIGGER signing_identities_authority_biu BEFORE INSERT OR UPDATE ON public.signing_identities FOR EACH ROW EXECUTE FUNCTION public.set_signing_identity_authority();
CREATE TRIGGER forward_signers_authority_biu BEFORE INSERT OR UPDATE ON public.forward_signers FOR EACH ROW EXECUTE FUNCTION public.set_forward_signer_authority();

REVOKE ALL ON public.outbound_authority_epoch,public.signing_identities,public.forward_signers,public.final_queue_forward_signers FROM PUBLIC,gotth_mail_app,gotth_mail_gate,gotth_mail_jobs,gotth_mail_import,gotth_mail_scim;
REVOKE ALL ON SEQUENCE public.outbound_authority_generation_seq FROM PUBLIC,gotth_mail_app,gotth_mail_gate,gotth_mail_jobs,gotth_mail_import,gotth_mail_scim;
GRANT SELECT ON public.outbound_authority_epoch,public.signing_identities,public.forward_signers,public.final_queue_forward_signers TO gotth_mail_app,gotth_mail_gate;
REVOKE ALL ON FUNCTION public.gotth_is_canonical_domain(text),public.gotth_is_authority_local_part(text) FROM PUBLIC,gotth_mail_app,gotth_mail_gate,gotth_mail_jobs,gotth_mail_import,gotth_mail_scim;
GRANT EXECUTE ON FUNCTION public.gotth_is_canonical_domain(text),public.gotth_is_authority_local_part(text) TO gotth_mail_app,gotth_mail_scim,gotth_mail_import;
REVOKE ALL ON FUNCTION public.set_domain_authority(),public.set_mailbox_authority(),public.set_alias_authority(),public.set_system_sender_authority(),public.set_signing_identity_authority(),public.set_forward_signer_authority() FROM PUBLIC,gotth_mail_app,gotth_mail_gate,gotth_mail_jobs,gotth_mail_import,gotth_mail_scim;

ALTER FUNCTION public.gotth_is_canonical_domain(text) OWNER TO gotth_mail_schema_owner;
ALTER FUNCTION public.gotth_is_authority_local_part(text) OWNER TO gotth_mail_schema_owner;
ALTER FUNCTION public.set_domain_authority() OWNER TO gotth_mail_schema_owner;
ALTER FUNCTION public.set_mailbox_authority() OWNER TO gotth_mail_schema_owner;
ALTER FUNCTION public.set_alias_authority() OWNER TO gotth_mail_schema_owner;
ALTER FUNCTION public.set_system_sender_authority() OWNER TO gotth_mail_schema_owner;
ALTER FUNCTION public.set_signing_identity_authority() OWNER TO gotth_mail_schema_owner;
ALTER FUNCTION public.set_forward_signer_authority() OWNER TO gotth_mail_schema_owner;
ALTER TABLE public.outbound_authority_epoch OWNER TO gotth_mail_schema_owner;
ALTER SEQUENCE public.outbound_authority_generation_seq OWNER TO gotth_mail_schema_owner;
ALTER TABLE public.signing_identities OWNER TO gotth_mail_schema_owner;
ALTER TABLE public.forward_signers OWNER TO gotth_mail_schema_owner;
ALTER TABLE public.final_queue_forward_signers OWNER TO gotth_mail_schema_owner;
