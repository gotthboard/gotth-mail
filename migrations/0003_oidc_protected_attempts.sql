DELETE FROM oidc_login_states;

ALTER TABLE oidc_login_states
    DROP CONSTRAINT oidc_login_states_pkey,
    DROP COLUMN state_id,
    DROP COLUMN nonce,
    DROP COLUMN browser_binding_hash,
    ADD COLUMN state_hash bytea NOT NULL,
    ADD COLUMN nonce_ciphertext bytea NOT NULL,
    ADD COLUMN pkce_verifier_ciphertext bytea NOT NULL,
    ADD COLUMN context_ciphertext text NOT NULL,
    ADD COLUMN browser_binding_hash bytea NOT NULL,
    ADD CONSTRAINT oidc_login_states_pkey PRIMARY KEY (state_hash),
    ADD CONSTRAINT oidc_login_states_state_hash_size CHECK (octet_length(state_hash) = 32),
    ADD CONSTRAINT oidc_login_states_nonce_size CHECK (octet_length(nonce_ciphertext) = 72),
    ADD CONSTRAINT oidc_login_states_pkce_size CHECK (octet_length(pkce_verifier_ciphertext) = 72),
    ADD CONSTRAINT oidc_login_states_context_size CHECK (length(context_ciphertext) BETWEEN 1 AND 65536),
    ADD CONSTRAINT oidc_login_states_browser_hash_size CHECK (octet_length(browser_binding_hash) = 32),
    ADD CONSTRAINT oidc_login_states_redirect_size CHECK (length(redirect_after_login) BETWEEN 1 AND 2048),
    ADD CONSTRAINT oidc_login_states_expiry_order CHECK (expires_at > created_at),
    ADD CONSTRAINT oidc_login_states_use_order CHECK (used_at IS NULL OR used_at >= created_at);
