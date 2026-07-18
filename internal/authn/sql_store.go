package authn

import (
	"context"
	"database/sql"
	"time"
)

type SQLStore struct{ DB *sql.DB }

func (s SQLStore) PutState(st LoginState) error {
	_, err := s.DB.ExecContext(context.Background(), `INSERT INTO oidc_login_states(state_id, nonce, browser_binding_hash, redirect_after_login, created_at, expires_at, used_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, st.StateID, st.Nonce, st.BrowserBindingHash, st.RedirectAfterLogin, st.CreatedAt, st.ExpiresAt, nullTimePtr(st.UsedAt))
	return err
}

func (s SQLStore) Session(id string) (Session, bool) {
	var sess Session
	err := s.DB.QueryRowContext(context.Background(), `SELECT id, identity_ref_id, csrf_secret_hash, auth_method, created_at, expires_at, last_seen_at FROM sessions WHERE id=$1 AND revoked_at IS NULL`, id).Scan(&sess.ID, &sess.IdentityRefID, &sess.CSRFSecretHash, &sess.AuthMethod, &sess.CreatedAt, &sess.ExpiresAt, &sess.LastSeenAt)
	return sess, err == nil
}

func (s SQLStore) consumeState(stateID, browserHash string, now time.Time) (LoginState, error) {
	tx, err := s.DB.BeginTx(context.Background(), nil)
	if err != nil {
		return LoginState{}, err
	}
	defer tx.Rollback()
	var st LoginState
	err = tx.QueryRowContext(context.Background(), `UPDATE oidc_login_states SET used_at=$1 WHERE state_id=$2 AND browser_binding_hash=$3 AND used_at IS NULL AND expires_at >= $1 RETURNING state_id, nonce, browser_binding_hash, redirect_after_login, created_at, expires_at, used_at`, now, stateID, browserHash).Scan(&st.StateID, &st.Nonce, &st.BrowserBindingHash, &st.RedirectAfterLogin, &st.CreatedAt, &st.ExpiresAt, &st.UsedAt)
	if err == sql.ErrNoRows {
		return LoginState{}, ErrInvalidOIDCState
	}
	if err != nil {
		return LoginState{}, err
	}
	if err := tx.Commit(); err != nil {
		return LoginState{}, err
	}
	return st, nil
}

func (s SQLStore) putSession(sess Session) error {
	_, err := s.DB.ExecContext(context.Background(), `INSERT INTO sessions(id, identity_ref_id, csrf_secret_hash, auth_method, created_at, expires_at, last_seen_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, sess.ID, sess.IdentityRefID, sess.CSRFSecretHash, sess.AuthMethod, sess.CreatedAt, sess.ExpiresAt, sess.LastSeenAt)
	return err
}

func nullTimePtr(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}
