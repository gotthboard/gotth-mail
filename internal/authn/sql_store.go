package authn

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"

	gotthoidc "github.com/gotthboard/gotth-oidc/pkg/oidc"
)

type SQLStore struct{ DB *sql.DB }

// PutAttempt performs one bounded insert. Time complexity is O(1) plus the
// database primary-key lookup; retained data is bounded by the schema checks.
func (s SQLStore) PutAttempt(ctx context.Context, attempt LoginAttempt) error {
	if s.DB == nil {
		return fmt.Errorf("OIDC SQL store is unavailable")
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO oidc_login_states(state_hash, nonce_ciphertext, pkce_verifier_ciphertext, context_ciphertext, browser_binding_hash, redirect_after_login, created_at, expires_at, used_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		attempt.Protected.StateHash[:], attempt.Protected.NonceCiphertext[:], attempt.Protected.PKCEVerifierCiphertext[:], attempt.Protected.ContextCiphertext,
		attempt.BrowserBindingHash[:], attempt.RedirectAfterLogin, attempt.CreatedAt, attempt.ExpiresAt, nullTimePtr(attempt.UsedAt))
	return err
}

func (s SQLStore) Session(ctx context.Context, id string) (Session, bool) {
	if s.DB == nil {
		return Session{}, false
	}
	var session Session
	err := s.DB.QueryRowContext(ctx, `SELECT id, identity_ref_id, csrf_secret_hash, auth_method, created_at, expires_at, last_seen_at FROM sessions WHERE id=$1 AND revoked_at IS NULL`, id).Scan(&session.ID, &session.IdentityRefID, &session.CSRFSecretHash, &session.AuthMethod, &session.CreatedAt, &session.ExpiresAt, &session.LastSeenAt)
	return session, err == nil
}

// ConsumeAttempt is a single conditional UPDATE, so concurrent callbacks can
// admit at most one winner. It is O(1) through the state-hash primary key.
func (s SQLStore) ConsumeAttempt(ctx context.Context, state, browserBinding string, now time.Time) (LoginAttempt, error) {
	if s.DB == nil {
		return LoginAttempt{}, fmt.Errorf("OIDC SQL store is unavailable")
	}
	stateHash := sha256.Sum256([]byte(state))
	browserHash := sha256.Sum256([]byte(browserBinding))
	var attempt LoginAttempt
	var storedState, nonce, pkce, storedBrowser []byte
	err := s.DB.QueryRowContext(ctx, `UPDATE oidc_login_states SET used_at=$1 WHERE state_hash=$2 AND browser_binding_hash=$3 AND used_at IS NULL AND expires_at >= $1 RETURNING state_hash, nonce_ciphertext, pkce_verifier_ciphertext, context_ciphertext, browser_binding_hash, redirect_after_login, created_at, expires_at, used_at`,
		now, stateHash[:], browserHash[:]).Scan(&storedState, &nonce, &pkce, &attempt.Protected.ContextCiphertext, &storedBrowser, &attempt.RedirectAfterLogin, &attempt.CreatedAt, &attempt.ExpiresAt, &attempt.UsedAt)
	if err == sql.ErrNoRows {
		return LoginAttempt{}, ErrInvalidOIDCState
	}
	if err != nil {
		return LoginAttempt{}, err
	}
	if err := decodeProtectedAttempt(&attempt, storedState, nonce, pkce, storedBrowser); err != nil {
		return LoginAttempt{}, err
	}
	return attempt, nil
}

func (s SQLStore) PutSession(ctx context.Context, session Session) error {
	if s.DB == nil {
		return fmt.Errorf("OIDC SQL store is unavailable")
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO sessions(id, identity_ref_id, csrf_secret_hash, auth_method, created_at, expires_at, last_seen_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, session.ID, session.IdentityRefID, session.CSRFSecretHash, session.AuthMethod, session.CreatedAt, session.ExpiresAt, session.LastSeenAt)
	return err
}

func decodeProtectedAttempt(attempt *LoginAttempt, state, nonce, pkce, browser []byte) error {
	if len(state) != sha256.Size || len(nonce) != len(gotthoidc.ProtectedAttempt{}.NonceCiphertext) || len(pkce) != len(gotthoidc.ProtectedAttempt{}.PKCEVerifierCiphertext) || len(browser) != sha256.Size {
		return fmt.Errorf("stored OIDC attempt has invalid protected-field size")
	}
	copy(attempt.Protected.StateHash[:], state)
	copy(attempt.Protected.NonceCiphertext[:], nonce)
	copy(attempt.Protected.PKCEVerifierCiphertext[:], pkce)
	copy(attempt.BrowserBindingHash[:], browser)
	return nil
}

func nullTimePtr(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}
