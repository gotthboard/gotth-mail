package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
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

// PutIdentitySession binds one verified OIDC identity to exactly one active
// SCIM-provisioned mailbox and admits the identity reference, session, and
// redacted success audit in one transaction.
func (s SQLStore) PutIdentitySession(ctx context.Context, identity Identity, session Session) (Session, error) {
	if s.DB == nil {
		return Session{}, fmt.Errorf("OIDC SQL store is unavailable")
	}
	if strings.TrimSpace(identity.Issuer) == "" || strings.TrimSpace(identity.Subject) == "" || strings.TrimSpace(identity.Email) == "" {
		return Session{}, fmt.Errorf("verified OIDC identity is incomplete")
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return Session{}, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT m.id::text, lower(m.local_part || '@' || d.name)
		FROM scim_resources sr
		JOIN mailboxes m ON m.scim_resource_id=sr.id
		JOIN domains d ON d.id=m.domain_id
		WHERE sr.resource_type='User' AND sr.external_id=$1 AND m.enabled=true
		ORDER BY sr.scope, sr.id
		LIMIT 2`, identity.Subject)
	if err != nil {
		return Session{}, err
	}
	type candidate struct{ mailboxID, email string }
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.mailboxID, &item.email); err != nil {
			rows.Close()
			return Session{}, err
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Session{}, err
	}
	if err := rows.Close(); err != nil {
		return Session{}, err
	}
	if len(candidates) != 1 {
		return Session{}, fmt.Errorf("verified OIDC identity does not resolve to exactly one active SCIM mailbox")
	}
	if !strings.EqualFold(candidates[0].email, strings.TrimSpace(identity.Email)) {
		return Session{}, fmt.Errorf("verified OIDC email does not match the SCIM mailbox")
	}
	identityID, err := randomUUID()
	if err != nil {
		return Session{}, err
	}
	var boundIdentityID, boundMailboxID string
	err = tx.QueryRowContext(ctx, `INSERT INTO identity_refs(id, provider, issuer, subject, mailbox_id, created_at, updated_at)
		VALUES ($1,'authentik',$2,$3,$4,$5,$5)
		ON CONFLICT (provider, issuer, subject) DO UPDATE SET updated_at=EXCLUDED.updated_at
		RETURNING id::text, mailbox_id::text`, identityID, identity.Issuer, identity.Subject, candidates[0].mailboxID, session.CreatedAt).Scan(&boundIdentityID, &boundMailboxID)
	if err != nil {
		return Session{}, err
	}
	if boundMailboxID != candidates[0].mailboxID {
		return Session{}, fmt.Errorf("verified OIDC identity is already bound to another mailbox")
	}
	session.IdentityRefID = boundIdentityID
	if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(id, identity_ref_id, csrf_secret_hash, auth_method, created_at, expires_at, last_seen_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, session.ID, session.IdentityRefID, session.CSRFSecretHash, session.AuthMethod, session.CreatedAt, session.ExpiresAt, session.LastSeenAt); err != nil {
		return Session{}, err
	}
	if err := audit.WriteSQL(ctx, tx, audit.Event{
		Time: session.CreatedAt, Actor: audit.ActorRef{Type: "oidc_subject", ID: boundIdentityID},
		Action: "oidc.session.create", Resource: audit.ResourceRef{Type: "identity", ID: boundIdentityID},
		AfterRedacted: map[string]any{"mailbox": candidates[0].email}, CorrelationID: "oidc", Result: "success",
	}); err != nil {
		return Session{}, err
	}
	if err := tx.Commit(); err != nil {
		return Session{}, err
	}
	return session, nil
}

func (s SQLStore) BoundSession(ctx context.Context, id string, now time.Time) (BoundSession, bool) {
	if s.DB == nil || id == "" {
		return BoundSession{}, false
	}
	var bound BoundSession
	err := s.DB.QueryRowContext(ctx, `SELECT s.id, s.identity_ref_id::text, s.csrf_secret_hash, s.auth_method, s.created_at, s.expires_at, s.last_seen_at,
		ir.issuer, ir.subject, lower(m.local_part || '@' || d.name)
		FROM sessions s
		JOIN identity_refs ir ON ir.id=s.identity_ref_id
		JOIN mailboxes m ON m.id=ir.mailbox_id
		JOIN domains d ON d.id=m.domain_id
		WHERE s.id=$1 AND s.revoked_at IS NULL AND s.expires_at>$2 AND s.created_at<=$2 AND m.enabled=true`, id, now.UTC()).Scan(
		&bound.ID, &bound.IdentityRefID, &bound.CSRFSecretHash, &bound.AuthMethod,
		&bound.CreatedAt, &bound.ExpiresAt, &bound.LastSeenAt,
		&bound.Issuer, &bound.Subject, &bound.Mailbox,
	)
	if err != nil {
		return BoundSession{}, false
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT rb.role, COALESCE(lower(d.name),'') FROM role_bindings rb LEFT JOIN domains d ON d.id=rb.domain_id WHERE rb.identity_ref_id=$1 ORDER BY rb.role, d.name`, bound.IdentityRefID)
	if err != nil {
		return BoundSession{}, false
	}
	defer rows.Close()
	for rows.Next() {
		var assignment authz.RoleAssignment
		if err := rows.Scan(&assignment.Role, &assignment.Domain); err != nil {
			return BoundSession{}, false
		}
		bound.Roles = append(bound.Roles, assignment)
	}
	if err := rows.Err(); err != nil {
		return BoundSession{}, false
	}
	return bound, true
}

func randomUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
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
