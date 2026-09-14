// Package scimtoken implements the operator-only credential admission path
// used by an Authentik SCIM provider. It never returns or persists plaintext.
package scimtoken

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"syscall"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/daemon"
	"forgejo/gotthboard/gotth-mail/internal/identity"
)

const (
	minSecretBytes = 32
	maxSecretBytes = 512
)

var actorIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

type Plan struct {
	PlanID    string `json:"plan_id"`
	ActorID   string `json:"actor_id"`
	Operation string `json:"operation"`
}

type Result struct {
	Plan    Plan `json:"plan"`
	Changed bool `json:"changed"`
}

type Service struct {
	DB  *sql.DB
	Now func() time.Time
}

type tokenState struct {
	found       bool
	verifier    string
	revoked     bool
	subjectType string
	subjectID   string
	kind        string
}

type rowQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// ReadSecret opens the final path component without following a symlink and
// accepts only a bounded owner-only regular file containing bearer-safe ASCII.
func ReadSecret(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("--secret-file required")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open secret file: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open secret file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat secret file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("secret file must be regular")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("secret file must be owned by the effective user")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("secret file must not grant group or world permissions")
	}
	secret, err := io.ReadAll(io.LimitReader(file, maxSecretBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read secret file: %w", err)
	}
	if err := validateSecret(secret); err != nil {
		clear(secret)
		return nil, err
	}
	return secret, nil
}

func validateSecret(secret []byte) error {
	if len(secret) < minSecretBytes || len(secret) > maxSecretBytes {
		return fmt.Errorf("SCIM bearer must contain %d-%d bytes", minSecretBytes, maxSecretBytes)
	}
	for _, char := range secret {
		if !bearerByte(char) {
			return errors.New("SCIM bearer contains non-bearer-safe bytes")
		}
	}
	return nil
}

func bearerByte(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
		char >= '0' && char <= '9' || char == '-' || char == '.' ||
		char == '_' || char == '~' || char == '+' || char == '/' || char == '='
}

func (s Service) Preview(ctx context.Context, actorID string, secret []byte) (Plan, error) {
	if s.DB == nil {
		return Plan{}, errors.New("SCIM token database is unavailable")
	}
	state, err := loadState(ctx, s.DB, actorID, false)
	if err != nil {
		return Plan{}, err
	}
	return buildPlan(actorID, secret, state)
}

func (s Service) Apply(ctx context.Context, actorID string, secret []byte, confirmation string) (Result, error) {
	if s.DB == nil {
		return Result{}, errors.New("SCIM token database is unavailable")
	}
	if err := validateActorID(actorID); err != nil {
		return Result{}, err
	}
	if err := validateSecret(secret); err != nil {
		return Result{}, err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Result{}, err
	}
	defer tx.Rollback()
	state, err := loadState(ctx, tx, actorID, true)
	if err != nil {
		return Result{}, err
	}
	plan, err := buildPlan(actorID, secret, state)
	if err != nil {
		return Result{}, err
	}
	if !equalDigest(plan.PlanID, confirmation) {
		return Result{}, errors.New("confirmation digest does not match current SCIM token state")
	}
	if plan.Operation == "unchanged" {
		return Result{Plan: plan, Changed: false}, nil
	}
	verifier, err := identity.HashSecret(string(secret))
	if err != nil {
		return Result{}, err
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	if state.found {
		_, err = tx.ExecContext(ctx, `UPDATE tokens SET verifier=$1, revoked_at=NULL WHERE id=$2 AND subject_type='token' AND subject_id=$3 AND kind='scim_client'`, verifier, identity.TokenStorageID(actorID), actorID)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO tokens(id, subject_type, subject_id, kind, verifier, label, scope_json, created_at, revoked_at) VALUES ($1,'token',$2,'scim_client',$3,$2,'[]',$4,NULL)`, identity.TokenStorageID(actorID), actorID, verifier, now)
	}
	if err != nil {
		return Result{}, err
	}
	if err := audit.WriteSQL(ctx, tx, audit.Event{
		Time: now, Actor: audit.ActorRef{Type: "local_admin", ID: "cli"},
		Action:        "scim.token." + plan.Operation,
		Resource:      audit.ResourceRef{Type: "scim_client", ID: actorID},
		AfterRedacted: map[string]any{"actor_id": actorID, "operation": plan.Operation},
		CorrelationID: "gotth-mailctl-scim-token", Result: "success",
	}); err != nil {
		return Result{}, err
	}
	if err := tx.Commit(); err != nil {
		return Result{}, err
	}
	return Result{Plan: plan, Changed: true}, nil
}

func loadState(ctx context.Context, queryer rowQueryer, actorID string, lock bool) (tokenState, error) {
	if err := validateActorID(actorID); err != nil {
		return tokenState{}, err
	}
	query := `SELECT subject_type, subject_id, kind, verifier, revoked_at IS NOT NULL FROM tokens WHERE id=$1`
	if lock {
		query += ` FOR UPDATE`
	}
	var state tokenState
	err := queryer.QueryRowContext(ctx, query, identity.TokenStorageID(actorID)).Scan(&state.subjectType, &state.subjectID, &state.kind, &state.verifier, &state.revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return tokenState{}, nil
	}
	if err != nil {
		return tokenState{}, err
	}
	state.found = true
	if state.subjectType != "token" || state.subjectID != actorID || state.kind != "scim_client" {
		return tokenState{}, errors.New("stable token row is owned by a different subject or kind")
	}
	return state, nil
}

func buildPlan(actorID string, secret []byte, state tokenState) (Plan, error) {
	if err := validateActorID(actorID); err != nil {
		return Plan{}, err
	}
	if err := validateSecret(secret); err != nil {
		return Plan{}, err
	}
	operation := "create"
	if state.found {
		if daemon.VerifyDjangoPBKDF2SHA256(state.verifier, string(secret)) == nil {
			if state.revoked {
				operation = "reactivate"
			} else {
				operation = "unchanged"
			}
		} else {
			operation = "rotate"
		}
	}
	secretDigest := sha256.Sum256(secret)
	verifierDigest := sha256.Sum256([]byte(state.verifier))
	payload := struct {
		Domain        string `json:"domain"`
		ActorID       string `json:"actor_id"`
		Operation     string `json:"operation"`
		SecretDigest  string `json:"secret_digest"`
		VerifierState string `json:"verifier_state"`
		Revoked       bool   `json:"revoked"`
	}{"gotth-mail/scim-token-plan/v1", actorID, operation, hex.EncodeToString(secretDigest[:]), "absent", state.revoked}
	if state.found {
		payload.VerifierState = hex.EncodeToString(verifierDigest[:])
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Plan{}, err
	}
	digest := sha256.Sum256(encoded)
	return Plan{PlanID: hex.EncodeToString(digest[:]), ActorID: actorID, Operation: operation}, nil
}

func validateActorID(actorID string) error {
	if !actorIDPattern.MatchString(actorID) {
		return errors.New("SCIM token actor ID must be a lowercase stable identifier")
	}
	return nil
}

func equalDigest(expected, actual string) bool {
	left, leftErr := hex.DecodeString(expected)
	right, rightErr := hex.DecodeString(actual)
	return leftErr == nil && rightErr == nil && len(left) == sha256.Size && len(right) == sha256.Size && subtle.ConstantTimeCompare(left, right) == 1
}
