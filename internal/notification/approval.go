package notification

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
)

type TransportActor struct {
	Transport, ExternalID string
}

type ActorMapping struct {
	TransportActor TransportActor
	Actor          authz.Actor
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type SQLActorMapper struct{ DB *sql.DB }

func (s SQLActorMapper) Put(ctx context.Context, m ActorMapping, now time.Time) error {
	if s.DB == nil {
		return errors.New("notification actor mapping db required")
	}
	m.TransportActor.Transport = cleanToken(m.TransportActor.Transport, 40)
	m.TransportActor.ExternalID = strings.TrimSpace(m.TransportActor.ExternalID)
	m.Actor.Type = cleanToken(m.Actor.Type, 40)
	m.Actor.ID = strings.TrimSpace(m.Actor.ID)
	if m.TransportActor.Transport == "" || m.TransportActor.ExternalID == "" || m.Actor.Type == "" || m.Actor.ID == "" {
		return errors.New("complete notification actor mapping required")
	}
	scopes, err := json.Marshal(m.Actor.Scopes)
	if err != nil {
		return err
	}
	now = now.UTC()
	_, err = s.DB.ExecContext(ctx, `INSERT INTO notification_actor_mappings(transport, external_actor_id, actor_type, actor_id, scopes_json, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$6) ON CONFLICT (transport, external_actor_id) DO UPDATE SET actor_type=EXCLUDED.actor_type, actor_id=EXCLUDED.actor_id, scopes_json=EXCLUDED.scopes_json, updated_at=EXCLUDED.updated_at`, m.TransportActor.Transport, m.TransportActor.ExternalID, m.Actor.Type, m.Actor.ID, string(scopes), now)
	return err
}

func (s SQLActorMapper) Map(ctx context.Context, ta TransportActor) (authz.Actor, bool, error) {
	if s.DB == nil {
		return authz.Actor{}, false, errors.New("notification actor mapping db required")
	}
	transport := cleanToken(ta.Transport, 40)
	externalID := strings.TrimSpace(ta.ExternalID)
	if transport == "" || externalID == "" {
		return authz.Actor{}, false, nil
	}
	var a authz.Actor
	var scopes string
	err := s.DB.QueryRowContext(ctx, `SELECT actor_type, actor_id, scopes_json FROM notification_actor_mappings WHERE transport=$1 AND external_actor_id=$2`, transport, externalID).Scan(&a.Type, &a.ID, &scopes)
	if errors.Is(err, sql.ErrNoRows) {
		return authz.Actor{}, false, nil
	}
	if err != nil {
		return authz.Actor{}, false, err
	}
	if err := json.Unmarshal([]byte(scopes), &a.Scopes); err != nil {
		return authz.Actor{}, false, err
	}
	return a, true, nil
}

type ApprovalRequest struct {
	ID             string
	TransportActor TransportActor
	Actor          authz.Actor
	Action         authz.Action
	Resource       authz.Resource
	RequestHash    string
	CorrelationID  string
	ExpiresAt      time.Time
	CreatedAt      time.Time
	UsedAt         *time.Time
	Result         string
}

type ApprovalConfirmation struct {
	ID             string
	TransportActor TransportActor
	Actor          authz.Actor
	Action         authz.Action
	Resource       authz.Resource
	RequestHash    string
	Now            time.Time
}

type SQLApprovalStore struct {
	DB    *sql.DB
	Audit audit.Writer
}

func (s SQLApprovalStore) Create(ctx context.Context, r ApprovalRequest, now time.Time) (ApprovalRequest, error) {
	if s.DB == nil {
		return ApprovalRequest{}, errors.New("notification approval db required")
	}
	r.TransportActor.Transport = cleanToken(r.TransportActor.Transport, 40)
	r.TransportActor.ExternalID = strings.TrimSpace(r.TransportActor.ExternalID)
	r.Actor.Type = cleanToken(r.Actor.Type, 40)
	r.Actor.ID = strings.TrimSpace(r.Actor.ID)
	r.RequestHash = cleanToken(r.RequestHash, 128)
	r.CorrelationID = cleanToken(r.CorrelationID, 128)
	if r.ID == "" {
		r.ID = newID()
	}
	if r.TransportActor.Transport == "" || r.TransportActor.ExternalID == "" || r.Actor.Type == "" || r.Actor.ID == "" || r.Action == "" || r.Resource.Type == "" || r.Resource.ID == "" || r.RequestHash == "" || !r.ExpiresAt.After(now) {
		return ApprovalRequest{}, errors.New("complete unexpired approval request required")
	}
	r.CreatedAt = now.UTC()
	r.Result = "pending"
	_, err := s.DB.ExecContext(ctx, `INSERT INTO notification_approvals(id, transport, external_actor_id, actor_type, actor_id, action, resource_type, resource_id, request_hash, correlation_id, expires_at, result, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending',$12,$12)`, r.ID, r.TransportActor.Transport, r.TransportActor.ExternalID, r.Actor.Type, r.Actor.ID, string(r.Action), r.Resource.Type, r.Resource.ID, r.RequestHash, r.CorrelationID, r.ExpiresAt.UTC(), r.CreatedAt)
	if err != nil {
		return ApprovalRequest{}, err
	}
	return r, s.audit(ctx, r, "notification.approval.create", "success", nil)
}

func (s SQLApprovalStore) Confirm(ctx context.Context, c ApprovalConfirmation) (ApprovalRequest, error) {
	if s.DB == nil {
		return ApprovalRequest{}, errors.New("notification approval db required")
	}
	r, ok, err := s.Get(ctx, c.ID)
	if err != nil {
		return ApprovalRequest{}, err
	}
	if !ok {
		return ApprovalRequest{}, errors.New("approval request not found")
	}
	fail := func(msg string) (ApprovalRequest, error) {
		_ = s.mark(ctx, r.ID, "rejected", c.Now)
		_ = s.audit(ctx, r, "notification.approval.confirm", "denied", errors.New(msg))
		return ApprovalRequest{}, errors.New(msg)
	}
	if r.UsedAt != nil || r.Result != "pending" {
		return fail("approval replay rejected")
	}
	if !c.Now.Before(r.ExpiresAt) {
		return fail("approval expired")
	}
	if cleanToken(c.TransportActor.Transport, 40) != r.TransportActor.Transport || strings.TrimSpace(c.TransportActor.ExternalID) != r.TransportActor.ExternalID || cleanToken(c.Actor.Type, 40) != r.Actor.Type || strings.TrimSpace(c.Actor.ID) != r.Actor.ID || c.Action != r.Action || c.Resource.Type != r.Resource.Type || c.Resource.ID != r.Resource.ID || cleanToken(c.RequestHash, 128) != r.RequestHash {
		return fail("approval binding mismatch")
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE notification_approvals SET used_at=$2, result='approved', updated_at=$2 WHERE id=$1 AND used_at IS NULL AND result='pending'`, r.ID, c.Now.UTC())
	if err != nil {
		return ApprovalRequest{}, err
	}
	if n, err := res.RowsAffected(); err == nil && n != 1 {
		return fail("approval replay rejected")
	}
	r.UsedAt = &[]time.Time{c.Now.UTC()}[0]
	r.Result = "approved"
	return r, s.audit(ctx, r, "notification.approval.confirm", "success", nil)
}

func (s SQLApprovalStore) Get(ctx context.Context, id string) (ApprovalRequest, bool, error) {
	if s.DB == nil {
		return ApprovalRequest{}, false, errors.New("notification approval db required")
	}
	var r ApprovalRequest
	var used sql.NullTime
	err := s.DB.QueryRowContext(ctx, `SELECT id, transport, external_actor_id, actor_type, actor_id, action, resource_type, resource_id, request_hash, correlation_id, expires_at, used_at, result, created_at FROM notification_approvals WHERE id=$1`, id).Scan(&r.ID, &r.TransportActor.Transport, &r.TransportActor.ExternalID, &r.Actor.Type, &r.Actor.ID, &r.Action, &r.Resource.Type, &r.Resource.ID, &r.RequestHash, &r.CorrelationID, &r.ExpiresAt, &used, &r.Result, &r.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ApprovalRequest{}, false, nil
	}
	if err != nil {
		return ApprovalRequest{}, false, err
	}
	if used.Valid {
		r.UsedAt = &used.Time
	}
	return r, true, nil
}

func (s SQLApprovalStore) mark(ctx context.Context, id, result string, now time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE notification_approvals SET result=$2, updated_at=$3 WHERE id=$1 AND result='pending'`, id, result, now.UTC())
	return err
}

func (s SQLApprovalStore) audit(ctx context.Context, r ApprovalRequest, action, result string, err error) error {
	if s.Audit == nil {
		return nil
	}
	e := audit.Event{Actor: audit.ActorRef{Type: r.Actor.Type, ID: r.Actor.ID}, Action: action, Resource: audit.ResourceRef{Type: r.Resource.Type, ID: r.Resource.ID}, CorrelationID: r.CorrelationID, Result: result, AfterRedacted: map[string]any{"approval_id": r.ID, "transport": r.TransportActor.Transport, "external_actor_id": r.TransportActor.ExternalID, "request_hash": r.RequestHash}}
	if err != nil {
		e.ErrorCode = err.Error()
	}
	return s.Audit.Write(ctx, e)
}

func cleanToken(v string, n int) string { return boundToken(v, n) }

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}
