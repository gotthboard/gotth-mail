package identityadopt

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/scimstore"
	gotthscim "github.com/gotthboard/gotth-scim/pkg/scim"
)

type Request struct {
	Mailbox string
	Subject string
	Scope   string
	Manager string
}

type Plan struct {
	PlanID             string    `json:"plan_id"`
	MailboxID          string    `json:"mailbox_id"`
	Mailbox            string    `json:"mailbox"`
	DisplayName        string    `json:"display_name,omitempty"`
	Active             bool      `json:"active"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	Subject            string    `json:"subject"`
	Scope              string    `json:"scope"`
	Manager            string    `json:"manager"`
	ExistingResourceID string    `json:"existing_resource_id,omitempty"`
	AlreadyAdopted     bool      `json:"already_adopted"`
}

type Result struct {
	Plan       Plan   `json:"plan"`
	ResourceID string `json:"resource_id"`
	Created    bool   `json:"created"`
}

type Service struct {
	DB      *sql.DB
	Now     func() time.Time
	Entropy io.Reader
}

func (s Service) Preview(ctx context.Context, request Request) (Plan, error) {
	if s.DB == nil {
		return Plan{}, errors.New("legacy adoption database is unavailable")
	}
	request.Mailbox = strings.ToLower(strings.TrimSpace(request.Mailbox))
	request.Subject = strings.TrimSpace(request.Subject)
	request.Scope = strings.TrimSpace(request.Scope)
	request.Manager = strings.TrimSpace(request.Manager)
	address, err := mail.ParseAddress(request.Mailbox)
	if err != nil || address.Address != request.Mailbox || strings.Count(request.Mailbox, "@") != 1 {
		return Plan{}, errors.New("mailbox must be one exact address")
	}
	if request.Subject == "" || len(request.Subject) > 65536 || request.Scope == "" || len(request.Scope) > 1024 || request.Manager == "" || len(request.Manager) > 1024 {
		return Plan{}, errors.New("subject, scope, and manager are required and bounded")
	}
	var plan Plan
	var domainEnabled bool
	err = s.DB.QueryRowContext(ctx, `SELECT m.id::text, lower(m.local_part || '@' || d.name), COALESCE(m.display_name,''), m.enabled, d.enabled, m.created_at, m.updated_at, COALESCE(m.scim_resource_id,'') FROM mailboxes m JOIN domains d ON d.id=m.domain_id WHERE lower(m.local_part || '@' || d.name)=$1`, request.Mailbox).Scan(&plan.MailboxID, &plan.Mailbox, &plan.DisplayName, &plan.Active, &domainEnabled, &plan.CreatedAt, &plan.UpdatedAt, &plan.ExistingResourceID)
	if errors.Is(err, sql.ErrNoRows) {
		return Plan{}, errors.New("mailbox not found")
	}
	if err != nil {
		return Plan{}, err
	}
	if !domainEnabled {
		return Plan{}, errors.New("mailbox domain is disabled")
	}
	plan.Subject, plan.Scope, plan.Manager = request.Subject, request.Scope, request.Manager
	plan.CreatedAt, plan.UpdatedAt = plan.CreatedAt.UTC(), plan.UpdatedAt.UTC()
	if plan.ExistingResourceID != "" {
		var scope, resourceType, externalID, manager string
		var data []byte
		err = s.DB.QueryRowContext(ctx, `SELECT scope, resource_type, external_id, manager, data FROM scim_resources WHERE id=$1`, plan.ExistingResourceID).Scan(&scope, &resourceType, &externalID, &manager, &data)
		if err != nil || scope != plan.Scope || resourceType != "User" || externalID != plan.Subject || manager != plan.Manager {
			return Plan{}, errors.New("mailbox already has different SCIM ownership")
		}
		document, err := gotthscim.DecodeDocument(data)
		if err != nil {
			return Plan{}, errors.New("mailbox SCIM ownership record is invalid")
		}
		userName, ok := document["userName"].(string)
		if !ok || !strings.EqualFold(userName, plan.Mailbox) {
			return Plan{}, errors.New("mailbox SCIM ownership record names a different mailbox")
		}
		plan.AlreadyAdopted = true
	} else {
		var conflict bool
		if err := s.DB.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM scim_resources WHERE resource_type='User' AND external_id=$1)`, plan.Subject).Scan(&conflict); err != nil {
			return Plan{}, err
		}
		if conflict {
			return Plan{}, errors.New("Authentik subject already owns another SCIM User")
		}
		if err := s.DB.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM scim_tombstones WHERE scope=$1 AND resource_type='User' AND external_id=$2)`, plan.Scope, plan.Subject).Scan(&conflict); err != nil {
			return Plan{}, err
		}
		if conflict {
			return Plan{}, errors.New("Authentik subject is permanently tombstoned in this scope")
		}
	}
	plan.PlanID, err = digestPlan(plan)
	return plan, err
}

func (s Service) Apply(ctx context.Context, request Request, confirmation string) (Result, error) {
	plan, err := s.Preview(ctx, request)
	if err != nil {
		return Result{}, err
	}
	if !equalDigest(plan.PlanID, strings.TrimSpace(confirmation)) {
		return Result{}, errors.New("confirmation digest does not match current mailbox state")
	}
	if plan.AlreadyAdopted {
		return Result{Plan: plan, ResourceID: plan.ExistingResourceID}, nil
	}
	identityService, err := identity.NewSQLService(ctx, s.DB)
	if err != nil {
		return Result{}, err
	}
	identityService.Authorizer = authz.StaticAuthorizer{}
	store := &scimstore.SQLStore{DB: s.DB, Identity: identityService}
	registry, err := gotthscim.NewRegistry(gotthscim.DefaultDefinitions())
	if err != nil {
		return Result{}, err
	}
	clock := s.Now
	if clock == nil {
		clock = time.Now
	}
	entropy := s.Entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	reconciler, err := gotthscim.NewReconciler(store, registry, func() time.Time { return clock().UTC() }, entropy)
	if err != nil {
		return Result{}, err
	}
	document, err := json.Marshal(struct {
		Schemas     []string `json:"schemas"`
		UserName    string   `json:"userName"`
		DisplayName string   `json:"displayName,omitempty"`
		Active      bool     `json:"active"`
	}{[]string{gotthscim.UserSchema}, plan.Mailbox, plan.DisplayName, plan.Active})
	if err != nil {
		return Result{}, err
	}
	ctx = scimstore.WithRequestMetadata(ctx, authz.Actor{Type: "scim_client", ID: "legacy-mailbox-adoption"}, plan.PlanID, "", "gotth-mailctl")
	ctx = scimstore.WithLegacyMailboxAdoption(ctx, plan.MailboxID, plan.Mailbox, plan.UpdatedAt)
	result, err := reconciler.Reconcile(ctx, gotthscim.ReconcileRequest{Scope: plan.Scope, Manager: plan.Manager, Resources: []gotthscim.DesiredResource{{ResourceType: "User", ExternalID: plan.Subject, Data: document}}})
	if err != nil {
		return Result{}, err
	}
	if result.Created != 1 {
		return Result{}, fmt.Errorf("legacy adoption created %d resources, want 1", result.Created)
	}
	var resourceID string
	if err := s.DB.QueryRowContext(ctx, `SELECT id FROM scim_resources WHERE scope=$1 AND resource_type='User' AND external_id=$2 AND manager=$3`, plan.Scope, plan.Subject, plan.Manager).Scan(&resourceID); err != nil {
		return Result{}, err
	}
	return Result{Plan: plan, ResourceID: resourceID, Created: true}, nil
}

func digestPlan(plan Plan) (string, error) {
	plan.PlanID = ""
	encoded, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func equalDigest(expected, actual string) bool {
	left, leftErr := hex.DecodeString(expected)
	right, rightErr := hex.DecodeString(actual)
	return leftErr == nil && rightErr == nil && len(left) == sha256.Size && len(right) == sha256.Size && subtle.ConstantTimeCompare(left, right) == 1
}
