// Package rolebinding implements the operator-only durable role grant and
// revoke boundary for already-verified Authentik identities.
package rolebinding

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
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"forgejo/gotthboard/gotth-mail/internal/audit"
)

const (
	OperationGrant  = "grant"
	OperationRevoke = "revoke"

	RoleGlobalAdmin        = "global_admin"
	RoleDomainManager      = "domain_manager"
	RoleScopedDomainAccess = "scoped_domain_access"
)

type Request struct {
	Operation string `json:"operation"`
	Issuer    string `json:"issuer"`
	Subject   string `json:"subject"`
	Mailbox   string `json:"mailbox"`
	Role      string `json:"role"`
	Domain    string `json:"domain,omitempty"`
}

type Plan struct {
	PlanID           string `json:"plan_id"`
	IdentityID       string `json:"identity_id"`
	Mailbox          string `json:"mailbox"`
	Role             string `json:"role"`
	Domain           string `json:"domain,omitempty"`
	Operation        string `json:"operation"`
	OperatorOwned    bool   `json:"operator_owned"`
	GroupSourceCount int    `json:"group_source_count"`
	EffectiveAfter   bool   `json:"effective_after"`
}

type Result struct {
	Plan    Plan `json:"plan"`
	Changed bool `json:"changed"`
}

type Service struct {
	DB            *sql.DB
	CurrentIssuer string
	Now           func() time.Time
	Entropy       io.Reader
}

type state struct {
	identityID, mailbox, domainID                             string
	mailboxEnabled, mailboxDomainEnabled, targetDomainEnabled bool
	bindingID                                                 string
	bindingUpdated                                            time.Time
	operatorOwned                                             bool
	authorityRevision                                         int64
	currentIssuer                                             string
	sources                                                   []groupSource
}

type groupSource struct {
	ID             string
	Revision       int64
	Issuer         string
	Enabled        bool
	Deleted        bool
	MatchesBinding bool
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// Preview reads one coherent authority snapshot without mutation.
// Complexity: successful time O(B+Q), Omega(B+Q), Theta(B+Q); auxiliary
// space O(B+S), Omega(B), no tight bound for delegated SQL space S. B is
// request/source encoded bytes (including fixed state); Q is up to four indexed
// reads plus transaction cost. Early errors have Omega(1), no uniform tight bound.
func (service Service) Preview(ctx context.Context, request Request) (Plan, error) {
	if service.DB == nil {
		return Plan{}, errors.New("role-binding database is unavailable")
	}
	request, err := normalize(request)
	if err != nil {
		return Plan{}, err
	}
	tx, err := service.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return Plan{}, err
	}
	defer tx.Rollback()
	current, err := load(ctx, tx, request, false)
	if err != nil {
		return Plan{}, err
	}
	current.currentIssuer = service.CurrentIssuer
	plan, err := buildPlan(request, current)
	if err != nil {
		return Plan{}, err
	}
	if err := tx.Commit(); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

// Apply changes only the operator origin, once, with its audit in one transaction.
// Complexity: successful time O(B+Q+W), Omega(B+Q+W), Theta(B+Q+W); auxiliary
// space O(B+S), Omega(B), no tight bound for delegated SQL space S. B is encoded
// request/source bytes; Q is snapshot/lock cost and W mutation/audit/commit cost.
// Contention and database work are included symbolically; no retry or network.
// Early errors have Omega(1) time/space, no uniform tight time bound.
func (service Service) Apply(ctx context.Context, request Request, confirmation string) (Result, error) {
	if service.DB == nil {
		return Result{}, errors.New("role-binding database is unavailable")
	}
	request, err := normalize(request)
	if err != nil {
		return Result{}, err
	}
	tx, err := service.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Result{}, err
	}
	defer tx.Rollback()
	current, err := load(ctx, tx, request, true)
	if err != nil {
		return Result{}, err
	}
	current.currentIssuer = service.CurrentIssuer
	plan, err := buildPlan(request, current)
	if err != nil {
		return Result{}, err
	}
	if !equalDigest(plan.PlanID, strings.TrimSpace(confirmation)) {
		return Result{}, errors.New("confirmation digest does not match current role-binding state")
	}
	if plan.Operation == "unchanged" {
		if err := tx.Commit(); err != nil {
			return Result{}, err
		}
		return Result{Plan: plan, Changed: false}, nil
	}
	now := time.Now().UTC()
	if service.Now != nil {
		now = service.Now().UTC()
	}
	if plan.Operation == OperationGrant && current.bindingID == "" {
		id, err := randomUUID(service.Entropy)
		if err != nil {
			return Result{}, err
		}
		var domain any
		if current.domainID != "" {
			domain = current.domainID
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO role_bindings(id,identity_ref_id,role,domain_id,operator_owned,created_at,updated_at) VALUES ($1,$2,$3,$4,TRUE,$5,$5)`, id, current.identityID, request.Role, domain, now)
		if err != nil {
			return Result{}, err
		}
	} else {
		result, err := tx.ExecContext(ctx, `UPDATE role_bindings SET operator_owned=$3, authority_revision=authority_revision+1, updated_at=$4 WHERE id=$1 AND identity_ref_id=$2`, current.bindingID, current.identityID, plan.Operation == OperationGrant, now)
		if err != nil {
			return Result{}, err
		}
		affected, err := result.RowsAffected()
		if err != nil || affected != 1 {
			return Result{}, errors.New("role-binding origin mutation did not affect one exact row")
		}
	}
	if plan.Operation == OperationRevoke {
		if _, err := tx.ExecContext(ctx, `DELETE FROM role_bindings WHERE id=$1 AND NOT operator_owned AND NOT EXISTS (SELECT 1 FROM role_binding_group_sources s WHERE s.binding_id=role_bindings.id)`, current.bindingID); err != nil {
			return Result{}, err
		}
	}
	redacted := map[string]any{"role": request.Role, "operator_owned_after": plan.Operation == OperationGrant, "operator_owned_before": current.operatorOwned, "group_source_count": plan.GroupSourceCount, "effective_after": plan.EffectiveAfter}
	if request.Domain != "" {
		redacted["domain"] = request.Domain
	}
	event := audit.Event{
		Time: now, Actor: audit.ActorRef{Type: "local_admin", ID: "cli"},
		Action:        "identity.role_binding." + plan.Operation,
		Resource:      audit.ResourceRef{Type: "identity", ID: current.identityID},
		CorrelationID: "gotth-mailctl-role-binding", Result: "success",
	}
	if plan.Operation == OperationGrant {
		event.AfterRedacted = redacted
	} else {
		event.BeforeRedacted = redacted
	}
	if err := audit.WriteSQL(ctx, tx, event); err != nil {
		return Result{}, err
	}
	if err := tx.Commit(); err != nil {
		return Result{}, err
	}
	return Result{Plan: plan, Changed: true}, nil
}

// load reads exact identity/domain/binding and sorted independent origins.
// Complexity: time O(B+Q), Omega(B+Q), Theta(B+Q) on success; auxiliary
// space O(B+S), Omega(B), tight Theta not established for database space S.
// B is returned origin bytes (including fixed state); Q includes indexed lookup,
// sort and lock costs. Early errors have Omega(1), no uniform tight time bound.
func load(ctx context.Context, database queryer, request Request, lock bool) (state, error) {
	query := `SELECT ir.id::text, lower(m.local_part || '@' || md.name), m.enabled, md.enabled
		FROM identity_refs ir
		JOIN mailboxes m ON m.id=ir.mailbox_id
		JOIN domains md ON md.id=m.domain_id
		WHERE ir.provider='authentik' AND ir.issuer=$1 AND ir.subject=$2
		  AND lower(m.local_part || '@' || md.name)=$3`
	if lock {
		query += ` FOR UPDATE OF ir, m, md`
	}
	var current state
	if err := database.QueryRowContext(ctx, query, request.Issuer, request.Subject, request.Mailbox).Scan(&current.identityID, &current.mailbox, &current.mailboxEnabled, &current.mailboxDomainEnabled); errors.Is(err, sql.ErrNoRows) {
		return state{}, errors.New("exact verified Authentik identity was not found")
	} else if err != nil {
		return state{}, err
	}
	if request.Domain != "" {
		domainQuery := `SELECT id::text, enabled FROM domains WHERE name=$1`
		if lock {
			domainQuery += ` FOR UPDATE`
		}
		if err := database.QueryRowContext(ctx, domainQuery, request.Domain).Scan(&current.domainID, &current.targetDomainEnabled); errors.Is(err, sql.ErrNoRows) {
			return state{}, errors.New("role-binding domain was not found")
		} else if err != nil {
			return state{}, err
		}
	} else {
		current.targetDomainEnabled = true
	}
	if request.Operation == OperationGrant && (!current.mailboxEnabled || !current.mailboxDomainEnabled || !current.targetDomainEnabled) {
		return state{}, errors.New("role binding cannot be granted for disabled state")
	}
	bindingQuery := `SELECT id::text, updated_at, operator_owned, authority_revision FROM role_bindings WHERE identity_ref_id=$1 AND role=$2 AND domain_id IS NOT DISTINCT FROM $3::uuid`
	if lock {
		bindingQuery += ` FOR UPDATE`
	}
	var domain any
	if current.domainID != "" {
		domain = current.domainID
	}
	err := database.QueryRowContext(ctx, bindingQuery, current.identityID, request.Role, domain).Scan(&current.bindingID, &current.bindingUpdated, &current.operatorOwned, &current.authorityRevision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return state{}, err
	}
	if current.bindingID != "" {
		rows, err := database.QueryContext(ctx, `SELECT m.id::text,m.revision,m.issuer,m.enabled,m.group_deleted,(m.role=rb.role AND m.domain_id IS NOT DISTINCT FROM rb.domain_id) FROM role_binding_group_sources s JOIN identity_group_role_mappings m ON m.id=s.mapping_id JOIN role_bindings rb ON rb.id=s.binding_id WHERE s.binding_id=$1 ORDER BY m.id`, current.bindingID)
		if err != nil {
			return state{}, err
		}
		defer rows.Close()
		for rows.Next() {
			var source groupSource
			if err := rows.Scan(&source.ID, &source.Revision, &source.Issuer, &source.Enabled, &source.Deleted, &source.MatchesBinding); err != nil {
				return state{}, err
			}
			current.sources = append(current.sources, source)
		}
		if err := rows.Err(); err != nil {
			return state{}, err
		}
	}
	return current, nil
}

// buildPlan binds request, local predicates and every origin revision to v2.
// Complexity: for B encoded request/origin bytes, time O(B), Omega(B), Theta(B)
// and auxiliary space O(B), Omega(B), Theta(B), including JSON and SHA256.
func buildPlan(request Request, current state) (Plan, error) {
	effective := request.Operation
	if request.Operation == OperationGrant && current.operatorOwned || request.Operation == OperationRevoke && !current.operatorOwned {
		effective = "unchanged"
	}
	plan := Plan{IdentityID: current.identityID, Mailbox: current.mailbox, Role: request.Role, Domain: request.Domain, Operation: effective, OperatorOwned: current.operatorOwned, GroupSourceCount: len(current.sources)}
	operatorAfter := current.operatorOwned
	if effective == OperationGrant {
		operatorAfter = true
	} else if effective == OperationRevoke {
		operatorAfter = false
	}
	plan.EffectiveAfter = operatorAfter
	if !operatorAfter && current.mailboxEnabled && current.mailboxDomainEnabled && current.targetDomainEnabled && current.currentIssuer != "" && current.currentIssuer == request.Issuer {
		for _, source := range current.sources {
			if source.Enabled && !source.Deleted && source.MatchesBinding && source.Issuer == current.currentIssuer {
				plan.EffectiveAfter = true
				break
			}
		}
	}
	payload := struct {
		Schema, RequestedOperation, IdentityID, Mailbox, Role, Domain, DomainID, ExistingBindingID, ExistingBindingUpdated string
		OperatorOwned                                                                                                      bool
		AuthorityRevision                                                                                                  int64
		CurrentIssuer                                                                                                      string
		MailboxEnabled, MailboxDomainEnabled, TargetDomainEnabled                                                          bool
		Sources                                                                                                            []groupSource
	}{Schema: "gotth-mail/role-binding-plan/v2", RequestedOperation: request.Operation, IdentityID: current.identityID, Mailbox: current.mailbox, Role: request.Role, Domain: request.Domain, DomainID: current.domainID, ExistingBindingID: current.bindingID, OperatorOwned: current.operatorOwned, AuthorityRevision: current.authorityRevision, CurrentIssuer: current.currentIssuer, MailboxEnabled: current.mailboxEnabled, MailboxDomainEnabled: current.mailboxDomainEnabled, TargetDomainEnabled: current.targetDomainEnabled, Sources: current.sources}
	if current.bindingID != "" {
		payload.ExistingBindingUpdated = current.bindingUpdated.UTC().Format(time.RFC3339Nano)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Plan{}, err
	}
	digest := sha256.Sum256(encoded)
	plan.PlanID = hex.EncodeToString(digest[:])
	return plan, nil
}

func normalize(request Request) (Request, error) {
	request.Operation = strings.TrimSpace(request.Operation)
	if request.Issuer != strings.TrimSpace(request.Issuer) || request.Subject != strings.TrimSpace(request.Subject) {
		return Request{}, errors.New("role-binding identity is invalid")
	}
	request.Mailbox = strings.ToLower(strings.TrimSpace(request.Mailbox))
	request.Role = strings.TrimSpace(request.Role)
	request.Domain = strings.ToLower(strings.TrimSpace(request.Domain))
	if request.Operation != OperationGrant && request.Operation != OperationRevoke {
		return Request{}, errors.New("role-binding operation must be grant or revoke")
	}
	if !validIssuer(request.Issuer) || !validText(request.Subject, 1, 1024) {
		return Request{}, errors.New("role-binding identity is invalid")
	}
	address, err := mail.ParseAddress(request.Mailbox)
	if err != nil || address.Address != request.Mailbox || strings.Count(request.Mailbox, "@") != 1 {
		return Request{}, errors.New("role-binding mailbox is invalid")
	}
	switch request.Role {
	case RoleGlobalAdmin:
		if request.Domain != "" {
			return Request{}, errors.New("global administrator role cannot name a domain")
		}
	case RoleDomainManager, RoleScopedDomainAccess:
		if !validDomain(request.Domain) {
			return Request{}, errors.New("domain-scoped role requires one valid domain")
		}
	default:
		return Request{}, errors.New("role-binding role is invalid")
	}
	return request, nil
}

func validIssuer(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.Host == strings.ToLower(parsed.Host) && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Path == "/application/o/gotth-mail/" && parsed.String() == value
}

func validText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	return length >= minimum && length <= maximum && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validDomain(value string) bool {
	if len(value) < 3 || len(value) > 253 || strings.HasSuffix(value, ".") || strings.Contains(value, "..") || value != strings.ToLower(value) {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	return true
}

func randomUUID(source io.Reader) (string, error) {
	if source == nil {
		source = rand.Reader
	}
	var value [16]byte
	if _, err := io.ReadFull(source, value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func equalDigest(expected, actual string) bool {
	left, leftErr := hex.DecodeString(expected)
	right, rightErr := hex.DecodeString(actual)
	return leftErr == nil && rightErr == nil && len(left) == sha256.Size && len(right) == sha256.Size && subtle.ConstantTimeCompare(left, right) == 1
}
