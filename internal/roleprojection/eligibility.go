package roleprojection

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	gotthscim "github.com/gotthboard/gotth-scim/pkg/scim"
)

// Eligibility is an internal read model, never a public plan or audit payload.
// Fields bind exact ownership and canonical state; local flags do not erase origins.
type Eligibility struct {
	Found                                                                                  bool
	Provider, Issuer, Subject, MailboxID, UserID, Scope, ExternalID, Version, DocumentHash string
	MailboxEnabled, MailboxDomainEnabled, Active                                           bool
	Mappings                                                                               []EligibleMapping
}
type EligibleMapping struct {
	ID, Role, Domain, Issuer, Scope, GroupID, GroupVersion string
	Revision                                               int64
	DomainEnabled                                          bool
}

// ReadEligibility is the shared exact structural predicate for projection and
// pure mapping previews. lock is true only in the existing writer transaction.
// Complexity: B canonical bytes, E returned mapping bytes, Q/S delegated SQL:
// time O(B+E+Q), Omega(B+E+Q), Theta(B+E+Q) on successful full reads; auxiliary
// O(B+E+S), Omega(B+E), no tight Theta established. Early errors Omega(1).
func ReadEligibility(ctx context.Context, tx *sql.Tx, id string, lock bool) (Eligibility, error) {
	s, data, err := readIdentity(ctx, tx, id, lock)
	if err != nil || !s.Found {
		return s, err
	}
	if s.Provider != "authentik" || s.UserID == "" || s.Scope == "" || s.ExternalID != s.Subject {
		return s, nil
	}
	doc, err := gotthscim.DecodeDocument(data)
	if err != nil {
		return s, err
	}
	s.Active = true
	if value, present := doc["active"]; present {
		var ok bool
		s.Active, ok = value.(bool)
		if !ok {
			return s, errors.New("canonical SCIM active must be boolean")
		}
	}
	if !s.Active {
		return s, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT gm.id::text,gm.role,COALESCE(gm.domain_id::text,''),gm.issuer,gm.scope,gm.group_id,g.version,gm.revision,(gm.domain_id IS NULL OR COALESCE(d.enabled,false))
 FROM identity_group_role_mappings gm JOIN scim_resources g ON g.resource_type='Group' AND g.scope=gm.scope AND g.id=gm.group_id
 JOIN scim_group_members edge ON edge.scope=gm.scope AND edge.group_id=g.id AND edge.user_id=$1
 LEFT JOIN domains d ON d.id=gm.domain_id
 WHERE gm.scope=$2 AND gm.issuer=$3 AND gm.enabled AND NOT gm.group_deleted ORDER BY gm.id`, s.UserID, s.Scope, s.Issuer)
	if err != nil {
		return s, err
	}
	defer rows.Close()
	for rows.Next() {
		var m EligibleMapping
		if err = rows.Scan(&m.ID, &m.Role, &m.Domain, &m.Issuer, &m.Scope, &m.GroupID, &m.GroupVersion, &m.Revision, &m.DomainEnabled); err != nil {
			return s, err
		}
		if !ValidRoleDomain(m.Role, m.Domain) {
			return s, errors.New("projection mapping role is unsupported")
		}
		s.Mappings = append(s.Mappings, m)
	}
	if err = rows.Err(); err != nil {
		return s, err
	}
	return s, rows.Close()
}

// ReadIdentityMetadata binds ownership/local/User state without parsing authority.
// Disable/no-op must remain possible for malformed or removed canonical Users.
// Complexity: B User bytes, Q/S SQL: time O(B+Q), Omega(B+Q), Theta(B+Q);
// auxiliary O(B+S), Omega(B), tight Theta not established on successful reads.
func ReadIdentityMetadata(ctx context.Context, tx *sql.Tx, id string) (Eligibility, error) {
	s, _, err := readIdentity(ctx, tx, id, false)
	return s, err
}

// readIdentity owns the common exact mailbox/User lookup and private fingerprint.
// Complexity: B User bytes, Q/S SQL: time O(B+Q), Omega(B+Q), Theta(B+Q);
// auxiliary O(B+S), Omega(B), tight Theta not established on successful reads.
func readIdentity(ctx context.Context, tx *sql.Tx, id string, lock bool) (Eligibility, []byte, error) {
	var s Eligibility
	var user, scope, external, version, mailbox sql.NullString
	var data []byte
	q := `SELECT ir.provider,ir.issuer,ir.subject,m.id::text,COALESCE(m.enabled,false),COALESCE(md.enabled,false),u.id,u.scope,u.external_id,u.version,u.data FROM identity_refs ir LEFT JOIN mailboxes m ON m.id=ir.mailbox_id LEFT JOIN domains md ON md.id=m.domain_id LEFT JOIN scim_resources u ON u.id=m.scim_resource_id AND u.resource_type='User' WHERE ir.id=$1`
	if lock {
		q += " FOR UPDATE OF ir"
	}
	err := tx.QueryRowContext(ctx, q, id).Scan(&s.Provider, &s.Issuer, &s.Subject, &mailbox, &s.MailboxEnabled, &s.MailboxDomainEnabled, &user, &scope, &external, &version, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return s, nil, nil
	}
	if err != nil {
		return s, nil, err
	}
	s.Found = true
	s.MailboxID = mailbox.String
	s.UserID = user.String
	s.Scope = scope.String
	s.ExternalID = external.String
	s.Version = version.String
	sum := sha256.Sum256(data)
	s.DocumentHash = hex.EncodeToString(sum[:])

	return s, data, nil
}

// ValidRoleDomain checks the existing global/scoped shape on normalized internal
// role/domain values. Complexity: time/space O(1), Omega(1), Theta(1): fixed roles.
func ValidRoleDomain(role, domain string) bool {
	switch role {
	case "global_admin":
		return domain == ""
	case "domain_manager", "scoped_domain_access":
		return domain != ""
	default:
		return false
	}
}
