package ops

import (
	"context"
	"database/sql"
	"forgejo/gotthboard/gotth-mail/internal/identityruntime"
	"net/url"
	"strings"
	"time"
)

// IdentityDiagnostic is local deployment input, never provider-discovered authority.
type IdentityDiagnostic struct {
	DB               *sql.DB
	CurrentIssuer    string
	AuthorityInvalid bool
}

// IdentityMappingHealth is emitted only by the explicit local diagnostic surface.
type IdentityMappingHealth struct {
	ID       string  `json:"mapping_id"`
	Revision int64   `json:"revision"`
	Issuer   string  `json:"issuer,omitempty"`
	Scope    string  `json:"scope"`
	GroupID  string  `json:"group_id"`
	Role     string  `json:"role"`
	DomainID *string `json:"domain_id"`
	Eligible bool    `json:"eligible"`
	Reason   string  `json:"reason"`
}
type IdentityHealth struct {
	Status           Status                  `json:"status"`
	Reason           string                  `json:"reason"`
	DatabaseStatus   Status                  `json:"database_status"`
	ObservedAt       time.Time               `json:"observed_at"`
	EligibleMappings int                     `json:"eligible_mappings"`
	Mappings         []IdentityMappingHealth `json:"mappings"`
}

// Inspect reads one coherent local inventory, not membership/grants/live profile
// correlation. It never writes, repairs, retries or performs provider I/O.
// Complexity: N returned mapping bytes/rows, Q/S delegated SQL costs: successful
// time O(N+Q), Omega(N+Q), Theta(N+Q); auxiliary O(N+S), Omega(N), tight Theta
// not established. Early errors Omega(1); one query, fixed3s earlier-cancel deadline.
func (d IdentityDiagnostic) Inspect(ctx context.Context) IdentityHealth {
	h := IdentityHealth{Status: Fail, Reason: "local_identity_database_unavailable", DatabaseStatus: Unknown, ObservedAt: time.Now().UTC(), Mappings: []IdentityMappingHealth{}}
	if d.DB == nil {
		h.DatabaseStatus = Fail
		return h
	}
	issuer := identityruntime.NormalizeIssuer(d.CurrentIssuer)
	if d.AuthorityInvalid || issuer != "" && !diagnosticIssuerValid(issuer) {
		h.Reason = "local_identity_authority_invalid"
		return h
	}
	if issuer == "" {
		h.Status = Warn
		h.Reason = "local_identity_authority_missing"
		return h
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	failure := func() IdentityHealth {
		h.Status = Fail
		h.DatabaseStatus = Fail
		h.Reason = "local_identity_schema_or_query_unavailable"
		if ctx.Err() != nil {
			h.Reason = "local_identity_inspection_cancelled"
		}
		h.Mappings = []IdentityMappingHealth{}
		h.EligibleMappings = 0
		return h
	}
	tx, err := d.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return failure()
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT gm.id::text,gm.revision,gm.issuer,gm.scope,gm.group_id,gm.role,gm.domain_id::text,gm.enabled,gm.group_deleted,
 g.id IS NOT NULL,COALESCE(d.enabled,false),
 EXISTS(SELECT 1 FROM scim_tombstones t WHERE t.scope=gm.scope AND t.resource_type='Group' AND t.id=gm.group_id)
 OR EXISTS(SELECT 1 FROM identity_group_role_mappings retired WHERE retired.scope=gm.scope AND retired.group_id=gm.group_id AND retired.group_deleted)
 FROM identity_group_role_mappings gm
 LEFT JOIN scim_resources g ON g.scope=gm.scope AND g.resource_type='Group' AND g.id=gm.group_id
 LEFT JOIN domains d ON d.id=gm.domain_id ORDER BY gm.id`)
	if err != nil {
		return failure()
	}
	covered := map[string]bool{}
	for rows.Next() {
		var m IdentityMappingHealth
		var domain sql.NullString
		var enabled, deleted, group, domainEnabled, retired bool
		if err = rows.Scan(&m.ID, &m.Revision, &m.Issuer, &m.Scope, &m.GroupID, &m.Role, &domain, &enabled, &deleted, &group, &domainEnabled, &retired); err != nil {
			break
		}
		if domain.Valid {
			v := domain.String
			m.DomainID = &v
		}
		switch {
		case !diagnosticIssuerValid(m.Issuer):
			m.Issuer = ""
			m.Reason = "invalid_issuer"
		case deleted || retired:
			m.Reason = "retired_group"
		case !enabled:
			m.Reason = "disabled_mapping"
		case m.Issuer != issuer:
			m.Reason = "old_issuer"
		case !group:
			m.Reason = "missing_same_scope_group"
		case m.Role == "global_admin" && domain.Valid || (m.Role == "domain_manager" || m.Role == "scoped_domain_access") && !domain.Valid:
			m.Reason = "invalid_role_domain"
		case m.Role != "global_admin" && m.Role != "domain_manager" && m.Role != "scoped_domain_access":
			m.Reason = "unknown_role"
		case domain.Valid && !domainEnabled:
			m.Reason = "disabled_or_missing_domain"
		default:
			m.Eligible = true
			m.Reason = "eligible_local_mapping"
			covered[m.Role] = true
			h.EligibleMappings++
		}
		h.Mappings = append(h.Mappings, m)
	}
	if err == nil {
		err = rows.Err()
	}
	closeErr := rows.Close()
	if err != nil || closeErr != nil {
		return failure()
	}
	if err = tx.Commit(); err != nil {
		return failure()
	}
	h.DatabaseStatus = OK
	h.Reason = "local_role_coverage_incomplete"
	if covered["global_admin"] && covered["domain_manager"] && covered["scoped_domain_access"] {
		h.Status = OK
		h.Reason = "local_role_coverage_complete"
		if h.EligibleMappings != len(h.Mappings) {
			h.Status = Warn
			h.Reason = "local_role_coverage_complete_with_inactive_mappings"
		}
	}
	return h
}

// diagnosticIssuerValid mirrors the admitted normalized issuer shape solely for
// safe diagnostics; malformed URLs (including credentials) are never disclosed.
// Complexity: n URL bytes, time/space O(n), Omega(1), no uniform tight Theta;
// URL parsing is delegated and bounded by stored mapping/input contracts.
func diagnosticIssuerValid(value string) bool {
	u, e := url.Parse(value)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.Host == strings.ToLower(u.Host) && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Path == "/application/o/gotth-mail/" && u.String() == value
}
