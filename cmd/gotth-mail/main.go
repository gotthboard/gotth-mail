package main

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"strings"

	"forgejo/gotthboard/gotth-mail/internal/admin"
	"forgejo/gotthboard/gotth-mail/internal/api"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/daemon"
	"forgejo/gotthboard/gotth-mail/internal/diag"
	"forgejo/gotthboard/gotth-mail/internal/httpui"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/version"
	gotthoidc "github.com/gotthboard/gotth-oidc/pkg/oidc"
	_ "github.com/lib/pq"
)

func main() {
	if err := version.Validate(version.Version); err != nil {
		log.Fatal(err)
	}
	server := api.Server{Authz: authz.StaticAuthorizer{}}
	if os.Getenv("GOTTH_MAIL_REFERENCE_FIXTURE") == "1" {
		server = referenceServer()
	}
	db, err := configureDatabaseFromEnv(context.Background(), &server)
	if err != nil {
		log.Fatalf("configure database: %v", err)
	}
	if db != nil {
		defer db.Close()
	}
	if err := configurePostfixHelperFromEnv(&server); err != nil {
		log.Fatalf("configure Postfix helper: %v", err)
	}
	if policyAddr := strings.TrimSpace(os.Getenv("GOTTH_MAIL_POSTFIX_POLICY_LISTEN")); policyAddr != "" {
		go servePostfixPolicy(policyAddr, server.Daemon)
	}
	if err := configureOIDCFromEnv(context.Background(), &server, http.DefaultClient); err != nil {
		log.Fatalf("configure oidc: %v", err)
	}
	if err := configureSCIMFromEnv(&server); err != nil {
		log.Fatalf("configure scim: %v", err)
	}
	mux := runtimeMux(server)
	addr := os.Getenv("GOTTH_MAIL_LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	log.Fatal(http.ListenAndServe(addr, mux))
}

func runtimeMux(server api.Server) http.Handler {
	if server.Identity == nil {
		var domains []string
		for name := range server.Daemon.Domains {
			domains = append(domains, name)
		}
		server.Identity = identity.NewService(domains...)
	}
	mux := http.NewServeMux()
	serverHandler := server.Handler()
	mux.Handle("/api/", serverHandler)
	mux.Handle("/scim/", serverHandler)
	mux.Handle("/internal/", serverHandler)
	mux.Handle("/healthz", serverHandler)
	mux.Handle("/readyz", serverHandler)
	mux.Handle("/webmail", serverHandler)
	sessions, _ := server.OIDCStore.(authn.IdentitySessionStore)
	mux.Handle("/", httpui.HandlerWithAdminIdentityAndSessions(referenceAdminStore(), server.Identity, server.Authz, sessions, server.OIDCNow))
	return mux
}

func configureSCIMFromEnv(server *api.Server) error {
	externalURL := strings.TrimSpace(os.Getenv("GOTTH_MAIL_SCIM_EXTERNAL_URL"))
	if externalURL == "" {
		return nil
	}
	if server.AuditDB == nil || server.Identity == nil {
		return fmt.Errorf("GOTTH_MAIL_DATABASE_URL or GOTTH_MAIL_DATABASE_URL_FILE is required when SCIM is enabled")
	}
	handler, err := api.NewSCIMHandler(externalURL, server.AuditDB, server.Identity, server.Authz, audit.SQLWriter{DB: server.AuditDB})
	if err != nil {
		return err
	}
	server.SCIM = handler
	return nil
}

func configureOIDCFromEnv(ctx context.Context, server *api.Server, client *http.Client) error {
	issuer := strings.TrimSpace(os.Getenv("GOTTH_MAIL_AUTHENTIK_ISSUER"))
	clientID := strings.TrimSpace(os.Getenv("GOTTH_MAIL_AUTHENTIK_CLIENT_ID"))
	redirectURI := strings.TrimSpace(os.Getenv("GOTTH_MAIL_AUTHENTIK_REDIRECT_URI"))
	if issuer == "" && clientID == "" && redirectURI == "" {
		return nil
	}
	if issuer == "" || clientID == "" || redirectURI == "" {
		return fmt.Errorf("GOTTH_MAIL_AUTHENTIK_ISSUER, GOTTH_MAIL_AUTHENTIK_CLIENT_ID, and GOTTH_MAIL_AUTHENTIK_REDIRECT_URI are required together")
	}
	if server.OIDCStore == nil {
		return fmt.Errorf("GOTTH_MAIL_DATABASE_URL or GOTTH_MAIL_DATABASE_URL_FILE is required when OIDC is enabled")
	}
	clientSecret, err := secretFromEnvOrFile("GOTTH_MAIL_AUTHENTIK_CLIENT_SECRET", "GOTTH_MAIL_AUTHENTIK_CLIENT_SECRET_FILE")
	if err != nil {
		return err
	}
	issuer = strings.TrimRight(issuer, "/") + "/"
	transport := http.DefaultTransport
	if client != nil && client.Transport != nil {
		transport = client.Transport
	}
	oidcClient, err := gotthoidc.New(ctx, gotthoidc.Config{
		IssuerURL: issuer, ClientID: clientID, ClientSecret: clientSecret,
		RedirectURL: redirectURI, Transport: transport, AllowInsecureLoopback: insecureLoopback(issuer),
		IdentityPolicy: gotthoidc.IdentityPolicy{RequireVerifiedEmail: true},
	})
	if err != nil {
		return err
	}
	server.OIDCClient = oidcClient
	server.OIDCRedirectURI = redirectURI
	return nil
}

// configureDatabaseFromEnv performs one connection, one ping, one migration
// transaction, and one bounded state load. It retains only the connection pool.
func configureDatabaseFromEnv(ctx context.Context, server *api.Server) (*sql.DB, error) {
	dsn, err := secretFromEnvOrFile("GOTTH_MAIL_DATABASE_URL", "GOTTH_MAIL_DATABASE_URL_FILE")
	if err != nil {
		return nil, err
	}
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil, nil
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	closeOnError := func(cause error) (*sql.DB, error) {
		_ = db.Close()
		return nil, cause
	}
	if err := db.PingContext(ctx); err != nil {
		return closeOnError(fmt.Errorf("ping database: %w", err))
	}
	if err := store.MigrateSQL(ctx, db); err != nil {
		return closeOnError(fmt.Errorf("migrate database: %w", err))
	}
	if os.Getenv("GOTTH_MAIL_REFERENCE_FIXTURE") == "1" {
		if err := seedReferenceDatabase(ctx, db); err != nil {
			return closeOnError(fmt.Errorf("seed reference database: %w", err))
		}
	}
	identityService, err := identity.NewSQLService(ctx, db)
	if err != nil {
		return closeOnError(fmt.Errorf("load identity state: %w", err))
	}
	server.AuditDB = db
	identityService.Audit = audit.SQLWriter{DB: db}
	server.OIDCStore = authn.SQLStore{DB: db}
	server.Identity = identityService
	policy := &outboundpolicy.EnforcementService{DB: db, Queue: outboundpolicy.QueueStore{DB: db}, HoldActor: audit.ActorRef{Type: "service", ID: "outbound-policy"}}
	server.Daemon.OutboundPolicy = policy
	server.Daemon.OutboundAdmission = &outboundpolicy.QueueAdmissionService{DB: db, Queue: outboundpolicy.QueueStore{DB: db}}
	if configuredSender := strings.TrimSpace(os.Getenv("GOTTH_MAIL_NOTIFICATION_EMAIL_FROM")); configuredSender != "" {
		parsed, err := mail.ParseAddress(configuredSender)
		if err != nil {
			return closeOnError(fmt.Errorf("parse notification system sender: %w", err))
		}
		id := "system:" + strings.ToLower(parsed.Address)
		if _, err := (outboundpolicy.SystemSenderStore{DB: db}).Bind(ctx, audit.ActorRef{Type: "service", ID: "runtime-config"}, "runtime-config:notification-system-sender", id, parsed.Address); err != nil {
			return closeOnError(fmt.Errorf("bind notification system sender: %w", err))
		}
	}
	return db, nil
}

// seedReferenceDatabase installs the fixed idempotent container-smoke objects
// in SQL so runtime policy and in-memory daemon fixtures describe the same
// addresses. It is unreachable unless the explicit reference-fixture switch
// is set.
// Complexity: time O(s), Omega(s), tight Theta(s); auxiliary space O(1), where
// s is the fixed seed statement count. Database round trips are O(s).
func seedReferenceDatabase(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statements := []string{
		`INSERT INTO domains(id,name,enabled,outbound_scope,outbound_policy_revision,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000d01','example.test',true,'same_domain_only',2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON CONFLICT (name) DO NOTHING`,
		`INSERT INTO mailboxes(id,domain_id,local_part,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000d02','00000000-0000-4000-8000-000000000d01','smoke',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON CONFLICT (domain_id,local_part) DO NOTHING`,
		`INSERT INTO mailboxes(id,domain_id,local_part,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000d03','00000000-0000-4000-8000-000000000d01','postmaster',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON CONFLICT (domain_id,local_part) DO NOTHING`,
		`INSERT INTO aliases(id,domain_id,local_part,targets_json,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000d04','00000000-0000-4000-8000-000000000d01','alias','["smoke@example.test"]',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP) ON CONFLICT (domain_id,local_part) DO NOTHING`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// configurePostfixHelperFromEnv binds the privileged queue helper only when
// its URL and secret are both explicit.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n), where
// n is bounded environment configuration text.
func configurePostfixHelperFromEnv(server *api.Server) error {
	helperURL := strings.TrimSpace(os.Getenv("GOTTH_MAIL_POSTFIX_HELPER_URL"))
	token, err := secretFromEnvOrFile("GOTTH_MAIL_POSTFIX_HELPER_TOKEN", "GOTTH_MAIL_POSTFIX_HELPER_TOKEN_FILE")
	if err != nil {
		return err
	}
	if helperURL == "" && token == "" {
		return nil
	}
	if helperURL == "" || token == "" || server.AuditDB == nil || server.Daemon.OutboundAdmission == nil {
		return fmt.Errorf("GOTTH_MAIL_DATABASE_URL, GOTTH_MAIL_POSTFIX_HELPER_URL, and one Postfix helper token source are required together")
	}
	boundary, err := outboundpolicy.NewRemotePostfixBoundary(helperURL, token)
	if err != nil {
		return err
	}
	server.Daemon.OutboundReconciler = &outboundpolicy.QueueReconciler{
		Store:     outboundpolicy.QueueStore{DB: server.AuditDB},
		Inspector: boundary,
		Holder:    boundary,
	}
	return server.Daemon.ConfigurePostfixHelperToken(token)
}

func secretFromEnvOrFile(valueName, fileName string) (string, error) {
	const maxConfigSecretBytes = 64 << 10
	direct := os.Getenv(valueName)
	file := strings.TrimSpace(os.Getenv(fileName))
	if direct != "" && file != "" {
		return "", fmt.Errorf("%s and %s are mutually exclusive", valueName, fileName)
	}
	if file == "" {
		if len(direct) > maxConfigSecretBytes {
			return "", fmt.Errorf("%s exceeds %d bytes", valueName, maxConfigSecretBytes)
		}
		return direct, nil
	}
	handle, err := os.Open(file)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", fileName, err)
	}
	defer handle.Close()
	data, err := io.ReadAll(io.LimitReader(handle, maxConfigSecretBytes+1))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", fileName, err)
	}
	if len(data) > maxConfigSecretBytes {
		return "", fmt.Errorf("%s exceeds %d bytes", fileName, maxConfigSecretBytes)
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}

func insecureLoopback(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" {
		return false
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

func servePostfixPolicy(addr string, svc daemon.Service) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("postfix policy listen failed: %v", err)
		return
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("postfix policy accept failed: %v", err)
			continue
		}
		go handlePostfixPolicy(conn, svc)
	}
}

func handlePostfixPolicy(conn net.Conn, svc daemon.Service) {
	defer conn.Close()
	fields := map[string]string{}
	s := bufio.NewScanner(conn)
	s.Buffer(make([]byte, 4096), 64<<10)
	for s.Scan() {
		line := s.Text()
		if line == "" {
			break
		}
		if len(fields) >= 64 || len(line) > 4096 {
			_, _ = fmt.Fprint(conn, "action=451 4.3.0 outbound policy request too large\n\n")
			return
		}
		k, v, ok := strings.Cut(line, "=")
		if ok && k != "" {
			fields[k] = v
		}
	}
	if err := s.Err(); err != nil {
		_, _ = fmt.Fprint(conn, "action=451 4.3.0 outbound policy request unreadable\n\n")
		return
	}
	if fields["request"] != "smtpd_access_policy" || fields["protocol_state"] != "RCPT" {
		_, _ = fmt.Fprint(conn, "action=451 4.3.0 unsupported outbound policy request\n\n")
		return
	}
	recipient := fields["recipient"]
	correlationID := "postfix-policy"
	if instance := cleanPostfixToken(fields["instance"], 96); instance != "" {
		correlationID += ":" + instance
	}
	var decision daemon.Response
	if strings.TrimSpace(fields["sasl_username"]) != "" {
		decision = svc.PostfixSubmissionRecipient(context.Background(), correlationID, fields["sasl_username"], fields["sender"], recipient)
	} else {
		domain := postfixAddressDomain(recipient)
		if domain == "" {
			decision = daemon.Response{CorrelationID: correlationID, Decision: daemon.Error, Reason: "malformed_recipient"}
		} else if hosted := svc.PostfixDomain(correlationID, domain); hosted.Decision == daemon.NotFound {
			decision = daemon.Response{CorrelationID: correlationID, Decision: daemon.OK, Reason: "nonlocal_recipient_deferred_to_relay_policy"}
		} else if hosted.Decision != daemon.OK {
			decision = hosted
		} else {
			decision = svc.PostfixRecipient(correlationID, recipient)
		}
	}
	log.Printf("postfix policy correlation_id=%s decision=%s reason=%s", correlationID, decision.Decision, decision.Reason)
	switch decision.Decision {
	case daemon.OK:
		_, _ = fmt.Fprint(conn, "action=DUNNO\n\n")
	case daemon.NotFound:
		_, _ = fmt.Fprint(conn, "action=550 5.1.1 recipient unknown\n\n")
	case daemon.Defer:
		_, _ = fmt.Fprint(conn, "action=451 4.3.0 outbound policy unavailable\n\n")
	default:
		_, _ = fmt.Fprint(conn, "action=550 5.7.1 outbound recipient forbidden\n\n")
	}
}

// postfixAddressDomain returns the canonical policy domain without accepting
// display-name syntax in the Postfix protocol field.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n),
// Omega(1), where n is the bounded address length.
func postfixAddressDomain(address string) string {
	trimmed := strings.TrimSpace(address)
	at := strings.LastIndexByte(trimmed, '@')
	if at <= 0 || at == len(trimmed)-1 {
		return ""
	}
	domain, err := outboundpolicy.NormalizeDomain(trimmed[at+1:])
	if err != nil {
		return ""
	}
	return domain
}

// cleanPostfixToken bounds an opaque protocol token before it reaches logs or
// correlation state.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n),
// Omega(1), where n is capped by limit.
func cleanPostfixToken(value string, limit int) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > limit {
		return ""
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e || r == ':' {
			return ""
		}
	}
	return value
}

func referenceServer() api.Server {
	verifier := daemon.MakeDjangoPBKDF2SHA256("smoke-secret", "smokesalt", 1200)
	return api.Server{
		Authz: authz.StaticAuthorizer{},
		Daemon: daemon.Service{
			Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true, Transport: "virtual:", DKIMSelector: "mail", DKIMPrivateKeyPath: "/run/rspamd/dkim/example.test.mail.key"}},
			Mailboxes: map[string]daemon.Mailbox{
				"smoke@example.test":      {Address: "smoke@example.test", Enabled: true, Home: "/mail/example.test/smoke", UID: 5000, GID: 5000, QuotaBytes: 1073741824, Verifier: verifier},
				"postmaster@example.test": {Address: "postmaster@example.test", Enabled: true, Home: "/mail/example.test/postmaster", UID: 5000, GID: 5000, QuotaBytes: 1073741824, Verifier: verifier},
			},
			Aliases: map[string]daemon.Alias{"alias@example.test": {Address: "alias@example.test", Enabled: true, Targets: []string{"smoke@example.test"}}},
		},
		Plugins:   plugin.FirstMechanismPlugins("dev-plugin-token"),
		DNSChecks: []diag.DNSRecordCheck{{Family: "MX", Name: "example.test", Status: diag.Present, Remediation: "ok"}},
		CertCheck: diag.CertCheck{Status: diag.CertFail, Reason: "acme_not_configured_reference_manual_mode"},
		WebmailOK: true,
	}
}

func referenceAdminStore() *admin.Store {
	s := admin.NewStore()
	_ = s.UpsertDomain(admin.Domain{Name: "example.test", Enabled: true, MailHost: "mail.example.test", DKIMSelector: "mail"})
	_ = s.UpsertUser(admin.User{Address: "smoke@example.test", Enabled: true, QuotaMB: 1024})
	_ = s.UpsertAlias(admin.Alias{Address: "alias@example.test", Enabled: true, Targets: []string{"smoke@example.test"}})
	return s
}
