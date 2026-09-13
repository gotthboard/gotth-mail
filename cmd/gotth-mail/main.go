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
	"net/url"
	"os"
	"strings"

	"forgejo/gotthboard/gotth-mail/internal/admin"
	"forgejo/gotthboard/gotth-mail/internal/api"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/daemon"
	"forgejo/gotthboard/gotth-mail/internal/diag"
	"forgejo/gotthboard/gotth-mail/internal/httpui"
	"forgejo/gotthboard/gotth-mail/internal/identity"
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
	mux := http.NewServeMux()
	server := api.Server{Authz: authz.StaticAuthorizer{}}
	if os.Getenv("GOTTH_MAIL_REFERENCE_FIXTURE") == "1" {
		server = referenceServer()
		go servePostfixPolicy(os.Getenv("GOTTH_MAIL_POSTFIX_POLICY_LISTEN"), server.Daemon)
	}
	db, err := configureDatabaseFromEnv(context.Background(), &server)
	if err != nil {
		log.Fatalf("configure database: %v", err)
	}
	if db != nil {
		defer db.Close()
	}
	if err := configureOIDCFromEnv(context.Background(), &server, http.DefaultClient); err != nil {
		log.Fatalf("configure oidc: %v", err)
	}
	mux.Handle("/api/", server.Handler())
	mux.Handle("/internal/", server.Handler())
	mux.Handle("/healthz", server.Handler())
	mux.Handle("/readyz", server.Handler())
	mux.Handle("/webmail", server.Handler())
	mux.Handle("/", httpui.HandlerWithAdmin(referenceAdminStore()))
	addr := os.Getenv("GOTTH_MAIL_LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	log.Fatal(http.ListenAndServe(addr, mux))
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
	identityService, err := identity.NewSQLService(ctx, db)
	if err != nil {
		return closeOnError(fmt.Errorf("load identity state: %w", err))
	}
	server.AuditDB = db
	server.OIDCStore = authn.SQLStore{DB: db}
	server.Identity = identityService
	return db, nil
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
	if addr == "" {
		addr = ":10025"
	}
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
	for s.Scan() {
		line := s.Text()
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			fields[k] = v
		}
	}
	recipient := fields["recipient"]
	decision := svc.PostfixRecipient("postfix-policy", recipient)
	log.Printf("postfix policy recipient=%s decision=%s reason=%s", recipient, decision.Decision, decision.Reason)
	switch decision.Decision {
	case daemon.OK:
		_, _ = fmt.Fprint(conn, "action=OK\n\n")
	case daemon.NotFound:
		_, _ = fmt.Fprint(conn, "action=REJECT recipient unknown\n\n")
	case daemon.Defer:
		_, _ = fmt.Fprint(conn, "action=DEFER_IF_PERMIT temporary lookup failure\n\n")
	default:
		_, _ = fmt.Fprint(conn, "action=REJECT recipient rejected\n\n")
	}
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
