package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/admin"
	"forgejo/gotthboard/gotth-mail/internal/api"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/daemon"
	"forgejo/gotthboard/gotth-mail/internal/diag"
	"forgejo/gotthboard/gotth-mail/internal/httpui"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	"forgejo/gotthboard/gotth-mail/internal/version"
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
	issuer = strings.TrimRight(issuer, "/") + "/"
	cfg := authn.OIDCConfig{Issuer: issuer, ClientID: clientID, ClientSecret: os.Getenv("GOTTH_MAIL_AUTHENTIK_CLIENT_SECRET"), RedirectURI: redirectURI, ClockSkew: time.Minute}
	d, jwks, err := authn.DiscoverProvider(ctx, client, cfg)
	if err != nil {
		return err
	}
	cfg.TokenEndpoint = d.TokenEndpoint
	server.OIDCConfig = cfg
	server.OIDCAuthorizeEndpoint = d.AuthorizationEndpoint
	server.OIDCJWKS = jwks
	if server.OIDCStore == nil {
		server.OIDCStore = authn.NewStore()
	}
	if server.OIDCExchanger == nil {
		server.OIDCExchanger = authn.HTTPCodeExchanger{Client: client}
	}
	return nil
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
