package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"forgejo/linus/gophermailforge/internal/api"
	"forgejo/linus/gophermailforge/internal/authz"
	"forgejo/linus/gophermailforge/internal/daemon"
	"forgejo/linus/gophermailforge/internal/httpui"
	"forgejo/linus/gophermailforge/internal/plugin"
)

func main() {
	mux := http.NewServeMux()
	server := api.Server{Authz: authz.StaticAuthorizer{}}
	if os.Getenv("GMF_REFERENCE_FIXTURE") == "1" {
		server = referenceServer()
		go servePostfixPolicy(os.Getenv("GMF_POSTFIX_POLICY_LISTEN"), server.Daemon)
	}
	mux.Handle("/api/", server.Handler())
	mux.Handle("/internal/", server.Handler())
	mux.Handle("/healthz", server.Handler())
	mux.Handle("/readyz", server.Handler())
	mux.Handle("/", httpui.Handler())
	addr := os.Getenv("GMF_LISTEN")
	if addr == "" {
		addr = ":8080"
	}
	log.Fatal(http.ListenAndServe(addr, mux))
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
		Plugins: plugin.FirstMechanismPlugins("dev-plugin-token"),
	}
}
