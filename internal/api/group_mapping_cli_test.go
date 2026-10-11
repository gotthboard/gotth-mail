package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/identityruntime"
	"forgejo/gotthboard/gotth-mail/internal/rolebinding"
	gotthoidc "github.com/gotthboard/gotth-oidc/pkg/oidc"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGroupMappingCLIVertical(t *testing.T) { groupMappingCLIVertical(t, "domain_manager") }
func TestGroupMappingCLIAllRoles(t *testing.T) {
	for _, role := range []string{"global_admin", "scoped_domain_access"} {
		t.Run(role, func(t *testing.T) { groupMappingCLIVertical(t, role) })
	}
}
func groupMappingCLIVertical(t *testing.T, role string) {
	db, ids, h, u, groups := projectionFixture(t)
	projectionExec(t, db, "DELETE FROM identity_group_role_mappings")
	root := t.TempDir()
	binary := filepath.Join(root, "gotth-mailctl")
	build := exec.Command("go", "build", "-p=1", "-o", binary, "./cmd/gotth-mailctl")
	build.Dir = "../.."
	t.Logf("native CLI compile argv=%q cwd=%s inherited constrained lane environment", build.Args, build.Dir)
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("CLI compile %v: %s", e, out)
	}
	f, e := os.Open(binary)
	if e != nil {
		t.Fatal(e)
	}
	binaryHash := sha256.New()
	if _, e = io.Copy(binaryHash, f); e != nil {
		f.Close()
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	t.Logf("native CLI compile_exit=0 binary_sha256=%x", binaryHash.Sum(nil))
	var port string
	if e := db.QueryRow("SHOW port").Scan(&port); e != nil {
		t.Fatal(e)
	}
	configPath := filepath.Join(root, "config.yaml")
	config := fmt.Sprintf(`server:
  public_url: "https://mail.example.test"
  listen: ":8080"
  environment: "development"
database:
  dsn: "postgres://gotth_mail@127.0.0.1:%s/gotth_mail?sslmode=disable"
tls:
  mode: "manual"
  cert_path: "cert.pem"
  key_path: "key.pem"
authentik:
  enabled: true
  base_url: "https://not-the-authority.example"
  oidc_client_id: "gotth-mail"
  scim_base_url: "https://not-the-authority.example/scim"
roles:
  global_admin_group: "not-authoritative"
  domain_manager_group: "not-authoritative"
  scoped_domain_group_prefix: "ignored-"
render:
  staging_dir: %q
  applied_dir: %q
plugins:
  - name: "stub-dns"
    seam: "dns"
    image: "stub:v0"
    endpoint: "dns:9443"
`, port, filepath.Join(root, "staged"), filepath.Join(root, "applied"))
	if e := os.WriteFile(configPath, []byte(config), 0600); e != nil {
		t.Fatal(e)
	}
	authority := filepath.Join(root, "authority.json")
	writeAuthority := func(body string) {
		t.Helper()
		if e := os.WriteFile(authority, []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
	}
	writeAuthority(fmt.Sprintf(`{"GOTTH_MAIL_AUTHENTIK_ISSUER":%q}`, projectionIssuer))
	call := func(args []string, path string) ([]byte, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Env = append(os.Environ(), identityruntime.ConfigFileEnv+"="+path)
		out, e := cmd.CombinedOutput()
		code := -1
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		t.Logf("native CLI argv=%q authority_file=%q inherited_lane_environment=true native_exit=%d error=%v", cmd.Args, path, code, e)
		return out, e
	}
	args := func(op, group string) []string {
		a := []string{"identity", "group-role", "preview", "--config", configPath, "--operation", op, "--issuer", projectionIssuer, "--scim-actor", "scim-test", "--group-id", group, "--role", role, "--domain", "example.test"}
		if role == "global_admin" {
			a = a[:len(a)-2]
		}
		return a
	}
	preview := func(a []string) rolebinding.GroupPlan {
		t.Helper()
		out, e := call(a, authority)
		if e != nil {
			t.Fatalf("preview %v: %s", e, out)
		}
		var p rolebinding.GroupPlan
		if e = json.Unmarshal(out, &p); e != nil {
			t.Fatal(e)
		}
		if p.GroupID == "" || p.Scope != provisioningScope("scim-test") || strings.Contains(string(out), "projection-subject") || strings.Contains(string(out), projectionIssuer) {
			t.Fatalf("unsafe/untargeted preview %s", out)
		}
		return p
	}
	apply := func(a []string, p rolebinding.GroupPlan) {
		t.Helper()
		a = append([]string(nil), a...)
		a[2] = "apply"
		a = append(a, "--confirm", p.PlanID)
		out, e := call(a, authority)
		if e != nil {
			t.Fatalf("apply %v: %s", e, out)
		}
		var r rolebinding.GroupResult
		if e = json.Unmarshal(out, &r); e != nil || !r.Changed {
			t.Fatal("apply result", string(out), e)
		}
	}
	a := args("admit", groups[0])
	before := projectionSnapshot(t, db)
	if out, e := call(a, ""); e == nil {
		t.Fatalf("empty authority fell back to BaseURL/request: %s", out)
	}
	writeAuthority(`{"GOTTH_MAIL_AUTHENTIK_ISSUER":"bad","unknown":1}`)
	if out, e := call(a, authority); e == nil {
		t.Fatalf("malformed authority accepted %s", out)
	}
	writeAuthority(fmt.Sprintf(`{"GOTTH_MAIL_AUTHENTIK_ISSUER":%q}`, projectionIssuer))
	for _, bad := range [][]string{append(append([]string(nil), a...), "--scope", "injected"), append(append([]string(nil), a...), "--unknown", "x")} {
		if out, e := call(bad, authority); e == nil {
			t.Fatalf("unknown flag accepted %s", out)
		}
	}
	for index, value := range map[int]string{8: "https://other.example/application/o/gotth-mail/", 10: "foreign-actor", 12: u, 14: "unknown"} {
		bad := append([]string(nil), a...)
		bad[index] = value
		if out, e := call(bad, authority); e == nil {
			t.Fatalf("invalid exact CLI input index=%d accepted %s", index, out)
		}
	}
	if role != "global_admin" {
		missing := append([]string(nil), a...)
		missing[len(missing)-1] = "missing.test"
		if out, e := call(missing, authority); e == nil {
			t.Fatalf("missing exact domain accepted %s", out)
		}
	}
	if e := os.Chmod(authority, 0644); e != nil {
		t.Fatal(e)
	}
	if out, e := call(a, authority); e == nil {
		t.Fatalf("unprotected authority accepted %s", out)
	}
	if e := os.Chmod(authority, 0600); e != nil {
		t.Fatal(e)
	}
	if projectionSnapshot(t, db) != before {
		t.Fatal("denied CLI mutated state")
	}
	shape := append([]string(nil), a...)
	if role == "global_admin" {
		shape = append(shape, "--domain", "example.test")
	} else {
		shape = shape[:len(shape)-2]
	}
	if out, e := call(shape, authority); e == nil {
		t.Fatalf("role/domain shape accepted %s", out)
	}
	p := preview(a)
	if !p.FutureMemberDelegation || p.MemberCount != 0 || p.AddedSources != 0 {
		t.Fatal("future delegation unclear", p)
	}
	staleApply := append([]string(nil), a...)
	staleApply[2] = "apply"
	staleApply = append(staleApply, "--confirm", p.PlanID)
	writeAuthority(`{"GOTTH_MAIL_AUTHENTIK_ISSUER":"https://other.example/application/o/gotth-mail/"}`)
	if out, e := call(staleApply, authority); e == nil {
		t.Fatalf("changed authority confirmation accepted %s", out)
	}
	writeAuthority(fmt.Sprintf(`{"GOTTH_MAIL_AUTHENTIK_ISSUER":%q}`, projectionIssuer))
	if projectionSnapshot(t, db) != before {
		t.Fatal("authority drift apply wrote")
	}
	apply(a, p)
	projectionCounts(t, db, 0, 0)
	projectionRequest(t, h, "PATCH", "/scim/v2/Groups/"+groups[0], projectionMembers(u), 200)
	projectionCounts(t, db, 0, 0)
	state := "mapping-cli-state"
	attempt := gotthoidc.ProtectedAttempt{StateHash: sha256.Sum256([]byte(state)), ContextCiphertext: "protected-context"}
	attempt.NonceCiphertext[0] = 1
	attempt.PKCEVerifierCiphertext[0] = 2
	email := "member@example.test"
	client := &apiOIDCClient{authorization: gotthoidc.Authorization{URL: "https://auth.example/authorize?state=" + state + "&nonce=nonce&code_challenge=challenge&code_challenge_method=S256", Attempt: attempt}, identity: gotthoidc.Identity{Issuer: projectionIssuer, Subject: "projection-subject", Email: &email}}
	store := authn.SQLStore{DB: db, CurrentIssuer: projectionIssuer}
	now := time.Now().UTC()
	login, e := authn.StartLogin(context.Background(), client, store, "browser", "/", now, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	completed, e := authn.CompleteCallback(context.Background(), client, store, authn.CallbackInput{Response: gotthoidc.AuthorizationResponse{State: login.StateID, Code: "synthetic-code"}, BrowserBinding: "browser"}, now.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	projectionCounts(t, db, 1, 1)
	check := func(want int) {
		t.Helper()
		b, ok := store.BoundSession(context.Background(), completed.Session.ID, now.Add(2*time.Second))
		if !ok || len(b.Roles) != want {
			t.Fatal("existing session authorization", b, ok, want)
		}
	}
	check(1)
	bound, ok := store.BoundSession(context.Background(), completed.Session.ID, now.Add(2*time.Second))
	if !ok {
		t.Fatal("bound missing")
	}
	actor := authz.Actor{Type: "oidc_subject", Mailbox: bound.Mailbox, Roles: bound.Roles}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/webmail/identity", nil)
	request.AddCookie(&http.Cookie{Name: "gotth_mail_session", Value: completed.Session.ID})
	apiActor, apiBound, authenticated := (Server{OIDCStore: store, OIDCNow: func() time.Time { return now.Add(2 * time.Second) }}).identityRequestActor(httptest.NewRecorder(), request, ids)
	if !authenticated || apiBound == nil || len(apiActor.Roles) != 0 || apiActor.Mailbox != bound.Mailbox {
		t.Fatal("API actor broadened", apiActor, authenticated)
	}
	decision, e := (authz.StaticAuthorizer{}).Decide(context.Background(), apiActor, "domain:write", authz.Resource{Type: "domain", ID: "example.test"})
	if e != nil || decision.Allow {
		t.Fatal("mailbox API acquired role authority", decision, e)
	}
	for _, tc := range []struct {
		action, domain string
		want           bool
	}{{"domain:read", "example.test", true}, {"domain:write", "example.test", role != "scoped_domain_access"}, {"domain:write", "other.test", role == "global_admin"}} {
		decision, e := (authz.StaticAuthorizer{}).Decide(context.Background(), actor, authz.Action(tc.action), authz.Resource{Type: "domain", ID: tc.domain})
		if e != nil || decision.Allow != tc.want {
			t.Fatal("real bound roles authz", role, tc, decision, e)
		}
	}
	var binding string
	if e = db.QueryRow("SELECT id::text FROM role_bindings").Scan(&binding); e != nil {
		t.Fatal(e)
	}
	a2 := args("admit", groups[1])
	apply(a2, preview(a2))
	projectionRequest(t, h, "PATCH", "/scim/v2/Groups/"+groups[1], projectionMembers(u), 200)
	projectionCounts(t, db, 1, 2)
	operator := func(op string) {
		t.Helper()
		a := []string{"identity", "role-binding", "preview", "--config", configPath, "--operation", op, "--issuer", projectionIssuer, "--subject", "projection-subject", "--mailbox", "member@example.test", "--role", role, "--domain", "example.test"}
		if role == "global_admin" {
			a = a[:len(a)-2]
		}
		out, e := call(a, authority)
		if e != nil {
			t.Fatal(string(out), e)
		}
		var p rolebinding.Plan
		if e = json.Unmarshal(out, &p); e != nil {
			t.Fatal(e)
		}
		a[2] = "apply"
		a = append(a, "--confirm", p.PlanID)
		if out, e = call(a, authority); e != nil {
			t.Fatal(string(out), e)
		}
	}
	operator("grant")
	a = args("disable", groups[0])
	p = preview(a)
	if !p.EffectiveAfter || p.Impacts[0].SourcesAfter != 1 || !p.Impacts[0].OperatorOwned {
		t.Fatal("disable falsely promised revocation", p)
	}
	apply(a, p)
	projectionCounts(t, db, 1, 1)
	check(1)
	var same string
	if e = db.QueryRow("SELECT id::text FROM role_bindings").Scan(&same); e != nil || same != binding {
		t.Fatal("UUID changed", same, e)
	}
	operator("revoke")
	check(1)
	a = args("disable", groups[1])
	apply(a, preview(a))
	projectionCounts(t, db, 0, 0)
	check(0)
	t.Log("real CLI preview/confirm -> actual SCIM -> existing provider stub/real OIDC binding -> BoundSession -> independent CLI disable/revoke passed; no live-provider proof")
}
