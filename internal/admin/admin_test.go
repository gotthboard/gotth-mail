package admin

import "testing"

func TestAdminStoreDomainUserAliasCRUD(t *testing.T) {
	s := NewStore()
	if err := s.UpsertDomain(Domain{Name: "Example.Test", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertUser(User{Address: "Smoke@Example.Test", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertAlias(Alias{Address: "Alias@Example.Test", Enabled: true, Targets: []string{"Smoke@Example.Test"}}); err != nil {
		t.Fatal(err)
	}
	d, u, a := s.Lists()
	if len(d) != 1 || d[0].Name != "example.test" || d[0].MailHost != "mail.example.test" || d[0].DKIMSelector != "mail" {
		t.Fatalf("domain not normalized/defaulted: %#v", d)
	}
	if len(u) != 1 || u[0].Address != "smoke@example.test" || u[0].QuotaMB != 1024 {
		t.Fatalf("user not normalized/defaulted: %#v", u)
	}
	if len(a) != 1 || a[0].Address != "alias@example.test" || a[0].Targets[0] != "smoke@example.test" {
		t.Fatalf("alias not normalized: %#v", a)
	}
	s.DeleteAlias("alias@example.test")
	s.DeleteUser("smoke@example.test")
	s.DeleteDomain("example.test")
	d, u, a = s.Lists()
	if len(d)+len(u)+len(a) != 0 {
		t.Fatalf("delete failed: %#v %#v %#v", d, u, a)
	}
}

func TestAdminStoreRejectsInvalidAlias(t *testing.T) {
	s := NewStore()
	if err := s.UpsertAlias(Alias{Address: "alias@example.test"}); err == nil {
		t.Fatal("missing targets accepted")
	}
	if err := s.UpsertUser(User{Address: "not-an-address"}); err == nil {
		t.Fatal("invalid user accepted")
	}
}
