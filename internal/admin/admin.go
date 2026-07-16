package admin

import (
	"fmt"
	"sort"
	"strings"
)

type Domain struct {
	Name         string `json:"name"`
	Enabled      bool   `json:"enabled"`
	MailHost     string `json:"mail_host"`
	DKIMSelector string `json:"dkim_selector"`
}

type User struct {
	Address string `json:"address"`
	Enabled bool   `json:"enabled"`
	QuotaMB int    `json:"quota_mb"`
}

type Alias struct {
	Address string   `json:"address"`
	Enabled bool     `json:"enabled"`
	Targets []string `json:"targets"`
}

type Store struct {
	Domains map[string]Domain
	Users   map[string]User
	Aliases map[string]Alias
}

func NewStore() *Store {
	return &Store{Domains: map[string]Domain{}, Users: map[string]User{}, Aliases: map[string]Alias{}}
}

func (s *Store) ensure() {
	if s.Domains == nil {
		s.Domains = map[string]Domain{}
	}
	if s.Users == nil {
		s.Users = map[string]User{}
	}
	if s.Aliases == nil {
		s.Aliases = map[string]Alias{}
	}
}

func (s *Store) UpsertDomain(d Domain) error {
	s.ensure()
	d.Name = normalize(d.Name)
	if d.Name == "" || strings.Contains(d.Name, "@") {
		return fmt.Errorf("invalid domain")
	}
	if d.MailHost == "" {
		d.MailHost = "mail." + d.Name
	}
	if d.DKIMSelector == "" {
		d.DKIMSelector = "mail"
	}
	s.Domains[d.Name] = d
	return nil
}
func (s *Store) DeleteDomain(name string) error {
	s.ensure()
	delete(s.Domains, normalize(name))
	return nil
}

func (s *Store) UpsertUser(u User) error {
	s.ensure()
	u.Address = normalize(u.Address)
	if !validAddress(u.Address) {
		return fmt.Errorf("invalid user address")
	}
	if u.QuotaMB <= 0 {
		u.QuotaMB = 1024
	}
	s.Users[u.Address] = u
	return nil
}
func (s *Store) DeleteUser(address string) error {
	s.ensure()
	delete(s.Users, normalize(address))
	return nil
}

func (s *Store) UpsertAlias(a Alias) error {
	s.ensure()
	a.Address = normalize(a.Address)
	if !validAddress(a.Address) || len(a.Targets) == 0 {
		return fmt.Errorf("invalid alias")
	}
	for i := range a.Targets {
		a.Targets[i] = normalize(a.Targets[i])
		if !validAddress(a.Targets[i]) {
			return fmt.Errorf("invalid alias target")
		}
	}
	s.Aliases[a.Address] = a
	return nil
}
func (s *Store) DeleteAlias(address string) error {
	s.ensure()
	delete(s.Aliases, normalize(address))
	return nil
}

func (s *Store) Lists() ([]Domain, []User, []Alias) {
	s.ensure()
	domains := make([]Domain, 0, len(s.Domains))
	for _, v := range s.Domains {
		domains = append(domains, v)
	}
	users := make([]User, 0, len(s.Users))
	for _, v := range s.Users {
		users = append(users, v)
	}
	aliases := make([]Alias, 0, len(s.Aliases))
	for _, v := range s.Aliases {
		aliases = append(aliases, v)
	}
	sort.Slice(domains, func(i, j int) bool { return domains[i].Name < domains[j].Name })
	sort.Slice(users, func(i, j int) bool { return users[i].Address < users[j].Address })
	sort.Slice(aliases, func(i, j int) bool { return aliases[i].Address < aliases[j].Address })
	return domains, users, aliases
}

func normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
func validAddress(s string) bool {
	local, domain, ok := strings.Cut(s, "@")
	return ok && local != "" && domain != "" && !strings.Contains(domain, "@")
}
