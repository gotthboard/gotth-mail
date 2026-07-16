package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server    Server    `yaml:"server"`
	Database  Database  `yaml:"database"`
	TLS       TLS       `yaml:"tls"`
	Authentik Authentik `yaml:"authentik"`
	Roles     Roles     `yaml:"roles"`
	Render    Render    `yaml:"render"`
	Plugins   []Plugin  `yaml:"plugins"`
}
type Server struct {
	PublicURL   string `yaml:"public_url"`
	Listen      string `yaml:"listen"`
	Environment string `yaml:"environment"`
}
type Database struct {
	DSN string `yaml:"dsn"`
}
type TLS struct {
	Mode     string `yaml:"mode"`
	CertPath string `yaml:"cert_path"`
	KeyPath  string `yaml:"key_path"`
}
type Authentik struct {
	Enabled      bool   `yaml:"enabled"`
	BaseURL      string `yaml:"base_url"`
	OIDCClientID string `yaml:"oidc_client_id"`
	SCIMBaseURL  string `yaml:"scim_base_url"`
}
type Roles struct {
	GlobalAdminGroup        string `yaml:"global_admin_group"`
	DomainManagerGroup      string `yaml:"domain_manager_group"`
	ScopedDomainGroupPrefix string `yaml:"scoped_domain_group_prefix"`
}
type Render struct {
	StagingDir   string   `yaml:"staging_dir"`
	AppliedDir   string   `yaml:"applied_dir"`
	OverrideDirs []string `yaml:"override_dir"`
}

func (r *Render) UnmarshalYAML(value *yaml.Node) error {
	type rawRender struct {
		StagingDir string    `yaml:"staging_dir"`
		AppliedDir string    `yaml:"applied_dir"`
		Override   yaml.Node `yaml:"override_dir"`
	}
	var rr rawRender
	if err := value.Decode(&rr); err != nil {
		return err
	}
	r.StagingDir = rr.StagingDir
	r.AppliedDir = rr.AppliedDir
	if rr.Override.Kind == 0 {
		return nil
	}
	if rr.Override.Kind == yaml.SequenceNode {
		return rr.Override.Decode(&r.OverrideDirs)
	}
	var one string
	if err := rr.Override.Decode(&one); err != nil {
		return err
	}
	if one != "" {
		r.OverrideDirs = []string{one}
	}
	return nil
}

type Plugin struct {
	Name     string `yaml:"name"`
	Seam     string `yaml:"seam"`
	Image    string `yaml:"image"`
	Endpoint string `yaml:"endpoint"`
}

var allowedSeams = map[string]bool{"webmail": true, "dns": true, "acme": true, "backup": true, "notification": true, "import": true}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return Parse(string(b))
}

func Parse(s string) (Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewBufferString(s))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c Config) Validate() error {
	if c.Server.PublicURL == "" {
		return errors.New("server.public_url required")
	}
	u, err := url.Parse(c.Server.PublicURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("server.public_url must be absolute")
	}
	if c.Server.Listen == "" {
		return errors.New("server.listen required")
	}
	if c.Database.DSN == "" {
		return errors.New("database.dsn required")
	}
	if c.TLS.Mode != "manual" && c.TLS.Mode != "letsencrypt" && c.TLS.Mode != "dev_self_signed" {
		return errors.New("tls.mode invalid")
	}
	prod := c.Server.Environment == "production" || strings.HasPrefix(c.Server.PublicURL, "https://") && !strings.Contains(u.Host, ".test")
	if prod && c.TLS.Mode == "dev_self_signed" {
		return errors.New("production cannot use dev_self_signed")
	}
	if c.TLS.Mode == "manual" && (c.TLS.CertPath == "" || c.TLS.KeyPath == "") {
		return errors.New("manual TLS requires cert_path and key_path")
	}
	if !c.Authentik.Enabled {
		return errors.New("authentik.enabled must be true in v0 topology")
	}
	au, err := url.Parse(c.Authentik.BaseURL)
	if err != nil || au.Scheme == "" || au.Host == "" {
		return errors.New("authentik.base_url must be absolute")
	}
	if au.Host == "" || u.Host == "" {
		return errors.New("public/authentik host required")
	}
	if c.Roles.GlobalAdminGroup == "" || c.Roles.DomainManagerGroup == "" || c.Roles.ScopedDomainGroupPrefix == "" {
		return errors.New("role mappings required")
	}
	if c.Render.StagingDir == "" || c.Render.AppliedDir == "" {
		return errors.New("render dirs required")
	}
	if samePath(c.Render.StagingDir, c.Render.AppliedDir) {
		return errors.New("render dirs must not overlap")
	}
	for _, o := range c.Render.OverrideDirs {
		if samePath(o, c.Render.StagingDir) || samePath(o, c.Render.AppliedDir) {
			return errors.New("override paths must not overlap generated dirs")
		}
	}
	for _, p := range c.Plugins {
		if p.Name == "" || p.Image == "" || p.Endpoint == "" {
			return errors.New("plugin name/image/endpoint required")
		}
		if !allowedSeams[p.Seam] {
			return fmt.Errorf("plugin seam invalid: %s", p.Seam)
		}
	}
	return nil
}

func samePath(a, b string) bool {
	aa := filepath.Clean(a)
	bb := filepath.Clean(b)
	return aa == bb || strings.HasPrefix(aa, bb+string(os.PathSeparator)) || strings.HasPrefix(bb, aa+string(os.PathSeparator))
}
