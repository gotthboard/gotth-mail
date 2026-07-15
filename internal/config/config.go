package config

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Server    Server
	Database  Database
	TLS       TLS
	Authentik Authentik
	Roles     Roles
	Render    Render
	Plugins   []Plugin
}
type Server struct{ PublicURL, Listen, Environment string }
type Database struct{ DSN string }
type TLS struct{ Mode, CertPath, KeyPath string }
type Authentik struct {
	Enabled                            bool
	BaseURL, OIDCClientID, SCIMBaseURL string
}
type Roles struct{ GlobalAdminGroup, DomainManagerGroup, ScopedDomainGroupPrefix string }
type Render struct {
	StagingDir, AppliedDir string
	OverrideDirs           []string
}
type Plugin struct{ Name, Seam, Image, Endpoint string }

var allowedTop = map[string]bool{"server": true, "database": true, "tls": true, "authentik": true, "roles": true, "render": true, "plugins": true}
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
	scanner := bufio.NewScanner(strings.NewReader(s))
	section := ""
	inPlugin := false
	var cur *Plugin
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(raw, " ") && strings.HasSuffix(line, ":") {
			section = strings.TrimSuffix(line, ":")
			if !allowedTop[section] {
				return c, fmt.Errorf("unknown top-level section %q", section)
			}
			inPlugin = false
			continue
		}
		if section == "plugins" && strings.HasPrefix(line, "- ") {
			p := Plugin{}
			c.Plugins = append(c.Plugins, p)
			cur = &c.Plugins[len(c.Plugins)-1]
			inPlugin = true
			kv := strings.TrimSpace(strings.TrimPrefix(line, "- "))
			if kv != "" {
				setPlugin(cur, kv)
			}
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return c, fmt.Errorf("invalid line %q", line)
		}
		key := strings.TrimSpace(parts[0])
		val := unquote(strings.TrimSpace(parts[1]))
		if inPlugin && cur != nil {
			setPlugin(cur, key+":"+val)
			continue
		}
		switch section {
		case "server":
			if key == "public_url" {
				c.Server.PublicURL = val
			} else if key == "listen" {
				c.Server.Listen = val
			} else if key == "environment" {
				c.Server.Environment = val
			} else {
				return c, fmt.Errorf("unknown server key %q", key)
			}
		case "database":
			if key == "dsn" {
				c.Database.DSN = val
			} else {
				return c, fmt.Errorf("unknown database key %q", key)
			}
		case "tls":
			if key == "mode" {
				c.TLS.Mode = val
			} else if key == "cert_path" {
				c.TLS.CertPath = val
			} else if key == "key_path" {
				c.TLS.KeyPath = val
			} else {
				return c, fmt.Errorf("unknown tls key %q", key)
			}
		case "authentik":
			if key == "enabled" {
				c.Authentik.Enabled = val == "true"
			} else if key == "base_url" {
				c.Authentik.BaseURL = val
			} else if key == "oidc_client_id" {
				c.Authentik.OIDCClientID = val
			} else if key == "scim_base_url" {
				c.Authentik.SCIMBaseURL = val
			} else {
				return c, fmt.Errorf("unknown authentik key %q", key)
			}
		case "roles":
			if key == "global_admin_group" {
				c.Roles.GlobalAdminGroup = val
			} else if key == "domain_manager_group" {
				c.Roles.DomainManagerGroup = val
			} else if key == "scoped_domain_group_prefix" {
				c.Roles.ScopedDomainGroupPrefix = val
			} else {
				return c, fmt.Errorf("unknown roles key %q", key)
			}
		case "render":
			if key == "staging_dir" {
				c.Render.StagingDir = val
			} else if key == "applied_dir" {
				c.Render.AppliedDir = val
			} else if key == "override_dir" {
				c.Render.OverrideDirs = append(c.Render.OverrideDirs, val)
			} else {
				return c, fmt.Errorf("unknown render key %q", key)
			}
		default:
			return c, fmt.Errorf("key outside section %q", line)
		}
	}
	return c, scanner.Err()
}
func setPlugin(p *Plugin, kv string) {
	parts := strings.SplitN(kv, ":", 2)
	if len(parts) != 2 {
		return
	}
	k := strings.TrimSpace(parts[0])
	v := unquote(strings.TrimSpace(parts[1]))
	switch k {
	case "name":
		p.Name = v
	case "seam":
		p.Seam = v
	case "image":
		p.Image = v
	case "endpoint":
		p.Endpoint = v
	}
}
func unquote(s string) string { return strings.Trim(s, " \t\"") }
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
