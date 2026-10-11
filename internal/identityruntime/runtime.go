// Package identityruntime holds the shared deployment authority for identity roles.
package identityruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
)

const ConfigFileEnv = "GOTTH_MAIL_IDENTITY_RUNTIME_CONFIG_FILE"
const IssuerEnv = "GOTTH_MAIL_AUTHENTIK_ISSUER"

// NormalizeIssuer preserves the existing OIDC environment normalization, not URL rewriting.
// Complexity: n input bytes; worst time O(n), Omega(n), Theta(n); auxiliary
// space O(n), Omega(1), no uniform tight bound (a suffix allocation is optional).
func NormalizeIssuer(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	return strings.TrimRight(value, "/") + "/"
}

// Scope derives the opaque scope only from the stable authenticated SCIM actor ID.
// Complexity: n actor bytes; time O(n), Omega(n), Theta(n); auxiliary space
// O(n), Omega(n), Theta(n), including the prefixed SHA256 input and fixed output.
func Scope(actorID string) string {
	digest := sha256.Sum256([]byte("gotth-mail/scim-scope/v1\x00" + actorID))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// LoadIssuer reads only one protected deployment file. No group/service-reader
// access is admitted by this loader: deploy an owner-readable file to each consumer.
// Complexity: n<=4097 bytes read; success time O(n+F), Omega(n+F), Theta(n+F),
// auxiliary O(n), Omega(n), Theta(n). F is delegated open/stat/read/close cost.
// Early rejection is O(n+F), Omega(1), no uniform tight bound. No FIFO blocking.
func LoadIssuer(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", errors.New("identity runtime file cannot be opened")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return "", errors.New("identity runtime file unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", errors.New("identity runtime file cannot be inspected")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || (stat.Uid != 0 && int(stat.Uid) != os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("identity runtime file must be protected and owned by root or effective user")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 {
		return "", errors.New("identity runtime file exceeds limit or cannot be read")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return "", errors.New("identity runtime file must contain one issuer object")
	}
	if !decoder.More() {
		return "", errors.New("identity runtime issuer is missing")
	}
	key, err := decoder.Token()
	if err != nil || key != IssuerEnv {
		return "", errors.New("identity runtime key is invalid")
	}
	var raw string
	if err := decoder.Decode(&raw); err != nil || NormalizeIssuer(raw) == "" {
		return "", errors.New("identity runtime issuer is invalid")
	}
	if decoder.More() {
		return "", errors.New("identity runtime keys are duplicate or unknown")
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return "", errors.New("identity runtime object is invalid")
	}
	if _, err = decoder.Token(); err != io.EOF {
		return "", errors.New("identity runtime trailing value is invalid")
	}
	return NormalizeIssuer(raw), nil
}

// ServiceIssuer additionally binds the deployment authority to the OIDC environment.
// Complexity: n file bytes, e environment bytes, F filesystem work; successful
// time O(n+e+F), Omega(n+e+F), Theta(n+e+F); auxiliary O(n+e), Omega(n),
// no uniform tight space bound. Empty path: time/space O(1), Omega(1), Theta(1).
// Early failures have Omega(1) time/space; no uniform tight time bound.
func ServiceIssuer(path, environment string) (string, error) {
	issuer, err := LoadIssuer(path)
	if err != nil || issuer == "" {
		return issuer, err
	}
	if NormalizeIssuer(environment) != issuer {
		return "", errors.New("identity runtime issuer does not match OIDC environment")
	}
	return issuer, nil
}
