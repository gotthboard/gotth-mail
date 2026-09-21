package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	manifestSchema = 1
	maxSpecBytes   = 1 << 20
	maxMemberBytes = 16 << 20
	archiveName    = "gotth-mail-config.tar"
	manifestName   = "gotth-mail-release.json"
)

var (
	versionPattern   = regexp.MustCompile(`^1\.0\.0(?:-(?:alpha|beta)\.[1-9][0-9]*)?$`)
	commitPattern    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	memberPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*$`)
	goVersionPattern = regexp.MustCompile(`^go1\.[0-9]+\.[0-9]+[-+:A-Za-z0-9._]*$`)
)

var roleRepositories = []struct {
	role       string
	repository string
}{
	{"control-plane", "ghcr.io/gotthboard/gotth-mail-control-plane"},
	{"dovecot", "ghcr.io/gotthboard/gotth-mail-dovecot"},
	{"front", "ghcr.io/gotthboard/gotth-mail-front"},
	{"postfix", "ghcr.io/gotthboard/gotth-mail-postfix"},
	{"rspamd", "ghcr.io/gotthboard/gotth-mail-rspamd"},
}

var requiredConfiguration = map[string]struct{}{
	"control/environment": {}, "front/nginx.conf": {},
	"postfix/environment": {}, "postfix/main.cf": {}, "postfix/master.cf": {},
	"dovecot/dovecot.conf": {}, "rspamd/rspamd.conf": {}, "rspamd/override.inc": {},
}

var configurationEnvironmentKeys = map[string]map[string]struct{}{
	"control/environment": {
		"GOTTH_MAIL_LISTEN": {}, "GOTTH_MAIL_DATABASE_URL_FILE": {},
		"GOTTH_MAIL_AUTHENTIK_ISSUER": {}, "GOTTH_MAIL_AUTHENTIK_CLIENT_ID": {},
		"GOTTH_MAIL_AUTHENTIK_CLIENT_SECRET_FILE": {}, "GOTTH_MAIL_AUTHENTIK_REDIRECT_URI": {},
		"GOTTH_MAIL_SCIM_EXTERNAL_URL": {}, "GOTTH_MAIL_FRONT_AUTH_TOKEN_FILE": {},
		"GOTTH_MAIL_EXTENSION_MASTER_KEY_FILE": {}, "GOTTH_MAIL_EXTENSION_ARTIFACT_ROOT": {},
		"GOTTH_MAIL_EXTENSION_RUNTIME_ROOT": {}, "GOTTH_MAIL_NOTIFICATION_PLUGIN_NAME": {},
		"GOTTH_MAIL_NOTIFICATION_PLUGIN_ENDPOINT": {}, "GOTTH_MAIL_NOTIFICATION_PLUGIN_SERVICE_TOKEN_FILE": {},
		"GOTTH_MAIL_NOTIFICATION_EMAIL_FROM": {}, "GOTTH_MAIL_POSTFIX_HELPER_URL": {},
		"GOTTH_MAIL_POSTFIX_HELPER_TOKEN_FILE": {}, "GOTTH_MAIL_POSTFIX_RELEASE_TOKEN_FILE": {},
		"GOTTH_MAIL_POSTFIX_POLICY_LISTEN": {}, "GOTTH_MAIL_POSTFIX_AUTOMATIC_SENDER_ADDRESS": {},
		"GOTTH_MAIL_POSTFIX_AUTOMATIC_SENDER_ID": {}, "GOTTH_MAIL_WEBMAIL_RUNTIME_FILE": {},
		"GOTTH_MAIL_POSTFIX_DOMAIN_MAP_LISTEN": {}, "GOTTH_MAIL_POSTFIX_MAILBOX_MAP_LISTEN": {},
		"GOTTH_MAIL_POSTFIX_ALIAS_MAP_LISTEN": {},
	},
	"postfix/environment": {
		"GOTTH_MAIL_CORE_URL": {}, "GOTTH_MAIL_POSTFIX_HELPER_TOKEN_FILE": {},
		"GOTTH_MAIL_POSTFIX_RELEASE_TOKEN_FILE": {}, "GOTTH_MAIL_POSTFIX_INSTANCE": {},
		"GOTTH_MAIL_POSTFIX_HELPER_LISTEN": {}, "GOTTH_MAIL_OUTBOUND_RELAY_ADDR": {},
	},
}

var forbiddenConfigurationFragments = [][]byte{
	[]byte("example.test"), []byte("mailu"), []byte("roundcube"), []byte("telegram"),
	[]byte("-----begin private key-----"), []byte("-----begin rsa private key-----"),
	[]byte("-----begin ec private key-----"), []byte("-----begin openssh private key-----"),
}

type fileArtifact struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

type roleArtifact struct {
	Role        string `json:"role"`
	Image       string `json:"image"`
	ImageDigest string `json:"image_digest"`
}

type extensionArtifact struct {
	Repository     string `json:"repository"`
	Version        string `json:"version"`
	ArtifactDigest string `json:"artifact_digest"`
	ManifestDigest string `json:"manifest_digest"`
}

type schemaRange struct {
	Minimum uint32 `json:"minimum"`
	Current uint32 `json:"current"`
	Maximum uint32 `json:"maximum"`
}

type buildMetadata struct {
	GoVersion      string `json:"go_version"`
	GOOS           string `json:"goos"`
	GOARCH         string `json:"goarch"`
	BuildDateEpoch int64  `json:"build_date_epoch"`
}

type releaseSpec struct {
	ProductVersion   string              `json:"product_version"`
	TagObject        string              `json:"tag_object"`
	SourceCommit     string              `json:"source_commit"`
	ForgejoRefCommit string              `json:"forgejo_ref_commit"`
	GitHubRefCommit  string              `json:"github_ref_commit"`
	Images           map[string]string   `json:"images"`
	Extensions       []extensionArtifact `json:"extensions"`
	Schema           schemaRange         `json:"schema"`
	Build            buildMetadata       `json:"build"`
}

type releaseManifest struct {
	SchemaVersion        int                 `json:"schema_version"`
	ProductVersion       string              `json:"product_version"`
	Tag                  string              `json:"tag"`
	TagObject            string              `json:"tag_object"`
	SourceCommit         string              `json:"source_commit"`
	ForgejoRefCommit     string              `json:"forgejo_ref_commit"`
	GitHubRefCommit      string              `json:"github_ref_commit"`
	ForgejoRepository    string              `json:"forgejo_repository"`
	GitHubRepository     string              `json:"github_repository"`
	ConfigurationArchive fileArtifact        `json:"configuration_archive"`
	ConfigurationMembers []fileArtifact      `json:"configuration_members"`
	Roles                []roleArtifact      `json:"roles"`
	Extensions           []extensionArtifact `json:"extensions"`
	Schema               schemaRange         `json:"schema"`
	Build                buildMetadata       `json:"build"`
}

func main() {
	flags := flag.NewFlagSet("gotth-mail-release", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	specPath := flags.String("spec", "", "")
	configDir := flags.String("config-dir", "", "")
	outputDir := flags.String("output-dir", "", "")
	if err := flags.Parse(os.Args[1:]); err != nil || flags.NArg() != 0 || *specPath == "" || *configDir == "" || *outputDir == "" {
		fmt.Fprintln(os.Stderr, "usage: gotth-mail-release --spec FILE --config-dir DIR --output-dir DIR")
		os.Exit(2)
	}
	if err := buildRelease(*specPath, *configDir, *outputDir); err != nil {
		fmt.Fprintln(os.Stderr, "gotth-mail-release:", err)
		os.Exit(1)
	}
}

// buildRelease assembles one closed release manifest and configuration
// archive. Complexity: time O(s+c), Omega(s+c), tight Theta(s+c); auxiliary
// space O(s+c), Omega(c), where s is the bounded specification size and c is
// the total bounded configuration byte count.
func buildRelease(specPath, configDir, outputDir string) error {
	spec, err := readSpec(specPath)
	if err != nil {
		return err
	}
	members, contents, err := readConfiguration(configDir)
	if err != nil {
		return err
	}
	archive, err := encodeArchive(members, contents)
	if err != nil {
		return err
	}
	archiveSum := sha256.Sum256(archive)
	manifest := releaseManifest{
		SchemaVersion: manifestSchema, ProductVersion: spec.ProductVersion, Tag: "v" + spec.ProductVersion,
		TagObject: spec.TagObject, SourceCommit: spec.SourceCommit,
		ForgejoRefCommit: spec.ForgejoRefCommit, GitHubRefCommit: spec.GitHubRefCommit,
		ForgejoRepository:    "https://git.dannyhunn.com/gotthboard/gotth-mail",
		GitHubRepository:     "https://github.com/gotthboard/gotth-mail",
		ConfigurationArchive: fileArtifact{Name: archiveName, Digest: digest(archiveSum[:]), Size: int64(len(archive))},
		ConfigurationMembers: members, Extensions: spec.Extensions, Schema: spec.Schema, Build: spec.Build,
	}
	for _, role := range roleRepositories {
		value := spec.Images[role.role]
		manifest.Roles = append(manifest.Roles, roleArtifact{Role: role.role, Image: role.repository + "@" + value, ImageDigest: value})
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return errors.New("encode release manifest")
	}
	encoded = append(encoded, '\n')
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := writeAtomic(filepath.Join(outputDir, archiveName), archive, 0o440); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(outputDir, manifestName), encoded, 0o440)
}

// readSpec decodes and validates one bounded closed release specification.
// Complexity: time O(n+e), Omega(n+e), tight Theta(n+e); auxiliary space
// O(n+e), Omega(e), where n is the bounded JSON byte count and e is the
// extension count; the five image roles are constant.
func readSpec(path string) (releaseSpec, error) {
	handle, err := os.Open(path)
	if err != nil {
		return releaseSpec{}, fmt.Errorf("open release specification: %w", err)
	}
	defer handle.Close()
	decoder := json.NewDecoder(io.LimitReader(handle, maxSpecBytes+1))
	decoder.DisallowUnknownFields()
	var spec releaseSpec
	if err := decoder.Decode(&spec); err != nil {
		return releaseSpec{}, errors.New("decode release specification")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return releaseSpec{}, errors.New("release specification has trailing data")
	}
	if !versionPattern.MatchString(spec.ProductVersion) || !commitPattern.MatchString(spec.TagObject) || !commitPattern.MatchString(spec.SourceCommit) || spec.ForgejoRefCommit != spec.SourceCommit || spec.GitHubRefCommit != spec.SourceCommit || len(spec.Images) != len(roleRepositories) || spec.Schema.Minimum == 0 || spec.Schema.Minimum > spec.Schema.Current || spec.Schema.Current > spec.Schema.Maximum || !goVersionPattern.MatchString(spec.Build.GoVersion) || spec.Build.GOOS != "linux" || spec.Build.GOARCH != "amd64" || spec.Build.BuildDateEpoch <= 0 {
		return releaseSpec{}, errors.New("release specification contract is invalid")
	}
	for _, role := range roleRepositories {
		if !digestPattern.MatchString(spec.Images[role.role]) {
			return releaseSpec{}, errors.New("release image digest contract is invalid")
		}
	}
	previous := ""
	for _, extension := range spec.Extensions {
		if extension.Repository <= previous || !strings.HasPrefix(extension.Repository, "github.com/gotthboard/gotth-extension-") || !versionPattern.MatchString(extension.Version) || !digestPattern.MatchString(extension.ArtifactDigest) || !digestPattern.MatchString(extension.ManifestDigest) {
			return releaseSpec{}, errors.New("release extension contract is invalid")
		}
		previous = extension.Repository
	}
	return spec, nil
}

func readConfiguration(root string) ([]fileArtifact, map[string][]byte, error) {
	contents := make(map[string][]byte, len(requiredConfiguration))
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		name, err := filepath.Rel(root, path)
		if err != nil || name == "." {
			return err
		}
		name = filepath.ToSlash(name)
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("configuration symlink rejected")
		}
		if entry.IsDir() {
			return nil
		}
		if _, ok := requiredConfiguration[name]; !ok || !memberPattern.MatchString(name) {
			return errors.New("unknown configuration member")
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 || len(data) > maxMemberBytes {
			return errors.New("configuration member is unreadable or invalid")
		}
		if err := validateConfigurationMember(name, data); err != nil {
			return err
		}
		contents[name] = data
		return nil
	})
	if err != nil || len(contents) != len(requiredConfiguration) {
		return nil, nil, errors.New("configuration set is incomplete or invalid")
	}
	names := make([]string, 0, len(contents))
	for name := range contents {
		names = append(names, name)
	}
	sort.Strings(names)
	members := make([]fileArtifact, 0, len(names))
	for _, name := range names {
		sum := sha256.Sum256(contents[name])
		members = append(members, fileArtifact{Name: name, Digest: digest(sum[:]), Size: int64(len(contents[name]))})
	}
	return members, contents, nil
}

// validateConfigurationMember rejects reference-stack material and values in
// slots that must remain file-backed. Complexity: time O(n), Omega(n), tight
// Theta(n); auxiliary space O(n), Omega(n), where n is the member byte count.
func validateConfigurationMember(name string, data []byte) error {
	lower := bytes.ToLower(data)
	for _, fragment := range forbiddenConfigurationFragments {
		if bytes.Contains(lower, fragment) {
			return errors.New("configuration contains forbidden release material")
		}
	}
	switch name {
	case "front/nginx.conf":
		if bytes.Count(data, []byte("@GOTTH_MAIL_FRONT_AUTH_TOKEN@")) != 1 {
			return errors.New("front configuration has invalid secret placeholder contract")
		}
	case "rspamd/override.inc":
		if bytes.Count(data, []byte("@GOTTH_MAIL_RSPAMD_CONTROLLER_TOKEN@")) != 2 {
			return errors.New("Rspamd configuration has invalid secret placeholder contract")
		}
	case "control/environment", "postfix/environment":
		return validateConfigurationEnvironment(name, data)
	}
	return nil
}

// validateConfigurationEnvironment accepts only runtime-supported names and
// requires every secret-bearing slot to reference an immutable file.
// Complexity: time O(n), Omega(n), tight Theta(n); auxiliary space O(k),
// Omega(k), where n is the member byte count and k is its assignment count.
func validateConfigurationEnvironment(name string, data []byte) error {
	allowed := configurationEnvironmentKeys[name]
	seen := make(map[string]struct{})
	for _, raw := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		_, admitted := allowed[key]
		if !found || !admitted || value == "" || strings.TrimSpace(key) != key || strings.ContainsAny(value, "\x00\r\n") {
			return errors.New("configuration environment contains invalid assignment")
		}
		if _, duplicate := seen[key]; duplicate {
			return errors.New("configuration environment contains duplicate assignment")
		}
		seen[key] = struct{}{}
		upper := strings.ToUpper(key)
		secretBearing := strings.Contains(upper, "TOKEN") || strings.Contains(upper, "SECRET") || strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "MASTER_KEY") || strings.Contains(upper, "DATABASE_URL")
		if secretBearing && (!strings.HasSuffix(key, "_FILE") || !strings.HasPrefix(value, "/run/secrets/") || filepath.Clean(value) != value) {
			return errors.New("configuration secret slot is not an immutable file reference")
		}
	}
	return nil
}

func encodeArchive(members []fileArtifact, contents map[string][]byte) ([]byte, error) {
	var output bytes.Buffer
	archive := tar.NewWriter(&output)
	for _, member := range members {
		header := &tar.Header{Name: member.Name, Mode: 0o440, Size: member.Size, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}
		if err := archive.WriteHeader(header); err != nil {
			return nil, errors.New("write configuration archive header")
		}
		if _, err := archive.Write(contents[member.Name]); err != nil {
			return nil, errors.New("write configuration archive member")
		}
	}
	if err := archive.Close(); err != nil {
		return nil, errors.New("close configuration archive")
	}
	return output.Bytes(), nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".gotth-mail-release-*")
	if err != nil {
		return fmt.Errorf("create release output: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return errors.New("set release output mode")
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return errors.New("write release output")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return errors.New("sync release output")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close release output")
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if _, inspectErr := os.Lstat(path); inspectErr == nil {
			return errors.New("release output already exists")
		}
		return errors.New("publish release output")
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errors.New("open release output directory")
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return errors.New("sync release output directory")
	}
	return nil
}

func digest(value []byte) string { return "sha256:" + hex.EncodeToString(value) }
