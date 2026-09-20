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
	versionPattern = regexp.MustCompile(`^1\.0\.0-(?:alpha|beta)\.[1-9][0-9]*$`)
	commitPattern  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	memberPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*$`)
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
	"dovecot/dovecot.conf": {}, "rspamd/rspamd.conf": {},
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

type releaseSpec struct {
	ProductVersion   string              `json:"product_version"`
	TagObject        string              `json:"tag_object"`
	SourceCommit     string              `json:"source_commit"`
	ForgejoRefCommit string              `json:"forgejo_ref_commit"`
	GitHubRefCommit  string              `json:"github_ref_commit"`
	Images           map[string]string   `json:"images"`
	Extensions       []extensionArtifact `json:"extensions"`
	Schema           schemaRange         `json:"schema"`
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
	Build                struct {
		GoVersion string `json:"go_version"`
		GOOS      string `json:"goos"`
		GOARCH    string `json:"goarch"`
	} `json:"build"`
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
		ConfigurationMembers: members, Extensions: spec.Extensions, Schema: spec.Schema,
	}
	manifest.Build.GoVersion, manifest.Build.GOOS, manifest.Build.GOARCH = "go1.26.6", "linux", "amd64"
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
	if !versionPattern.MatchString(spec.ProductVersion) || !commitPattern.MatchString(spec.TagObject) || !commitPattern.MatchString(spec.SourceCommit) || spec.ForgejoRefCommit != spec.SourceCommit || spec.GitHubRefCommit != spec.SourceCommit || len(spec.Images) != len(roleRepositories) || spec.Schema.Minimum == 0 || spec.Schema.Minimum > spec.Schema.Current || spec.Schema.Current > spec.Schema.Maximum {
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
	if _, err := os.Lstat(path); err == nil {
		return errors.New("release output already exists")
	} else if !os.IsNotExist(err) {
		return errors.New("inspect release output")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return errors.New("publish release output")
	}
	return nil
}

func digest(value []byte) string { return "sha256:" + hex.EncodeToString(value) }
