package extensionsruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"golang.org/x/sys/unix"
)

type crashReport struct {
	PID            int
	RunDir, Socket string
	Instance       extensionsadmin.Instance
}

// This child owns the real supervisor. The outer test kills it, not the extension.
func TestCrashParentHelper(t *testing.T) {
	if os.Getenv("GOTTH_CRASH_HELPER") != "1" {
		return
	}
	base := os.Getenv("GOTTH_CRASH_BASE")
	s, err := New(filepath.Join(base, "a"), filepath.Join(base, "r"))
	if err != nil {
		t.Fatal(err)
	}
	i := extensionsadmin.Instance{InstanceID: "00000000-0000-4000-8000-000000000027", ExtensionID: ExtensionID, Repository: Repository, ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: os.Getenv("GOTTH_EXTENSION_WEBHOOK_TEST_MANIFEST_SHA256"), GrantDigest: strings.Repeat("2", 64), SessionDigest: strings.Repeat("3", 64), Capabilities: capabilities, Interfaces: []string{Interface}, SecretSlots: []string{SecretSlot}, Metadata: webhookMetadata(), Configuration: map[string]any{"webhook.endpoint": "https://127.0.0.1:1/hook", "webhook.timeout-seconds": float64(1)}, ConfigurationRev: 2}
	if err := s.Start(context.Background(), i, map[string][]byte{SecretSlot: []byte(strings.Repeat("k", 32))}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Probe(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	if err := s.AdmitRouting(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	p := s.processes[i.InstanceID]
	pipe := os.NewFile(3, "ready")
	if err := json.NewEncoder(pipe).Encode(crashReport{p.command.Process.Pid, p.runDir, p.socket, i}); err != nil {
		t.Fatal(err)
	}
	pipe.Close()
	// Bounded even if the outer test dies. Normal path is SIGKILL from outer test.
	time.Sleep(20 * time.Second)
	s.RevokeRouting(context.Background(), i)
	s.Stop(context.Background(), i)
	t.Fatal("outer test failed to kill supervisor parent")
}

func TestAbruptParentDeath(t *testing.T) {
	binary := os.Getenv("GOTTH_EXTENSION_WEBHOOK_TEST_BINARY")
	if binary == "" || os.Getenv("GOTTH_EXTENSION_WEBHOOK_TEST_MANIFEST_SHA256") == "" {
		t.Skip("independent webhook artifact required")
	}
	base, err := os.MkdirTemp("", "cr-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	a, r := filepath.Join(base, "a"), filepath.Join(base, "r")
	install := filepath.Join(a, strings.Repeat("1", 64))
	if err := os.MkdirAll(install, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(r, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(install, executableName), data, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(install, "artifact-pin"), []byte("sha256:"+strings.Repeat("1", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	defer wr.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashParentHelper$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), "GOTTH_CRASH_HELPER=1", "GOTTH_CRASH_BASE="+base)
	cmd.ExtraFiles = []*os.File{wr}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	wr.Close()
	if err := rd.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var report crashReport
	if err := json.NewDecoder(rd).Decode(&report); err != nil {
		t.Fatal("helper never proved ready", err)
	}
	if report.PID <= 1 || filepath.Dir(report.RunDir) != r {
		t.Fatal("invalid readiness report")
	}
	// Only exact reported child fixture PID is a fallback cleanup target.
	pidfd, err := unix.PidfdOpen(report.PID, 0)
	if err != nil {
		t.Fatal("stable child identity unavailable", err)
	}
	defer unix.Close(pidfd)
	defer unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("helper did not die abruptly")
	}
	deadline := time.Now().Add(5 * time.Second)
	gone := false
	for time.Now().Before(deadline) {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", report.PID))
		if os.IsNotExist(err) {
			gone = true
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		// Zombie cannot execute; init/subreaper owns reaping after parent SIGKILL.
		fields := strings.Fields(string(stat[strings.LastIndex(string(stat), ")")+1:]))
		if len(fields) > 0 && fields[0] == "Z" {
			gone = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !gone {
		t.Fatal("real extension survived parent SIGKILL")
	}
	conn, err := net.DialTimeout("unix", report.Socket, 100*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("orphan socket still accepts connections")
	}
	for _, p := range []string{report.RunDir, filepath.Join(report.RunDir, "secrets"), filepath.Join(report.RunDir, "secrets", SecretSlot), filepath.Join(report.RunDir, "service.token")} {
		info, err := os.Lstat(p)
		if err != nil || info.Mode().Perm()&0077 != 0 {
			t.Fatalf("leftover protection failed %s %v", p, err)
		}
	}
	t.Log("parent SIGKILL ended real extension; socket refuses connections; protected plaintext files remain")
	blocked, err := New(a, r)
	if err != nil {
		t.Fatal("extension leftovers killed unrelated startup", err)
	}
	if err := blocked.Start(context.Background(), report.Instance, map[string][]byte{SecretSlot: []byte(strings.Repeat("k", 32))}); err == nil {
		t.Error("crash leftovers allowed activation")
		blocked.RevokeRouting(context.Background(), report.Instance)
		if err := blocked.Stop(context.Background(), report.Instance); err != nil {
			t.Fatal(err)
		}
	}
	if err := blocked.AdmitRouting(context.Background(), report.Instance); err == nil {
		t.Error("crash leftovers allowed routing")
	}
	health, err := blocked.Health(context.Background(), ExtensionID)
	if err == nil || health.Healthy || health.Message != "extension.runtime-blocked" {
		t.Errorf("missing blocked health: %#v %v", health, err)
	}
	if blocked.active != "" || len(blocked.processes) != 0 {
		t.Error("crash state adopted")
	}
	if _, err := os.Stat(filepath.Join(report.RunDir, "secrets", SecretSlot)); err != nil {
		t.Fatal("startup deleted unproven crash state", err)
	}
	// Harness knows the exact child is dead. Production must require equivalent
	// operator proof, not PID guessing or automatic directory deletion.
	if err := os.RemoveAll(report.RunDir); err != nil {
		t.Fatal(err)
	}
	if blocked.BlockedReason() == "" {
		t.Fatal("quarantine silently cleared after file cleanup")
	}
	s, err := New(a, r)
	if err != nil {
		t.Fatal(err)
	}
	if s.active != "" || len(s.processes) != 0 {
		t.Fatal("startup granted runtime authority")
	}
	if err := s.AdmitRouting(context.Background(), report.Instance); err == nil {
		t.Fatal("unstarted instance admitted")
	}
	if err := s.Start(context.Background(), report.Instance, map[string][]byte{SecretSlot: []byte(strings.Repeat("k", 32))}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		s.RevokeRouting(context.Background(), report.Instance)
		s.Stop(context.Background(), report.Instance)
	}()
	if _, err := s.Probe(context.Background(), report.Instance); err != nil {
		t.Fatal(err)
	}
	if err := s.AdmitRouting(context.Background(), report.Instance); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownRuntimeEntries(t *testing.T) {
	for _, kind := range []string{"file", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			a, r := filepath.Join(base, "a"), filepath.Join(base, "r")
			os.Mkdir(a, 0700)
			os.Mkdir(r, 0700)
			first, err := New(a, r)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(r, "unknown")
			switch kind {
			case "file":
				err = os.WriteFile(path, []byte("untouched"), 0600)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "symlink":
				err = os.Symlink(a, path)
			}
			if err != nil {
				t.Fatal(err)
			}
			second, err := New(a, r)
			if err != nil {
				t.Fatal("valid-root isolation lost", err)
			}
			for _, s := range []*Supervisor{first, second} {
				health, err := s.Health(context.Background(), ExtensionID)
				if err == nil || health.Message != "extension.runtime-blocked" {
					t.Errorf("unknown entry not surfaced: %#v %v", health, err)
				}
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("unknown data removed", err)
			}
		})
	}
}
