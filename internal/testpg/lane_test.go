package testpg

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The child is deliberately a real testing.T: Fatal and Skip must be observed,
// not simulated by a fake test interface or accepted as arbitrary exit failures.
func TestDBLaneChild(t *testing.T) {
	if os.Getenv("GOTTH_TESTPG_CHILD") != "1" {
		return
	}
	db := DB(t, func(_ context.Context, db *sql.DB) error {
		return os.WriteFile(os.Getenv("GOTTH_TESTPG_MIGRATION"), []byte("migrated"), 0600)
	})
	var actual int
	if err := db.QueryRow("SHOW server_version_num").Scan(&actual); err != nil {
		t.Fatal(err)
	}
	t.Logf("CHILD_DB_READY actual=%d", actual)
}

func TestDBLaneContract(t *testing.T) {
	db := DB(t, nil)
	var actual int
	if err := db.QueryRow("SHOW server_version_num").Scan(&actual); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tools := map[string]string{}
	for _, name := range []string{"initdb", "postgres", "createdb"} {
		p, err := exec.LookPath(name)
		if err != nil {
			t.Fatal(err)
		}
		tools[name] = p
	}
	type testCase struct {
		name, expectation, missing    string
		unset, invalid, success, skip bool
	}
	cases := []testCase{
		{name: "unset_native", unset: true, success: true},
		{name: "matching_native", expectation: strconv.Itoa(actual), success: true},
		{name: "wrong_patch", expectation: strconv.Itoa(actual + 1)},
		{name: "wrong_major", expectation: strconv.Itoa(actual + 10000)},
		{name: "empty", invalid: true},
		{name: "malformed", expectation: "17.x", invalid: true},
		{name: "zero", expectation: "0", invalid: true},
		{name: "negative", expectation: "-1", invalid: true},
		{name: "overflow", expectation: "2147483648", invalid: true},
		{name: "whitespace", expectation: " 170010", invalid: true},
		{name: "unset_missing", unset: true, missing: "initdb", skip: true},
	}
	for _, name := range []string{"initdb", "postgres", "createdb"} {
		cases = append(cases, testCase{name: "declared_missing_" + name, expectation: strconv.Itoa(actual), missing: name})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			migration := filepath.Join(root, "migration")
			launch := filepath.Join(root, "launch")
			path := os.Getenv("PATH")
			if tc.invalid || tc.missing != "" {
				path = filepath.Join(root, "bin")
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				for name, target := range tools {
					if name == tc.missing {
						continue
					}
					p := filepath.Join(path, name)
					if tc.invalid {
						script := fmt.Sprintf("#!/bin/sh\nprintf invoked > '%s'\nexit 99\n", launch)
						if err := os.WriteFile(p, []byte(script), 0700); err != nil {
							t.Fatal(err)
						}
					} else if err := os.Symlink(target, p); err != nil {
						t.Fatal(err)
					}
				}
			}
			env := []string{}
			for _, item := range os.Environ() {
				if strings.HasPrefix(item, "GOTTH_MAIL_TEST_PG_VERSION_NUM=") || strings.HasPrefix(item, "GOTTH_TESTPG_") || strings.HasPrefix(item, "PATH=") {
					continue
				}
				env = append(env, item)
			}
			env = append(env, "PATH="+path, "GOTTH_TESTPG_CHILD=1", "GOTTH_TESTPG_MIGRATION="+migration)
			if !tc.unset {
				env = append(env, "GOTTH_MAIL_TEST_PG_VERSION_NUM="+tc.expectation)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestDBLaneChild$", "-test.v", "-test.timeout=30s")
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			text := string(out)
			t.Logf("child output:\n%s", text)
			if ctx.Err() != nil || strings.Contains(text, "panic:") {
				t.Fatalf("unexpected child termination: %v", err)
			}
			marker, markerErr := os.ReadFile(migration)
			if tc.success {
				if err != nil || !strings.Contains(text, fmt.Sprintf("CHILD_DB_READY actual=%d", actual)) || markerErr != nil || string(marker) != "migrated" {
					t.Fatalf("successful migration contract failed: %v", err)
				}
				return
			}
			if !os.IsNotExist(markerErr) {
				t.Fatal("migration ran or marker inspection failed before rejection")
			}
			if _, err := os.Stat(launch); !os.IsNotExist(err) {
				t.Fatal("invalid declaration launched equipment")
			}
			if tc.skip {
				if err != nil || !strings.Contains(text, "--- SKIP: TestDBLaneChild") || !strings.Contains(text, "local initdb not available") {
					t.Fatal("unset missing-tool skip changed")
				}
				return
			}
			want := "PostgreSQL version mismatch"
			if tc.invalid {
				want = "invalid GOTTH_MAIL_TEST_PG_VERSION_NUM"
			}
			if tc.missing != "" {
				want = "declared PostgreSQL lane requires " + tc.missing
			}
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 || !strings.Contains(text, "--- FAIL: TestDBLaneChild") || !strings.Contains(text, want) || strings.Contains(text, "--- SKIP:") {
				t.Fatalf("expected precise rejection %q, got %v", want, err)
			}
		})
	}
}
