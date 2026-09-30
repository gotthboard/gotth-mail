package extensionsadmin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"github.com/lib/pq"
)

func TestVerifyPreviewTarget(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// Exhaustive placement grammar; raw native cast is an independent oracle.
	digits := strings.ReplaceAll("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11", "-", "")
	count := 0
	for mask := 0; mask < 128; mask++ {
		for _, braces := range []bool{false, true} {
			for _, upper := range []bool{false, true} {
				var b strings.Builder
				if braces {
					b.WriteByte('{')
				}
				for i := 0; i < 8; i++ {
					b.WriteString(digits[i*4 : i*4+4])
					if i < 7 && mask&(1<<i) != 0 {
						b.WriteByte('-')
					}
				}
				if braces {
					b.WriteByte('}')
				}
				alias := b.String()
				if upper {
					alias = strings.ToUpper(alias)
				}
				var canonical string
				if err := db.QueryRowContext(ctx, "SELECT $1::uuid::text", alias).Scan(&canonical); err != nil || canonical != "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11" {
					t.Fatal("native alias grammar changed")
				}
				tx, err := db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal("alias begin")
				}
				if err = verifyPreviewTarget(ctx, tx, alias, canonical); err != nil {
					t.Error("helper rejected native alias")
				}
				if err = tx.Rollback(); err != nil {
					t.Fatal("alias rollback")
				}
				count++
			}
		}
	}
	if count != 512 {
		t.Fatal("incomplete alias matrix")
	}
	t.Log("512 native/helper alias comparisons including valid40/41bytes")
	const id = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	cases := []struct {
		name, target string
		denied       bool
	}{
		{"canonical", id, false}, {"uppercase", strings.ToUpper(id), false},
		{"braces", "{" + id + "}", false}, {"no-hyphens", strings.ReplaceAll(id, "-", ""), false},
		{"four-digit-groups", "a0ee-bc99-9c0b-4ef8-bb6d-6bb9-bd38-0a11", false},
		{"different", "b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11", true},
		{"empty", "", true}, {"malformed", "invalid", true},
		{"31-digits", strings.Repeat("a", 31), true}, {"33-digits", strings.Repeat("a", 33), true},
		{"large-invalid", strings.Repeat("a", 65536), true},
	}
	for _, n := range []int{42, 29999, 30000, 30001} {
		cases = append(cases, struct {
			name, target string
			denied       bool
		}{fmt.Sprint("long-", n), strings.Repeat("a", n), true})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal("begin failed")
			}
			var backend int
			if err := tx.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&backend); err != nil {
				t.Fatal("backend identity")
			}
			err = verifyPreviewTarget(ctx, tx, tc.target, id)
			if tc.denied && !errors.Is(err, ErrConfirmation) || !tc.denied && err != nil {
				var pe *pq.Error
				code := "non-PG"
				if errors.As(err, &pe) {
					code = string(pe.Code)
				}
				t.Errorf("target classification wrong: type=%T code=%s", err, code)
			}
			if len(tc.target) > 41 {
				var same int
				if err := tx.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&same); err != nil || same != backend {
					t.Fatal("long denial poisoned SAME transaction")
				}
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal("rollback failed")
			}
			var reused int
			if err := db.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&reused); err != nil || reused != backend {
				t.Fatal("pooled connection not recovered")
			}
		})
	}
	t.Run("aborted-transaction-operational-error", func(t *testing.T) {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal("begin failed")
		}
		defer tx.Rollback()
		if _, err = tx.Exec("SELECT 1/0"); err == nil {
			t.Fatal("SQL fault absent")
		}
		err = verifyPreviewTarget(context.Background(), tx, id, id)
		var pe *pq.Error
		if errors.Is(err, ErrConfirmation) || !errors.As(err, &pe) || pe.Code != "25P02" {
			t.Error("operational SQL error swallowed")
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal("begin failed")
		}
		defer tx.Rollback()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err = verifyPreviewTarget(ctx, tx, id, id)
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrConfirmation) {
			t.Error("cancellation classification wrong")
		}
	})
	t.Run("finished-transaction", func(t *testing.T) {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal("begin failed")
		}
		if err = tx.Rollback(); err != nil {
			t.Fatal("rollback failed")
		}
		if err = verifyPreviewTarget(context.Background(), tx, id, id); !errors.Is(err, sql.ErrTxDone) {
			t.Error("transaction failure swallowed")
		}
	})
}
