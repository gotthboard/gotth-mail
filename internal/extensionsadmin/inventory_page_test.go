package extensionsadmin

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func inventoryPageDB(t *testing.T) (*sql.DB, *Service) {
	t.Helper()
	db := testpg.DB(t, store.MigrateSQL)
	rt := &recordingRuntime{}
	svc, err := NewService(db, []byte(strings.Repeat("k", 32)), rt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if len(rt.calls) != 0 {
			t.Errorf("unexpected runtime calls: %v", rt.calls)
		}
	})
	var encoding, collate, ctype string
	if err = db.QueryRow("SELECT pg_encoding_to_char(encoding), datcollate, datctype FROM pg_database WHERE datname=current_database()").Scan(&encoding, &collate, &ctype); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual database encoding=%s collate=%s ctype=%s", encoding, collate, ctype)
	return db, svc
}

func inventoryPageSeed(t *testing.T, db *sql.DB, n int) {
	t.Helper()
	if _, err := db.Exec("DELETE FROM extension_instances"); err != nil {
		t.Fatal(err)
	}
	_, err := db.Exec(`INSERT INTO extension_instances(instance_id,product,extension_id,repository,artifact_pin,manifest_sha256,grant_sha256,session_sha256,metadata_json,lifecycle,health_code,created_at,updated_at) SELECT md5(g::text)::uuid,$1,'page.'||lpad(g::text,3,'0'),'https://github.com/gotthboard/gotth-extension-page','sha256:'||repeat('1',64),repeat('2',64),repeat('3',64),repeat('4',64),'{"fields":[]}'::jsonb,'stopped','extension.ready',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP FROM generate_series(1,$2::integer) g`, Product, n)
	if err != nil {
		t.Fatal(err)
	}
}

// Independent ordering oracle: use the actual server collation, never Go sort.
func inventoryPageKeys(t *testing.T, db *sql.DB, after string) []string {
	t.Helper()
	query := "SELECT extension_id FROM extension_instances WHERE product=$1 ORDER BY extension_id"
	args := []any{Product}
	if after != "" {
		query = "SELECT extension_id FROM extension_instances WHERE product=$1 AND extension_id>$2 ORDER BY extension_id"
		args = append(args, after)
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var key string
		if err = rows.Scan(&key); err != nil {
			t.Fatal(err)
		}
		out = append(out, key)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err = rows.Close(); err != nil {
		t.Fatal(err)
	}
	return out
}

func inventoryPageCheck(t *testing.T, svc *Service, want []string, after string) {
	t.Helper()
	got, err := svc.ListInventoryPage(context.Background(), after)
	if err != nil {
		t.Fatal(err)
	}
	limit := len(want)
	if limit > 50 {
		limit = 50
	}
	if len(got.Items) != limit || got.HasMore != (len(want) > 50) {
		t.Fatalf("page size/more: %d/%v want %d/%v", len(got.Items), got.HasMore, limit, len(want) > 50)
	}
	for i, item := range got.Items {
		if item.ExtensionID != want[i] {
			t.Fatalf("SQL order/membership index%d got%q want%q", i, item.ExtensionID, want[i])
		}
		if item.Secrets == nil {
			t.Fatal("empty grants must still load nonnil status")
		}
	}
}

func TestInventoryPageSQLPopulation(t *testing.T) {
	db, svc := inventoryPageDB(t)
	for _, n := range []int{0, 1, 49, 50, 51, 100, 101} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			inventoryPageSeed(t, db, n)
			want := inventoryPageKeys(t, db, "")
			inventoryPageCheck(t, svc, want, "")
			var all []string
			after := ""
			for pages := 0; ; pages++ {
				if pages > n/50+1 {
					t.Fatal("pagination did not terminate")
				}
				got, err := svc.ListInventoryPage(context.Background(), after)
				if err != nil {
					t.Fatal(err)
				}
				for _, v := range got.Items {
					all = append(all, v.ExtensionID)
				}
				if !got.HasMore {
					break
				}
				if len(got.Items) != 50 {
					t.Fatal("short page with more")
				}
				after = got.Items[len(got.Items)-1].ExtensionID
			}
			if !reflect.DeepEqual(all, want) {
				t.Fatal("complete traversal lost, duplicated or reordered entries")
			}
			inventoryPageCheck(t, svc, inventoryPageKeys(t, db, "page.050x"), "page.050x")
			if n > 0 {
				last := want[len(want)-1]
				inventoryPageCheck(t, svc, nil, last)
				if _, err := db.Exec("DELETE FROM extension_instances WHERE extension_id=$1", last); err != nil {
					t.Fatal(err)
				}
				inventoryPageCheck(t, svc, nil, last)
			}
		})
	}
	inventoryPageSeed(t, db, 101)
	if _, err := db.Exec("DELETE FROM extension_instances WHERE extension_id='page.050'"); err != nil {
		t.Fatal(err)
	}
	inventoryPageCheck(t, svc, inventoryPageKeys(t, db, "page.050"), "page.050")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := svc.ListInventoryPage(canceled, "")
	if !errors.Is(err, context.Canceled) || len(got.Items) != 0 || got.HasMore {
		t.Fatal("canceled read must return no page")
	}
}

func TestInventoryPageSQLKeyDomain(t *testing.T) {
	// initdb inherits locale. The default C lane is SQL_ASCII, where the
	// schema character limit counts bytes rather than UTF-8 characters.
	// Scope UTF-8 to this fixture; keep every Unicode/binding assertion.
	t.Setenv("LC_ALL", "C.UTF-8")
	db, svc := inventoryPageDB(t)
	var encoding string
	if err := db.QueryRow("SHOW server_encoding").Scan(&encoding); err != nil || encoding != "UTF8" {
		t.Fatalf("Unicode fixture requires UTF8: encoding=%q err=%v", encoding, err)
	}
	inventoryPageSeed(t, db, 60)
	keys := []string{strings.Repeat("界", 128), strings.Repeat("😀", 128), "quo\"te", "back\\slash", "comma,key", "{braces}", " white space ", "UPPER.key", "éclair.key", "zeta.key", "new\nline"}
	for i, key := range keys {
		if _, err := db.Exec("UPDATE extension_instances SET extension_id=$1 WHERE instance_id=md5($2)::uuid", key, fmt.Sprint(i+1)); err != nil {
			t.Fatal(err)
		}
	}
	want := inventoryPageKeys(t, db, "")
	var seen []string
	after := ""
	for i := 0; i < 3; i++ {
		page, err := svc.ListInventoryPage(context.Background(), after)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range page.Items {
			seen = append(seen, v.ExtensionID)
		}
		if !page.HasMore {
			break
		}
		after = page.Items[len(page.Items)-1].ExtensionID
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatal("key-domain traversal differs from SQL order")
	}
	for _, key := range keys {
		inventoryPageCheck(t, svc, inventoryPageKeys(t, db, key), key)
	}
	if _, err := db.Exec("UPDATE extension_instances SET extension_id=$1 WHERE instance_id=md5('60')::uuid", keys[0]); err == nil {
		t.Fatal("existing duplicate-extension constraint lost")
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM extension_instances").Scan(&count); err != nil || count != 60 {
		t.Fatal("duplicate attempt changed population")
	}
}

func TestInventoryPageSQLCorruptionIsolation(t *testing.T) {
	db, svc := inventoryPageDB(t)
	inventoryPageSeed(t, db, 101)
	bad := []struct{ name, column, value string }{
		{"metadata", "metadata_json", `{"fields":"wrong"}`},
		{"configuration", "configuration_json", `[1]`},
		{"capabilities", "capabilities_json", `{}`},
		{"interfaces", "interfaces_json", `[1]`},
		{"slots", "secret_slots_json", `{}`},
	}
	for _, tc := range bad {
		for _, index := range []int{1, 51, 101} {
			t.Run(fmt.Sprintf("%s/%d", tc.name, index), func(t *testing.T) {
				var old string
				if err := db.QueryRow("SELECT "+tc.column+"::text FROM extension_instances WHERE instance_id=md5($1)::uuid", fmt.Sprint(index)).Scan(&old); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec("UPDATE extension_instances SET "+tc.column+"=$1::jsonb WHERE instance_id=md5($2)::uuid", tc.value, fmt.Sprint(index)); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if _, err := db.Exec("UPDATE extension_instances SET "+tc.column+"=$1::jsonb WHERE instance_id=md5($2)::uuid", old, fmt.Sprint(index)); err != nil {
						t.Error(err)
					}
				})
				page, err := svc.ListInventoryPage(context.Background(), "")
				if index == 1 {
					if err == nil || len(page.Items) != 0 || page.HasMore {
						t.Fatal("selected malformed payload did not fail closed")
					}
				} else {
					if err != nil || len(page.Items) != 50 || !page.HasMore {
						t.Fatal("off-page malformed payload affected selected page")
					}
					seek := fmt.Sprintf("page.%03d", index-1)
					page, err = svc.ListInventoryPage(context.Background(), seek)
					if err == nil || len(page.Items) != 0 || page.HasMore {
						t.Fatal("same malformed payload must fail when selected")
					}
				}
				if _, err = svc.List(context.Background()); err == nil {
					t.Fatal("legacy List no longer fails on malformed full population")
				}
			})
		}
	}
	t.Run("current-slot-infinity", func(t *testing.T) {
		for _, index := range []int{1, 51, 101} {
			if _, err := db.Exec(`UPDATE extension_instances SET secret_slots_json='["secret.current"]' WHERE instance_id=md5($1)::uuid`, fmt.Sprint(index)); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO extension_secrets(instance_id,slot,nonce,ciphertext,configured_at,rotated_at) VALUES(md5($1)::uuid,'secret.current',decode(repeat('00',12),'hex'),decode(repeat('00',17),'hex'),CURRENT_TIMESTAMP,'infinity')`, fmt.Sprint(index)); err != nil {
				t.Fatal(err)
			}
			page, err := svc.ListInventoryPage(context.Background(), "")
			if index == 1 {
				if err == nil || len(page.Items) != 0 || page.HasMore {
					t.Fatal("selected current status infinity accepted")
				}
			} else {
				if err != nil || len(page.Items) != 50 || !page.HasMore {
					t.Fatal("off-page status was loaded")
				}
				page, err = svc.ListInventoryPage(context.Background(), fmt.Sprintf("page.%03d", index-1))
				if err == nil || len(page.Items) != 0 || page.HasMore {
					t.Fatal("selected later infinity accepted")
				}
			}
			if _, err = svc.List(context.Background()); err == nil {
				t.Fatal("List infinity behavior changed")
			}
			if _, err = db.Exec("DELETE FROM extension_secrets WHERE instance_id=md5($1)::uuid", fmt.Sprint(index)); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("decodable-invalid-metadata-is-not-new-policy", func(t *testing.T) {
		if _, err := db.Exec(`UPDATE extension_instances SET metadata_json='{"fields":[{"name":"x.y","kind":"unknown"}]}' WHERE extension_id='page.001'`); err != nil {
			t.Fatal(err)
		}
		page, err := svc.ListInventoryPage(context.Background(), "")
		if err != nil || len(page.Items) != 50 {
			t.Fatal("new semantic validation introduced")
		}
	})
}

// A small database/sql driver fixture for query/error boundaries only. Actual
// key collation, array binding, SQL constraints and payloads are tested above.
// Call/violation/close ledgers are asserted AFTER production returns, never by
// throwing assertions from callbacks that production might catch.
type inventoryPageStep struct {
	kind                        string
	values                      [][]driver.Value
	queryErr, nextErr, closeErr error
	moreResults                 bool
}
type inventoryPageScript struct {
	mu         sync.Mutex
	steps      []inventoryPageStep
	calls      []string
	args       [][]driver.NamedValue
	violations []string
	closes     int
}
type inventoryPageConnector struct{ script *inventoryPageScript }

func (c inventoryPageConnector) Connect(context.Context) (driver.Conn, error) {
	return &inventoryPageConn{c.script}, nil
}
func (c inventoryPageConnector) Driver() driver.Driver { return inventoryPageDriver{} }

type inventoryPageDriver struct{}

func (inventoryPageDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use connector") }

type inventoryPageConn struct{ s *inventoryPageScript }

func (c *inventoryPageConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c *inventoryPageConn) Close() error { return nil }
func (c *inventoryPageConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected transaction")
}
func (c *inventoryPageConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	i := len(c.s.calls)
	c.s.calls = append(c.s.calls, q)
	c.s.args = append(c.s.args, append([]driver.NamedValue(nil), args...))
	if i >= len(c.s.steps) {
		c.s.violations = append(c.s.violations, "extra query")
		return nil, errors.New("extra query")
	}
	step := c.s.steps[i]
	want := "SELECT extension_id FROM extension_instances WHERE product=$1 ORDER BY extension_id LIMIT 51"
	if step.kind == "payload" {
		want = "SELECT " + instanceColumns + " FROM extension_instances WHERE product=$1 AND extension_id=ANY($2::text[]) ORDER BY extension_id"
	}
	if step.kind == "status" {
		want = secretStatusQuery
	}
	if q != want {
		c.s.violations = append(c.s.violations, "query shape: "+step.kind)
		return nil, errors.New("query shape")
	}
	if step.queryErr != nil {
		return nil, step.queryErr
	}
	cols := []string{"extension_id"}
	if step.kind == "payload" {
		cols = strings.Split(instanceColumns, ", ")
	}
	if step.kind == "status" {
		cols = []string{"slot", "rotated_at"}
	}
	return &inventoryPageRows{s: c.s, step: step, cols: cols}, nil
}

type inventoryPageRows struct {
	s    *inventoryPageScript
	step inventoryPageStep
	cols []string
	i    int
}

func (r *inventoryPageRows) Columns() []string { return r.cols }

// Multi-result fixtures keep EOF from auto-closing, exercising explicit Close.
func (r *inventoryPageRows) HasNextResultSet() bool { return r.step.moreResults }
func (r *inventoryPageRows) NextResultSet() error   { return io.EOF }
func (r *inventoryPageRows) Close() error {
	r.s.mu.Lock()
	r.s.closes++
	r.s.mu.Unlock()
	return r.step.closeErr
}
func (r *inventoryPageRows) Next(dst []driver.Value) error {
	if r.i < len(r.step.values) {
		copy(dst, r.step.values[r.i])
		r.i++
		return nil
	}
	if r.step.nextErr != nil {
		return r.step.nextErr
	}
	return io.EOF
}
func inventoryPageValues(key string) []driver.Value {
	return []driver.Value{"id-" + key, Product, key, "repository", "pin", nil, nil, "manifest", "grant", "session", []byte("[]"), []byte("[]"), []byte("[]"), []byte(`{"fields":[]}`), []byte("{}"), int64(1), "stopped", "extension.ready", nil, false, false, "", time.Unix(0, 0), time.Unix(0, 0)}
}

func TestInventoryPageFaultBoundaries(t *testing.T) {
	boom := errors.New("injected boundary failure")
	key := inventoryPageStep{kind: "keys", values: [][]driver.Value{{"aaa"}}}
	payload := inventoryPageStep{kind: "payload", values: [][]driver.Value{inventoryPageValues("aaa")}}
	status := inventoryPageStep{kind: "status"}
	oversized := inventoryPageStep{kind: "keys"}
	for i := 0; i < 52; i++ {
		oversized.values = append(oversized.values, []driver.Value{fmt.Sprintf("key.%03d", i)})
	}
	tests := []struct {
		name  string
		steps []inventoryPageStep
		fail  bool
	}{
		{"empty", []inventoryPageStep{{kind: "keys"}}, false},
		{"one", []inventoryPageStep{key, payload, status}, false},
		{"key-query", []inventoryPageStep{{kind: "keys", queryErr: boom}}, true},
		{"key-scan", []inventoryPageStep{{kind: "keys", values: [][]driver.Value{{nil}}}}, true},
		{"key-rows", []inventoryPageStep{{kind: "keys", values: key.values, nextErr: boom}}, true},
		{"key-close", []inventoryPageStep{{kind: "keys", values: key.values, closeErr: boom}}, true},
		{"key-explicit-close", []inventoryPageStep{{kind: "keys", values: key.values, closeErr: boom, moreResults: true}}, true},
		{"keys-exceed-query-bound", []inventoryPageStep{oversized}, true},
		{"payload-query", []inventoryPageStep{key, {kind: "payload", queryErr: boom}}, true},
		{"payload-scan", []inventoryPageStep{key, {kind: "payload", values: [][]driver.Value{{nil}}}}, true},
		{"payload-rows", []inventoryPageStep{key, {kind: "payload", values: payload.values, nextErr: boom}}, true},
		{"payload-close", []inventoryPageStep{key, {kind: "payload", values: payload.values, closeErr: boom}}, true},
		{"payload-explicit-close", []inventoryPageStep{key, {kind: "payload", values: payload.values, closeErr: boom, moreResults: true}}, true},
		{"selected-disappeared-between-reads", []inventoryPageStep{key, {kind: "payload"}}, true},
		{"wrong-membership", []inventoryPageStep{key, {kind: "payload", values: [][]driver.Value{inventoryPageValues("bbb")}}}, true},
		{"duplicate-membership", []inventoryPageStep{{kind: "keys", values: [][]driver.Value{{"aaa"}, {"bbb"}}}, {kind: "payload", values: [][]driver.Value{inventoryPageValues("aaa"), inventoryPageValues("aaa")}}}, true},
		{"empty-grant-status-query", []inventoryPageStep{key, payload, {kind: "status", queryErr: boom}}, true},
		{"status-rows", []inventoryPageStep{key, payload, {kind: "status", nextErr: boom}}, true},
		{"status-scan", []inventoryPageStep{key, payload, {kind: "status", values: [][]driver.Value{{"slot", []byte("infinity")}}}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &inventoryPageScript{steps: tc.steps}
			db := sql.OpenDB(inventoryPageConnector{s})
			defer db.Close()
			svc := &Service{DB: db}
			page, err := svc.ListInventoryPage(context.Background(), "")
			s.mu.Lock()
			defer s.mu.Unlock()
			if (err != nil) != tc.fail {
				t.Errorf("error=%v expectedFailure=%v", err, tc.fail)
			}
			if tc.fail && (len(page.Items) != 0 || page.HasMore) {
				t.Error("usable page on failure")
			}
			if len(s.calls) != len(tc.steps) || len(s.violations) != 0 {
				t.Errorf("dispatch ledger calls=%d want=%d violations=%v", len(s.calls), len(tc.steps), s.violations)
			}
			expectedClose := 0
			for _, v := range tc.steps {
				if v.queryErr == nil {
					expectedClose++
				}
			}
			if s.closes != expectedClose {
				t.Errorf("rows closed=%d want%d", s.closes, expectedClose)
			}
		})
	}
	t.Run("invalid-input-no-query", func(t *testing.T) {
		for _, after := range []string{"a", "ab", strings.Repeat("x", 129), strings.Repeat("😀", 129), "ab\x00c", string([]byte{0xff, 0xff, 0xff})} {
			s := &inventoryPageScript{}
			db := sql.OpenDB(inventoryPageConnector{s})
			svc := &Service{DB: db}
			page, err := svc.ListInventoryPage(context.Background(), after)
			if err == nil || len(page.Items) != 0 || page.HasMore {
				t.Error("invalid input accepted")
			}
			s.mu.Lock()
			if len(s.calls) != 0 || len(s.violations) != 0 {
				t.Error("invalid input dispatched SQL")
			}
			s.mu.Unlock()
			db.Close()
		}
	})
	t.Run("exact-query-budget-and-sentinel-binding", func(t *testing.T) {
		keys := inventoryPageStep{kind: "keys"}
		full := inventoryPageStep{kind: "payload"}
		var selected []string
		for i := 0; i < 51; i++ {
			k := fmt.Sprintf("key.%03d", i)
			keys.values = append(keys.values, []driver.Value{k})
			if i < 50 {
				selected = append(selected, k)
				full.values = append(full.values, inventoryPageValues(k))
			}
		}
		s := &inventoryPageScript{steps: []inventoryPageStep{keys, full}}
		for i := 0; i < 50; i++ {
			s.steps = append(s.steps, status)
		}
		db := sql.OpenDB(inventoryPageConnector{s})
		defer db.Close()
		svc := &Service{DB: db}
		page, err := svc.ListInventoryPage(context.Background(), "")
		if err != nil || len(page.Items) != 50 || !page.HasMore {
			t.Fatalf("page result: %v", err)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.calls) != 52 || len(s.violations) != 0 || s.closes != 52 {
			t.Fatalf("dispatch/close ledger calls%d closes%d violations%v", len(s.calls), s.closes, s.violations)
		}
		if len(s.args[1]) != 2 || s.args[1][1].Value != postgresTextArray(selected) {
			t.Error("payload did not bind exactly first50 keys")
		}
		for i, k := range selected {
			if len(s.args[i+2]) != 2 || s.args[i+2][0].Value != "id-"+k || s.args[i+2][1].Value != "{}" {
				t.Error("wrong status dispatch or empty grants skipped")
			}
		}
	})
}
