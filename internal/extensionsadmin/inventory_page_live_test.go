package extensionsadmin

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"
)

const livePageKeys = "SELECT extension_id FROM extension_instances WHERE product=$1 ORDER BY extension_id LIMIT 51"
const livePageIdentity = "SELECT host(inet_server_addr()), inet_server_port(), current_database(), current_user"

// Only the private testpg TCP trust fixture is admissible. No DSN is logged.
func livePageConnector(t *testing.T, db *sql.DB) *pq.Connector {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var host, database, role string
	var port int
	if err := db.QueryRowContext(ctx, livePageIdentity).Scan(&host, &port, &database, &role); err != nil {
		t.Fatal("fixture identity query failed")
	}
	if host != "127.0.0.1" || port < 1 || port > 65535 || database != "gotth_mail" || role != "gotth_mail" {
		t.Fatal("not the private TCP fixture")
	}
	c, err := pq.NewConnector(fmt.Sprintf("host=127.0.0.1 port=%d dbname=gotth_mail user=gotth_mail sslmode=disable connect_timeout=5", port))
	if err != nil {
		t.Fatal("fixture connector failed")
	}
	check := sql.OpenDB(c)
	defer check.Close()
	var h, d, r string
	var p int
	if err := check.QueryRowContext(ctx, livePageIdentity).Scan(&h, &p, &d, &r); err != nil || h != host || p != port || d != database || r != role {
		t.Fatal("second connection identity mismatch")
	}
	return c
}

// This is a named-query observation seam over real pq rows, not a SQL fake.
// Embed pq's actual context interfaces; preserve delegated inputs/errors and
// ownership. No global registration, query rewriting or synthetic driver rows.
type livePagePQConn interface {
	driver.Conn
	driver.QueryerContext
	driver.ExecerContext
	driver.ConnPrepareContext
	driver.ConnBeginTx
	driver.Pinger
	driver.NamedValueChecker
	driver.SessionResetter
	driver.Validator
}
type livePagePQRows interface {
	driver.Rows
	driver.RowsNextResultSet
	driver.RowsColumnTypeScanType
	driver.RowsColumnTypeDatabaseTypeName
	driver.RowsColumnTypeLength
	driver.RowsColumnTypePrecisionScale
}
type livePageCloseConnector struct {
	*pq.Connector
	mu             sync.Mutex
	ledger         []string
	observationErr error
	afterClose     func() error
}

func (c *livePageCloseConnector) note(event string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ledger = append(c.ledger, event)
}
func (c *livePageCloseConnector) Connect(ctx context.Context) (driver.Conn, error) {
	raw, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	conn, ok := raw.(livePagePQConn)
	if !ok {
		_ = raw.Close()
		return nil, errors.New("pq context interfaces changed")
	}
	return &livePageCloseConn{livePagePQConn: conn, owner: c}, nil
}

type livePageCloseConn struct {
	livePagePQConn
	owner *livePageCloseConnector
}

func (c *livePageCloseConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	switch q {
	case livePageKeys:
		c.owner.note("keys-query")
	case "SELECT " + instanceColumns + " FROM extension_instances WHERE product=$1 AND extension_id=ANY($2::text[]) ORDER BY extension_id":
		c.owner.note("payload-query")
	default:
		c.owner.note("unexpected-query")
	}
	rows, err := c.livePagePQConn.QueryContext(ctx, q, args)
	if err != nil || q != livePageKeys {
		return rows, err
	}
	r, ok := rows.(livePagePQRows)
	if !ok {
		_ = rows.Close()
		return nil, errors.New("pq rows interfaces changed")
	}
	return &livePageCloseRows{livePagePQRows: r, owner: c.owner}, nil
}

type livePageCloseRows struct {
	livePagePQRows
	owner *livePageCloseConnector
	eof   bool
	count int
}

func (r *livePageCloseRows) Next(dest []driver.Value) error {
	err := r.livePagePQRows.Next(dest)
	if err == nil {
		r.count++
	}
	if err == io.EOF {
		r.eof = true
	}
	return err
}
func (r *livePageCloseRows) Close() error {
	err := r.livePagePQRows.Close()
	// database/sql owns Close and calls it once, including on successful EOF.
	// Observation failure is latched independently; never replace driver error.
	r.owner.mu.Lock()
	defer r.owner.mu.Unlock()
	if err == nil && r.eof && r.count == 51 {
		r.owner.ledger = append(r.owner.ledger, "keys-closed")
		r.owner.observationErr = r.owner.afterClose()
		if r.owner.observationErr == nil {
			r.owner.ledger = append(r.owner.ledger, "delete-committed")
		}
	} else {
		r.owner.observationErr = errors.New("key read did not successfully close with 51 real rows")
	}
	return err
}

func TestInventoryPageLiveSelectedDeletion(t *testing.T) {
	db, svc := inventoryPageDB(t)
	inventoryPageSeed(t, db, 51)
	keys := inventoryPageKeys(t, db, "")
	if len(keys) != 51 {
		t.Fatal("seed population")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := &livePageCloseConnector{Connector: livePageConnector(t, db)}
	c.afterClose = func() error {
		result, err := db.ExecContext(ctx, "DELETE FROM extension_instances WHERE product=$1 AND extension_id=$2", Product, keys[0])
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return errors.New("deletion count")
		}
		return nil
	}
	observed := sql.OpenDB(c)
	defer observed.Close()
	observed.SetMaxOpenConns(1)
	svc.DB = observed
	page, err := svc.ListInventoryPage(ctx, "")
	c.mu.Lock()
	ledger := append([]string(nil), c.ledger...)
	observationErr := c.observationErr
	c.mu.Unlock()
	if observationErr != nil {
		t.Fatal("real row-close deletion observation failed")
	}
	if !reflect.DeepEqual(ledger, []string{"keys-query", "keys-closed", "delete-committed", "payload-query"}) {
		t.Fatal("query/close/commit ledger mismatch")
	}
	if err == nil || err.Error() != "inventory selection changed" || page.Items != nil || page.HasMore {
		t.Fatal("selected deletion must fail with zero usable page")
	}
	if !reflect.DeepEqual(inventoryPageKeys(t, db, ""), keys[1:]) {
		t.Fatal("independent committed deletion membership mismatch")
	}
	t.Log("LIVE deletion realKeys=51 closedBeforeDelete=true committedRows=1 payloadQueries=1 retries=0 zeroPage=true")
}

func TestInventoryPageLiveInflightCancellation(t *testing.T) {
	db, svc := inventoryPageDB(t)
	inventoryPageSeed(t, db, 51)
	want := inventoryPageKeys(t, db, "")
	target := sql.OpenDB(livePageConnector(t, db))
	defer target.Close()
	target.SetMaxOpenConns(1)
	target.SetMaxIdleConns(1)
	setup, stopSetup := context.WithTimeout(context.Background(), 20*time.Second)
	defer stopSetup()
	var targetPID int
	if err := target.QueryRowContext(setup, "SELECT pg_backend_pid()").Scan(&targetPID); err != nil {
		t.Fatal("target identity failed")
	}
	lock, err := db.BeginTx(setup, nil)
	if err != nil {
		t.Fatal("lock transaction failed")
	}
	defer lock.Rollback()
	var lockPID int
	if err := lock.QueryRowContext(setup, "SELECT pg_backend_pid()").Scan(&lockPID); err != nil || lockPID == targetPID {
		t.Fatal("independent lock backend failed")
	}
	if _, err := lock.ExecContext(setup, "LOCK TABLE extension_instances IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal("fixture table lock failed")
	}
	svc.DB = target
	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		page InventoryPage
		err  error
	}
	done := make(chan result, 1)
	started, reaped := false, false
	// Installed before launch. Failure cleanup releases the lock and reaps the
	// sole worker. The outer test/namespace deadline additionally bounds pq I/O.
	defer func() {
		cancel()
		_ = lock.Rollback()
		if started && !reaped {
			select {
			case <-done:
			case <-time.After(12 * time.Second):
				t.Error("cancellation worker did not reap")
			}
		}
	}()
	started = true
	go func() { p, e := svc.ListInventoryPage(ctx, ""); done <- result{p, e} }()
	poll, stopPoll := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopPoll()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	observed := false
	for !observed {
		err := db.QueryRowContext(poll, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND datname=current_database() AND usename=current_user AND state='active' AND wait_event_type='Lock' AND wait_event='relation' AND query=$3 AND $2=ANY(pg_blocking_pids(pid)))`, targetPID, lockPID, livePageKeys).Scan(&observed)
		if err != nil {
			t.Fatal("server lock-wait observation failed")
		}
		if observed {
			break
		}
		select {
		case <-done:
			reaped = true
			t.Fatal("method completed before backend lock wait")
		case <-poll.Done():
			t.Fatal("backend did not enter owned lock wait")
		case <-ticker.C:
		}
	}
	if ctx.Err() != nil {
		t.Fatal("context canceled before backend observation")
	}
	cancel()
	var got result
	select {
	case got = <-done:
		reaped = true
	case <-time.After(12 * time.Second):
		t.Fatal("in-flight cancellation did not finish while lock held")
	}
	var pe *pq.Error
	canceled := errors.Is(got.err, context.Canceled) || (errors.As(got.err, &pe) && pe.Code == "57014")
	if !canceled || got.page.Items != nil || got.page.HasMore {
		t.Fatal("not precise cancellation with zero page")
	}
	var held bool
	if err := lock.QueryRowContext(setup, "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid() AND relation='extension_instances'::regclass AND mode='AccessExclusiveLock' AND granted)").Scan(&held); err != nil || !held {
		t.Fatal("lock was not held through method completion")
	}
	if err := lock.Rollback(); err != nil {
		t.Fatal("lock rollback failed")
	}
	if !reflect.DeepEqual(inventoryPageKeys(t, db, ""), want) {
		t.Fatal("cancellation changed SQL membership")
	}
	follow, stopFollow := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopFollow()
	var one int
	if err := target.QueryRowContext(follow, "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatal("post-cancel connection recovery failed")
	}
	t.Log("LIVE cancellation backendActive=true ownedRelationLockWait=true canceledWhileLockHeld=true zeroPage=true workerReaped=true followup=true")
}

func TestInventoryPageLiveUSLocale(t *testing.T) {
	flag, present := os.LookupEnv("GOTTH_MAIL_TEST_US_LOCALE")
	if !present {
		t.Skip("US locale proof requires explicit GOTTH_MAIL_TEST_US_LOCALE=1")
	}
	if flag != "1" {
		t.Fatal("invalid GOTTH_MAIL_TEST_US_LOCALE: expected 1")
	}
	// This broader locale proof is not equivalence to the deployed libc version.
	t.Setenv("LC_ALL", "en_US.utf8")
	db, svc := inventoryPageDB(t)
	var encoding, collate, ctype, provider, version string
	if err := db.QueryRow("SELECT pg_encoding_to_char(encoding),datcollate,datctype,datlocprovider::text,datcollversion FROM pg_database WHERE datname=current_database()").Scan(&encoding, &collate, &ctype, &provider, &version); err != nil {
		t.Fatal("locale attestation failed")
	}
	if encoding != "UTF8" || collate != "en_US.utf8" || ctype != "en_US.utf8" || provider != "c" || version == "" {
		t.Fatal("locale fixture mismatch")
	}
	t.Logf("LIVE locale encoding=%s collate=%s ctype=%s provider=%s version=%s", encoding, collate, ctype, provider, version)
	inventoryPageSeed(t, db, 101)
	keys := []string{"abc", "ABC", "a-b", "a.b", "a_b", "éclair", "eclair", "界界界", "😀😀😀", strings.Repeat("界", 128), strings.Repeat("😀", 128), "quo\"te", "back\\slash", "comma,key", "{braces}"}
	for i, key := range keys {
		if _, err := db.Exec("UPDATE extension_instances SET extension_id=$1 WHERE instance_id=md5($2)::uuid", key, fmt.Sprint(i+1)); err != nil {
			t.Fatal("locale seed update failed")
		}
	}
	want := inventoryPageKeys(t, db, "")
	var seen []string
	after := ""
	for i := 0; i < 4; i++ {
		p, err := svc.ListInventoryPage(context.Background(), after)
		if err != nil {
			t.Fatal("locale traversal failed")
		}
		for _, item := range p.Items {
			seen = append(seen, item.ExtensionID)
		}
		if !p.HasMore {
			break
		}
		if len(p.Items) != 50 {
			t.Fatal("locale short page")
		}
		after = p.Items[len(p.Items)-1].ExtensionID
	}
	if len(want) != 101 || !reflect.DeepEqual(seen, want) {
		t.Fatal("locale complete traversal differs from server order")
	}
	for _, key := range keys {
		inventoryPageCheck(t, svc, inventoryPageKeys(t, db, key), key)
	}
	t.Log("LIVE locale traversed=101 SQLOrder=true UnicodePunctuationBoundaries=true cursorChecks=15")
}

// Synthetic forwarding control on the actual wrapper, not a pq implementation.
// Unused methods remain nil: any accidental extra delegate call panics the test.
type livePageOptionalProbe struct {
	livePagePQConn
	named *driver.NamedValue
	ctx   context.Context
	err   error
	valid bool
	calls [3]int
}

func (p *livePageOptionalProbe) CheckNamedValue(nv *driver.NamedValue) error {
	p.calls[0]++
	p.named = nv
	nv.Value = int64(7)
	return p.err
}
func (p *livePageOptionalProbe) ResetSession(ctx context.Context) error {
	p.calls[1]++
	p.ctx = ctx
	return p.err
}
func (p *livePageOptionalProbe) IsValid() bool {
	p.calls[2]++
	return p.valid
}
func TestInventoryPageLiveOptionalForwarding(t *testing.T) {
	probe := &livePageOptionalProbe{}
	wrapped := &livePageCloseConn{livePagePQConn: probe}
	var checker driver.NamedValueChecker = wrapped
	var resetter driver.SessionResetter = wrapped
	var validator driver.Validator = wrapped
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sentinel := errors.New("optional forwarding sentinel")
	for _, err := range []error{nil, sentinel} {
		probe.err = err
		nv := driver.NamedValue{Name: "bound", Ordinal: 2, Value: "original"}
		if got := checker.CheckNamedValue(&nv); got != err || probe.named != &nv || nv.Value != int64(7) || nv.Name != "bound" || nv.Ordinal != 2 {
			t.Fatal("NamedValueChecker delegation changed")
		}
		if got := resetter.ResetSession(ctx); got != err || probe.ctx != ctx {
			t.Fatal("SessionResetter delegation changed")
		}
		for _, valid := range []bool{false, true} {
			probe.valid = valid
			if validator.IsValid() != valid {
				t.Fatal("Validator delegation changed")
			}
		}
	}
	if probe.calls != [3]int{2, 2, 4} {
		t.Fatal("optional delegate call population changed")
	}
	t.Log("CONTROL optionalInterfaces=3 namedPointerMutationError=true resetContextError=true validityBoth=true calls=2/2/4")
}
