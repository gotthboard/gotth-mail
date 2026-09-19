package outboundpolicy

import (
	"context"
	"database/sql"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestQueueAdmissionResolvesAuthenticatedAndChainedAliasSources(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	seedAdmissionState(t, db)
	metadata := QueueMetadata{
		QueueID:            "BCDFGHJKLMNPz2345",
		ArrivalFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		EnvelopeSender:     "user@example.test",
		Recipients:         []string{"outside@example.net"},
	}
	record, created, err := (QueueAdmissionService{DB: db}).Admit(context.Background(), QueueAdmissionRequest{
		Metadata:             metadata,
		AuthenticatedMailbox: "user@example.test",
		Deliveries:           []QueueDelivery{{OriginalRecipient: "first@example.test", Recipient: "outside@example.net"}},
	})
	if err != nil || !created {
		t.Fatalf("record=%#v created=%v err=%v", record, created, err)
	}
	if len(record.Sources) != 4 {
		t.Fatalf("sources=%#v", record.Sources)
	}
	for _, want := range []QueueSource{
		{Kind: SourceAuthenticatedMailbox, ObjectID: "00000000-0000-4000-8000-000000000b02"},
		{Kind: SourceEnvelopeSender, ObjectID: "00000000-0000-4000-8000-000000000b02"},
		{Kind: SourceAlias, ObjectID: "00000000-0000-4000-8000-000000000b03"},
		{Kind: SourceAlias, ObjectID: "00000000-0000-4000-8000-000000000b04"},
	} {
		if !hasQueueSource(record.Sources, want) {
			t.Fatalf("missing source %#v in %#v", want, record.Sources)
		}
	}
}

func TestQueueAdmissionResolvesInboundForwardWithoutTrustingEnvelopeSender(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	seedAdmissionState(t, db)
	metadata := QueueMetadata{
		QueueID:            "CDFGHJKLMNPQz2345",
		ArrivalFingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		EnvelopeSender:     "external@example.net",
		Recipients:         []string{"outside@example.net"},
	}
	record, _, err := (QueueAdmissionService{DB: db}).Admit(context.Background(), QueueAdmissionRequest{
		Metadata:   metadata,
		Deliveries: []QueueDelivery{{OriginalRecipient: "first@example.test", Recipient: "outside@example.net"}},
	})
	if err != nil || len(record.Sources) != 2 {
		t.Fatalf("record=%#v err=%v", record, err)
	}
}

func TestQueueAdmissionRejectsUnprovenExpansionAndMissingAuthority(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	seedAdmissionState(t, db)
	service := QueueAdmissionService{DB: db}
	base := QueueAdmissionRequest{Metadata: QueueMetadata{
		QueueID:            "DFGHJKLMNPQRz2345",
		ArrivalFingerprint: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		EnvelopeSender:     "external@example.net",
		Recipients:         []string{"outside@example.net"},
	}, Deliveries: []QueueDelivery{{OriginalRecipient: "unknown@example.test", Recipient: "outside@example.net"}}}
	if _, _, err := service.Admit(context.Background(), base); err == nil {
		t.Fatal("admitted an external delivery without local authority")
	}
	base.Deliveries[0].OriginalRecipient = "first@example.test"
	base.Deliveries[0].Recipient = "wrong@example.net"
	if _, _, err := service.Admit(context.Background(), base); err == nil {
		t.Fatal("admitted an unproven alias expansion")
	}
}

func TestQueueAdmissionRejectsExpansionCycle(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	seedAdmissionState(t, db)
	if _, err := db.Exec(`UPDATE aliases SET targets_json='["first@example.test"]' WHERE id='00000000-0000-4000-8000-000000000b04'`); err != nil {
		t.Fatal(err)
	}
	_, _, err := (QueueAdmissionService{DB: db}).Admit(context.Background(), QueueAdmissionRequest{
		Metadata: QueueMetadata{
			QueueID:            "FGHJKLMNPQRTz2345",
			ArrivalFingerprint: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			EnvelopeSender:     "external@example.net",
			Recipients:         []string{"outside@example.net"},
		},
		Deliveries: []QueueDelivery{{OriginalRecipient: "first@example.test", Recipient: "outside@example.net"}},
	})
	if err == nil {
		t.Fatal("admitted a cyclic expansion")
	}
}

func TestSMTPRecipientExpansionRejectsForbiddenLeafBeforeQueueing(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	seedAdmissionState(t, db)
	service := EnforcementService{DB: db}
	decision, err := service.DecideSMTPRecipient(context.Background(), "smtp-expand", "user@example.test", "user@example.test", "first@example.test")
	if err != nil || decision.Action != ActionReject || decision.Reason != ReasonRecipientForbidden {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
	if _, err := db.Exec(`UPDATE aliases SET targets_json='["user@example.test"]' WHERE id='00000000-0000-4000-8000-000000000b04'`); err != nil {
		t.Fatal(err)
	}
	decision, err = service.DecideSMTPRecipient(context.Background(), "smtp-expand-allowed", "user@example.test", "user@example.test", "first@example.test")
	if err != nil || decision.Action != ActionOK || decision.Reason != ReasonSameDomain {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
}

func TestSMTPRecipientExpansionDefersReachableCycle(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	seedAdmissionState(t, db)
	if _, err := db.Exec(`UPDATE aliases SET targets_json='["outside@example.net","first@example.test"]' WHERE id='00000000-0000-4000-8000-000000000b04'`); err != nil {
		t.Fatal(err)
	}
	decision, err := (EnforcementService{DB: db}).DecideSMTPRecipient(context.Background(), "smtp-cycle", "user@example.test", "user@example.test", "first@example.test")
	if err == nil || decision.Action != ActionDefer || decision.Reason != ReasonUnavailable {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
}

func seedAdmissionState(t *testing.T, db *sql.DB) {
	t.Helper()
	statements := []string{
		`INSERT INTO domains(id,name,enabled,outbound_scope,outbound_policy_revision,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000b01','example.test',true,'same_domain_only',2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		`INSERT INTO mailboxes(id,domain_id,local_part,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000b02','00000000-0000-4000-8000-000000000b01','user',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		`INSERT INTO aliases(id,domain_id,local_part,targets_json,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000b03','00000000-0000-4000-8000-000000000b01','first','["second@example.test"]',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		`INSERT INTO aliases(id,domain_id,local_part,targets_json,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000b04','00000000-0000-4000-8000-000000000b01','second','["outside@example.net"]',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
}

func hasQueueSource(sources []QueueSource, want QueueSource) bool {
	for _, source := range sources {
		if source == want {
			return true
		}
	}
	return false
}
