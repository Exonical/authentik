package kerberos

import (
	"strings"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/kdc"
	"github.com/Exonical/go-kerberos/krb5/principal"

	"github.com/sirupsen/logrus"
)

func TestAuditRequest(t *testing.T) {
	user, err := principal.Parse("alice@EXAMPLE.TEST")
	if err != nil {
		t.Fatal(err)
	}
	service, err := principal.Parse("krbtgt/EXAMPLE.TEST@EXAMPLE.TEST")
	if err != nil {
		t.Fatal(err)
	}
	impersonated, err := principal.Parse("bob@EXAMPLE.TEST")
	if err != nil {
		t.Fatal(err)
	}
	request := auditRequest(auditRecord{
		event:   "as_req",
		success: true,
		state: kdc.AuditState{
			RequestID:      "request-id",
			OutputTicketID: "ticket-id",
			Client:         *user,
			Service:        *service,
			Status:         "ok",
			PreauthType:    "encrypted_timestamp",
			AuthIndicators: []string{"password"},
			ErrorCode:      0,
			RemoteAddr:     "127.0.0.1:88",
			S4U2SelfUser:   impersonated,
		},
	})
	if request.Event != "as_req" || !request.Success ||
		request.Client != "alice@EXAMPLE.TEST" ||
		request.Service != "krbtgt/EXAMPLE.TEST@EXAMPLE.TEST" ||
		request.S4u2selfUser != "bob@EXAMPLE.TEST" ||
		request.TicketId != "ticket-id" {
		t.Fatalf("unexpected audit request: %+v", request)
	}
	if request.RequestId != "request-id" || request.Status != "ok" ||
		request.PreauthType != "encrypted_timestamp" ||
		strings.Join(request.AuthIndicators, ",") != "password" ||
		request.RemoteAddr != "127.0.0.1:88" {
		t.Fatalf("audit request fields were not mapped: %+v", request)
	}
}

func TestAuditCallbackDropsWhenQueueIsFull(t *testing.T) {
	instance := &ProviderInstance{
		auditEvents: make(chan auditRecord, 1),
		log:         logrus.New().WithField("test", true),
	}
	instance.auditCallback("as_req", true, kdc.AuditState{})
	instance.auditCallback("tgs_req", true, kdc.AuditState{})
	if len(instance.auditEvents) != 1 {
		t.Fatalf("audit queue length = %d, want 1", len(instance.auditEvents))
	}
	record := <-instance.auditEvents
	if record.event != "as_req" || !record.success {
		t.Fatalf("unexpected queued record: %+v", record)
	}
}
