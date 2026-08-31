package kerberos

import (
	"context"

	"github.com/Exonical/go-kerberos/krb5/kdc"
	"github.com/Exonical/go-kerberos/krb5/principal"

	api "goauthentik.io/packages/client-go"
)

const auditQueueSize = 256

func (rs *KerberosServer) startAudit(instance *ProviderInstance) {
	if !instance.Config.GetKdcAuditEnabled() {
		return
	}
	instance.auditEvents = make(chan auditRecord, auditQueueSize)
	ctx, cancel := context.WithCancel(context.Background())
	instance.auditCancel = cancel
	instance.auditDone = make(chan struct{})
	go func() {
		defer close(instance.auditDone)
		for {
			select {
			case <-ctx.Done():
				return
			case record := <-instance.auditEvents:
				instance.sendAuditEvent(ctx, record)
			}
		}
	}()
}

type auditRecord struct {
	event   string
	success bool
	state   kdc.AuditState
}

func (instance *ProviderInstance) stopAudit() {
	if instance == nil || instance.auditCancel == nil {
		return
	}
	instance.auditCancel()
	<-instance.auditDone
	instance.auditCancel = nil
	instance.auditDone = nil
}

func (instance *ProviderInstance) auditCallback(
	event string, success bool, state kdc.AuditState,
) {
	switch event {
	case "as_req", "tgs_req", "s4u2self", "s4u2proxy", "u2u":
	default:
		return
	}
	record := auditRecord{event: event, success: success, state: state}
	select {
	case instance.auditEvents <- record:
	default:
		if instance.log != nil {
			instance.log.Warn("Dropping KDC audit event: queue is full")
		}
	}
}

func auditPrincipal(value principal.Principal) string {
	return value.String()
}

func auditRequest(record auditRecord) api.KerberosAuditEventRequest {
	ticketID := record.state.OutputTicketID
	if ticketID == "" {
		ticketID = record.state.InputTicketID
	}
	s4u2selfUser := ""
	if record.state.S4U2SelfUser != nil {
		s4u2selfUser = auditPrincipal(*record.state.S4U2SelfUser)
	}
	return *api.NewKerberosAuditEventRequest(
		api.EventEnum(record.event),
		record.success,
		auditPrincipal(record.state.Client),
		auditPrincipal(record.state.Service),
		record.state.Status,
		record.state.PreauthType,
		record.state.RemoteAddr,
		s4u2selfUser,
		record.state.AuthIndicators,
		record.state.ErrorCode,
		record.state.RequestID,
		ticketID,
	)
}

func (instance *ProviderInstance) sendAuditEvent(ctx context.Context, record auditRecord) {
	_, err := instance.Store.server.ac.Client.OutpostsAPI.OutpostsKerberosAuditEventCreate(
		ctx,
		instance.Store.providerID,
	).KerberosAuditEventRequest(auditRequest(record)).Execute()
	if err != nil {
		if instance.log != nil {
			instance.log.WithError(err).Warn("Failed to send KDC audit event")
		}
	}
}
