// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"context"
	"fmt"
	"log/slog"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// responseFor is the response tag for a request tag, so that a refusal
// reaches the client as the right KIND of message.
//
// ⛔ A client waits for the response that matches what it sent. Answering a
// modify with a searchResDone leaves it waiting for a message that will never
// come, which looks like a hang rather than a refusal -- so an operation this
// server does not recognise gets no response at all and the connection ends,
// which RFC 4511 4.1.1 is explicit about.
func responseFor(tag ber.Tag) ber.Tag {
	switch tag {
	case appBindRequest:
		return appBindResponse
	case appSearchRequest:
		return appSearchResDone
	case appModifyRequest:
		return appModifyResponse
	case appAddRequest:
		return appAddResponse
	case appDelRequest:
		return appDelResponse
	case appModDNRequest:
		return appModDNResponse
	case appCompareRequest:
		return appCompareResponse
	case appExtendedRequest:
		return appExtendedResponse
	}
	return 0
}

// operation answers everything except unbind, abandon and StartTLS.
func (c *conn) operation(ctx context.Context, m *message, log *slog.Logger) {
	resp := responseFor(m.op.Tag)
	if resp == 0 {
		// Not an operation this protocol has. There is no response type to
		// send, so the connection ends with a notice saying why.
		log.Info("an operation this server does not know", "tag", int(m.op.Tag))
		c.notice(ProtocolError, fmt.Sprintf("operation %d is not one this server knows", m.op.Tag))
		c.close()
		return
	}

	// A search is decoded here, once, because whether it is the root DSE
	// read decides what the rules below are.
	var search *SearchRequest
	if m.op.Tag == appSearchRequest {
		req, err := decodeSearchRequest(m.op)
		if err != nil {
			c.send(resultMessage(m.id, resp, Refuse(ProtocolError, "%v", err)))
			return
		}
		search = req
	}

	// ⛔ A critical control nobody here handles means the operation MUST be
	// refused (RFC 4511 4.1.11): the client has said this is not the
	// operation it wants unless the control is honoured. Performing it
	// anyway does something else and reports success.
	// The controls this server honours. A critical one NOT in this list
	// refuses the operation, which is the whole point of criticality.
	if ctl := UnhandledCritical(m.controls, OIDPaging); ctl != nil {
		c.send(resultMessage(m.id, resp, Refuse(UnavailableCriticalExtension,
			"the control %s is marked critical and nothing here handles it", ctl.Type)))
		return
	}

	// ⛔ The root DSE is read BEFORE the confidentiality gate, and that is
	// deliberate rather than an oversight. It is where StartTLS is
	// advertised (RFC 4512 5.1), so a listener that demanded TLS to read it
	// would hide the only extension that offers TLS -- a client would have
	// to already know the answer to discover it. What it exposes is this
	// server's capabilities, which is what discovery IS; it publishes
	// nobody's data.
	if search != nil && isRootDSERead(search) {
		c.searchRootDSE(ctx, m, search)
		return
	}

	// ⛔ Confidentiality next, before anything reads the request further. A
	// bind password refused for the transport must not first be compared
	// against anything, and a search refused for the transport must not
	// first be answered.
	if c.srv.RequireTLS && !c.encrypted() {
		c.send(resultMessage(m.id, resp, Refuse(ConfidentialityRequired,
			"this listener requires TLS, and nothing asked for it")))
		return
	}

	switch m.op.Tag {
	case appBindRequest:
		c.bind(ctx, m, log)
	case appSearchRequest:
		// ⛔ A paged search is answered on a path of its own, because it
		// OUTLIVES this request: the handler stays running, parked on its
		// next entry, until the client asks for the next page or goes away.
		if ctl := Find(m.controls, OIDPaging); ctl != nil && c.srv.Search != nil {
			if err := Unsupported(search.Filter); err != nil {
				c.send(resultMessage(m.id, appSearchResDone, Refuse(InappropriateMatching, "%v", err)))
				return
			}
			log.Debug("paged search", "base", search.BaseObject,
				"scope", search.Scope.String(), "filter", shapeOf(search.Filter), "dn", c.BoundDN())
			c.searchPaged(ctx, m, search, ctl, log)
			return
		}
		c.search(ctx, m, search, log)
	case appCompareRequest:
		c.compare(ctx, m)
	case appAddRequest:
		c.add(ctx, m)
	case appModifyRequest:
		c.modify(ctx, m)
	case appDelRequest:
		c.del(ctx, m)
	case appModDNRequest:
		c.modifyDN(ctx, m)
	}
}

// answer sends a handler's result, turning an error it did not expect into
// `other` rather than into a hang.
//
// ⛔ A handler that returns an error has failed in a way it did not have a
// result code for. The client is told `other` and NOTHING else: whatever
// went wrong inside a directory is for the directory's own log, and a
// diagnostic built from an internal error hands a client the shape of the
// code behind it.
func (c *conn) answer(id int, resp ber.Tag, r Result, err error, log *slog.Logger, op string) {
	if err != nil {
		log.Error("the handler failed", "op", op, "err", err)
		c.send(resultMessage(id, resp, Result{Code: Other}))
		return
	}
	c.send(resultMessage(id, resp, r))
}

func (c *conn) compare(ctx context.Context, m *message) {
	if c.srv.Compare == nil {
		c.send(resultMessage(m.id, appCompareResponse, Refuse(UnwillingToPerform,
			"this server does not answer compare")))
		return
	}
	req, err := decodeCompareRequest(m.op)
	if err != nil {
		c.send(resultMessage(m.id, appCompareResponse, Refuse(ProtocolError, "%v", err)))
		return
	}
	r, err := c.srv.Compare.Compare(ctx, c, req)
	c.answer(m.id, appCompareResponse, r, err, c.srv.logger(), "compare")
}

func (c *conn) add(ctx context.Context, m *message) {
	if c.srv.Add == nil {
		c.send(resultMessage(m.id, appAddResponse, Refuse(UnwillingToPerform,
			"this server does not add entries")))
		return
	}
	req, err := decodeAddRequest(m.op)
	if err != nil {
		c.send(resultMessage(m.id, appAddResponse, Refuse(ProtocolError, "%v", err)))
		return
	}
	r, err := c.srv.Add.Add(ctx, c, req)
	c.answer(m.id, appAddResponse, r, err, c.srv.logger(), "add")
}

func (c *conn) modify(ctx context.Context, m *message) {
	if c.srv.Modify == nil {
		c.send(resultMessage(m.id, appModifyResponse, Refuse(UnwillingToPerform,
			"this server does not modify entries")))
		return
	}
	req, err := decodeModifyRequest(m.op)
	if err != nil {
		c.send(resultMessage(m.id, appModifyResponse, Refuse(ProtocolError, "%v", err)))
		return
	}
	r, err := c.srv.Modify.Modify(ctx, c, req)
	c.answer(m.id, appModifyResponse, r, err, c.srv.logger(), "modify")
}

func (c *conn) del(ctx context.Context, m *message) {
	if c.srv.Delete == nil {
		c.send(resultMessage(m.id, appDelResponse, Refuse(UnwillingToPerform,
			"this server does not delete entries")))
		return
	}
	// A DelRequest is [APPLICATION 10] LDAPDN -- the octets ARE the DN, with
	// no SEQUENCE around them.
	req := &DeleteRequest{DN: string(m.op.Data.Bytes())}
	r, err := c.srv.Delete.Delete(ctx, c, req)
	c.answer(m.id, appDelResponse, r, err, c.srv.logger(), "delete")
}

func (c *conn) modifyDN(ctx context.Context, m *message) {
	if c.srv.ModifyDN == nil {
		c.send(resultMessage(m.id, appModDNResponse, Refuse(UnwillingToPerform,
			"this server does not rename entries")))
		return
	}
	req, err := decodeModifyDNRequest(m.op)
	if err != nil {
		c.send(resultMessage(m.id, appModDNResponse, Refuse(ProtocolError, "%v", err)))
		return
	}
	r, err := c.srv.ModifyDN.ModifyDN(ctx, c, req)
	c.answer(m.id, appModDNResponse, r, err, c.srv.logger(), "modifydn")
}
