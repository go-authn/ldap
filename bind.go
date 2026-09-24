// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"context"
	"log/slog"
)

// bind answers a bind request, simple or SASL.
func (c *conn) bind(ctx context.Context, m *message, log *slog.Logger) {
	// ⛔ RFC 4511 4.2.1: the association is set to anonymous when the bind
	// request is RECEIVED, and stays anonymous unless the bind succeeds.
	//
	// Clearing it only on failure is not the same thing, and the difference
	// is a connection pool: it binds somebody who succeeds, re-binds
	// somebody whose password is wrong, and every operation after that is
	// answered with the first person's rights. The client is told
	// invalidCredentials and carries on. That is the defect this server
	// exists partly to not have.
	c.setBoundDN("")

	req, err := decodeBindRequest(m.op)
	if err != nil {
		c.send(bindResponse(m.id, SASLResult{Result: Refuse(ProtocolError, "%v", err)}))
		return
	}
	if req.Version != 3 {
		// LDAPv2 is a different protocol, not an older dialect of this one.
		// Answering it as though it were 3 makes a v2 client believe things
		// about the exchange that are not true.
		c.send(bindResponse(m.id, SASLResult{Result: Refuse(ProtocolError,
			"this server speaks LDAPv3, and the bind asked for version %d", req.Version)}))
		return
	}

	if req.SASL != nil {
		c.bindSASL(ctx, m, req, log)
		return
	}

	if c.srv.Bind == nil {
		c.send(bindResponse(m.id, SASLResult{Result: Refuse(AuthMethodNotSupported,
			"this server does not answer simple binds")}))
		return
	}
	r, err := c.srv.Bind.Bind(ctx, c, req)
	if err != nil {
		log.Error("the bind handler failed", "err", err)
		c.send(bindResponse(m.id, SASLResult{Result: Result{Code: Other}}))
		return
	}
	if r.Code == Success {
		// A simple bind proves the name it carried, and nothing else can
		// know better: there is no mechanism to ask.
		c.setBoundDN(req.Name)
	}
	c.send(bindResponse(m.id, SASLResult{Result: r}))
}

func (c *conn) bindSASL(ctx context.Context, m *message, req *BindRequest, log *slog.Logger) {
	if c.srv.SASL == nil {
		c.send(bindResponse(m.id, SASLResult{Result: Refuse(AuthMethodNotSupported,
			"this server speaks no SASL mechanism")}))
		return
	}
	r, err := c.srv.SASL.BindSASL(ctx, c, req)
	if err != nil {
		log.Error("the SASL handler failed", "mechanism", req.SASL.Mechanism, "err", err)
		c.send(bindResponse(m.id, SASLResult{Result: Result{Code: Other}}))
		return
	}
	if r.Code == Success {
		// ⛔ RFC 4513 5.2.1: the name field of a SASL bind is IGNORED. The
		// identity is whatever the mechanism established, so it comes from
		// the result -- taking it from req.Name would let a client name
		// itself anything and have the mechanism's success confirm it.
		c.setBoundDN(r.BoundDN)
	}
	// Everything else -- a challenge, a refusal -- leaves the connection
	// anonymous, which the clearing at the top of bind already did. A bind in
	// PROGRESS is not a bind that succeeded.
	c.send(bindResponse(m.id, r))
}
