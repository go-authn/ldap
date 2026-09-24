// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"bufio"
	"context"
	"crypto/tls"
	"log/slog"
)

// oidNoticeOfDisconnection is the responseName of the unsolicited
// notification a server sends before hanging up (RFC 4511 4.4.1).
const oidNoticeOfDisconnection = "1.3.6.1.4.1.1466.20036"

// extended answers an extended operation that is not StartTLS.
func (c *conn) extended(ctx context.Context, m *message, req *ExtendedRequest) {
	if req.Name == OIDWhoAmI {
		// RFC 4532. It is answered here rather than by a handler because the
		// answer is the CONNECTION's state, which no handler holds: "who do
		// you think I am" is a question about this socket.
		who := c.BoundDN()
		if who != "" {
			who = "dn:" + who
		}
		c.send(extendedResponse(m.id, ExtendedResult{
			Result: Result{Code: Success},
			Value:  []byte(who), // empty means anonymous, and is not absent
		}))
		return
	}
	if c.srv.Extended == nil {
		c.send(extendedResponse(m.id, ExtendedResult{
			Result: Refuse(ProtocolError, "this server answers no extended operation %s", req.Name),
		}))
		return
	}
	r, err := c.srv.Extended.Extended(ctx, c, req)
	if err != nil {
		c.srv.logger().Error("the extended handler failed", "oid", req.Name, "err", err)
		c.send(extendedResponse(m.id, ExtendedResult{Result: Result{Code: Other}}))
		return
	}
	c.send(extendedResponse(m.id, r))
}

// startTLS upgrades the connection (RFC 4511 4.14).
//
// ⛔ It runs in the READ goroutine, synchronously, and that is the whole
// design. This connection has exactly one reader, so replacing the socket
// between messages races nothing. The library this replaces did the exchange
// from StartTLS while its reader goroutine was reading the same socket; the
// two raced and the reader panicked on the packet it half-read, which no
// amount of care at the call site could fix.
func (c *conn) startTLS(id int, log *slog.Logger) {
	if c.srv.TLSConfig == nil {
		c.send(extendedResponse(id, ExtendedResult{
			Result: Refuse(ProtocolError, "this server has no certificate to offer"),
			Name:   OIDStartTLS,
		}))
		return
	}
	if c.encrypted() {
		// RFC 4511 4.14.3: a second StartTLS on a protected connection is an
		// operationsError. Doing it anyway would throw away the session that
		// is already carrying the conversation.
		c.send(extendedResponse(id, ExtendedResult{
			Result: Refuse(OperationsError, "this connection is already protected"),
			Name:   OIDStartTLS,
		}))
		return
	}
	// ⛔ RFC 4511 4.14.1: the client must have no outstanding operations.
	// Upgrading while one is in flight would hand its response to the
	// handshake, and the operation's goroutine would write ciphertext into a
	// socket that is still negotiating.
	c.mu.Lock()
	busy := len(c.inflight)
	c.mu.Unlock()
	if busy > 0 {
		c.send(extendedResponse(id, ExtendedResult{
			Result: Refuse(OperationsError, "%d operations are still in flight", busy),
			Name:   OIDStartTLS,
		}))
		return
	}

	// The success goes out in the CLEAR -- it is the last thing that does.
	c.send(extendedResponse(id, ExtendedResult{Result: Result{Code: Success}, Name: OIDStartTLS}))

	c.mu.Lock()
	raw := c.raw
	c.mu.Unlock()
	tc := tls.Server(raw, c.srv.TLSConfig)
	if err := tc.Handshake(); err != nil {
		// ⛔ Nothing is sent. The client is mid-handshake and expects TLS
		// records; an LDAP message now would be read as one and produce an
		// error about the wrong thing entirely. RFC 4511 4.14.2 says to
		// close.
		log.Info("the TLS handshake failed", "err", err)
		c.close()
		return
	}
	c.mu.Lock()
	c.raw = tc
	c.r = bufio.NewReader(tc)
	c.mu.Unlock()
	log.Debug("upgraded", "tls", tc.ConnectionState().NegotiatedProtocol)
}
