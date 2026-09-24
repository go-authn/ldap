// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// A conn is one client.
//
// ⛔ Reading is ONE goroutine and each operation runs in its own, with writes
// serialised by a mutex. That shape is what makes StartTLS safe here: the
// reader is the only thing touching the socket, so swapping it for a
// tls.Conn between messages races nothing. The library this replaces read
// the socket from its reader goroutine AND from StartTLS at the same time,
// and the reader panicked on the packet it half-read.
type conn struct {
	srv *Server
	raw net.Conn
	r   *bufio.Reader

	wmu sync.Mutex // serialises writes; every response goes through send

	mu       sync.Mutex
	boundDN  string
	controls []Control
	inflight map[int]context.CancelFunc
	closed   bool
}

func (s *Server) serve(nc net.Conn) {
	c := &conn{
		srv:      s,
		raw:      nc,
		r:        bufio.NewReader(nc),
		inflight: map[int]context.CancelFunc{},
	}
	if !s.add(c) {
		nc.Close()
		return
	}
	defer func() {
		s.remove(c)
		c.close()
		if s.Disconnected != nil {
			s.Disconnected.Disconnect(c)
		}
	}()

	log := s.logger().With("remote", nc.RemoteAddr().String())
	log.Debug("connected")
	defer log.Debug("disconnected")

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		if s.IdleTimeout > 0 {
			// The deadline is reset per message rather than set once: a
			// connection sending steadily is not idle, and one set once
			// would close a busy client mid-conversation.
			_ = nc.SetReadDeadline(time.Now().Add(s.IdleTimeout))
		}
		m, err := readMessage(c.r, s.maxMessageSize())
		if err != nil {
			switch {
			case errors.Is(err, errClosed) || c.isClosed():
				// The client hung up, or this server is stopping. Neither is
				// a fault and neither gets a notice -- there is nobody to
				// read one.
			case isTimeout(err):
				// ⛔ An idle timeout is not a protocol error. The client did
				// nothing wrong; this server decided not to wait any longer,
				// and saying protocolError blames the client for the
				// server's own policy -- which sends whoever reads the
				// client's log looking for a bug that is not there.
				// RFC 4511 4.4.1 has `unavailable` for a server ending a
				// connection of its own accord.
				log.Debug("closing an idle connection", "after", s.IdleTimeout)
				c.notice(Unavailable, "this connection was idle")
			default:
				log.Info("refusing a message", "err", err)
				// A message that cannot be parsed has no id to answer under,
				// so RFC 4511 4.1.1 and 5.1 leave one thing to do: a notice
				// of disconnection, and hang up. Answering under a guessed
				// id would attach the error to somebody else's operation.
				c.notice(ProtocolError, err.Error())
			}
			return
		}
		if done := c.dispatch(&wg, m, log); done {
			return
		}
	}
}

// dispatch answers one message. It returns true when the connection ends.
func (c *conn) dispatch(wg *sync.WaitGroup, m *message, log *slog.Logger) bool {
	switch m.op.Tag {
	case appUnbindRequest:
		// RFC 4511 4.3: there is no response to an unbind, ever.
		return true

	case appAbandonRequest:
		c.abandon(m)
		return false

	case appExtendedRequest:
		// StartTLS is handled by the server itself and SYNCHRONOUSLY, in
		// this goroutine: it replaces the socket, and nothing else may be
		// reading it while that happens.
		req, err := decodeExtendedRequest(m.op)
		if err != nil {
			c.send(resultMessage(m.id, appExtendedResponse, Refuse(ProtocolError, "%v", err)))
			return false
		}
		if req.Name == OIDStartTLS {
			c.startTLS(m.id, log)
			return false
		}
		c.run(wg, m, func(ctx context.Context) { c.extended(ctx, m, req) })
		return false
	}

	c.run(wg, m, func(ctx context.Context) { c.operation(ctx, m, log) })
	return false
}

// run starts an operation, tracked so that an abandon can reach it.
func (c *conn) run(wg *sync.WaitGroup, m *message, f func(context.Context)) {
	ctx, cancel := context.WithCancel(context.Background())
	if c.srv.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, c.srv.Timeout)
	}
	c.mu.Lock()
	// ⛔ RFC 4511 4.1.1.1: a message id must not be reused while an operation
	// with it is outstanding. One that is says two different things about the
	// same id, and an abandon could not name which.
	if _, busy := c.inflight[m.id]; busy {
		c.mu.Unlock()
		cancel()
		c.send(resultMessage(m.id, responseFor(m.op.Tag), Refuse(ProtocolError,
			"message id %d is already in flight", m.id)))
		return
	}
	c.inflight[m.id] = cancel
	c.controls = m.controls
	c.mu.Unlock()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		defer func() {
			c.mu.Lock()
			delete(c.inflight, m.id)
			c.mu.Unlock()
		}()
		f(ctx)
	}()
}

// abandon cancels an operation. There is no response to an abandon.
func (c *conn) abandon(m *message) {
	// ⛔ An AbandonRequest is [APPLICATION 16] MessageID -- an application
	// tagged PRIMITIVE. ber decodes no universal type for it, so Value is
	// nil and the octets are in Data. Reading Value here silently abandoned
	// nothing, on every abandon, and there is no response to say so.
	id, ok := taggedInteger(m.op)
	if !ok {
		// An abandon naming nothing. There is no way to report it, because
		// an abandon has no response -- so it is dropped, which is what RFC
		// 4511 4.11 says to do with one that names an unknown operation.
		return
	}
	c.mu.Lock()
	cancel := c.inflight[int(id)]
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if c.srv.Abandon != nil {
		c.srv.Abandon.Abandon(context.Background(), c, int(id))
	}
}

// send writes one response.
//
// ⛔ The socket is read under the mutex, not from c.raw directly. StartTLS
// replaces it, and although it only does so while nothing is in flight --
// so no send can be running -- that is an ARGUMENT about bookkeeping rather
// than a guarantee. An argument that the race detector cannot check is one
// that stops being true the first time the bookkeeping changes.
func (c *conn) send(p *ber.Packet) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.isClosed() {
		return
	}
	c.mu.Lock()
	w := c.raw
	c.mu.Unlock()
	if _, err := w.Write(p.Bytes()); err != nil {
		// The client went away mid-answer. Closing here stops the rest of
		// the operation writing into a socket nobody is reading.
		c.close()
	}
}

// notice is an unsolicited notification of disconnection (RFC 4511 4.4.1):
// an extended response with message id ZERO, which is the only message a
// server sends on its own.
func (c *conn) notice(code ResultCode, why string) {
	m := newMessage(0)
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appExtendedResponse, nil, "extendedResp")
	appendResult(op, Result{Code: code, Diagnostic: why})
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagExtResponseName,
		"1.3.6.1.4.1.1466.20036", "responseName"))
	m.AppendChild(op)
	c.send(m)
}

func (c *conn) close() {
	c.mu.Lock()
	already := c.closed
	raw := c.raw
	c.closed = true
	cancels := make([]context.CancelFunc, 0, len(c.inflight))
	for _, cancel := range c.inflight {
		cancels = append(cancels, cancel)
	}
	c.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	if !already {
		raw.Close()
	}
}

func (c *conn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// --- Session --------------------------------------------------------------

func (c *conn) BoundDN() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.boundDN
}

func (c *conn) setBoundDN(dn string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.boundDN = dn
}

func (c *conn) TLS() (tls.ConnectionState, bool) {
	c.mu.Lock()
	raw := c.raw
	c.mu.Unlock()
	tc, ok := raw.(*tls.Conn)
	if !ok {
		return tls.ConnectionState{}, false
	}
	return tc.ConnectionState(), true
}

func (c *conn) RemoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.raw.RemoteAddr()
}

func (c *conn) Conn() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.raw
}

func (c *conn) Controls() []Control {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.controls
}

// encrypted reports whether this connection is one a credential may cross.
func (c *conn) encrypted() bool {
	_, ok := c.TLS()
	return ok
}

// taggedInteger reads an INTEGER out of a context- or application-tagged
// primitive, where ber leaves the octets in Data rather than decoding them.
//
// It is big-endian two's complement (X.690 8.3). A message id is positive,
// but the sign is honoured rather than assumed, so that a negative one is
// refused by the caller rather than read as an enormous positive.
func taggedInteger(p *ber.Packet) (int64, bool) {
	if v, ok := p.Value.(int64); ok {
		return v, true
	}
	b := p.Data.Bytes()
	if len(b) == 0 || len(b) > 8 {
		return 0, false
	}
	v := int64(0)
	if b[0]&0x80 != 0 {
		v = -1 // sign-extend
	}
	for _, c := range b {
		v = v<<8 | int64(c)
	}
	return v, true
}

// isTimeout reports whether a read failed because this server stopped
// waiting, rather than because of anything the client sent.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
