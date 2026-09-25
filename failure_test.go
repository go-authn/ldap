// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"errors"
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// A listener that fails in a way that is NOT "closed", so that a real accept
// failure is told apart from a shutdown. A server that treated every accept
// error as a shutdown would exit silently on a descriptor limit and look
// like it had been asked to stop.
type brokenListener struct {
	err    error
	closed bool
}

func (b *brokenListener) Accept() (net.Conn, error) { return nil, b.err }
func (b *brokenListener) Close() error {
	b.closed = true
	return b.err
}
func (b *brokenListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestARealAcceptErrorIsNotASilentShutdown(t *testing.T) {
	boom := errors.New("too many open files")
	s := &Server{}
	if err := s.Serve(&brokenListener{err: boom}); !errors.Is(err, boom) {
		t.Errorf("Serve returned %v, want the accept error", err)
	}

	// And Close reports a listener that would not close, rather than
	// swallowing it -- a listener still holding its port after a "clean"
	// shutdown is what makes the next start fail with "address in use".
	s2 := &Server{}
	ln := &brokenListener{err: boom}
	go func() { _ = s2.Serve(ln) }()
	time.Sleep(20 * time.Millisecond)
	if err := s2.Close(); err != nil && !errors.Is(err, boom) {
		t.Errorf("Close returned %v", err)
	}
}

// A connection arriving as the server is closing is refused rather than
// served: otherwise Close returns while a connection it never counted is
// still answering.
func TestAConnectionArrivingDuringCloseIsRefused(t *testing.T) {
	s := &Server{}
	_ = s.Close()
	if s.add(&conn{}) {
		t.Error("a closing server accepted a new connection")
	}
	if s.track(&brokenListener{}) {
		t.Error("a closing server accepted a new listener")
	}
}

func TestTheMessageSizeCanBeSet(t *testing.T) {
	if got := (&Server{MaxMessageSize: 99}).maxMessageSize(); got != 99 {
		t.Errorf("MaxMessageSize came back as %d", got)
	}
	// And a message over it is refused on a real connection.
	r := serve(t, &Server{Bind: reader(), MaxMessageSize: 64})
	c := dial(t, r)
	defer c.Close()
	c.write(t, 1, ber.NewString(ber.ClassApplication, ber.TypePrimitive, appExtendedRequest,
		string(make([]byte, 4096)), "big"))
	p := c.read(t)
	if resultOf(t, p).Code != ProtocolError {
		t.Errorf("an oversized message answered %s", resultOf(t, p).Code)
	}
}

// Sending on a connection that is already closed does nothing, rather than
// writing into a socket that is gone.
func TestSendingOnAClosedConnectionIsSilent(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	c := newConn(&Server{}, left)
	c.close()
	// No deadline, no reader: if this wrote anything it would block forever.
	done := make(chan struct{})
	go func() {
		c.send(resultMessage(1, appSearchResDone, Result{Code: Success}))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("send blocked on a closed connection")
	}
	// Closing twice is safe -- a connection that ends while an operation is
	// finishing gets there from two directions.
	c.close()
}

// ⛔ A TLS handshake that fails sends NOTHING. The client is mid-handshake
// and expects TLS records; an LDAP message now would be read as one and
// produce an error about the wrong thing entirely (RFC 4511 4.14.2 says to
// close).
func TestAFailedHandshakeClosesWithoutSayingAnythingElse(t *testing.T) {
	r := serve(t, &Server{Bind: reader(), TLSConfig: selfSigned(t)})
	c := dial(t, r)
	defer c.Close()

	if code := c.startTLS(t); code != Success {
		t.Fatalf("StartTLS answered %s", code)
	}
	// Rubbish where a ClientHello belongs.
	if _, err := c.c.Write([]byte("this is not a ClientHello")); err != nil {
		t.Fatal(err)
	}
	_ = c.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	// Whatever comes back must not be an LDAP message: the server either
	// sends a TLS alert or closes. Both leave readFrame with an error.
	if _, err := readFrame(c.r, DefaultMaxMessageSize); err == nil {
		t.Error("an LDAP message was sent after a failed handshake")
	}
}

// A listener that blocks in Accept until closed, and fails to close. It has
// to block, because a listener whose Accept returns at once is untracked by
// Serve before Close can reach it.
type stubbornListener struct {
	block chan struct{}
	err   error
}

func (s *stubbornListener) Accept() (net.Conn, error) {
	<-s.block
	return nil, net.ErrClosed
}
func (s *stubbornListener) Close() error {
	close(s.block)
	return s.err
}
func (s *stubbornListener) Addr() net.Addr { return &net.TCPAddr{} }

// ⛔ Close reports a listener that would not close. A listener still holding
// its port after a "clean" shutdown is what makes the next start fail with
// "address already in use" -- and swallowing the error means the restart
// script says the stop worked.
func TestCloseReportsAListenerThatWouldNotClose(t *testing.T) {
	boom := errors.New("the listener is stuck")
	ln := &stubbornListener{block: make(chan struct{}), err: boom}
	s := &Server{}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	time.Sleep(20 * time.Millisecond)

	if err := s.Close(); !errors.Is(err, boom) {
		t.Errorf("Close returned %v, want the listener's error", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Serve did not return")
	}
}

// A connection that arrives while the server is closing is hung up on rather
// than served -- otherwise Close returns while a connection it never counted
// is still answering.
func TestAConnectionArrivingAfterCloseIsHungUpOn(t *testing.T) {
	s := &Server{Bind: reader()}
	_ = s.Close()

	left, right := net.Pipe()
	defer right.Close()
	done := make(chan struct{})
	go func() { s.serve(left); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the server tried to serve a connection after Close")
	}
	// The socket is closed, so a read from the other end ends at once.
	_ = right.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := right.Read(make([]byte, 1)); err == nil {
		t.Error("the connection was left open")
	}
}

// A Disconnecter is told when a connection ends, however it ended. It is
// what lets a deployment release whatever the session was holding.
func TestADisconnecterIsToldTheConnectionEnded(t *testing.T) {
	ended := make(chan string, 1)
	s := &Server{
		Bind:         reader(),
		Disconnected: disconnectFunc(func(sess Session) { ended <- sess.BoundDN() }),
	}
	r := serve(t, s)
	c := dial(t, r)
	if code := c.bind(t, "cn=reader,dc=example,dc=org", "let me read"); code != Success {
		t.Fatal("the control failed: the bind did not succeed")
	}
	c.Close()

	select {
	case dn := <-ended:
		// It is told WHO left, which is the only moment that is knowable.
		if dn != "cn=reader,dc=example,dc=org" {
			t.Errorf("it was told %q left", dn)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the Disconnecter was never told")
	}
}

type disconnectFunc func(Session)

func (f disconnectFunc) Disconnect(s Session) { f(s) }

// A write that fails closes the connection, so the rest of an operation does
// not keep filling a socket nobody is reading.
func TestAFailedWriteClosesTheConnection(t *testing.T) {
	left, right := net.Pipe()
	right.Close() // the far end is gone before anything is sent
	c := newConn(&Server{}, left)

	c.send(resultMessage(1, appSearchResDone, Result{Code: Success}))
	if !c.isClosed() {
		t.Error("a failed write left the connection open")
	}
}
