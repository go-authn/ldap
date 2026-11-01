// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"bufio"
	"context"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// expectNotice reads one message from a connection that was refused: a
// notice of disconnection (id 0) carrying want, then the end of the stream.
func expectNotice(t *testing.T, c *client, want ResultCode) {
	t.Helper()
	_ = c.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	p := c.read(t)
	if id, _ := p.Children[0].Value.(int64); id != 0 {
		t.Fatalf("answered under id %d, want a notice (id 0)", id)
	}
	if res := resultOf(t, p); res.Code != want {
		t.Fatalf("the notice says %s, want %s", res.Code, want)
	}
	if _, err := readFrame(c.r, DefaultMaxMessageSize); err == nil || isTimeout(err) {
		t.Fatalf("the connection stayed open after the notice: %v", err)
	}
}

// ⛔ A flood beyond MaxConnections is refused, not queued: each excess
// connection is told busy (RFC 4511 4.4.1) and closed, and the ones already
// held keep working. Room made by a departure is usable again.
func TestAFloodBeyondMaxConnectionsIsRefused(t *testing.T) {
	r := serve(t, &Server{Bind: reader(), Search: &directory{}, MaxConnections: 3})
	var held []*client
	for i := 0; i < 3; i++ {
		c := dial(t, r)
		defer c.Close()
		if code := c.bind(t, reader().dn, reader().pw); code != Success {
			t.Fatalf("held connection %d bind: %s", i, code)
		}
		held = append(held, c)
	}
	for i := 0; i < 50; i++ {
		c := dial(t, r)
		expectNotice(t, c, Busy)
		c.Close()
	}
	if code := held[0].bind(t, reader().dn, reader().pw); code != Success {
		t.Errorf("a held connection stopped working: %s", code)
	}
	// Free a slot; the count drops when the server sees the close.
	held[2].Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c := dial(t, r)
		_ = c.c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if code := c.bind(t, reader().dn, reader().pw); code == Success {
			c.Close()
			break
		}
		c.Close()
		if time.Now().After(deadline) {
			t.Fatal("a slot freed by a departure was never reusable")
		}
	}
}

func TestMaxConnectionsPerIP(t *testing.T) {
	r := serve(t, &Server{Bind: reader(), MaxConnectionsPerIP: 2})
	a, b := dial(t, r), dial(t, r)
	defer a.Close()
	defer b.Close()
	for _, c := range []*client{a, b} {
		if code := c.bind(t, reader().dn, reader().pw); code != Success {
			t.Fatalf("bind: %s", code)
		}
	}
	c := dial(t, r) // same address 127.0.0.1: the third
	defer c.Close()
	expectNotice(t, c, Busy)
}

// The counters return to zero: a server that leaked a count would refuse
// everybody after enough short connections.
func TestConnectionCountsAreReleased(t *testing.T) {
	s := &Server{Bind: reader(), MaxConnections: 2, MaxConnectionsPerIP: 2}
	r := serve(t, s)
	for i := 0; i < 20; i++ {
		c := dial(t, r)
		if code := c.bind(t, reader().dn, reader().pw); code != Success {
			t.Fatalf("connection %d refused: %s", i, code)
		}
		c.Close()
		for deadline := time.Now().Add(5 * time.Second); ; {
			s.mu.Lock()
			n, m := s.nconn, len(s.perIP)
			s.mu.Unlock()
			if n == 0 && m == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("after close: nconn=%d perIP entries=%d", n, m)
			}
			time.Sleep(time.Millisecond)
		}
	}
}

// deaf is a search that blocks until released and NEVER looks at its context:
// a handler stuck on a slow source.
type deaf struct {
	release chan struct{}
	started atomic.Int32
	done    atomic.Int32
}

func (d *deaf) Search(_ context.Context, _ Session, _ *SearchRequest, _ EntryWriter) (Result, error) {
	d.started.Add(1)
	<-d.release
	d.done.Add(1)
	return Result{Code: Success}, nil
}

func goroutinesSettle(t *testing.T, atMost int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; {
		if n := runtime.NumGoroutine(); n <= atMost {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines, want at most %d", runtime.NumGoroutine(), atMost)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ⛔ A handler that blocks for ever and ignores its context must not hold the
// client: the server answers timeLimitExceeded itself at the deadline. The late
// result is dropped, and once the handler returns its goroutine is gone.
func TestAHandlerThatNeverReturnsIsAnsweredAtTheDeadline(t *testing.T) {
	d := &deaf{release: make(chan struct{})}
	r := serve(t, &Server{Bind: reader(), Search: d, Timeout: 100 * time.Millisecond})
	base := runtime.NumGoroutine()
	c := dial(t, r)
	defer c.Close()
	c.bind(t, reader().dn, reader().pw)

	start := time.Now()
	id := c.next()
	c.write(t, id, searchOp(t, "(uid=*)"))
	p := c.read(t)
	if got, _ := p.Children[0].Value.(int64); int(got) != id {
		t.Fatalf("answered under id %d, want %d", got, id)
	}
	if res := resultOf(t, p); res.Code != TimeLimitExceeded {
		t.Fatalf("answered %s, want timeLimitExceeded", res.Code)
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Errorf("took %v", el)
	}

	// The handler finally returns: nothing more is sent for that id, and the
	// connection still works.
	close(d.release)
	for deadline := time.Now().Add(5 * time.Second); d.done.Load() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("handler never finished")
		}
		time.Sleep(time.Millisecond)
	}
	if code := c.bind(t, reader().dn, reader().pw); code != Success {
		t.Errorf("next response was %s (a late result leaked, or the connection broke)", code)
	}
	c.Close()
	r.Close()
	goroutinesSettle(t, base)
}

// The stuck goroutines still count against the pending limit, so a client
// cannot leak them without bound: the connection is closed with busy.
func TestExpiredOperationsStillCountAsPending(t *testing.T) {
	d := &deaf{release: make(chan struct{})}
	defer close(d.release)
	r := serve(t, &Server{Bind: reader(), Search: d, Timeout: 50 * time.Millisecond, MaxPending: 3})
	c := dial(t, r)
	defer c.Close()
	for i := 0; i < 3; i++ {
		c.write(t, c.next(), searchOp(t, "(uid=*)"))
		if res := resultOf(t, c.read(t)); res.Code != TimeLimitExceeded {
			t.Fatalf("search %d: %s", i, res.Code)
		}
	}
	c.write(t, c.next(), searchOp(t, "(uid=*)"))
	expectNotice(t, c, Busy)
}

// A bind whose handler gives up with its context's error is a time limit, not
// `other`.
type timedOutBinder struct{}

func (timedOutBinder) Bind(ctx context.Context, _ Session, _ *BindRequest) (Result, error) {
	<-ctx.Done()
	return Result{}, ctx.Err()
}

func TestADeadlineOnABindSaysTimeLimit(t *testing.T) {
	r := serve(t, &Server{Bind: timedOutBinder{}, Timeout: 100 * time.Millisecond})
	c := dial(t, r)
	defer c.Close()
	if code := c.bind(t, "cn=x", "y"); code != TimeLimitExceeded {
		t.Errorf("a bind past the deadline answered %s", code)
	}
}

// Abandon cancels the handler's context and sends nothing.
func TestAbandonCancelsTheHandlersContext(t *testing.T) {
	p := &parked{release: make(chan struct{})}
	defer close(p.release)
	cancelled := make(chan struct{})
	s := &Server{Bind: reader(), Search: &ctxWatcher{parked: p, cancelled: cancelled}}
	r := serve(t, s)
	c := dial(t, r)
	defer c.Close()
	id := c.next()
	c.write(t, id, searchOp(t, "(uid=*)"))
	p.waitStarted(t, 1)

	ab := ber.Encode(ber.ClassApplication, ber.TypePrimitive, appAbandonRequest, nil, "abandonRequest")
	ab.Data.Write([]byte{byte(id)})
	c.write(t, c.next(), ab)
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler's context was not cancelled by an abandon")
	}
	if code := c.bind(t, reader().dn, reader().pw); code != Success {
		t.Errorf("the next response was %s: something was sent for the abandoned search", code)
	}
}

type ctxWatcher struct {
	*parked
	cancelled chan struct{}
}

func (w *ctxWatcher) Search(ctx context.Context, _ Session, _ *SearchRequest, _ EntryWriter) (Result, error) {
	w.started.Add(1)
	<-ctx.Done()
	close(w.cancelled)
	return Result{}, ctx.Err()
}

// The client's timeLimit (RFC 4511 4.5.1.5) is honoured by a handler that
// watches its context.
func TestAClientTimeLimitIsHonoured(t *testing.T) {
	w := &ctxWatcher{parked: &parked{}, cancelled: make(chan struct{})}
	r := serve(t, &Server{Bind: reader(), Search: w})
	c := dial(t, r)
	defer c.Close()
	// ⛔ AppendChild copies the child's bytes into the parent, so changing a
	// child afterwards changes nothing on the wire: the request is rebuilt.
	f, err := ParseFilter("(uid=*)")
	if err != nil {
		t.Fatal(err)
	}
	fp, err := EncodeFilter(f)
	if err != nil {
		t.Fatal(err)
	}
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchRequest, nil, "searchRequest")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dc=example,dc=org", "baseObject"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(ScopeWholeSubtree), "scope"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(0), "derefAliases"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "sizeLimit"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "timeLimit"))
	op.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))
	op.AppendChild(fp)
	op.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes"))
	start := time.Now()
	c.write(t, c.next(), op)
	w.waitStarted(t, 1)
	if res := resultOf(t, c.read(t)); res.Code != TimeLimitExceeded {
		t.Fatalf("answered %s", res.Code)
	}
	if el := time.Since(start); el > 4*time.Second {
		t.Errorf("took %v", el)
	}
}

type timedOutSASL struct{}

func (timedOutSASL) Mechanisms() []string { return []string{"X"} }

func (timedOutSASL) BindSASL(ctx context.Context, _ Session, _ *BindRequest) (SASLResult, error) {
	<-ctx.Done()
	return SASLResult{}, ctx.Err()
}

func TestADeadlineOnASASLBindSaysTimeLimit(t *testing.T) {
	r := serve(t, &Server{SASL: timedOutSASL{}, Timeout: 100 * time.Millisecond})
	c := dial(t, r)
	defer c.Close()
	if code, _, _ := c.bindSASL(t, "X", nil); code != TimeLimitExceeded {
		t.Errorf("a SASL bind past the deadline answered %s", code)
	}
}

func bufioReader(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }

// pipeConn is a conn whose peer end the test reads.
func pipeConn(t *testing.T, s *Server) (*conn, *client) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return newConn(s, a), &client{c: b, r: bufioReader(b)}
}

// ⛔ A handler failing with its operation's own deadline is a time limit for
// every kind of operation, and the answer does not depend on winning a race
// with the server's own timer.
func TestHandlerDeadlineErrorsAreTimeLimits(t *testing.T) {
	past, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	c, peer := pipeConn(t, &Server{})
	go c.answer(past, 7, appCompareResponse, Result{}, context.DeadlineExceeded, c.srv.logger(), "compare")
	if res := resultOf(t, peer.read(t)); res.Code != TimeLimitExceeded {
		t.Errorf("answer: %s", res.Code)
	}
	go c.answerWrite(past, 8, appDelResponse, &DeleteRequest{}, WriteResult{}, context.DeadlineExceeded, c.srv.logger(), "delete")
	if res := resultOf(t, peer.read(t)); res.Code != TimeLimitExceeded {
		t.Errorf("answerWrite: %s", res.Code)
	}
	// The same error under a live context is a failure of the handler's own.
	live := context.Background()
	go c.answer(live, 9, appCompareResponse, Result{}, context.DeadlineExceeded, c.srv.logger(), "compare")
	if res := resultOf(t, peer.read(t)); res.Code != Other {
		t.Errorf("a handler's own timeout under a live context answered %s", res.Code)
	}
}

// expire does nothing for an operation that is not outstanding or whose tag
// has no response.
func TestExpireIgnoresWhatIsNotOutstanding(t *testing.T) {
	c, peer := pipeConn(t, &Server{})
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchRequest, nil, "x")
	c.expire(&message{id: 5, op: op}) // not in flight: finished first
	unknown := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 30, nil, "x")
	c.expire(&message{id: 6, op: unknown})
	_ = peer.c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := readFrame(peer.r, DefaultMaxMessageSize); err == nil {
		t.Error("something was sent for an operation that was not outstanding")
	}
}

// Past maxRejecting refusals in progress a connection is closed without a
// word, so a flood cannot make the refusing itself unbounded.
func TestRefusalsAreBounded(t *testing.T) {
	s := &Server{}
	s.rejecting = maxRejecting
	a, b := net.Pipe()
	defer b.Close()
	s.refuse(a)
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := b.Read(make([]byte, 1)); n != 0 || err == nil || isTimeout(err) {
		t.Errorf("read %d bytes, err %v: want a bare close", n, err)
	}
}
