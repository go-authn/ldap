// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// parked is a search that does not answer until released: an operation kept
// in flight for as long as a test needs.
type parked struct {
	release chan struct{}
	started atomic.Int32
}

func (p *parked) Search(ctx context.Context, _ Session, _ *SearchRequest, _ EntryWriter) (Result, error) {
	p.started.Add(1)
	select {
	case <-p.release:
	case <-ctx.Done():
	}
	return Result{Code: Success}, nil
}

// waitStarted waits until n searches are parked in the handler.
func (p *parked) waitStarted(t *testing.T, n int32) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); p.started.Load() < n; {
		if time.Now().After(deadline) {
			t.Fatalf("%d searches started, want %d", p.started.Load(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// ⛔ A connection may have only so many operations in flight. Each runs in its
// own goroutine holding its decoded message, so a client pipelining requests
// faster than they are answered -- before any bind -- grew the server's memory
// without bound. Over the limit it is told why and closed, as slapd does with
// conn_max_pending (slapd.conf(5)): 100 before a bind, 1000 after, by default.
func TestAConnectionWithTooManyOperationsInFlightIsClosed(t *testing.T) {
	p := &parked{release: make(chan struct{})}
	r := serve(t, &Server{Bind: reader(), Search: p, MaxPending: 3, MaxPendingAuth: 5})

	// The limit itself is allowed, and every one of them is answered.
	c := dial(t, r)
	defer c.Close()
	for i := 0; i < 3; i++ {
		c.write(t, c.next(), searchOp(t, "(uid=*)"))
	}
	p.waitStarted(t, 3)
	close(p.release)
	for i := 0; i < 3; i++ {
		if res := resultOf(t, c.read(t)); res.Code != Success {
			t.Fatalf("search %d at the limit answered %s", i, res.Code)
		}
	}

	// One more than the limit, before a bind: a notice, and the connection
	// ends.
	p2 := &parked{release: make(chan struct{})}
	defer close(p2.release)
	r2 := serve(t, &Server{Bind: reader(), Search: p2, MaxPending: 3, MaxPendingAuth: 5})
	c2 := dial(t, r2)
	defer c2.Close()
	for i := 0; i < 3; i++ {
		c2.write(t, c2.next(), searchOp(t, "(uid=*)"))
	}
	p2.waitStarted(t, 3)
	c2.write(t, c2.next(), searchOp(t, "(uid=*)"))
	n := c2.read(t)
	if id, _ := n.Children[0].Value.(int64); id != 0 {
		t.Fatalf("the fourth search was answered under id %d, want a notice of disconnection (id 0)", id)
	}
	if res := resultOf(t, n); res.Code != Busy {
		t.Errorf("the notice says %s, want busy", res.Code)
	}
	// Closed, not merely quiet: the three operations still parked must not
	// hold the connection open. A timeout here is the connection left open.
	_ = c2.c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := readFrame(c2.r, DefaultMaxMessageSize); err == nil || isTimeout(err) {
		t.Errorf("the connection stayed open after the notice: %v", err)
	}

	// After a bind the other limit applies: five in flight is allowed there.
	p3 := &parked{release: make(chan struct{})}
	r3 := serve(t, &Server{Bind: reader(), Search: p3, MaxPending: 3, MaxPendingAuth: 5})
	c3 := dial(t, r3)
	defer c3.Close()
	if code := c3.bind(t, reader().dn, reader().pw); code != Success {
		t.Fatalf("bind answered %s", code)
	}
	for i := 0; i < 5; i++ {
		c3.write(t, c3.next(), searchOp(t, "(uid=*)"))
	}
	p3.waitStarted(t, 5)
	close(p3.release)
	for i := 0; i < 5; i++ {
		if res := resultOf(t, c3.read(t)); res.Code != Success {
			t.Fatalf("bound search %d answered %s", i, res.Code)
		}
	}
}

// The defaults are slapd's, and a negative value is no limit at all.
func TestMaxPendingDefaults(t *testing.T) {
	var s Server
	if got := s.maxPending(false); got != 100 {
		t.Errorf("before a bind: %d", got)
	}
	if got := s.maxPending(true); got != 1000 {
		t.Errorf("after a bind: %d", got)
	}
	s.MaxPending, s.MaxPendingAuth = -1, 7
	if s.maxPending(false) != -1 || s.maxPending(true) != 7 {
		t.Errorf("explicit limits were not taken as given: %d, %d", s.maxPending(false), s.maxPending(true))
	}
}
