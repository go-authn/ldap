// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// totalAlloc is the cumulative number of heap bytes this process has asked
// for. A delta of it measures what a piece of code REQUESTED, which is the
// thing under test here, and it does not depend on how fast the machine is
// or on when the collector last ran.
func totalAlloc() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.TotalAlloc
}

// headerClaiming is a SEQUENCE header with a four-byte long-form length.
func headerClaiming(n int) []byte {
	return []byte{0x30, 0x84, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// ⛔ The length prefix is a CLAIM, made by somebody who has not
// authenticated. Checking it against the limit stops a claim of four
// gigabytes, but a claim just under the limit was still honoured in full
// the moment it was read: six bytes on the wire reserved four mebibytes, and
// a connection that then sent nothing held them for as long as it stayed
// open. Fifty such connections, 300 bytes in all, held 200 MiB.
//
// What the reader asks for must follow what has ARRIVED. Sixteen reads of a
// header claiming just under the limit, each followed by end of input, must
// request a small fraction of what the claims add up to.
func TestAClaimedLengthIsNotReservedBeforeTheBytesArrive(t *testing.T) {
	const reads = 16
	claim := DefaultMaxMessageSize - 16
	header := headerClaiming(claim)

	before := totalAlloc()
	for i := 0; i < reads; i++ {
		_, err := frameOf(t, header, DefaultMaxMessageSize)
		if !errors.Is(err, errClosed) {
			t.Fatalf("a header with no body gave %v, want errClosed", err)
		}
	}
	got := totalAlloc() - before

	// The bufio.Reader frameOf builds is 4 KiB a read; the margin is
	// sixty-four times that. The defect requested 64 MiB here.
	const ceiling = reads * 256 << 10
	if got > ceiling {
		t.Errorf("%d header-only reads, each claiming %d bytes, requested %d bytes (%.1f MiB); "+
			"the ceiling is %d -- the claim is being reserved before the body arrives",
			reads, claim, got, float64(got)/(1<<20), ceiling)
	}
}

// The other half of the same property: a body that does arrive is read in
// full however large it is, and what is requested stays proportional to it.
// An eighth of a claimed body followed by end of input requests a small
// multiple of that eighth, not what the whole claim would.
func TestWhatIsRequestedFollowsWhatArrives(t *testing.T) {
	claim := DefaultMaxMessageSize - 16
	part := claim / 8
	in := append(headerClaiming(claim), make([]byte, part)...)

	before := totalAlloc()
	_, err := frameOf(t, in, DefaultMaxMessageSize)
	got := totalAlloc() - before
	if !errors.Is(err, errClosed) {
		t.Fatalf("a truncated body gave %v, want errClosed", err)
	}
	// The input itself is not counted (it was built before `before`). The
	// buffer at most doubles past what arrived, and the steps that got it
	// there sum to at most that again: four times what arrived, plus the
	// bufio buffer. The defect requested the whole claim, eight times it.
	if limit := uint64(4*part + 256<<10); got > limit {
		t.Errorf("an eighth of a %d-byte body requested %d bytes, more than %d", claim, got, limit)
	}

	// And a body at the limit, delivered in full, still comes back intact --
	// the cap is unchanged and incremental reading loses nothing.
	full := make([]byte, claim)
	for i := range full {
		full[i] = byte(i * 7)
	}
	out, err := frameOf(t, append(headerClaiming(claim), full...), DefaultMaxMessageSize)
	if err != nil {
		t.Fatalf("a body at the limit: %v", err)
	}
	if len(out) != 6+claim || !bytes.Equal(out[6:], full) {
		t.Errorf("a body at the limit came back as %d bytes, or changed", len(out))
	}
}

// A reader that hands out one byte at a time is how a slow sender looks to
// the frame reader. The body must still assemble correctly across many short
// reads and many growth steps.
type trickle struct{ r io.Reader }

func (t trickle) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return t.r.Read(p)
}

func TestABodyArrivingOneByteAtATimeIsAssembled(t *testing.T) {
	n := 70000 // over several growth steps
	body := make([]byte, n)
	for i := range body {
		body[i] = byte(i ^ i>>8)
	}
	in := append([]byte{0x30, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
	out, err := readFrame(bufio.NewReaderSize(trickle{bytes.NewReader(in)}, 16), DefaultMaxMessageSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out[5:], body) {
		t.Error("a trickled body came back changed")
	}
}

// The same property on the path a server actually runs, with no sleeps:
// net.Pipe is synchronous, so a Write returns only once the server has READ
// those bytes. After the header and one body byte have both been written,
// the server has read the claim and gone back for more -- whatever it
// reserves for the claim, it has reserved by then.
func TestAnIdleConnectionWithAClaimHoldsLittle(t *testing.T) {
	s := &Server{}
	t.Cleanup(func() { s.Close() })

	const conns = 16
	header := headerClaiming(DefaultMaxMessageSize - 16)
	clients := make([]net.Conn, 0, conns)
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()

	before := totalAlloc()
	for i := 0; i < conns; i++ {
		client, server := net.Pipe()
		clients = append(clients, client)
		go s.serve(server)
		if _, err := client.Write(header); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write([]byte{0}); err != nil {
			t.Fatal(err)
		}
	}
	got := totalAlloc() - before

	// A connection costs a bufio.Reader (4 KiB), a goroutine and a few
	// maps. 256 KiB each is a wide margin; the defect cost 4 MiB each.
	const ceiling = conns * 256 << 10
	if got > ceiling {
		t.Errorf("%d connections that sent 7 bytes each requested %d bytes (%.1f MiB, %.2f MiB each); the ceiling is %d",
			conns, got, float64(got)/(1<<20), float64(got)/conns/(1<<20), ceiling)
	}
}

// deadlineConn records the read deadlines a server sets on it.
type deadlineConn struct {
	net.Conn
	mu  sync.Mutex
	set []time.Time
}

func (d *deadlineConn) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.set = append(d.set, t)
	d.mu.Unlock()
	return d.Conn.SetReadDeadline(t)
}

func (d *deadlineConn) deadlines() []time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Time(nil), d.set...)
}

// ⛔ A server built as &Server{} -- which is how a caller who has not read
// about timeouts builds one -- must still put a deadline on every read. With
// none, a connection that sends nothing is held for ever, by anybody, before
// they have said who they are.
func TestAZeroValueServerStillSetsAReadDeadline(t *testing.T) {
	s := &Server{}
	t.Cleanup(func() { s.Close() })

	client, server := net.Pipe()
	defer client.Close()
	dc := &deadlineConn{Conn: server}
	start := time.Now()
	go s.serve(dc)

	// One byte, and its Write returns once the server is reading -- after
	// the deadline for that read was set.
	if _, err := client.Write([]byte{0x30}); err != nil {
		t.Fatal(err)
	}
	set := dc.deadlines()
	if len(set) == 0 {
		t.Fatal("a zero-value Server read a connection with no deadline at all")
	}
	if d := set[0]; d.IsZero() || !d.After(start) {
		t.Errorf("the first read deadline is %v, want a time after %v", d, start)
	}
}

// The slow sender itself: a connection that sends the start of a message and
// then nothing is closed once the idle timeout passes, with the same
// `unavailable` notice an idle connection between messages gets. The
// deadline covers the whole message, not only the wait for its first byte.
func TestAConnectionThatStopsMidMessageIsClosed(t *testing.T) {
	r := serve(t, &Server{Bind: reader(), IdleTimeout: 200 * time.Millisecond})
	c := dial(t, r)
	defer c.Close()

	if _, err := c.c.Write(headerClaiming(1 << 20)); err != nil {
		t.Fatal(err)
	}
	_ = c.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	res := resultOf(t, c.read(t))
	if res.Code != Unavailable {
		t.Errorf("a connection stalled mid-message was answered %s, want unavailable", res.Code)
	}
	if _, err := readFrame(c.r, DefaultMaxMessageSize); err == nil {
		t.Error("the connection stayed open after the notice")
	}
}

// The zero value is a timeout, not "never"; a negative value is how a caller
// asks for never; a positive value is taken as given.
func TestTheDefaultIdleTimeoutIsNotNever(t *testing.T) {
	if DefaultIdleTimeout <= 0 {
		t.Fatalf("DefaultIdleTimeout is %v", DefaultIdleTimeout)
	}
	for _, tc := range []struct {
		set, want time.Duration
	}{
		{0, DefaultIdleTimeout},
		{-1, 0},
		{time.Second, time.Second},
	} {
		if got := (&Server{IdleTimeout: tc.set}).idleTimeout(); got != tc.want {
			t.Errorf("IdleTimeout %v gives %v, want %v", tc.set, got, tc.want)
		}
	}
}

// And a server told "never" does exactly that: no deadline is set.
func TestANegativeIdleTimeoutSetsNoDeadline(t *testing.T) {
	s := &Server{IdleTimeout: -1}
	t.Cleanup(func() { s.Close() })

	client, server := net.Pipe()
	defer client.Close()
	dc := &deadlineConn{Conn: server}
	go s.serve(dc)
	if _, err := client.Write([]byte{0x30}); err != nil {
		t.Fatal(err)
	}
	if set := dc.deadlines(); len(set) != 0 {
		t.Errorf("IdleTimeout -1 set read deadlines %v", set)
	}
}
