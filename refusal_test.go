// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Everything here is a packet a client can send. The library this replaces
// indexed Children[0] unguarded in several of these positions: a malformed
// request took the process down rather than being refused.

func app(tag ber.Tag, children ...*ber.Packet) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "op")
	for _, c := range children {
		p.AppendChild(c)
	}
	return p
}

func str(v string) *ber.Packet {
	return ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "s")
}

func num(v int64) *ber.Packet {
	return ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, v, "n")
}

func enum(v int64) *ber.Packet {
	return ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, v, "e")
}

func boolean(v bool) *ber.Packet {
	return ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, v, "b")
}

func seq(children ...*ber.Packet) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "seq")
	for _, c := range children {
		p.AppendChild(c)
	}
	return p
}

// send one request and read one result, whatever its shape.
func (c *client) raw(t *testing.T, op *ber.Packet) Result {
	t.Helper()
	id := c.next()
	c.write(t, id, op)
	return resultOf(t, c.read(t))
}

func everything(t *testing.T) (*running, *client) {
	t.Helper()
	w := &writes{}
	s := &Server{
		Bind: reader(), SASL: &twoStep{}, Search: &directory{},
		Add: w, Modify: w, Delete: w, ModifyDN: w, Compare: w,
	}
	r := serve(t, s)
	c := dial(t, r)
	t.Cleanup(c.Close)
	return r, c
}

func TestMalformedRequestsAreRefusedNotPanics(t *testing.T) {
	_, c := everything(t)

	simple := ber.NewString(ber.ClassContext, ber.TypePrimitive, tagAuthSimple, "pw", "simple")
	filter := ber.NewString(ber.ClassContext, ber.TypePrimitive, tagFilterPresent, "cn", "present")

	for _, tc := range []struct {
		what string
		op   *ber.Packet
	}{
		// Bind
		{"a bind with two fields", app(appBindRequest, num(3), str("cn=x"))},
		{"a bind whose version is a string", app(appBindRequest, str("three"), str("cn=x"), simple)},
		{"a bind at version 0", app(appBindRequest, num(0), str("cn=x"), simple)},
		{"a bind at version 200", app(appBindRequest, num(200), str("cn=x"), simple)},
		{"a bind at version 2", app(appBindRequest, num(2), str("cn=x"), simple)},
		{"a bind with an unknown auth choice", app(appBindRequest, num(3), str("cn=x"),
			ber.NewString(ber.ClassContext, ber.TypePrimitive, 9, "?", "weird"))},
		{"SASL credentials with no mechanism", app(appBindRequest, num(3), str(""),
			ber.Encode(ber.ClassContext, ber.TypeConstructed, tagAuthSASL, nil, "sasl"))},

		// Search
		{"a search with seven fields", app(appSearchRequest, str("dc=x"), enum(2), enum(0), num(0), num(0), boolean(false), filter)},
		{"a search with scope 9", app(appSearchRequest, str("dc=x"), enum(9), enum(0), num(0), num(0), boolean(false), filter, seq())},
		{"a search with derefAliases 9", app(appSearchRequest, str("dc=x"), enum(2), enum(9), num(0), num(0), boolean(false), filter, seq())},
		{"a search with a negative sizeLimit", app(appSearchRequest, str("dc=x"), enum(2), enum(0), num(-1), num(0), boolean(false), filter, seq())},
		{"a search with a negative timeLimit", app(appSearchRequest, str("dc=x"), enum(2), enum(0), num(0), num(-1), boolean(false), filter, seq())},
		{"a search whose typesOnly is a string", app(appSearchRequest, str("dc=x"), enum(2), enum(0), num(0), num(0), str("no"), filter, seq())},
		{"a search with a filter tag that is not one", app(appSearchRequest, str("dc=x"), enum(2), enum(0), num(0), num(0), boolean(false),
			ber.Encode(ber.ClassContext, ber.TypeConstructed, 15, nil, "?"), seq())},

		// Compare
		{"a compare with one field", app(appCompareRequest, str("uid=a"))},
		{"a compare whose assertion has one field", app(appCompareRequest, str("uid=a"), seq(str("cn")))},

		// Add
		{"an add with one field", app(appAddRequest, str("uid=a"))},
		{"an add whose attribute has no value set", app(appAddRequest, str("uid=a"), seq(seq(str("cn"))))},

		// Modify
		{"a modify with one field", app(appModifyRequest, str("uid=a"))},
		{"a modify whose change has no operation", app(appModifyRequest, str("uid=a"), seq(seq()))},
		{"a modify with operation 9", app(appModifyRequest, str("uid=a"), seq(seq(enum(9), seq(str("cn"), seq()))))},
		{"a modify whose change has no attribute", app(appModifyRequest, str("uid=a"), seq(seq(enum(0))))},
		{"a modify whose attribute has no value set", app(appModifyRequest, str("uid=a"), seq(seq(enum(0), seq(str("cn")))))},

		// ModifyDN
		{"a modifyDN with two fields", app(appModDNRequest, str("uid=a"), str("uid=b"))},
		{"a modifyDN with five fields", app(appModDNRequest, str("uid=a"), str("uid=b"), boolean(true), str("ou=x"), str("?"))},
		{"a modifyDN whose deleteoldrdn is a string", app(appModDNRequest, str("uid=a"), str("uid=b"), str("yes"))},

		// Extended
		{"an extended request with no name", app(appExtendedRequest)},
		{"an extended request with three fields", app(appExtendedRequest,
			ber.NewString(ber.ClassContext, ber.TypePrimitive, tagExtRequestName, OIDWhoAmI, "n"),
			ber.NewString(ber.ClassContext, ber.TypePrimitive, tagExtRequestValue, "v", "v"),
			str("?"))},
		{"an extended request whose first field is not its name", app(appExtendedRequest, str(OIDWhoAmI))},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s PANICKED: %v", tc.what, r)
				}
			}()
			res := c.raw(t, tc.op)
			if res.Code.OK() {
				t.Errorf("%s was accepted (%s)", tc.what, res.Code)
			}
		}()
	}
}

// An operation tag that is not in the protocol has no response type to send,
// so the connection ends with a notice saying why -- answering under a
// guessed type leaves a client waiting for a message that never comes.
func TestAnUnknownOperationEndsTheConnection(t *testing.T) {
	r := serve(t, &Server{Bind: reader()})
	c := dial(t, r)
	defer c.Close()

	c.write(t, 1, ber.Encode(ber.ClassApplication, ber.TypeConstructed, 21, nil, "?"))
	p := c.read(t)
	if id, _ := p.Children[0].Value.(int64); id != 0 {
		t.Errorf("the notice carries id %d, want 0", id)
	}
	if resultOf(t, p).Code != ProtocolError {
		t.Errorf("it says %s", resultOf(t, p).Code)
	}
	if responseFor(99) != 0 {
		t.Error("responseFor invented a response type for an unknown tag")
	}
}

// A server with no Binder refuses simple binds with authMethodNotSupported,
// and one with no SASLBinder refuses SASL the same way -- "not this way", not
// "wrong password".
func TestASeverWithNoBinderSaysNotThisWay(t *testing.T) {
	r := serve(t, &Server{Search: &directory{}})
	c := dial(t, r)
	defer c.Close()

	if code := c.bind(t, "cn=x", "pw"); code != AuthMethodNotSupported {
		t.Errorf("a simple bind answered %s", code)
	}
	if code, _, _ := c.bindSASL(t, "TWOSTEP", []byte("i am gwen")); code != AuthMethodNotSupported {
		t.Errorf("a SASL bind answered %s", code)
	}
}

// A handler that fails is `other` and nothing else, for binds as for
// everything else.
func TestAFailingBindHandlerTellsTheClientNothing(t *testing.T) {
	r := serve(t, &Server{Bind: failing{}, SASL: failingSASL{}})
	c := dial(t, r)
	defer c.Close()

	if code := c.bind(t, "cn=x", "pw"); code != Other {
		t.Errorf("a failing simple bind answered %s", code)
	}
	if code, _, _ := c.bindSASL(t, "X", nil); code != Other {
		t.Errorf("a failing SASL bind answered %s", code)
	}
}

type failing struct{}

func (failing) Bind(context.Context, Session, *BindRequest) (Result, error) {
	return Result{}, context.DeadlineExceeded
}

type failingSASL struct{}

func (failingSASL) Mechanisms() []string { return []string{"X"} }
func (failingSASL) BindSASL(context.Context, Session, *BindRequest) (SASLResult, error) {
	return SASLResult{}, context.DeadlineExceeded
}

// A Session answers what a handler asks it, including on a connection that
// was never protected.
func TestASessionAnswersTheHandler(t *testing.T) {
	seen := make(chan Session, 1)
	r := serve(t, &Server{Bind: reader(), Search: sessionSearcher{seen}})
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")
	// ⛔ NOT OIDPaging. This test is about Session.Controls() carrying what
	// arrived, and a real OID used as a placeholder stops being a
	// placeholder the day the server implements it -- which paging did,
	// turning this into a refused search and a test that blocked forever on
	// a handler that was never called.
	c.searchWith(t, "(uid=*)", &Control{Type: OIDPreRead, Value: []byte("page")})

	s := <-seen
	if s.RemoteAddr() == nil {
		t.Error("RemoteAddr is nil")
	}
	if _, ok := s.TLS(); ok {
		t.Error("a plaintext connection reported a TLS state")
	}
	if _, ok := s.Conn().(*net.TCPConn); !ok {
		t.Errorf("Conn is a %T", s.Conn())
	}
	ctls := s.Controls()
	if len(ctls) != 1 || ctls[0].Type != OIDPreRead || string(ctls[0].Value) != "page" {
		t.Errorf("the controls arrived as %+v", ctls)
	}
	if s.BoundDN() != "cn=reader,dc=example,dc=org" {
		t.Errorf("BoundDN is %q", s.BoundDN())
	}
}

type sessionSearcher struct{ seen chan Session }

func (s sessionSearcher) Search(_ context.Context, sess Session, _ *SearchRequest, _ EntryWriter) (Result, error) {
	s.seen <- sess
	return Result{Code: Success}, nil
}

// A continuation reference names somewhere, or it is not a reference
// (RFC 4511 4.5.3 SIZE (1..MAX)) -- one naming nowhere tells a client to ask
// and does not say whom.
func TestAReferenceMustNameSomewhere(t *testing.T) {
	r := serve(t, &Server{Bind: reader(), Search: referrer{}})
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")

	dns, res := c.search(t, "(uid=*)")
	if res.Code != Success {
		t.Errorf("answered %s", res.Code)
	}
	if len(dns) != 0 {
		t.Errorf("it returned entries: %v", dns)
	}
}

type referrer struct{}

func (referrer) Search(_ context.Context, _ Session, _ *SearchRequest, w EntryWriter) (Result, error) {
	if err := w.Reference(); err == nil {
		return Result{}, nil // an empty reference was accepted
	}
	if err := w.Reference("ldap://other.example.org/dc=example,dc=org"); err != nil {
		return Result{}, err
	}
	return Result{Code: Success}, nil
}

// ⛔ RFC 4511 4.14.1: StartTLS with operations outstanding is refused.
// Upgrading while one is in flight would hand its response to the handshake.
func TestStartTLSWithAnOperationInFlightIsRefused(t *testing.T) {
	release := make(chan struct{})
	slow := newBlocking(release)
	r := serve(t, &Server{Bind: reader(), Search: slow, TLSConfig: selfSigned(t)})
	c := dial(t, r)
	defer c.Close()
	defer close(release)

	c.write(t, 1, searchOp(t, "(uid=*)"))
	slow.started(t)
	if code := c.startTLS(t); code != OperationsError {
		t.Errorf("StartTLS with one operation in flight answered %s", code)
	}
}

// taggedInteger, on the shapes a client can send.
func TestTaggedIntegerReadsWhatBerLeftInData(t *testing.T) {
	primitive := func(b ...byte) *ber.Packet {
		p := ber.Encode(ber.ClassApplication, ber.TypePrimitive, appAbandonRequest, nil, "abandon")
		p.Data.Write(b)
		return p
	}
	for _, tc := range []struct {
		what string
		p    *ber.Packet
		want int64
		ok   bool
	}{
		{"one byte", primitive(7), 7, true},
		{"two bytes", primitive(0x01, 0x00), 256, true},
		{"negative", primitive(0xff), -1, true},
		{"empty", primitive(), 0, false},
		{"nine bytes", primitive(1, 2, 3, 4, 5, 6, 7, 8, 9), 0, false},
		{"already decoded", num(42), 42, true},
	} {
		got, ok := taggedInteger(tc.p)
		if ok != tc.ok {
			t.Errorf("%s: ok=%v, want %v", tc.what, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("%s: %d, want %d", tc.what, got, tc.want)
		}
	}
}

// An abandon naming nothing readable is dropped: there is no response to an
// abandon, so there is no way to report it (RFC 4511 4.11).
func TestAnUnreadableAbandonIsDropped(t *testing.T) {
	r := serve(t, &Server{Bind: reader(), Search: &directory{}})
	c := dial(t, r)
	defer c.Close()

	c.write(t, 1, ber.Encode(ber.ClassApplication, ber.TypePrimitive, appAbandonRequest, nil, "abandon"))
	// The connection must still work, which is how "dropped" is told apart
	// from "the server fell over".
	if code := c.bind(t, "cn=reader,dc=example,dc=org", "let me read"); code != Success {
		t.Errorf("the connection did not survive a malformed abandon: %s", code)
	}
}

// An idle connection is closed, and a busy one is not -- the deadline is per
// message, so a client sending steadily is not idle.
func TestAnIdleConnectionIsClosed(t *testing.T) {
	r := serve(t, &Server{Bind: reader(), Search: &directory{}, IdleTimeout: 200 * time.Millisecond})
	c := dial(t, r)
	defer c.Close()

	// Busy: three binds inside the window, none of them closed.
	for i := 0; i < 3; i++ {
		if code := c.bind(t, "cn=reader,dc=example,dc=org", "let me read"); code != Success {
			t.Fatalf("a busy connection was closed after %d binds", i)
		}
		time.Sleep(80 * time.Millisecond)
	}
	// Idle: nothing for longer than the window. The server says why before
	// it hangs up, and it must NOT say protocolError -- the client did
	// nothing wrong.
	_ = c.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	p := c.read(t)
	if id, _ := p.Children[0].Value.(int64); id != 0 {
		t.Errorf("the notice carries id %d, want 0", id)
	}
	res := resultOf(t, p)
	if res.Code != Unavailable {
		t.Errorf("an idle timeout said %s; the client did nothing wrong", res.Code)
	}
	if !strings.Contains(res.Diagnostic, "idle") {
		t.Errorf("the notice says %q", res.Diagnostic)
	}
	if _, err := readFrame(c.r, DefaultMaxMessageSize); err == nil {
		t.Error("the connection stayed open after the notice")
	}
}

// A search that exceeds the server's time limit says timeLimitExceeded, not
// `other`: the client asked a question that was too expensive, which is
// different from the directory being broken.
func TestATimeLimitSaysSo(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	slow := newBlocking(release)
	r := serve(t, &Server{Bind: reader(), Search: slow, Timeout: 150 * time.Millisecond})
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")

	_, res := c.search(t, "(uid=*)")
	if res.Code != TimeLimitExceeded {
		t.Errorf("a search past the time limit answered %s", res.Code)
	}
}

// A refusal from a Searcher reaches the client as the code the handler chose.
func TestASearcherMayRefuse(t *testing.T) {
	refusal := Refuse(InsufficientAccessRights, "only a reader may search")
	r := serve(t, &Server{Bind: reader(), Search: &directory{refuse: &refusal}})
	c := dial(t, r)
	defer c.Close()

	_, res := c.search(t, "(uid=*)")
	if res.Code != InsufficientAccessRights {
		t.Errorf("answered %s", res.Code)
	}
	if !strings.Contains(res.Diagnostic, "only a reader") {
		t.Errorf("the diagnostic is %q", res.Diagnostic)
	}
}
