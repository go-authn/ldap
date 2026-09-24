// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// ⛔ RFC 4532: whoami asks the CONNECTION what it thinks, which no handler
// holds. It is the cheapest way for an operator to find out that a bind did
// not do what they believed.
func TestWhoAmIAnswersTheConnectionsOwnState(t *testing.T) {
	r := serve(t, &Server{Bind: reader(), Search: &directory{}})
	c := dial(t, r)
	defer c.Close()

	// Anonymous is an EMPTY answer, not an absent one: the client asked and
	// was told "nobody", which is different from not being answered.
	who, code := c.whoami(t)
	if code != Success {
		t.Fatalf("whoami answered %s", code)
	}
	if who != "" {
		t.Errorf("an unbound connection said %q", who)
	}
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")
	if who, _ := c.whoami(t); who != "dn:cn=reader,dc=example,dc=org" {
		t.Errorf("after binding it said %q", who)
	}
	// And after a refused bind it is anonymous again.
	c.bind(t, "cn=reader,dc=example,dc=org", "wrong")
	if who, _ := c.whoami(t); who != "" {
		t.Errorf("after a REFUSED bind it said %q", who)
	}
}

// An extended operation nobody answers is a protocolError naming the OID, so
// an operator can see which one was asked for.
func TestAnUnknownExtendedOperationNamesItself(t *testing.T) {
	r := serve(t, &Server{Bind: reader()})
	c := dial(t, r)
	defer c.Close()

	id := c.next()
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appExtendedRequest, nil, "extendedReq")
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagExtRequestName, OIDPasswordModify, "requestName"))
	c.write(t, id, op)
	res := resultOf(t, c.read(t))
	if res.Code != ProtocolError {
		t.Errorf("answered %s", res.Code)
	}
	if !strings.Contains(res.Diagnostic, OIDPasswordModify) {
		t.Errorf("the refusal does not name the OID: %q", res.Diagnostic)
	}
}

// An Extender is asked for what it declares, and its errors are hidden the
// same way every other handler's are.
func TestAnExtenderIsReached(t *testing.T) {
	ext := &extender{}
	r := serve(t, &Server{Bind: reader(), Extended: ext})
	c := dial(t, r)
	defer c.Close()

	id := c.next()
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appExtendedRequest, nil, "extendedReq")
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagExtRequestName, OIDPasswordModify, "requestName"))
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagExtRequestValue, "hunter2", "requestValue"))
	c.write(t, id, op)
	if res := resultOf(t, c.read(t)); res.Code != Success {
		t.Fatalf("answered %s", res.Code)
	}
	if ext.seen == nil || string(ext.seen.Value) != "hunter2" {
		t.Errorf("the request arrived as %+v", ext.seen)
	}

	ext.err = context.DeadlineExceeded
	id = c.next()
	c.write(t, id, op)
	if res := resultOf(t, c.read(t)); res.Code != Other {
		t.Errorf("a failing extender answered %s, want other", res.Code)
	}
}

type extender struct {
	seen *ExtendedRequest
	err  error
}

func (e *extender) ExtendedNames() []string { return []string{OIDPasswordModify} }
func (e *extender) Extended(_ context.Context, _ Session, r *ExtendedRequest) (ExtendedResult, error) {
	e.seen = r
	if e.err != nil {
		return ExtendedResult{}, e.err
	}
	return ExtendedResult{Result: Result{Code: Success}, Name: r.Name}, nil
}

// ⛔ StartTLS happens in the READ goroutine. This connection has exactly one
// reader, so swapping the socket between messages races nothing -- which is
// the structural difference from the library this replaces, whose StartTLS
// read the socket while its reader goroutine was reading it too.
func TestStartTLSUpgradesAndTheConnectionKeepsWorking(t *testing.T) {
	cfg := selfSigned(t)
	s := &Server{Bind: reader(), Search: &directory{entries: people("alice")}, TLSConfig: cfg}
	r := serve(t, s)

	c := dial(t, r)
	defer c.Close()

	if code := c.startTLS(t); code != Success {
		t.Fatalf("StartTLS answered %s", code)
	}
	tc := tls.Client(c.c, &tls.Config{InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("the handshake failed: %v", err)
	}
	c.upgrade(tc)

	// The connection has to WORK afterwards; a handshake nothing is spoken
	// over proves less than it looks.
	if code := c.bind(t, "cn=reader,dc=example,dc=org", "let me read"); code != Success {
		t.Fatalf("the upgraded connection could not bind: %s", code)
	}
	dns, res := c.search(t, "(uid=alice)")
	if res.Code != Success || len(dns) != 1 {
		t.Errorf("the upgraded connection searched: %v %s", dns, res.Code)
	}

	// ⛔ A second StartTLS on a protected connection is an operationsError
	// (RFC 4511 4.14.3). Doing it anyway throws away the session already
	// carrying the conversation.
	if code := c.startTLS(t); code != OperationsError {
		t.Errorf("a second StartTLS answered %s", code)
	}
}

// A server with no certificate says so rather than failing the handshake.
func TestStartTLSWithNoCertificateIsRefusedInWords(t *testing.T) {
	r := serve(t, &Server{Bind: reader()})
	c := dial(t, r)
	defer c.Close()
	if code := c.startTLS(t); code != ProtocolError {
		t.Errorf("answered %s", code)
	}
}

// ⛔ RequireTLS refuses every operation on a connection that is not
// protected. It exists because StartTLS is asked for by the CLIENT: a server
// that merely offers it has promised nothing, and a client that does not ask
// sends its password in the clear while everything looks normal at both ends.
func TestRequireTLSRefusesEverythingInTheClear(t *testing.T) {
	cfg := selfSigned(t)
	r := serve(t, &Server{
		Bind: reader(), Search: &directory{entries: people("alice")},
		TLSConfig: cfg, RequireTLS: true,
	})
	c := dial(t, r)
	defer c.Close()

	// The RIGHT password, refused for the transport and not the credential.
	if code := c.bind(t, "cn=reader,dc=example,dc=org", "let me read"); code != ConfidentialityRequired {
		t.Errorf("a bind in the clear answered %s", code)
	}
	if _, res := c.search(t, "(uid=*)"); res.Code != ConfidentialityRequired {
		t.Errorf("a search in the clear answered %s", res.Code)
	}

	// After the upgrade the same bind works, which is what makes the refusal
	// about the transport rather than about the password.
	if code := c.startTLS(t); code != Success {
		t.Fatalf("StartTLS answered %s", code)
	}
	tc := tls.Client(c.c, &tls.Config{InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	c.upgrade(tc)
	if code := c.bind(t, "cn=reader,dc=example,dc=org", "let me read"); code != Success {
		t.Errorf("after StartTLS the bind answered %s", code)
	}
}

// ⛔ A critical control nobody handles means the operation MUST be refused
// (RFC 4511 4.1.11): the client has said this is not the operation it wants
// unless the control is honoured. Performing it anyway does something else
// and reports success.
func TestACriticalControlNobodyHandlesRefusesTheOperation(t *testing.T) {
	r := serve(t, &Server{Bind: reader(), Search: &directory{entries: people("alice")}})
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")

	// Critical: refused.
	if _, res := c.searchWith(t, "(uid=*)", &Control{Type: OIDManageDsaIT, Criticality: true}); res.Code != UnavailableCriticalExtension {
		t.Errorf("a critical unknown control answered %s", res.Code)
	}
	// NON-critical: ignored, which is what non-critical means.
	if dns, res := c.searchWith(t, "(uid=*)", &Control{Type: OIDManageDsaIT}); res.Code != Success || len(dns) != 1 {
		t.Errorf("a non-critical unknown control answered %s with %d entries", res.Code, len(dns))
	}
}

// ⛔ RFC 4511 4.1.1.1: a message id must not be reused while an operation
// with it is outstanding. One that is says two things about the same id, and
// an abandon could not name which.
func TestAMessageIdInFlightIsNotReused(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	slow := newBlocking(release)
	r := serve(t, &Server{Bind: reader(), Search: slow})
	c := dial(t, r)
	defer c.Close()
	defer once.Do(func() { close(release) })

	// Two searches with the SAME id, the first still running.
	op := searchOp(t, "(uid=*)")
	c.write(t, 42, op)
	slow.started(t)
	c.write(t, 42, op)

	res := resultOf(t, c.read(t))
	if res.Code != ProtocolError {
		t.Errorf("a reused message id answered %s", res.Code)
	}
	once.Do(func() { close(release) })
}

// ⛔ An abandoned operation gets NO response (RFC 4511 4.11). A searchResDone
// sent after an abandon arrives for an operation the client has forgotten.
func TestAnAbandonedSearchIsNotAnswered(t *testing.T) {
	release := make(chan struct{})
	slow := newBlocking(release)
	seen := make(chan int, 1)
	r := serve(t, &Server{
		Bind: reader(), Search: slow,
		Abandon: abandonFunc(func(_ context.Context, _ Session, id int) { seen <- id }),
	})
	c := dial(t, r)
	defer c.Close()
	defer close(release)

	c.write(t, 7, searchOp(t, "(uid=*)"))
	slow.started(t)
	// The abandon itself has no response, ever.
	c.write(t, 8, ber.NewInteger(ber.ClassApplication, ber.TypePrimitive, appAbandonRequest, int64(7), "abandonRequest"))

	select {
	case id := <-seen:
		if id != 7 {
			t.Errorf("the abandon named %d", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the abandon never reached the handler")
	}

	// The search's context must be cancelled, and nothing must be sent.
	select {
	case <-slow.cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the abandoned search was not cancelled")
	}
	_ = c.c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := readFrame(c.r, DefaultMaxMessageSize); err == nil {
		t.Error("something was sent in answer to an abandoned operation")
	}
}

type abandonFunc func(context.Context, Session, int)

func (f abandonFunc) Abandon(ctx context.Context, s Session, id int) { f(ctx, s, id) }

type blockingSearcher struct {
	release   chan struct{}
	begin     chan struct{}
	cancelled chan struct{}
}

func newBlocking(release chan struct{}) *blockingSearcher {
	return &blockingSearcher{
		release:   release,
		begin:     make(chan struct{}, 1),
		cancelled: make(chan struct{}, 1),
	}
}

func (b *blockingSearcher) started(t *testing.T) {
	t.Helper()
	select {
	case <-b.begin:
	case <-time.After(5 * time.Second):
		t.Fatal("the search never started")
	}
}

func (b *blockingSearcher) Search(ctx context.Context, _ Session, _ *SearchRequest, _ EntryWriter) (Result, error) {
	select {
	case b.begin <- struct{}{}:
	default:
	}
	select {
	case <-b.release:
		return Result{Code: Success}, nil
	case <-ctx.Done():
		select {
		case b.cancelled <- struct{}{}:
		default:
		}
		return Result{}, ctx.Err()
	}
}

// A malformed message has no id to answer under, so RFC 4511 leaves one
// thing to do: a notice of disconnection, and hang up. Answering under a
// guessed id would attach the error to somebody else's operation.
func TestAMalformedMessageEndsTheConnectionWithANotice(t *testing.T) {
	r := serve(t, &Server{Bind: reader()})
	c := dial(t, r)
	defer c.Close()

	// A well-framed SEQUENCE whose message id is zero -- reserved for the
	// server's own notification.
	m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "messageID"))
	m.AppendChild(ber.Encode(ber.ClassApplication, ber.TypePrimitive, appUnbindRequest, nil, "unbindRequest"))
	if _, err := c.c.Write(m.Bytes()); err != nil {
		t.Fatal(err)
	}

	p := c.read(t)
	id, _ := p.Children[0].Value.(int64)
	if id != 0 {
		t.Errorf("the notice carries message id %d, want 0", id)
	}
	if p.Children[1].Tag != appExtendedResponse {
		t.Errorf("the notice is a %d, want an extendedResponse", p.Children[1].Tag)
	}
	if resultOf(t, p).Code != ProtocolError {
		t.Errorf("the notice says %s", resultOf(t, p).Code)
	}
}

// An unbind gets no response and ends the connection.
func TestUnbindEndsTheConnectionSilently(t *testing.T) {
	r := serve(t, &Server{Bind: reader()})
	c := dial(t, r)
	defer c.Close()

	c.write(t, 1, ber.Encode(ber.ClassApplication, ber.TypePrimitive, appUnbindRequest, nil, "unbindRequest"))
	_ = c.c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := readFrame(c.r, DefaultMaxMessageSize); err == nil {
		t.Error("an unbind was answered")
	}
}

// ⛔ Close closes the CONNECTIONS, not only the listeners. A server that
// stopped accepting and left the established ones answering looks stopped
// and is not, which is the shape of a restart that does not take.
func TestCloseEndsEstablishedConnectionsToo(t *testing.T) {
	s := &Server{Bind: reader(), Search: &directory{}}
	r := serve(t, s)
	c := dial(t, r)
	defer c.Close()
	if code := c.bind(t, "cn=reader,dc=example,dc=org", "let me read"); code != Success {
		t.Fatal("the control failed: the connection did not work before Close")
	}

	s.Close()
	_ = c.c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := readFrame(c.r, DefaultMaxMessageSize); err == nil {
		t.Error("an established connection survived Close")
	}
	// And Serve on a closed server refuses rather than listening again.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := s.Serve(ln); err == nil {
		t.Error("a closed server accepted a new listener")
	}
}

func TestListenAndServeUsesTheAddressItWasGiven(t *testing.T) {
	s := &Server{Bind: reader()}
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe("127.0.0.1:0") }()
	// It cannot be dialled -- port 0 means the kernel chose one nobody was
	// told -- so this asserts only that it starts and stops cleanly.
	time.Sleep(50 * time.Millisecond)
	s.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ListenAndServe: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("ListenAndServe did not stop")
	}
	if err := s.ListenAndServe("127.0.0.1:1"); err == nil {
		t.Error("a privileged port was listened on")
	}
}

func selfSigned(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}
