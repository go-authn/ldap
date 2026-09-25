// SPDX-License-Identifier: BSD-3-Clause

package ldaptest_test

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
	"testing"
	"time"

	"github.com/go-authn/ldap"
	"github.com/go-authn/ldap/ldaptest"
)

// A server just complete enough to answer everything this client can ask.
type fixture struct{ entries []*ldap.Entry }

func (f *fixture) Bind(_ context.Context, _ ldap.Session, req *ldap.BindRequest) (ldap.Result, error) {
	if req.Name == "" && len(req.Simple) == 0 {
		return ldap.Result{Code: ldap.Success}, nil // anonymous
	}
	if req.Name == "cn=reader" && string(req.Simple) == "let me read" {
		return ldap.Result{Code: ldap.Success}, nil
	}
	return ldap.Result{Code: ldap.InvalidCredentials}, nil
}

func (f *fixture) Search(_ context.Context, _ ldap.Session, req *ldap.SearchRequest, w ldap.EntryWriter) (ldap.Result, error) {
	for _, e := range f.entries {
		if ldap.InScope(e.DN, req.BaseObject, req.Scope) && req.Filter.Matches(e) {
			if err := w.Entry(e); err != nil {
				return ldap.Result{}, err
			}
		}
	}
	return ldap.Result{Code: ldap.Success}, nil
}

func (f *fixture) Mechanisms() []string { return []string{"ECHO"} }

func (f *fixture) BindSASL(_ context.Context, _ ldap.Session, req *ldap.BindRequest) (ldap.SASLResult, error) {
	switch {
	case req.SASL.Credentials == nil:
		return ldap.SASLResult{
			Result:      ldap.Result{Code: ldap.SaslBindInProgress},
			ServerCreds: []byte("who are you"),
		}, nil
	case string(req.SASL.Credentials) == "gwen":
		return ldap.SASLResult{
			Result:      ldap.Result{Code: ldap.Success},
			BoundDN:     "uid=gwen,dc=example,dc=org",
			ServerCreds: []byte{},
		}, nil
	}
	return ldap.SASLResult{Result: ldap.Result{Code: ldap.InvalidCredentials}}, nil
}

func (f *fixture) ExtendedNames() []string { return []string{"1.2.3.4"} }

func (f *fixture) Extended(_ context.Context, _ ldap.Session, req *ldap.ExtendedRequest) (ldap.ExtendedResult, error) {
	return ldap.ExtendedResult{Result: ldap.Result{Code: ldap.Success}, Name: req.Name, Value: req.Value}, nil
}

func serve(t *testing.T, s *ldap.Server) *ldaptest.Client {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { s.Close() })

	c, err := ldaptest.Dial(ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// ⛔ A deadline on every exchange, so that a server which stops
	// answering FAILS rather than hangs. A test that hangs is one somebody
	// cancels and reruns, and a flake that is cancelled is never diagnosed.
	if err := c.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func entries() []*ldap.Entry {
	return []*ldap.Entry{
		// ⛔ objectClass is here because the default filter is
		// (objectClass=*), and an entry without it matches nothing. Leaving
		// it off made two searches return zero entries and look like a
		// server defect: the fixture was the thing that was wrong.
		{DN: "uid=alice,dc=example,dc=org", Attributes: []*ldap.Attribute{
			ldap.StringAttribute("objectClass", "top", "person"),
			ldap.StringAttribute("uid", "alice"),
			ldap.StringAttribute("cn", "Alice"),
		}},
		{DN: "uid=bob,dc=example,dc=org", Attributes: []*ldap.Attribute{
			ldap.StringAttribute("objectClass", "top", "person"),
			ldap.StringAttribute("uid", "bob"),
		}},
	}
}

func TestTheClientDrivesEveryOperationItOffers(t *testing.T) {
	f := &fixture{entries: entries()}
	c := serve(t, &ldap.Server{
		Bind: f, Search: f, SASL: f, Extended: f,
		NamingContexts: []string{"dc=example,dc=org"},
	})

	// Bind: the anonymous one, the right password, and the wrong one.
	if res, err := c.Bind("", ""); err != nil || res.Code != ldap.Success {
		t.Fatalf("the anonymous bind answered %s (%v)", res.Code, err)
	}
	if res, _ := c.Bind("cn=reader", "wrong"); res.Code != ldap.InvalidCredentials {
		t.Errorf("a wrong password answered %s", res.Code)
	}
	if res, err := c.Bind("cn=reader", "let me read"); err != nil || res.Code != ldap.Success {
		t.Fatalf("the reader could not bind: %s (%v)", res.Code, err)
	}

	// Search, and the shape of what came back.
	got, err := c.Search(ldaptest.Search{
		Base: "dc=example,dc=org", Scope: ldap.ScopeWholeSubtree, Filter: "(uid=*)",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := got.Result; res.Code != ldap.Success {
		t.Errorf("the search answered %s", res.Code)
	}
	if dns := got.DNs(); len(dns) != 2 || !strings.Contains(dns[0], "alice") {
		t.Errorf("the search returned %v", dns)
	}
	if vals := got.Values(); len(vals) != 7 {
		t.Errorf("the values came back as %v", vals)
	}

	// The size limit stops it, and what arrived STANDS.
	small, err := c.Search(ldaptest.Search{
		Base: "dc=example,dc=org", Scope: ldap.ScopeWholeSubtree, SizeLimit: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(small.Entries) != 1 || small.Result.Code != ldap.SizeLimitExceeded {
		t.Errorf("a size limit of 1 gave %d entries and %s", len(small.Entries), small.Result.Code)
	}

	// The root DSE, which is the zero Search.
	root, err := c.Search(ldaptest.Search{Attrs: []string{"+"}})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(root.Values(), "namingContexts: dc=example,dc=org") {
		t.Errorf("the root DSE came back as %v", root.Values())
	}
	if !contains(root.Values(), "supportedSASLMechanisms: ECHO") {
		t.Error("the mechanism the fixture offers is not advertised")
	}

	// WhoAmI reports the connection's own state.
	who, res, err := c.WhoAmI()
	if err != nil || res.Code != ldap.Success {
		t.Fatalf("whoami answered %s (%v)", res.Code, err)
	}
	if who != "dn:cn=reader" {
		t.Errorf("whoami said %q", who)
	}

	// An extended operation, there and back.
	if res, err := c.Extended("1.2.3.4", []byte("x")); err != nil || res.Code != ldap.Success {
		t.Errorf("the extended operation answered %s (%v)", res.Code, err)
	}
}

// ⛔ The reason this package exists: a SASL bind with an arbitrary
// mechanism, and the distinction between an ABSENT serverSaslCreds and an
// EMPTY one. go-ldap/ldap/v3 offers no way to send the first and ldapsearch
// no way to observe the second.
func TestASASLExchangeInBothOfItsSteps(t *testing.T) {
	f := &fixture{}
	c := serve(t, &ldap.Server{Bind: f, Search: f, SASL: f})

	// No credentials at all: a challenge, not a refusal.
	step, err := c.BindSASL("ECHO", nil)
	if err != nil {
		t.Fatal(err)
	}
	if step.Code != ldap.SaslBindInProgress {
		t.Fatalf("step one answered %s", step.Code)
	}
	if !step.Present || string(step.ServerCreds) != "who are you" {
		t.Errorf("the challenge came back as %q (present=%v)", step.ServerCreds, step.Present)
	}

	// The answer: success, with an EMPTY serverSaslCreds that is present.
	step, err = c.BindSASL("ECHO", []byte("gwen"))
	if err != nil {
		t.Fatal(err)
	}
	if step.Code != ldap.Success {
		t.Fatalf("step two answered %s", step.Code)
	}
	if !step.Present {
		t.Error("an empty serverSaslCreds came back as ABSENT, which is a different message")
	}
	if len(step.ServerCreds) != 0 {
		t.Errorf("serverSaslCreds came back as %q", step.ServerCreds)
	}

	// And the connection is bound as the DN the MECHANISM chose, which the
	// client never sent.
	who, _, err := c.WhoAmI()
	if err != nil {
		t.Fatal(err)
	}
	if who != "dn:uid=gwen,dc=example,dc=org" {
		t.Errorf("the connection is bound as %q", who)
	}
}

// StartTLS, and more LDAP on the same connection afterwards -- a handshake
// that is never spoken over proves less than it looks.
func TestStartTLSAndThenMoreLDAP(t *testing.T) {
	f := &fixture{entries: entries()}
	c := serve(t, &ldap.Server{Bind: f, Search: f, TLSConfig: selfSigned(t)})

	res, err := c.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil || res.Code != ldap.Success {
		t.Fatalf("StartTLS answered %s (%v)", res.Code, err)
	}
	if res, err := c.Bind("cn=reader", "let me read"); err != nil || res.Code != ldap.Success {
		t.Fatalf("the upgraded connection could not bind: %s (%v)", res.Code, err)
	}
	got, err := c.Search(ldaptest.Search{Base: "dc=example,dc=org", Scope: ldap.ScopeWholeSubtree})
	if err != nil || len(got.Entries) != 2 {
		t.Errorf("the upgraded connection searched: %d entries (%v)", len(got.Entries), err)
	}

	// A server with no certificate refuses in words, and the client does not
	// then try to handshake with nothing.
	bare := serve(t, &ldap.Server{Bind: f})
	if res, err := bare.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Errorf("a refusal came back as an error: %v", err)
	} else if res.Code == ldap.Success {
		t.Error("a server with no certificate offered StartTLS")
	}
}

// A control reaches the server, criticality and all.
func TestControlsAreSent(t *testing.T) {
	f := &fixture{entries: entries()}
	c := serve(t, &ldap.Server{Bind: f, Search: f})
	c.Bind("cn=reader", "let me read")

	got, err := c.Search(ldaptest.Search{
		Base: "dc=example,dc=org", Scope: ldap.ScopeWholeSubtree,
		Controls: []ldap.Control{{Type: ldap.OIDManageDsaIT, Criticality: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Nothing here handles it, so it must be REFUSED rather than ignored.
	if got.Result.Code != ldap.UnavailableCriticalExtension {
		t.Errorf("a critical control nobody handles answered %s", got.Result.Code)
	}
	// Non-critical: ignored, which is what non-critical means.
	ok, err := c.Search(ldaptest.Search{
		Base: "dc=example,dc=org", Scope: ldap.ScopeWholeSubtree,
		Controls: []ldap.Control{{Type: ldap.OIDPaging, Value: []byte("x")}},
	})
	if err != nil || ok.Result.Code != ldap.Success {
		t.Errorf("a non-critical control answered %s (%v)", ok.Result.Code, err)
	}
}

// The failures a caller has to be able to tell apart.
func TestWhatTheClientRefuses(t *testing.T) {
	f := &fixture{}
	c := serve(t, &ldap.Server{Bind: f, Search: f})

	if _, err := c.Search(ldaptest.Search{Filter: "(not a filter"}); err == nil {
		t.Error("a filter that does not parse was sent")
	}
	if _, err := ldaptest.Dial("127.0.0.1:1", 500*time.Millisecond); err == nil {
		t.Error("a dial to a closed port succeeded")
	}
	// After the connection is closed, every operation reports it rather than
	// blocking.
	c.Close()
	if _, err := c.Bind("cn=reader", "let me read"); err == nil {
		t.Error("a bind on a closed connection succeeded")
	}
	if _, err := c.Read(); err == nil {
		t.Error("a read on a closed connection succeeded")
	}
	if c.Conn() == nil {
		t.Error("Conn is nil")
	}
	if _, _, err := c.WhoAmI(); err == nil {
		t.Error("whoami on a closed connection succeeded")
	}
	if _, err := c.Extended("1.2.3.4", nil); err == nil {
		t.Error("an extended operation on a closed connection succeeded")
	}
	if _, err := c.BindSASL("ECHO", nil); err == nil {
		t.Error("a SASL bind on a closed connection succeeded")
	}
	if _, err := c.StartTLS(nil); err == nil {
		t.Error("StartTLS on a closed connection succeeded")
	}
	if err := c.SetDeadline(time.Now()); err == nil {
		t.Error("a deadline on a closed connection was set")
	}
}

func contains(all []string, want string) bool {
	for _, s := range all {
		if s == want {
			return true
		}
	}
	return false
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
