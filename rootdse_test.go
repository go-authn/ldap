// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"context"
	"net"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

func rootServer(t *testing.T, s *Server) *running {
	t.Helper()
	if s.NamingContexts == nil {
		s.NamingContexts = []string{"dc=example,dc=org"}
	}
	s.Vendor, s.VendorVersion = "go-authn", "v0.1.0"
	return serve(t, s)
}

// readRoot asks the root DSE the way RFC 4512 5.1 says to.
func readRoot(t *testing.T, bin string, r *running, attrs ...string) string {
	t.Helper()
	args := append([]string{"-x", "-H", r.url(), "-b", "", "-s", "base", "(objectClass=*)"}, attrs...)
	out, _ := exec.Command(bin, args...).CombinedOutput()
	return string(out)
}

// ⛔ The root DSE is read BEFORE a bind, by design: it is where a client
// finds out which SASL mechanisms exist and whether StartTLS is offered. A
// server that required a bind to read it would require a client to
// authenticate before it could discover how to.
func TestTheRootDSEIsReadableBeforeAnyBind(t *testing.T) {
	bin := judge(t)
	r := rootServer(t, &Server{Bind: reader(), SASL: &twoStep{}, TLSConfig: selfSigned(t)})

	out := readRoot(t, bin, r, "+")
	for _, want := range []string{
		"supportedLDAPVersion: 3",
		"namingContexts: dc=example,dc=org",
		"supportedSASLMechanisms: TWOSTEP",
		"supportedExtension: " + OIDStartTLS,
		"supportedExtension: " + OIDWhoAmI,
		"vendorName: go-authn",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the root DSE does not carry %q:\n%s", want, out)
		}
	}
}

// ⛔ RFC 4512 5.1: root DSE attributes are OPERATIONAL and "are not returned
// in search requests unless requested by name". A bare query gets the user
// attributes only. A server that sends them all anyway hands a client the
// answer to a question it did not ask — and for supportedSASLMechanisms and
// namingContexts that is a list of ways in and a map of the tree.
func TestTheRootDSEOnlyGivesUpWhatWasAskedFor(t *testing.T) {
	bin := judge(t)
	r := rootServer(t, &Server{Bind: reader(), SASL: &twoStep{}})

	// Bare: objectClass is the one user attribute, and nothing else comes.
	bare := readRoot(t, bin, r)
	if !strings.Contains(bare, "objectClass:") {
		t.Errorf("a bare query did not return objectClass:\n%s", bare)
	}
	for _, leak := range []string{"supportedSASLMechanisms", "namingContexts", "vendorName"} {
		if strings.Contains(bare, leak) {
			t.Errorf("a bare query returned the operational attribute %s:\n%s", leak, bare)
		}
	}

	// "*" is the same: it means all USER attributes, not all attributes.
	if star := readRoot(t, bin, r, "*"); strings.Contains(star, "namingContexts") {
		t.Errorf("* returned an operational attribute:\n%s", star)
	}

	// By name: an operational attribute IS returned when it is named, and
	// only it.
	named := readRoot(t, bin, r, "namingContexts")
	if !strings.Contains(named, "namingContexts: dc=example,dc=org") {
		t.Errorf("asking for namingContexts by name did not return it:\n%s", named)
	}
	if strings.Contains(named, "supportedSASLMechanisms") {
		t.Errorf("asking for one attribute returned another:\n%s", named)
	}

	// "1.1" is nothing at all.
	if none := readRoot(t, bin, r, "1.1"); strings.Contains(none, "objectClass:") {
		t.Errorf("1.1 returned an attribute:\n%s", none)
	}
}

// ⛔ "The root DSE SHALL NOT be included if the client performs a subtree
// search starting from the root" (RFC 4512 5.1). A subtree search from ""
// reaches the handler like any other search, and this server's own entry
// must not be mixed into somebody's answer.
func TestASubtreeSearchFromTheRootDoesNotIncludeTheRootDSE(t *testing.T) {
	bin := judge(t)
	r := rootServer(t, &Server{Bind: reader(), Search: &directory{entries: people("alice")}})

	out, _ := exec.Command(bin, "-x", "-H", r.url(),
		"-D", "cn=reader,dc=example,dc=org", "-w", "let me read",
		"-b", "", "-s", "sub", "(objectClass=*)", "+", "*").CombinedOutput()
	if strings.Contains(string(out), "supportedLDAPVersion") {
		t.Errorf("a subtree search from the root returned the root DSE:\n%s", out)
	}
	if !strings.Contains(string(out), "uid: alice") {
		t.Errorf("a subtree search from the root did not reach the directory:\n%s", out)
	}
}

// ⛔ StartTLS is advertised only where it can still be used. On a connection
// already protected, a second one is an operationsError (RFC 4511 4.14.3),
// and advertising it there invites exactly that. RFC 4512 5.1 says these
// values "may depend on session-specific factors", which is why the entry is
// built per connection.
func TestStartTLSIsNotAdvertisedOnAConnectionThatAlreadyHasIt(t *testing.T) {
	r := rootServer(t, &Server{Bind: reader(), TLSConfig: selfSigned(t)})
	c := dial(t, r)
	defer c.Close()

	// Before: offered.
	if !strings.Contains(c.rootValues(t), OIDStartTLS) {
		t.Error("StartTLS is not advertised on a plaintext connection")
	}
	if code := c.startTLS(t); code != Success {
		t.Fatalf("StartTLS answered %s", code)
	}
	c.handshake(t)
	// After: not offered, on the SAME connection.
	if strings.Contains(c.rootValues(t), OIDStartTLS) {
		t.Error("StartTLS is still advertised on a connection that already has it")
	}
}

// A server offering no SASL advertises no mechanisms, rather than an empty
// attribute: a mechanism list that exists and is empty says something
// different from one that is absent.
func TestNoSASLMeansNoMechanismsAttribute(t *testing.T) {
	r := rootServer(t, &Server{Bind: reader()})
	c := dial(t, r)
	defer c.Close()
	if strings.Contains(c.rootValues(t), "supportedSASLMechanisms") {
		t.Error("a server with no SASL advertised the attribute")
	}
}

// The filter still applies to the root DSE: a client asking something with
// no answer gets none, rather than the entry regardless.
func TestTheFilterAppliesToTheRootDSEToo(t *testing.T) {
	r := rootServer(t, &Server{Bind: reader()})
	c := dial(t, r)
	defer c.Close()

	if dns, _ := c.searchBase(t, "", "(objectClass=*)", "+"); len(dns) != 1 {
		t.Errorf("(objectClass=*) returned %d entries, want the root DSE", len(dns))
	}
	if dns, _ := c.searchBase(t, "", "(objectClass=nothing)", "+"); len(dns) != 0 {
		t.Errorf("a filter with no answer returned %d entries", len(dns))
	}
}

// An altServer list is published when there is one.
func TestAltServersArePublished(t *testing.T) {
	r := rootServer(t, &Server{Bind: reader(), AltServers: []string{"ldap://other.example.org/"}})
	c := dial(t, r)
	defer c.Close()
	if !strings.Contains(c.rootValues(t), "ldap://other.example.org/") {
		t.Error("altServer is not published")
	}
	// And a server with none publishes no attribute at all.
	r2 := rootServer(t, &Server{Bind: reader()})
	c2 := dial(t, r2)
	defer c2.Close()
	if strings.Contains(c2.rootValues(t), "altServer") {
		t.Error("a server with no alternatives advertised the attribute")
	}
}

// An Extender's OIDs are advertised, so that a client can discover what it
// may ask for rather than guessing.
func TestAnExtendersOIDsAreAdvertised(t *testing.T) {
	r := rootServer(t, &Server{Bind: reader(), Extended: &extender{}})
	c := dial(t, r)
	defer c.Close()
	if !strings.Contains(c.rootValues(t), OIDPasswordModify) {
		t.Error("an Extender's OID is not advertised")
	}
}

// ⛔ And the root DSE is readable even on a listener that requires TLS --
// otherwise the only extension that offers TLS is hidden behind TLS, and a
// client would have to already know the answer to discover it.
func TestTheRootDSEIsReadableEvenWhenTLSIsRequired(t *testing.T) {
	r := rootServer(t, &Server{Bind: reader(), TLSConfig: selfSigned(t), RequireTLS: true})
	c := dial(t, r)
	defer c.Close()

	values := c.rootValues(t)
	if !strings.Contains(values, OIDStartTLS) {
		t.Errorf("a TLS-requiring listener hid StartTLS from discovery:\n%s", values)
	}
	// Everything else is still refused, which is what makes this an
	// exception rather than a hole.
	if code := c.bind(t, "cn=reader,dc=example,dc=org", "let me read"); code != ConfidentialityRequired {
		t.Errorf("a bind in the clear answered %s", code)
	}
	if _, res := c.searchBase(t, "dc=example,dc=org", "(uid=*)"); res.Code != ConfidentialityRequired {
		t.Errorf("a real search in the clear answered %s", res.Code)
	}
}

// ⛔ A root DSE read that cannot send its entry sends no searchResDone
// either. Half an answer is worse than none: a client that received a
// success after an entry it never got believes the directory published
// nothing, which is a different statement from "the connection broke".
//
// Driven directly rather than over a socket, because "the client left at
// exactly this moment" is not something a network test can arrange
// reliably -- and a test that only usually reaches the line it is about is
// not a test of that line.
func TestARootDSEReadThatCannotSendSendsNothingAtAll(t *testing.T) {
	left, right := net.Pipe()
	right.Close() // the far end is gone before anything is written
	s := &Server{NamingContexts: []string{"dc=example,dc=org"}}
	c := newConn(s, left)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := &SearchRequest{Scope: ScopeBaseObject, Filter: &Present{Attribute: "objectClass"}}

	done := make(chan struct{})
	go func() { c.searchRootDSE(ctx, &message{id: 1}, req); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the root DSE read blocked")
	}
	// It stopped at the entry, so the connection was never told the search
	// finished.
	if c.isClosed() {
		t.Log("the connection closed, which is also a way of not lying")
	}
}

// ⛔ The root DSE advertised neither supportedControl nor supportedFeatures
// while the server honoured three controls and implemented both features.
// For controls that is not a gap but a false statement: RFC 4512 5.1.3 says
// "if the server does not support any request controls, this attribute will
// be absent", so an absent attribute says there are none. Paged results
// shipped and no client reading the root DSE could find it.
//
// This test does NOT compare the advertisement against another list -- two
// lists agree until somebody edits one. It compares it against the SERVER'S
// BEHAVIOUR: everything advertised must survive being sent critically, and a
// control that is not advertised must be refused when it is.
func TestEveryAdvertisedControlIsOneTheServerHonours(t *testing.T) {
	r := serve(t, &Server{Bind: reader(), Search: &directory{entries: people("alice")}})
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")

	advertised := SupportedControls()
	if len(advertised) == 0 {
		t.Fatal("no controls advertised")
	}
	for _, oid := range advertised {
		// Critical, and the operation must NOT be refused for it.
		_, res := c.searchWith(t, "(uid=*)", &Control{Type: oid, Criticality: true})
		if res.Code == UnavailableCriticalExtension {
			t.Errorf("the root DSE advertises %s but a critical one is refused", oid)
		}
	}

	// The converse: a control this server does not advertise is refused when
	// critical. ManageDsaIT is named as a constant precisely because a client
	// may send it, and nothing here follows aliases or referrals.
	if slices.Contains(advertised, OIDManageDsaIT) {
		t.Fatal("ManageDsaIT is advertised, but nothing here honours it")
	}
	if _, res := c.searchWith(t, "(uid=*)", &Control{Type: OIDManageDsaIT, Criticality: true}); res.Code != UnavailableCriticalExtension {
		t.Errorf("an unadvertised critical control answered %s", res.Code)
	}
}

// And OpenLDAP's own client must be able to read both attributes back, since
// a client discovering capabilities is the entire reason they exist.
func TestTheJudgeReadsTheControlsAndFeatures(t *testing.T) {
	bin := judge(t)
	r := rootServer(t, &Server{Bind: reader()})

	got := readRoot(t, bin, r, "supportedControl", "supportedFeatures")
	for _, oid := range append(SupportedControls(),
		FeatureAllOperationalAttributes, FeatureAbsoluteFilters) {
		if !strings.Contains(got, oid) {
			t.Errorf("ldapsearch did not see %s in the root DSE:\n%s", oid, got)
		}
	}
}
