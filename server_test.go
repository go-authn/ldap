// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"strings"
	"testing"
)

// The whole thing, end to end, judged by OpenLDAP: bind, search, and the
// filter that started this project.
func TestOpenLDAPReadsThisServer(t *testing.T) {
	bin := judge(t)
	dir := &directory{entries: people("svc-web-prod", "svc-web-stage", "svc-db-prod", "app-web-prod", "svc-prod")}
	r := serve(t, &Server{Bind: reader(), Search: dir})

	for _, tc := range []struct {
		filter string
		want   []string
	}{
		// ⛔ The one the fork got wrong. It evaluated this as (uid=svc-*)
		// and returned svc-web-stage.
		{"(uid=svc-*-prod)", []string{"svc-db-prod", "svc-web-prod"}},
		{"(uid=svc-*)", []string{"svc-db-prod", "svc-prod", "svc-web-prod", "svc-web-stage"}},
		{"(uid=*-prod)", []string{"app-web-prod", "svc-db-prod", "svc-prod", "svc-web-prod"}},
		{"(uid=*web*)", []string{"app-web-prod", "svc-web-prod", "svc-web-stage"}},
		{"(objectClass=posixAccount)", []string{"app-web-prod", "svc-db-prod", "svc-prod", "svc-web-prod", "svc-web-stage"}},
		{"(&(uid=svc-*)(uid=*-prod))", []string{"svc-db-prod", "svc-prod", "svc-web-prod"}},
		{"(|(uid=svc-prod)(uid=app-web-prod))", []string{"app-web-prod", "svc-prod"}},
		{"(!(uid=svc-*))", []string{"app-web-prod"}},
		{"(uid=nobody)", nil},
	} {
		got, out := r.ask(t, bin, nil, tc.filter)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s\n  returned %v\n  want     %v\n%s", tc.filter, got, tc.want, out)
		}
	}
}

// ⛔ RFC 4511 4.2.1: a failed bind leaves the connection anonymous.
//
// The library this replaces kept the PREVIOUS bind's authorisation, so on a
// pooled connection -- which is how every LDAP client library is used -- the
// person whose password was refused was served as the last person who
// succeeded. Proving it needs ONE connection carrying two binds and a
// search, which is why this drives the wire directly rather than running
// ldapsearch twice: two ldapsearch runs are two connections, and the bug
// only exists on one.
func TestARefusedBindLeavesTheConnectionAnonymous(t *testing.T) {
	var seen []string
	dir := &directory{entries: people("alice")}
	dir.onSearch = func(*SearchRequest) {}
	s := &Server{Bind: reader(), Search: dir}
	// The Searcher records who the server thought it was talking to.
	s.Search = &recordingSearcher{inner: dir, seen: &seen}
	r := serve(t, s)

	c := dial(t, r)
	defer c.Close()

	// 1. A bind that succeeds, and a search, as the control: without it this
	// test would pass against a server that never bound anybody.
	if code := c.bind(t, "cn=reader,dc=example,dc=org", "let me read"); code != Success {
		t.Fatalf("the reader could not bind: %s", code)
	}
	c.search(t, "(uid=*)")
	if len(seen) != 1 || seen[0] != "cn=reader,dc=example,dc=org" {
		t.Fatalf("the control failed: the server searched as %v", seen)
	}

	// 2. A refused bind on the SAME connection.
	if code := c.bind(t, "uid=alice,ou=people,dc=example,dc=org", "wrong"); code != InvalidCredentials {
		t.Fatalf("a wrong password answered %s", code)
	}

	// 3. The connection must now be anonymous.
	c.search(t, "(uid=*)")
	if len(seen) != 2 {
		t.Fatalf("the second search did not reach the handler: %v", seen)
	}
	if seen[1] != "" {
		t.Errorf("after a REFUSED bind the server searched as %q; it must be anonymous", seen[1])
	}
}

// ⛔ And a bind still IN PROGRESS is not a bind that succeeded. A SASL
// exchange that stopped half way must leave the connection anonymous too,
// which is the case a check written only for "failed" would miss.
func TestASASLBindInProgressIsNotAuthorisation(t *testing.T) {
	var seen []string
	dir := &directory{entries: people("alice")}
	s := &Server{
		Bind:   reader(),
		SASL:   &twoStep{},
		Search: &recordingSearcher{inner: dir, seen: &seen},
	}
	r := serve(t, s)
	c := dial(t, r)
	defer c.Close()

	// Prove somebody first, so "anonymous" afterwards is a CHANGE and not
	// the state this connection started in.
	// ⛔ An EMPTY serverSaslCreds is present, not absent: RFC 4511 4.2.2
	// gives a zero-length OCTET STRING and a missing field different
	// meanings, and a mechanism that says "nothing more to add" is not the
	// same as one that says nothing.
	code, creds, present := c.bindSASL(t, "TWOSTEP", []byte("i am gwen"))
	if code != Success {
		t.Fatalf("the SASL bind answered %s", code)
	}
	if !present {
		t.Error("an empty serverSaslCreds came back as absent")
	}
	if len(creds) != 0 {
		t.Errorf("serverSaslCreds came back as %q", creds)
	}
	c.search(t, "(uid=*)")
	if len(seen) != 1 || seen[0] != "uid=gwen,dc=example,dc=org" {
		t.Fatalf("the control failed: bound as %v", seen)
	}

	// Now start an exchange and stop half way.
	if code, creds, _ := c.bindSASL(t, "TWOSTEP", nil); code != SaslBindInProgress {
		t.Fatalf("expected a challenge, got %s", code)
	} else if string(creds) != "who are you" {
		t.Errorf("the challenge came back as %q", creds)
	}
	c.search(t, "(uid=*)")
	if len(seen) != 2 {
		t.Fatalf("the second search did not reach the handler")
	}
	if seen[1] != "" {
		t.Errorf("a bind still in progress left the connection bound as %q", seen[1])
	}
}

// The scope rule, judged by ldapsearch: base, one and sub are three
// different questions (RFC 4511 4.5.1.2).
//
// ⛔ singleLevel is the IMMEDIATE subordinates of the base -- the base itself
// is not in it, and neither is anything two levels down. The tree here has a
// row at each depth on purpose, because a scope test whose entries are all at
// one depth cannot tell "one" from "sub".
func TestScopeIsObeyed(t *testing.T) {
	bin := judge(t)
	dir := &directory{entries: append(
		people("alice", "bob"), // uid=…,ou=people,dc=example,dc=org  (two down)
		&Entry{DN: "dc=example,dc=org", Attributes: []*Attribute{StringAttribute("uid", "root")}},
		&Entry{DN: "ou=people,dc=example,dc=org", Attributes: []*Attribute{StringAttribute("uid", "people")}},
	)}
	r := serve(t, &Server{Bind: reader(), Search: dir})

	for _, tc := range []struct {
		scope string
		want  []string
	}{
		{"base", []string{"root"}},
		{"one", []string{"people"}},
		{"sub", []string{"alice", "bob", "people", "root"}},
	} {
		got, out := r.ask(t, bin, []string{"-s", tc.scope}, "(uid=*)")
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("scope %s returned %v, want %v\n%s", tc.scope, got, tc.want, out)
		}
	}
}

// ⛔ RFC 4511 4.5.1.8: an empty attribute list means all USER attributes,
// "1.1" means NONE. Projecting in the server rather than in each handler is
// what stops a handler that forgets from returning more than was asked for
// -- and "more" out of a directory is the attribute somebody deliberately
// did not request.
func TestTheAttributeSelectionIsObeyed(t *testing.T) {
	bin := judge(t)
	r := serve(t, &Server{Bind: reader(), Search: &directory{entries: people("alice")}})

	// Asking for uid alone must not bring cn.
	_, out := r.ask(t, bin, nil, "(uid=alice)")
	if strings.Contains(out, "cn: alice") {
		t.Errorf("asking for uid returned cn as well:\n%s", out)
	}
	if !strings.Contains(out, "uid: alice") {
		t.Errorf("asking for uid did not return it:\n%s", out)
	}

	// "1.1" must bring the DN and nothing else.
	out2, _ := runSearch(t, bin, r, "(uid=alice)", "1.1")
	if strings.Contains(out2, "uid: alice") || strings.Contains(out2, "cn: alice") {
		t.Errorf("1.1 returned attributes:\n%s", out2)
	}
	if !strings.Contains(out2, "dn: uid=alice") {
		t.Errorf("1.1 did not return the DN:\n%s", out2)
	}

	// "*" must bring everything.
	out3, _ := runSearch(t, bin, r, "(uid=alice)", "*")
	if !strings.Contains(out3, "cn: alice") || !strings.Contains(out3, "objectClass: person") {
		t.Errorf("* did not return everything:\n%s", out3)
	}
}

// ⛔ The size limit: the entries already sent STAND and the result says the
// limit was reached (RFC 4511 4.5.2). It is not an error and not an empty
// answer -- a client that asked for two and got two has what it asked for.
func TestTheSizeLimitKeepsWhatItSent(t *testing.T) {
	bin := judge(t)
	r := serve(t, &Server{Bind: reader(), Search: &directory{entries: people("a", "b", "c", "d", "e")}})

	got, out := r.ask(t, bin, []string{"-z", "2"}, "(uid=*)")
	if len(got) != 2 {
		t.Errorf("a size limit of 2 returned %d entries\n%s", len(got), out)
	}
	if !strings.Contains(out, "Size limit exceeded") {
		t.Errorf("the result did not say the limit was reached:\n%s", out)
	}

	// ⛔ And the SERVER's limit is not raised by a client asking for more.
	r2 := serve(t, &Server{Bind: reader(), MaxEntries: 1, Search: &directory{entries: people("a", "b", "c")}})
	got2, out2 := r2.ask(t, bin, []string{"-z", "100"}, "(uid=*)")
	if len(got2) != 1 {
		t.Errorf("a client asking for 100 got %d against a server limit of 1\n%s", len(got2), out2)
	}
}

// A filter naming a matching rule this server does not implement is refused
// with inappropriateMatching, not answered with the entries that happen to
// match the rest -- answering a narrower question quietly is
// indistinguishable from the answer being right.
func TestAnUnimplementedMatchingRuleIsRefused(t *testing.T) {
	bin := judge(t)
	r := serve(t, &Server{Bind: reader(), Search: &directory{entries: people("alice")}})

	got, out := r.ask(t, bin, nil, "(memberOf:1.2.840.113556.1.4.1941:=cn=admins,dc=example,dc=org)")
	if len(got) != 0 {
		t.Errorf("it returned %v", got)
	}
	if !strings.Contains(out, "Inappropriate matching") {
		t.Errorf("the refusal was not inappropriateMatching:\n%s", out)
	}
}

// ⛔ RFC 4513 has two empty-password cases, one field apart.
//
//   - 5.1.1 ANONYMOUS, name "" and password "": legitimate, and what every
//     client sends before it has discovered anything.
//   - 5.1.2 UNAUTHENTICATED, a NAME with an empty password: refused. A
//     server that passes it through as proof lets anybody in as anybody,
//     and the client cannot tell it from a real success.
//
// Both directions are asserted, because getting it wrong one way locks out
// every anonymous client -- including from the root DSE it needs in order to
// discover the server at all -- and the other way opens the directory. The
// first is how these tests failed: ldapsearch's own anonymous bind was
// refused, and the root DSE tests reported nothing at all.
func TestTheTwoEmptyPasswordBinds(t *testing.T) {
	bin := judge(t)
	r := serve(t, &Server{Bind: reader(), Search: &directory{entries: people("alice")}})

	named, _ := runBind(t, bin, r, "cn=reader,dc=example,dc=org", "")
	if !strings.Contains(named, "Invalid credentials") {
		t.Errorf("a NAME with an empty password was not refused:\n%s", named)
	}
	anonymous, _ := runBind(t, bin, r, "", "")
	if strings.Contains(anonymous, "Invalid credentials") {
		t.Errorf("an anonymous bind was refused:\n%s", anonymous)
	}
}

// An operation with no handler is unwillingToPerform, not
// insufficientAccessRights: "I do not do that" and "you may not do that"
// send an administrator to two different places.
func TestAnOperationWithNoHandlerSaysSoRatherThanRefusingAccess(t *testing.T) {
	bin := judge(t)
	r := serve(t, &Server{Bind: reader()}) // no Search

	_, out := r.ask(t, bin, nil, "(uid=*)")
	if !strings.Contains(out, "Server is unwilling to perform") {
		t.Errorf("a server with no Searcher answered:\n%s", out)
	}
}

func runSearch(t *testing.T, bin string, r *running, filter, attr string) (string, error) {
	t.Helper()
	return run(t, bin, "-x", "-H", r.url(),
		"-D", "cn=reader,dc=example,dc=org", "-w", "let me read",
		"-b", "dc=example,dc=org", filter, attr)
}

func runBind(t *testing.T, bin string, r *running, dn, pw string) (string, error) {
	t.Helper()
	return run(t, bin, "-x", "-H", r.url(), "-D", dn, "-w", pw,
		"-b", "dc=example,dc=org", "(uid=*)", "uid")
}
