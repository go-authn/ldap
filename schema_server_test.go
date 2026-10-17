// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/ldap/schema"
)

// account is a valid RFC 2307 account, the shape authnd's people should have.
func account(uid, uidNumber string) *Entry {
	return &Entry{DN: "uid=" + uid + ",ou=people,dc=example,dc=org", Attributes: []*Attribute{
		StringAttribute("objectClass", "top", "account", "posixAccount"),
		StringAttribute("uid", uid),
		StringAttribute("cn", strings.ToUpper(uid[:1])+uid[1:]+"  Smith"),
		StringAttribute("cn;lang-fr", "Monsieur "+uid),
		StringAttribute("uidNumber", uidNumber),
		StringAttribute("gidNumber", "100"),
		StringAttribute("homeDirectory", "/home/"+uid),
		StringAttribute("description", "Product  Dev Team"),
		OperationalAttribute("createTimestamp", "20261012000000Z"),
	}}
}

// The entries every test here uses are valid against the schema: what the
// filters are tested on is a directory a schema-aware server would publish.
func TestTheTestEntriesAreValid(t *testing.T) {
	for _, e := range []*Entry{account("alice", "999"), account("bob", "1000")} {
		if err := e.Validate(schema.Standard()); err != nil {
			t.Error(err)
		}
	}
	bad := &Entry{DN: "uid=x", Attributes: []*Attribute{StringAttribute("objectClass", "top", "person"), StringAttribute("uid", "x")}}
	if err := bad.Validate(schema.Standard()); err == nil {
		t.Error("a person with no cn, sn or room for uid passed")
	}
}

func TestEvaluateWithASchema(t *testing.T) {
	s := schema.Standard()
	alice := account("alice", "999")
	for _, c := range []struct {
		filter string
		want   schema.Truth
	}{
		{"(uid=ALICE)", schema.True}, // uid is caseIgnoreMatch
		{"(cn=alice smith)", schema.True},
		{"(cn= Alice   Smith )", schema.True},
		{"(name=alice smith)", schema.True}, // cn is a subtype of name
		{"(cn;lang-fr=monsieur alice)", schema.True},
		{"(cn;lang-de=monsieur alice)", schema.False},
		{"(cn;x-secret=alice smith)", schema.Undefined}, // RFC 4512 2.5: an unrecognized option
		{"(homeDirectory=/HOME/alice)", schema.False},   // caseExactIA5Match
		{"(uidNumber=999)", schema.True},
		{"(uidNumber=0999)", schema.Undefined}, // not an Integer
		{"(shoeSize=12)", schema.Undefined},    // RFC 4511 4.5.1.7's example
		{"(shoeSize=*)", schema.Undefined},
		{"(shoeSize>=12)", schema.Undefined},
		{"(!(shoeSize=12))", schema.Undefined}, // NOT of Undefined is Undefined
		{"(|(shoeSize=12)(uid=alice))", schema.True},
		{"(|(shoeSize=12)(uid=bob))", schema.Undefined},
		{"(&(shoeSize=12)(uid=bob))", schema.False},
		{"(&(shoeSize=12)(uid=alice))", schema.Undefined},
		{"(&)", schema.True},
		{"(|)", schema.False},
		{"(uid=*)", schema.True},
		{"(name=*)", schema.True},
		{"(mail=*)", schema.False},
		{"(cn;lang-de=*)", schema.False},
		{"(uid~=Alice)", schema.True},
		{"(uidNumber>=1000)", schema.Undefined}, // RFC 2307: uidNumber has no ORDERING
		{"(uidNumber<=1000)", schema.Undefined},
		{"(createTimestamp>=20260101000000Z)", schema.True}, // generalizedTimeOrderingMatch
		{"(createTimestamp>=20270101000000Z)", schema.False},
		{"(createTimestamp<=20261012000000Z)", schema.True}, // by EQUALITY
		{"(createTimestamp<=20261012020000+0200)", schema.True},
		{"(createTimestamp<=20250101000000Z)", schema.False},
		{"(createTimestamp<=nonsense)", schema.Undefined},
		{"(cn=al*sm*)", schema.True},
		{"(cn=*SMITH)", schema.True},
		{"(cn=al*x*)", schema.False},
		{"(description=*dev t*)", schema.True},
		{"(objectClass=posixaccount)", schema.True},
		{"(objectClass=1.3.6.1.1.1.2.0)", schema.True}, // objectIdentifierMatch reads the OID
		{"(objectClass=shoe)", schema.Undefined},
		{"(objectClass=person)", schema.False},
		// extensible matches (RFC 4511 4.5.1.7.7)
		{"(uidNumber:integerOrderingMatch:=1000)", schema.True}, // 999 < 1000 as integers
		{"(uidNumber:2.5.13.15:=998)", schema.False},
		{"(cn:caseExactMatch:=Alice Smith)", schema.True},
		{"(cn:caseExactMatch:=alice smith)", schema.False},
		{"(uid:integerMatch:=1)", schema.Undefined},
		{"(uidNumber:caseIgnoreMatch:=999)", schema.Undefined}, // the strings are equal; the rule does not apply to an Integer          // not suitable for uid
		{"(uid:nonsenseMatch:=x)", schema.Undefined},         // not recognized
		{"(uid:certificateExactMatch:=x)", schema.Undefined}, // not implemented
		{"(shoeSize:caseIgnoreMatch:=x)", schema.Undefined},
		{"(:caseIgnoreIA5Match:=/home/ALICE)", schema.True}, // every attribute the rule applies to
		{"(:integerMatch:=12345)", schema.False},
		{"(uid:=ALICE)", schema.True},
		{"(cn:caseIgnoreSubstringsMatch:=al*th)", schema.True},
		{"(ou:dn:=people)", schema.True}, // the DN's ou=people
		{"(ou:dn:=nobody)", schema.False},
		{"(shoeSize:dn:=people)", schema.Undefined},
		{"(ou:dn:caseExactMatch:=people)", schema.True},
		{"(ou:dn:caseExactMatch:=People)", schema.False},
		{"(shoeSize:dn:caseExactMatch:=x)", schema.Undefined},
		{"(:dn:caseIgnoreMatch:=PEOPLE)", schema.True},   // ou=people in the DN
		{"(:dn:caseIgnoreMatch:=EXAMPLE)", schema.False}, // dc is IA5: caseIgnoreMatch does not apply to it
		{"(:dn:integerMatch:=1)", schema.False},
	} {
		f, err := ParseFilter(c.filter)
		if err != nil {
			t.Fatalf("%s: %v", c.filter, err)
		}
		if got := Evaluate(f, alice, s); got != c.want {
			t.Errorf("%s is %v, want %v", c.filter, got, c.want)
		}
	}
}

// ⛔ Without a schema nothing changes: Evaluate is Matches.
func TestEvaluateWithoutASchemaIsMatches(t *testing.T) {
	alice := account("alice", "999")
	for _, filter := range []string{"(uidNumber>=1000)", "(uid=ALICE)", "(shoeSize=*)", "(!(shoeSize=1))", "(cn=al*)"} {
		f, _ := ParseFilter(filter)
		want := schema.False
		if f.Matches(alice) {
			want = schema.True
		}
		if got := Evaluate(f, alice, nil); got != want {
			t.Errorf("%s: %v, Matches says %v", filter, got, want)
		}
		req := &SearchRequest{Filter: f}
		if req.Matches(alice) != f.Matches(alice) {
			t.Errorf("%s: SearchRequest.Matches differs", filter)
		}
	}
	// "999" >= "1000" as strings, which is exactly what a schema fixes.
	f, _ := ParseFilter("(uidNumber>=1000)")
	if !f.Matches(account("alice", "999")) {
		t.Error("the schema-less comparison changed")
	}
}

// schemaServer is a server with the standard schema whose handler sends
// EVERY entry, filtered or not, so that what is tested is the server.
func schemaServer(t *testing.T, s *Server, entries ...*Entry) *running {
	t.Helper()
	s.Schema = schema.Standard()
	if s.Bind == nil {
		s.Bind = reader()
	}
	if s.Search == nil {
		s.Search = &sendsEverything{entries: entries}
	}
	return rootServer(t, s)
}

type sendsEverything struct{ entries []*Entry }

func (d *sendsEverything) Search(ctx context.Context, s Session, req *SearchRequest, w EntryWriter) (Result, error) {
	for _, e := range d.entries {
		if err := w.Entry(e); err != nil {
			return Result{}, err
		}
	}
	return Result{Code: Success}, nil
}

// readSubschema asks for the subschema the way RFC 4512 4.4 says to.
func readSubschema(t *testing.T, bin string, r *running, base, filter string, attrs ...string) string {
	t.Helper()
	args := append([]string{"-x", "-LLL", "-o", "ldif-wrap=no", "-H", r.url(), "-b", base, "-s", "base", filter}, attrs...)
	out, _ := exec.Command(bin, args...).CombinedOutput()
	return string(out)
}

// The judge reads the subschema subentry: a bare read gets the user
// attributes, "+" gets the definitions, and every definition published is
// one the parser reads back.
func TestOpenLDAPReadsTheSubschema(t *testing.T) {
	bin := judge(t)
	r := schemaServer(t, &Server{})

	if out := readRoot(t, bin, r, "subschemaSubentry"); !strings.Contains(out, "subschemaSubentry: cn=Subschema") {
		t.Errorf("the root DSE does not name the subschema:\n%s", out)
	}
	bare := readSubschema(t, bin, r, "cn=Subschema", "(objectClass=subschema)")
	for _, want := range []string{"dn: cn=Subschema", "objectClass: subentry", "objectClass: subschema", "cn: Subschema"} {
		if !strings.Contains(bare, want) {
			t.Errorf("no %q in a bare read:\n%s", want, bare)
		}
	}
	if strings.Contains(bare, "attributeTypes") {
		t.Errorf("the operational definitions came without being asked for:\n%s", bare)
	}
	full := readSubschema(t, bin, r, "CN=SUBSCHEMA", "(objectClass=subschema)", "+")
	counts := map[string]int{}
	for _, line := range strings.Split(full, "\n") {
		name, value, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		counts[name]++
		var err error
		switch name {
		case "attributeTypes":
			_, err = schema.ParseAttributeType(value)
		case "objectClasses":
			_, err = schema.ParseObjectClass(value)
		case "matchingRules":
			_, err = schema.ParseMatchingRule(value)
		case "matchingRuleUse":
			_, err = schema.ParseMatchingRuleUse(value)
		case "ldapSyntaxes":
			_, err = schema.ParseSyntax(value)
		}
		if err != nil {
			t.Errorf("%s: %q does not read back: %v", name, value, err)
		}
	}
	s := schema.Standard()
	if counts["attributeTypes"] != len(s.AttributeTypes()) || counts["objectClasses"] != len(s.ObjectClasses()) ||
		counts["matchingRules"] != len(s.MatchingRules()) || counts["matchingRuleUse"] != len(s.MatchingRuleUses()) ||
		counts["ldapSyntaxes"] != len(s.Syntaxes()) || counts["subtreeSpecification"] != 1 {
		t.Errorf("counts %v", counts)
	}
	if named := readSubschema(t, bin, r, "cn=Subschema", "(objectClass=*)", "objectClasses"); strings.Contains(named, "attributeTypes:") || !strings.Contains(named, "NAME 'posixAccount'") {
		t.Error("asking for objectClasses by name brought something else")
	}
	if none := readSubschema(t, bin, r, "cn=Subschema", "(objectClass=person)"); strings.Contains(none, "dn:") {
		t.Errorf("the filter did not apply:\n%s", none)
	}
}

// ⛔ The subschema subentry, as published, satisfies the schema it
// publishes. OpenLDAP's claims 'subentry' and has no subtreeSpecification,
// which 'subentry' MUST have (RFC 3672 2.4).
func TestTheSubschemaEntryIsValidAgainstItself(t *testing.T) {
	s := schema.Standard()
	if err := subschemaEntry(s).Validate(s); err != nil {
		t.Error(err)
	}
	c := newConn(&Server{Schema: s, NamingContexts: []string{"dc=example,dc=org"}}, nil)
	if err := c.rootDSE().Validate(s); err != nil {
		t.Errorf("the root DSE: %v", err)
	}
}

func TestOnlyABaseSearchOfTheSubschemaIsAnsweredByTheServer(t *testing.T) {
	s := schema.Standard()
	for _, c := range []struct {
		base  string
		scope Scope
		want  bool
	}{
		{"cn=Subschema", ScopeBaseObject, true},
		{" cn = subschema ", ScopeBaseObject, true},
		{"2.5.4.3=Subschema", ScopeBaseObject, true},
		{"cn=Subschema", ScopeWholeSubtree, false}, // RFC 3672 3
		{"cn=Subschema", ScopeSingleLevel, false},
		{"cn=Subschema,dc=x", ScopeBaseObject, false},
	} {
		if got := isSubschemaRead(s, &SearchRequest{BaseObject: c.base, Scope: c.scope}); got != c.want {
			t.Errorf("%q %v: %v", c.base, c.scope, got)
		}
	}
	if isSubschemaRead(nil, &SearchRequest{BaseObject: "cn=Subschema"}) {
		t.Error("a server with no schema answered for cn=Subschema")
	}
}

// With a schema, the SERVER drops an entry a handler sent that the filter
// does not make True -- and a handler using SearchRequest.Matches does not
// send it in the first place.
func TestTheServerFiltersWithTheSchema(t *testing.T) {
	bin := judge(t)
	r := schemaServer(t, &Server{}, account("alice", "999"), account("bob", "1000"), account("carol", "10000"))

	for _, c := range []struct {
		filter string
		want   string
	}{
		{"(uid=ALICE)", "alice"},
		{"(cn=bob smith)", "bob"},
		{"(name=carol  smith)", "carol"},
		{"(!(uidNumber:integerOrderingMatch:=1000))", "bob carol"},
		{"(uidNumber:integerOrderingMatch:=1000)", "alice"},
		{"(uidNumber>=1000)", ""}, // Undefined: RFC 2307 gives uidNumber no ORDERING
		{"(shoeSize=12)", ""},
		{"(!(shoeSize=12))", ""},
		{"(uid:nonsenseMatch:=x)", ""}, // Undefined, not inappropriateMatching
	} {
		got, out := r.ask(t, bin, nil, c.filter)
		if strings.Join(got, " ") != c.want {
			t.Errorf("%s: %v, want %q\n%s", c.filter, got, c.want, out)
		}
		if strings.Contains(out, "Inappropriate") {
			t.Errorf("%s: refused rather than evaluated:\n%s", c.filter, out)
		}
	}
	// subschemaSubentry is on every entry, and only when asked for.
	if _, out := r.ask(t, bin, nil, "(uid=alice)", "+"); !strings.Contains(out, "subschemaSubentry: cn=Subschema") {
		t.Errorf("no subschemaSubentry with +:\n%s", out)
	}
	if _, out := r.ask(t, bin, nil, "(uid=alice)", "*"); strings.Contains(out, "subschemaSubentry") {
		t.Errorf("subschemaSubentry without being asked:\n%s", out)
	}
}

// A handler that already publishes subschemaSubentry is not given a second.
func TestAnEntrysOwnSubschemaSubentryIsKept(t *testing.T) {
	e := account("alice", "999")
	e.Attributes = append(e.Attributes, OperationalAttribute("subschemaSubentry", "cn=elsewhere"))
	r := schemaServer(t, &Server{}, e)
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")
	c.searchBase(t, "uid=alice,ou=people,dc=example,dc=org", "(uid=alice)", "subschemaSubentry")
	if got := strings.Join(c.values, "|"); got != "subschemaSubentry: cn=elsewhere" {
		t.Errorf("%q", got)
	}
}

// The subschema is behind the confidentiality gate; only the root DSE,
// where StartTLS is advertised, is in front of it.
func TestTheSubschemaNeedsTLSWhenTLSIsRequired(t *testing.T) {
	r := schemaServer(t, &Server{TLSConfig: selfSigned(t), RequireTLS: true})
	c := dial(t, r)
	defer c.Close()
	if _, res := c.searchBase(t, "cn=Subschema", "(objectClass=subschema)", "+"); res.Code != ConfidentialityRequired {
		t.Errorf("the subschema in the clear answered %s", res.Code)
	}
}

// A paged search filters with the schema too, and a dropped entry does not
// take a place on a page.
func TestAPagedSearchFiltersWithTheSchema(t *testing.T) {
	var entries []*Entry
	for i, n := range []string{"999", "1000", "1001", "5", "20000"} {
		entries = append(entries, account(string(rune('a'+i))+"x", n))
	}
	r := schemaServer(t, &Server{}, entries...)
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")
	dns, res := c.searchWith(t, "(!(uidNumber:integerOrderingMatch:=1000))", pagedControl(2, ""))
	if res.Code != Success || len(dns) != 2 {
		t.Fatalf("first page: %v %v", dns, res)
	}
	cookie, _ := c.cookieOf(t)
	more, res := c.searchWith(t, "(!(uidNumber:integerOrderingMatch:=1000))", pagedControl(2, cookie))
	if last, _ := c.cookieOf(t); res.Code != Success || len(more) != 1 || last != "" {
		t.Errorf("second page: %v %v", more, res)
	}
}

// ⛔ A subschema read that cannot send its entry sends no searchResDone, as
// the root DSE read does not.
func TestASubschemaReadThatCannotSendSendsNothingAtAll(t *testing.T) {
	left, right := net.Pipe()
	right.Close()
	c := newConn(&Server{Schema: schema.Standard()}, left)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		c.searchSubschema(ctx, &message{id: 1}, &SearchRequest{BaseObject: SubschemaDN, Filter: &Present{Attribute: "objectClass"}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the subschema read blocked")
	}
}
