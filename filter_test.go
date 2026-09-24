// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"strings"
	"testing"
)

func entry(dn string, kv ...string) *Entry {
	e := &Entry{DN: dn}
	for i := 0; i+1 < len(kv); i += 2 {
		if a := e.Attribute(kv[i]); a != nil {
			a.Values = append(a.Values, []byte(kv[i+1]))
			continue
		}
		e.Attributes = append(e.Attributes, StringAttribute(kv[i], kv[i+1]))
	}
	return e
}

// ⛔ The defect this whole design exists to prevent, asserted directly.
//
// The library this replaces evaluated `(uid=svc-*-prod)` as `(uid=svc-*)`,
// because it read only the FIRST component of a SubstringFilter. A directory
// that answers a broader question than it was asked has disclosed entries
// nobody asked for, and says nothing, because every entry it returns is real.
func TestASubstringFilterMatchesEveryComponentInOrder(t *testing.T) {
	people := []*Entry{
		entry("uid=svc-web-prod", "uid", "svc-web-prod"),
		entry("uid=svc-web-stage", "uid", "svc-web-stage"),
		entry("uid=svc-db-prod", "uid", "svc-db-prod"),
		entry("uid=app-web-prod", "uid", "app-web-prod"),
		entry("uid=svc-prod", "uid", "svc-prod"),
	}
	for _, tc := range []struct {
		filter string
		want   []string
	}{
		{"(uid=svc-*-prod)", []string{"svc-web-prod", "svc-db-prod"}},
		{"(uid=svc-*)", []string{"svc-web-prod", "svc-web-stage", "svc-db-prod", "svc-prod"}},
		{"(uid=*-prod)", []string{"svc-web-prod", "svc-db-prod", "app-web-prod", "svc-prod"}},
		{"(uid=*web*)", []string{"svc-web-prod", "svc-web-stage", "app-web-prod"}},
		{"(uid=*-*-*)", []string{"svc-web-prod", "svc-web-stage", "svc-db-prod", "app-web-prod"}},
		{"(uid=svc-web-prod)", []string{"svc-web-prod"}},
		{"(uid=*)", []string{"svc-web-prod", "svc-web-stage", "svc-db-prod", "app-web-prod", "svc-prod"}},
	} {
		f, err := ParseFilter(tc.filter)
		if err != nil {
			t.Fatalf("%s: %v", tc.filter, err)
		}
		var got []string
		for _, e := range people {
			if f.Matches(e) {
				got = append(got, string(e.Attribute("uid").Values[0]))
			}
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s\n  matched %v\n  want    %v", tc.filter, got, tc.want)
		}
	}
}

// ⛔ The components must not overlap. "svc-prod" starts with "svc-" and ends
// with "-prod", and a check that tested the two independently would say
// `(uid=svc-*-prod)` matches it -- there are not enough characters for both.
// It is in the table above as well; here it is on its own, because it is the
// case that separates "walks the components" from "tests them separately".
func TestSubstringComponentsDoNotOverlap(t *testing.T) {
	f, err := ParseFilter("(uid=svc-*-prod)")
	if err != nil {
		t.Fatal(err)
	}
	if f.Matches(entry("x", "uid", "svc-prod")) {
		t.Error("svc-prod matched: the initial and the final were allowed to share characters")
	}
	if !f.Matches(entry("x", "uid", "svc--prod")) {
		t.Error("svc--prod did not match, and it has exactly the characters both components need")
	}
}

// ⛔ An escaped asterisk is a VALUE, not syntax. A name like "10*" must not
// become a substring filter, or the question changes as it is written down.
func TestAnEscapedAsteriskIsNotSyntax(t *testing.T) {
	f, err := ParseFilter(`(cn=10\2a)`)
	if err != nil {
		t.Fatal(err)
	}
	eq, ok := f.(*Equality)
	if !ok {
		t.Fatalf("parsed as %T, want an equality match", f)
	}
	if eq.Value != "10*" {
		t.Errorf("value is %q, want %q", eq.Value, "10*")
	}
	if f.Matches(entry("x", "cn", "10 and then some")) {
		t.Error("it matched as a substring filter")
	}
	if !f.Matches(entry("x", "cn", "10*")) {
		t.Error("it did not match the literal value")
	}
}

// RFC 4526: `(&)` matches everything and `(|)` matches nothing. The two are
// each other's opposite and getting them the wrong way round turns a filter
// that should return no entries into one that returns the directory.
func TestTheAbsoluteTrueAndFalseFilters(t *testing.T) {
	yes, err := ParseFilter("(&)")
	if err != nil {
		t.Fatal(err)
	}
	no, err := ParseFilter("(|)")
	if err != nil {
		t.Fatal(err)
	}
	e := entry("x", "cn", "anything")
	if !yes.Matches(e) {
		t.Error("(&) did not match; RFC 4526 says it matches every entry")
	}
	if no.Matches(e) {
		t.Error("(|) matched; RFC 4526 says it matches nothing")
	}
}

// ⭐ String and Matches read the same tree, so a filter that survives a round
// trip through the string form must mean the same thing. This is the property
// the three-way drift violated, asserted as a property rather than case by
// case.
func TestAFilterMeansTheSameAfterARoundTrip(t *testing.T) {
	corpus := []*Entry{
		entry("a", "uid", "svc-web-prod", "mail", "a@example.org"),
		entry("b", "uid", "svc-prod"),
		entry("c", "uid", "APP-Web-Prod", "mail", "c@example.org"),
		entry("d", "cn", "O'Brien (contractor)"),
		entry("e", "cn", `back\slash`),
		entry("f", "cn", "10*"),
	}
	for _, src := range []string{
		"(uid=svc-*-prod)", "(uid=*)", "(&(uid=svc-*)(mail=*))",
		"(|(uid=svc-prod)(cn=10\\2a))", "(!(mail=*))",
		"(cn=O'Brien \\28contractor\\29)", "(cn=back\\5cslash)",
		"(uid>=svc)", "(uid<=svc-z)", "(uid~=svc-prod)",
		"(&)", "(|)", "(uid=*-*-*)",
	} {
		first, err := ParseFilter(src)
		if err != nil {
			t.Errorf("%s: %v", src, err)
			continue
		}
		again, err := ParseFilter(first.String())
		if err != nil {
			t.Errorf("%s rendered as %s, which does not parse: %v", src, first.String(), err)
			continue
		}
		for _, e := range corpus {
			if first.Matches(e) != again.Matches(e) {
				t.Errorf("%s and its round trip %s disagree about %s",
					src, first.String(), e.DN)
			}
		}
	}
}

// A filter naming a matching rule is refused rather than answered as an
// equality. (memberOf:1.2.840.113556.1.4.1941:=...) asks for a TRANSITIVE
// group search; answering it as equality says "not a member" about people
// who are.
func TestAMatchingRuleThisServerDoesNotHaveIsRefused(t *testing.T) {
	f, err := ParseFilter("(memberOf:1.2.840.113556.1.4.1941:=cn=admins,dc=example,dc=org)")
	if err != nil {
		t.Fatal(err)
	}
	if err := Unsupported(f); err == nil {
		t.Error("a matching rule nothing here implements was accepted")
	}
	if f.Matches(entry("x", "memberOf", "cn=admins,dc=example,dc=org")) {
		t.Error("it matched, so a caller ignoring Unsupported gets a silently narrower answer")
	}
	// And it is found inside a conjunction, not only at the top.
	nested, err := ParseFilter("(&(objectClass=person)(memberOf:1.2.840.113556.1.4.1941:=cn=admins))")
	if err != nil {
		t.Fatal(err)
	}
	if err := Unsupported(nested); err == nil {
		t.Error("a matching rule nested in an AND was not noticed")
	}
}

func TestFiltersThatAreNotFilters(t *testing.T) {
	for _, bad := range []string{
		"", "(", ")", "uid=x", "(uid)", "(=x)", "(uid=x))", "(uid=x)junk",
		`(cn=\)`, `(cn=\zz)`, "(&(uid=x)", "(uid>x)",
	} {
		if f, err := ParseFilter(bad); err == nil {
			t.Errorf("%q parsed as %s", bad, f.String())
		}
	}
}
