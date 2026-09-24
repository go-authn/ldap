// SPDX-License-Identifier: BSD-3-Clause

package ldap

import "testing"

// ⛔ Scope belongs to the protocol, and this is the table that proves it:
// almost every row is a case a hand-written suffix test gets wrong, and a
// hand-written one is what every consumer writes when the library does not
// offer this. The fixture in this very package had the empty-base rows
// backwards and a whole-tree search came back empty while looking correct.
func TestInScope(t *testing.T) {
	const base = "ou=people,dc=example,dc=org"
	for _, tc := range []struct {
		dn, base string
		scope    Scope
		want     bool
		why      string
	}{
		{base, base, ScopeBaseObject, true, "the base at base scope"},
		{base, base, ScopeSingleLevel, false, "the base is NOT its own single level"},
		{base, base, ScopeWholeSubtree, true, "the base is in its own subtree"},

		{"uid=a," + base, base, ScopeBaseObject, false, "a child at base scope"},
		{"uid=a," + base, base, ScopeSingleLevel, true, "an immediate child"},
		{"uid=a," + base, base, ScopeWholeSubtree, true, "a child in the subtree"},

		{"cn=x,uid=a," + base, base, ScopeSingleLevel, false, "a grandchild is not one level"},
		{"cn=x,uid=a," + base, base, ScopeWholeSubtree, true, "a grandchild is in the subtree"},

		{"dc=example,dc=org", base, ScopeWholeSubtree, false, "the PARENT is not in the subtree"},
		{"uid=a,ou=groups,dc=example,dc=org", base, ScopeWholeSubtree, false, "a sibling branch"},

		// ⛔ The one that looks like a suffix and is not. "ou=morepeople"
		// ends with "people" but is a different branch entirely, and a
		// strings.HasSuffix test puts every entry in it into this search.
		{"uid=a,ou=morepeople,dc=example,dc=org", base, ScopeWholeSubtree, false, "a branch whose name ENDS with the base's"},

		// An empty base is the root of the DIT.
		{"uid=a,ou=people,dc=example,dc=org", "", ScopeWholeSubtree, true, "everything is under the root"},
		{"dc=org", "", ScopeSingleLevel, true, "one RDN is one level below the root"},
		{"dc=example,dc=org", "", ScopeSingleLevel, false, "two RDNs are two levels below it"},
		{"", "", ScopeBaseObject, true, "the root DSE itself"},
		{"dc=org", "", ScopeBaseObject, false, "an entry is not the root DSE"},
		{"", "", ScopeSingleLevel, false, "the root DSE is not one level below itself"},

		// Spacing and case are not part of a DN's identity.
		{"uid=a, ou=people, dc=example, dc=org", base, ScopeSingleLevel, true, "spaces after the commas"},
		{"UID=A,OU=People,DC=Example,DC=Org", base, ScopeSingleLevel, true, "a different case"},
		{"uid=a," + base, "OU=PEOPLE, DC=EXAMPLE, DC=ORG", ScopeSingleLevel, true, "the BASE spelled differently"},

		// ⛔ A comma inside a value does not split the DN (RFC 4514 2.4).
		// Split naively, `cn=Smith\, John` becomes two RDNs and the entry
		// lands one level deeper than it is -- so it vanishes from the
		// single-level search that should return it.
		{`cn=Smith\, John,` + base, base, ScopeSingleLevel, true, "an escaped comma is not a separator"},
		{`cn=Smith\, John,` + base, base, ScopeWholeSubtree, true, "the same, in the subtree"},

		// A scope value that is not one of the three matches nothing rather
		// than everything: the decoder refuses those, and a default of
		// "everything" here would be a second chance to get it wrong.
		{"uid=a," + base, base, Scope(9), false, "a scope that is not one of the three"},
	} {
		if got := InScope(tc.dn, tc.base, tc.scope); got != tc.want {
			t.Errorf("%s\n  InScope(%q, %q, %s) = %v, want %v", tc.why, tc.dn, tc.base, tc.scope, got, tc.want)
		}
	}
}

func TestEqualDN(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"uid=a,ou=people", "uid=a,ou=people", true},
		{"uid=a, ou=people", "uid=a,ou=people", true},
		{"UID=A,OU=PEOPLE", "uid=a,ou=people", true},
		{"uid=a,ou=people", "uid=a,ou=groups", false},
		{"uid=a", "uid=a,ou=people", false},
		{"", "", true},
		{"", "uid=a", false},
		{`cn=Smith\, John`, `cn=Smith\, John`, true},
		{`cn=Smith\, John`, `cn=Smith`, false},
	} {
		if got := EqualDN(tc.a, tc.b); got != tc.want {
			t.Errorf("EqualDN(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// ⛔ What EqualDN does NOT do, stated as a test so that the limit is
// recorded rather than discovered. Unescaping a value needs a schema to know
// its matching rule, and this package has none -- so a deployment whose DNs
// differ only by escaping must say so rather than find out.
func TestEqualDNDoesNotUnescapeValues(t *testing.T) {
	if EqualDN(`cn=B\6fb`, "cn=Bob") {
		t.Error("EqualDN unescaped a value; it has no schema with which to do that correctly")
	}
}

func TestSplitDN(t *testing.T) {
	for _, tc := range []struct {
		dn   string
		want int
	}{
		{"", 0},
		{"dc=org", 1},
		{"dc=example,dc=org", 2},
		{"  dc=example ,  dc=org  ", 2},
		{`cn=Smith\, John,dc=org`, 2},
		{`cn=a\\,dc=org`, 2},
		// A separator with nothing either side names no RDN at all. Left as
		// one empty RDN it would compare equal to another empty one, and two
		// malformed DNs would name the same entry.
		{",", 0},
		{"dc=org,", 1},
	} {
		if got := len(splitDN(tc.dn)); got != tc.want {
			t.Errorf("splitDN(%q) gave %d RDNs, want %d", tc.dn, got, tc.want)
		}
	}
}
