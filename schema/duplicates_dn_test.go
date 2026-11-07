// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"fmt"
	"math/rand"
	"testing"
)

// dnPool is spellings of a few DNs: equal by distinguishedNameMatch under
// different case, spaces, AVA order in a multi-valued RDN and escapes, plus
// values that have no key (unknown type, not a DN, hex value, an unknown type
// beside a known one).
var dnPool = []string{
	"uid=alice,ou=people,dc=example,dc=org",
	"UID=Alice,OU=People,DC=Example,DC=Org",
	"uid = alice , ou=people,dc=example,dc=org",
	"uid=alice,ou=people,dc=example,dc=com",
	"uid=bob,ou=people,dc=example,dc=org",
	"uid=al\\69ce,ou=people,dc=example,dc=org",
	"uid=alice+cn=Alice Liddell,ou=people,dc=example,dc=org",
	"CN=alice  liddell+UID=ALICE,ou=people,dc=example,dc=org",
	"uid=alice+uid=bob,dc=org",
	"nosuch=x,dc=org",
	"NoSuch=X,dc=org",
	"nosuch=x+cn=y,dc=org",
	"cn=y+nosuch=x,dc=org",
	"cn=#040161,dc=org",
	"cn=a,dc=org",
	"not a dn",
	"uid=alice,,dc=org",
	"",
	"dc=org",
	"DC=ORG",
}

func groupEntry(members []string) Entry {
	e := entry("cn=g,ou=groups,dc=example,dc=org",
		"objectClass: top", "objectClass: groupOfNames", "cn: g")
	var vals [][]byte
	for _, m := range members {
		vals = append(vals, []byte(m))
	}
	e.Attributes = append(e.Attributes, Attribute{Description: "member", Values: vals})
	return e
}

// The one-pass duplicate check answers exactly as the pairwise one (the
// reference), for lists that mix keyed and unkeyed values.
func TestDuplicateDNsMatchReference(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for name, s := range map[string]*Schema{"standard": Standard(), "rules": rulesSchema(t)} {
		for range 20000 {
			var m []string
			for j, n := 0, 1+r.Intn(8); j < n; j++ {
				m = append(m, dnPool[r.Intn(len(dnPool))])
			}
			checkValidate(t, name, s, groupEntry(m))
		}
		// every pair, in both orders
		for _, a := range dnPool {
			for _, b := range dnPool {
				checkValidate(t, name, s, groupEntry([]string{a, b}))
			}
		}
	}
}

func TestDuplicateDNsAreFound(t *testing.T) {
	got := problems(t, Standard().Validate(groupEntry([]string{
		"uid=alice,ou=people,dc=example,dc=org", "UID=ALICE, OU=people,dc=example,dc=org"})))
	if len(got.Problems) == 0 {
		t.Fatal("two spellings of one DN were not reported")
	}
}

func BenchmarkValidateGroupOf50DNs(b *testing.B) {
	var m []string
	for i := range 50 {
		m = append(m, fmt.Sprintf("uid=user%05d,ou=people,dc=example,dc=org", i*7))
	}
	e := groupEntry(m)
	s := Standard()
	b.ReportAllocs()
	for b.Loop() {
		_ = s.Validate(e)
	}
}
