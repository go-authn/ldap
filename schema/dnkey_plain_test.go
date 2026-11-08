// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"fmt"
	"math/rand"
	"testing"
)

// checkPlain: when the plain path answers, it is the parsed path's answer.
// It reports whether it answered.
func checkPlain(t testing.TB, s *Schema, dn string) bool {
	t.Helper()
	got, ok := s.dnKeyPlain([]byte(dn))
	if !ok {
		return false
	}
	want, wok := s.dnKeyParsed([]byte(dn))
	if !wok || got != want {
		t.Fatalf("dnKeyPlain(%q) = %q, parsed %q (ok %v)", dn, got, want, wok)
	}
	return true
}

var plainCorpus = []string{
	"uid=alice,ou=people,dc=example,dc=org",
	"UID=Alice,OU=People,DC=Example,DC=Org",
	"uid=alice smith,ou=people,dc=example,dc=org",
	"uid=alice   smith,ou=people,dc=example,dc=org",
	"uid=alice  smith,dc=org",
	"cn=Alice Liddell,dc=org",
	"cn=a b c,dc=org",
	"CN=a,dc=org",
	"dc=org",
	"dc=ORG",
	"uid=a,uid=b",
	"mail=a@b.c,dc=org",
	"nosuch=x,dc=org",
	"jpegPhoto=x,dc=org",
	"objectClass=top,dc=org",
	"uidNumber=1000,dc=org",
	"1.2.3=x,dc=org",
	"cn=#040161,dc=org",
	"cn=a\\,b,dc=org",
	"cn=a\\2cb,dc=org",
	"uid=a+cn=b,dc=org",
	"uid=a;dc=org",
	"uid=é,dc=org",
	"uid= a,dc=org",
	"uid=a ,dc=org",
	"uid=a, dc=org",
	"uid =a,dc=org",
	"uid=,dc=org",
	"uid=a,",
	",uid=a",
	"uid=a,,dc=org",
	"",
	" ",
	"uid",
	"=a",
	"-uid=a",
	"u-id=a",
	"uid=a=b",
	"uid=\"a\"",
	"uid=<a>",
	"uid=a#b",
	"uid=a\x00b",
	"uid=a\tb",
	"2uid=a",
}

func TestDNKeyPlainMatchesParsed(t *testing.T) {
	answered := 0
	for name, s := range map[string]*Schema{"standard": Standard(), "rules": rulesSchema(t)} {
		for _, dn := range plainCorpus {
			if checkPlain(t, s, dn) {
				answered++
			}
			_ = name
		}
		r := rand.New(rand.NewSource(3))
		const alphabet = "abAB09 -_.@=,+;#\\\"<>é\x00\t"
		types := []string{"uid", "UID", "cn", "dc", "ou", "mail", "nosuch", "o", "sn", "1.2.3"}
		for range 100000 {
			var dn string
			for j, n := 0, 1+r.Intn(4); j < n; j++ {
				var val []byte
				for k, m := 0, r.Intn(7); k < m; k++ {
					val = append(val, alphabet[r.Intn(len(alphabet))])
				}
				if j > 0 {
					dn += ","
				}
				dn += types[r.Intn(len(types))] + "=" + string(val)
			}
			if checkPlain(t, s, dn) {
				answered++
			}
		}
	}
	if answered < 1000 {
		t.Fatalf("the plain path answered only %d times: the test is not testing it", answered)
	}
}

// The plain path must answer the common DN, or it saves nothing.
func TestDNKeyPlainAnswersTheCommonDN(t *testing.T) {
	if _, ok := Standard().dnKeyPlain([]byte("uid=user00001,ou=people,dc=example,dc=org")); !ok {
		t.Fatal("the plain path did not take uid=,ou=,dc=,dc=")
	}
}

// plainStringRules is the table's rules: for each, the key function of the
// table is prepare(value, fold, insignificantSpace, whole).
func TestPlainRulesAreTheTable(t *testing.T) {
	for oid, fold := range plainStringRules {
		impl, ok := rules[oid]
		if !ok || impl.custom != nil || impl.compare != nil || impl.kind != equality || impl.key == nil {
			t.Fatalf("%s is not a plain key rule", oid)
		}
		for _, v := range []string{"a", "A", "a b", "A  B", "a   b", "x y  z", "Ab"} {
			got, gok := impl.key(Standard(), []byte(v), whole)
			want, wok := prepare(v, fold, insignificantSpace, whole)
			if got != want || gok != wok {
				t.Errorf("%s key(%q) = %q, prepare says %q", oid, v, got, want)
			}
		}
	}
}

func FuzzDNKeyPlain(f *testing.F) {
	for _, dn := range plainCorpus {
		f.Add(dn)
	}
	s := Standard()
	f.Fuzz(func(t *testing.T, dn string) { checkPlain(t, s, dn) })
}

func BenchmarkDNKey(b *testing.B) {
	s := Standard()
	for _, dn := range []string{
		"uid=user00001,ou=people,dc=example,dc=org",
		"uid=user00001+cn=Some One,ou=people,dc=example,dc=org",
	} {
		for name, key := range map[string]func([]byte) (string, bool){"dnKey": s.dnKey, "parsed": s.dnKeyParsed} {
			b.Run(fmt.Sprintf("%s/%d", name, len(dn)), func(b *testing.B) {
				v := []byte(dn)
				b.ReportAllocs()
				for b.Loop() {
					if _, ok := key(v); !ok {
						b.Fatal(dn)
					}
				}
			})
		}
	}
}
