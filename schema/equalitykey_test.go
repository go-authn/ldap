// SPDX-License-Identifier: BSD-3-Clause

package schema

import "testing"

// EqualityKey agrees with Equal: two values have one key exactly when Equal
// says True, on the pairs that make a lower-casing differ from
// caseIgnoreMatch.
func TestEqualityKeyAgreesWithEqual(t *testing.T) {
	std := Standard()
	uid := std.AttributeType("uid")
	pairs := [][2]string{
		{"alice", "Alice"}, {"alice", "alice "}, {"al ice", "al  ice"},
		{"alice", "ａlice"}, {"sam", "ſam"}, {"alice", "al­ice"},
		{"alice", "bob"}, {"alice", "alicf"}, {"alice", "al ice"},
	}
	for _, p := range pairs {
		ka, oka := std.EqualityKey(uid, []byte(p[0]))
		kb, okb := std.EqualityKey(uid, []byte(p[1]))
		if !oka || !okb {
			t.Fatalf("no key for %q or %q", p[0], p[1])
		}
		want := std.Equal(uid, []byte(p[0]), []byte(p[1])) == True
		if (ka == kb) != want {
			t.Errorf("%q, %q: keys equal = %v, Equal = %v", p[0], p[1], ka == kb, want)
		}
	}
}

func TestEqualityKeyHasNoKeyWhereThereIsNoRule(t *testing.T) {
	std := Standard()
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("a nil attribute type panics: %v", r)
			}
		}()
		if _, ok := std.EqualityKey(nil, []byte("x")); ok {
			t.Error("a nil attribute type has a key")
		}
	}()
	for _, at := range std.AttributeTypes() {
		if at.equality == nil {
			if _, ok := std.EqualityKey(at, []byte("x")); ok {
				t.Errorf("%s has no equality rule and a key", at.Names)
			}
			return
		}
	}
	t.Skip("every standard attribute type has an equality rule")
}
