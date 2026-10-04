// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"strings"
	"testing"
)

func TestAttributeDescriptionsAreRFC4512s(t *testing.T) {
	for s, want := range map[string]bool{
		"cn": true, "objectClass": true, "msDS-UserAccountControl": true, "x500UniqueIdentifier": true,
		"2.5.4.3": true, "0.9.2342.19200300.100.1.1": true, "1.0": true,
		"userCertificate;binary": true, "cn;lang-fr;x-y": true,
		"": false, "1cn": false, "-cn": false, "cn_name": false, "c n": false, "cn=": false,
		"!x": false, "cn)(uid": false, "cn\x00": false,
		"2": false, "2.": false, ".2": false, "2..5": false, "01.2": false, "2.05": false, "2.5a": false,
		"cn;": false, "cn;;b": false, "cn;a_b": false, ";binary": false,
	} {
		if got := validAttributeDescription(s); got != want {
			t.Errorf("%q: %v, want %v", s, got, want)
		}
	}
}

// Both directions refuse a name that is not one: the wire, where FuzzMessage
// found `!00000000000` read back as a NOT, and the string form.
func TestAFilterNamingNoAttributeIsRefused(t *testing.T) {
	for _, s := range []string{"(cn_x=a)", "(!(01.2=*))", "(&(cn=a)(c n=b))", "(cn:caseExact_Match:=a)", "(cn;=a)"} {
		if _, err := ParseFilter(s); err == nil || !strings.Contains(err.Error(), "RFC 4512") {
			t.Errorf("ParseFilter(%q) = %v", s, err)
		}
	}
	for _, f := range []Filter{
		&Present{Attribute: "!x"},
		&Not{Filter: &Equality{Attribute: "cn)(uid", Value: "a"}},
		&Or{Filters: []Filter{&Present{Attribute: "cn"}, &Substrings{Attribute: "", Initial: "a"}}},
		&GreaterOrEqual{Attribute: "1", Value: "a"}, &LessOrEqual{Attribute: "-", Value: "a"}, &Approx{Attribute: ";", Value: "a"},
		&ExtensibleMatch{Attribute: "c n", Value: "a"},
		&ExtensibleMatch{MatchingRule: "2.", Value: "a"},
		&And{Filters: []Filter{&Present{Attribute: "c\x00"}}},
	} {
		p, err := EncodeFilter(f)
		if err != nil {
			t.Fatalf("%T will not encode: %v", f, err)
		}
		if _, err := DecodeFilter(p); err == nil || !strings.Contains(err.Error(), "RFC 4512") {
			t.Errorf("DecodeFilter(%s) = %v", f, err)
		}
	}
	// And the names that are names still pass, in both.
	for _, s := range []string{"(&(objectClass=person)(2.5.4.3=x)(userCertificate;binary=*))", "(:2.5.13.5:=a)", "(cn:dn:caseExactMatch:=a)"} {
		f, err := ParseFilter(s)
		if err != nil {
			t.Fatalf("ParseFilter(%q): %v", s, err)
		}
		p, _ := EncodeFilter(f)
		if _, err := DecodeFilter(p); err != nil {
			t.Errorf("DecodeFilter(%s): %v", s, err)
		}
	}
}
