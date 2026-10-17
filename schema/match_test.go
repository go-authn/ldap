// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"testing"
	"time"
)

func TestThreeValuedLogic(t *testing.T) {
	// RFC 4511 4.5.1.7.
	for _, c := range []struct{ a, b, and, or Truth }{
		{True, True, True, True}, {True, False, False, True}, {True, Undefined, Undefined, True},
		{False, False, False, False}, {False, Undefined, False, Undefined}, {Undefined, Undefined, Undefined, Undefined},
	} {
		if And(c.a, c.b) != c.and || And(c.b, c.a) != c.and || Or(c.a, c.b) != c.or || Or(c.b, c.a) != c.or {
			t.Errorf("%v %v: and %v or %v", c.a, c.b, And(c.a, c.b), Or(c.a, c.b))
		}
	}
	if Not(True) != False || Not(False) != True || Not(Undefined) != Undefined {
		t.Error("not")
	}
	if True.String() != "TRUE" || False.String() != "FALSE" || Undefined.String() != "Undefined" {
		t.Error("String")
	}
}

// RFC 4518 2.6.1 with errata 1757 and 1758, using the RFC's own examples.
func TestInsignificantSpaceHandling(t *testing.T) {
	for _, c := range []struct {
		in   string
		p    part
		want string
	}{
		{"foo bar  ", whole, " foo  bar "},
		{"   ", whole, "  "},
		{"", whole, "  "},
		{"foo bar  ", initialPart, " foo  bar "},
		{"foo bar  ", anyPart, "foo  bar "}, // erratum 1758: two spaces, not one
		{"foo bar  ", finalPart, "foo  bar "},
		{"  foo", anyPart, " foo"},
		{"  foo", finalPart, " foo "},
		{"foo", initialPart, " foo"},
		{"   ", anyPart, " "},
		{"\u00a0a\tb\u3000", whole, " a  b "}, // separators map to SPACE (2.2)
		{"a \u0301b", whole, " a \u0301b "},   // a SPACE followed by a combining mark is not a space
	} {
		got, ok := prepare(c.in, false, insignificantSpace, c.p)
		if !ok || got != c.want {
			t.Errorf("%q part %d: %q %v, want %q", c.in, c.p, got, ok, c.want)
		}
	}
}

func TestStringPreparation(t *testing.T) {
	for _, c := range []struct {
		in   string
		fold bool
		mode spaceMode
		want string
		ok   bool
	}{
		{"ABC", true, insignificantSpace, " abc ", true},
		{"Stra\u00dfe", true, insignificantSpace, " strasse ", true},                // full case folding
		{"\u2160", true, insignificantSpace, " i ", true},                           // NFKC, then folded again
		{"e\u0301", false, insignificantSpace, " \u00e9 ", true},                    // NFKC composes
		{"\ufb01x", false, insignificantSpace, " fix ", true},                       // NFKC decomposes the ligature
		{"a\u00adb\u200bc\ufe0fd\u0007", false, insignificantSpace, " abcd ", true}, // mapped to nothing, erratum 860
		{"\ufffd", false, insignificantSpace, "", false},                            // prohibited
		{"\ue000", false, insignificantSpace, "", false},                            // private use
		{"\ufdd0", false, insignificantSpace, "", false},                            // non-character
		{"\U0010FFFE", false, insignificantSpace, "", false},                        // non-character
		{"\u0340", false, insignificantSpace, " \u0300 ", true},                     // in C.8, but NFKC makes it U+0300 first
		{"\U000E0080", false, insignificantSpace, "", false},                        // unassigned
		{"\xff", false, insignificantSpace, "", false},                              // not UTF-8
		{"  123  456  ", false, numericSpace, "123456", true},                       // 2.6.2's example
		{"   ", false, numericSpace, "", true},
		{" -123  456 -", true, telephoneSpace, "123456", true}, // 2.6.3's example
		{"---", true, telephoneSpace, "", true},
		{"+1\u2212555", true, telephoneSpace, "+1555", true},
		{"1 \u0301", false, numericSpace, "1 \u0301", true},
	} {
		got, ok := prepare(c.in, c.fold, c.mode, whole)
		if ok != c.ok || got != c.want {
			t.Errorf("%q: %q %v, want %q %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func eq(s *Schema, attr, v, a string) Truth {
	return s.Equal(s.AttributeType(attr), []byte(v), []byte(a))
}
func less(s *Schema, attr, v, a string) Truth {
	return s.Less(s.AttributeType(attr), []byte(v), []byte(a))
}

// Each matching rule of RFC 4517 4.2 that is implemented, through an
// attribute type that uses it.
func TestEqualityRules(t *testing.T) {
	s := Standard()
	for _, c := range []struct {
		attr, v, a string
		want       Truth
	}{
		// caseIgnoreMatch
		{"cn", "Alice  Smith", " alice smith ", True},
		{"cn", "Alice", "Bob", False},
		{"cn", "a\ufffd", "a", Undefined},
		// caseExactMatch (labeledURI)
		{"labeledURI", "http://A  b", "http://A b", True},
		{"labeledURI", "http://A", "http://a", False},
		// caseIgnoreIA5Match / caseExactIA5Match
		{"mail", "A@Example.ORG", "a@example.org", True},
		{"mail", "\u00e9@x", "\u00e9@x", Undefined},
		{"homeDirectory", "/home/A", "/home/a", False},
		{"homeDirectory", "/home/a", "/home/a", True},
		// integerMatch
		{"uidNumber", "1000", "1000", True},
		{"uidNumber", "-5", "-5", True},
		{"uidNumber", "1000", "01000", Undefined},
		{"uidNumber", "-0", "0", Undefined},
		{"uidNumber", "x", "1", Undefined},
		{"uidNumber", "123456789012345678901234567890", "123456789012345678901234567890", True},
		// numericStringMatch
		{"x121Address", "123 456", "123456", True},
		{"x121Address", "123", "124", False},
		// telephoneNumberMatch
		{"telephoneNumber", "+1 512-315-0280", "+15123150280", True},
		{"telephoneNumber", "+1 512", "+1 513", False},
		// octetStringMatch
		{"sshPublicKey", "ssh-ed25519 AAAA", "ssh-ed25519 AAAA", True},
		{"sshPublicKey", "ssh-ed25519 AAAA", "SSH-ED25519 AAAA", False},
		// booleanMatch: none of the standard types uses it; see below.
		// generalizedTimeMatch
		{"createTimestamp", "199412161032Z", "199412160532-0500", True}, // RFC 4517 3.3.13's example
		{"createTimestamp", "1994121610Z", "199412161000Z", True},       // absent minutes are zero
		{"createTimestamp", "199412161032.5Z", "19941216103230Z", True},
		{"createTimestamp", "19941216103230Z", "19941216103231Z", False},
		{"createTimestamp", "19940231103230Z", "19940231103230Z", Undefined},
		// objectIdentifierMatch
		{"objectClass", "person", "2.5.6.6", True},
		{"objectClass", "PERSON", "person", True},
		{"objectClass", "person", "top", False},
		{"objectClass", "nonsense", "person", Undefined},
		// distinguishedNameMatch
		{"member", "UID=Alice, OU=People", "uid=alice,ou=people", True},
		{"member", "cn=Smith\\, John,ou=x", "cn=smith\\2C john,ou=x", True},
		{"member", "cn=a+sn=b,ou=x", "sn=B+cn=A,ou=x", True},
		{"member", "cn=a,ou=x", "cn=a,ou=y", False},
		{"member", "cn=a,ou=x", "cn=a", False},
		{"member", "cn=a+sn=b", "cn=a", False},
		{"member", "cn=a+sn=b", "cn=a+uid=b", False},
		{"member", "cn=#04024869", "cn=hi", True}, // RFC 4514's hex form: an OCTET STRING "Hi"
		{"member", "shoeSize=12", "shoeSize=12", Undefined},
		{"member", "cn=a+cn=b", "cn=a+cn=b", Undefined},
		{"member", "uidNumber=01", "uidNumber=01", Undefined},
		{"member", "not a dn", "cn=a", Undefined},
		{"member", "", "", True},
		// uniqueMemberMatch
		{"uniqueMember", "cn=a,o=x#'0101'B", "CN=A, O=X#'0101'B", True},
		{"uniqueMember", "cn=a,o=x#'0101'B", "cn=a,o=x#'0100'B", False},
		{"uniqueMember", "cn=a,o=x#'0101'B", "cn=a,o=x", False},
		{"uniqueMember", "cn=a,o=x", "cn=a,o=x", True},
		// caseIgnoreListMatch
		{"postalAddress", "1 Main St$Springfield", "1 MAIN  ST$springfield", True},
		{"postalAddress", "a\\24b$c", "A$B$C", False},
		{"postalAddress", "a\\24b$c\\5C", "a\\24B$C\\5c", True},
		{"postalAddress", "a$$b", "a$$b", Undefined},
		{"postalAddress", "a\\41", "a\\41", Undefined},
		{"postalAddress", "a$", "a$", Undefined},
		{"postalAddress", "a$\xff", "a$b", Undefined},
		// objectIdentifierFirstComponentMatch
		{"attributeTypes", "( 2.5.4.3 NAME 'cn' SUP name )", "cn", True},
		{"attributeTypes", "( 2.5.4.3 NAME 'cn' SUP name )", "2.5.4.4", False},
		// integerFirstComponentMatch
		{"dITStructureRules", "( 2 DESC 'x' FORM y )", "2", True},
		{"dITStructureRules", "( 2 DESC 'x' FORM y )", "3", False},
		// no EQUALITY at all: RFC 4512 2.5.1
		{"photo", "x", "x", Undefined},
		// a rule that is defined and not implemented: RFC 4523
		{"userCertificate", "x", "x", Undefined},
	} {
		if got := eq(s, c.attr, c.v, c.a); got != c.want {
			t.Errorf("%s: %q = %q is %v, want %v", c.attr, c.v, c.a, got, c.want)
		}
	}
}

func TestOrderingRules(t *testing.T) {
	s := Standard()
	for _, c := range []struct {
		attr, v, a string
		want       Truth
	}{
		{"createTimestamp", "20260101000000Z", "20261012000000Z", True},
		{"createTimestamp", "20261012000000Z", "20260101000000Z", False},
		{"createTimestamp", "20261012000000+0200", "20261012000000Z", True}, // two hours earlier
		{"createTimestamp", "202610120000Z", "20261012000000.5Z", True},
		{"createTimestamp", "nonsense", "20261012000000Z", Undefined},
		// uidNumber orders as an integer (rfc2307.schema says why it has the rule).
		{"uidNumber", "999", "1000", True},
		{"gidNumber", "10000", "9999", False},
		// RFC 4519: serialNumber... has none either; title has none.
		{"title", "a", "b", Undefined},
	} {
		if got := less(s, c.attr, c.v, c.a); got != c.want {
			t.Errorf("%s: %q < %q is %v, want %v", c.attr, c.v, c.a, got, c.want)
		}
	}
}

// The rules no standard attribute type uses for its own EQUALITY or
// ORDERING are tested as an extensible match uses them, through Rule.
func TestRulesAsAnExtensibleMatchUsesThem(t *testing.T) {
	s := Standard()
	for _, c := range []struct {
		rule, v, a string
		want       Truth
	}{
		{"integerOrderingMatch", "999", "1000", True}, // integers, not strings
		{"integerOrderingMatch", "10000", "9999", False},
		{"integerOrderingMatch", "-10", "-9", True},
		{"integerOrderingMatch", "1", "x", Undefined},
		{"caseIgnoreOrderingMatch", "Apple", "banana", True},
		{"caseIgnoreOrderingMatch", "banana", "APPLE", False},
		{"caseExactOrderingMatch", "Banana", "apple", True},
		{"numericStringOrderingMatch", "1 2", "13", True},
		{"octetStringOrderingMatch", "ab", "abc", True},
		{"octetStringOrderingMatch", "b", "abc", False},
		{"booleanMatch", "TRUE", "true", True},
		{"booleanMatch", "TRUE", "FALSE", False},
		{"booleanMatch", "yes", "TRUE", Undefined},
		{"bitStringMatch", "'0101'B", "'0101'b", True},
		{"bitStringMatch", "'0101'B", "'01010'B", False},
		{"bitStringMatch", "'0121'B", "'0101'B", Undefined},
		{"bitStringMatch", "0101", "'0101'B", Undefined},
		{"bitStringMatch", "'0101'X", "'0101'B", Undefined},
		{"wordMatch", "The Quick Fox", "quick", True},
		{"wordMatch", "The Quick Fox", "qui", False},
		{"keywordMatch", "a b", " B ", True},
		{"wordMatch", "a\ufffd", "a", Undefined},
		{"wordMatch", "a", "\ufffd", Undefined},
		{"caseIgnoreSubstringsMatch", "Alice Smith", "al*sm*", True},
		{"caseIgnoreSubstringsMatch", "Alice Smith", "*smith", True},
		{"caseIgnoreSubstringsMatch", "Alice Smith", "al*x*", False},
		{"caseIgnoreSubstringsMatch", "a*b", `a\2A*`, True},
		{"caseIgnoreSubstringsMatch", `a\b`, `*\5c*`, True},
		{"caseIgnoreSubstringsMatch", "ab", "a**b", Undefined}, // a zero-length substring
		{"caseIgnoreSubstringsMatch", "ab", "ab", Undefined},   // no asterisk at all
		{"caseIgnoreSubstringsMatch", "ab", `a\41*`, Undefined},
		{"directoryStringFirstComponentMatch", "x", "x", Undefined}, // defined, not implemented
		{"certificateExactMatch", "x", "x", Undefined},
	} {
		r := s.MatchingRule(c.rule)
		if got := s.Rule(r, []byte(c.v), []byte(c.a)); got != c.want {
			t.Errorf("%s(%q, %q) is %v, want %v", c.rule, c.v, c.a, got, c.want)
		}
	}
	if Implemented(nil) || Implemented(s.MatchingRule("certificateExactMatch")) || !Implemented(s.MatchingRule("caseIgnoreMatch")) {
		t.Error("Implemented")
	}
	// An equality rule asked for as an ordering is Undefined, not a guess.
	if s.evaluate(s.MatchingRule("caseIgnoreMatch"), ordering, []byte("a"), []byte("b")) != Undefined || s.evaluate(nil, equality, nil, nil) != Undefined {
		t.Error("evaluate with the wrong kind of rule")
	}
}

// RFC 4517 4.2.13: substrings match disjoint portions, in order, with RFC
// 4518's space handling -- and (cn=foo\20*\20bar) matches "foo  bar"
// (RFC 4518 Appendix B).
func TestSubstringRules(t *testing.T) {
	s := Standard()
	sub := func(attr, v string, ini string, any []string, fin string) Truth {
		a := SubstringAssertion{}
		if ini != "" {
			a.Initial = []byte(ini)
		}
		for _, x := range any {
			a.Any = append(a.Any, []byte(x))
		}
		if fin != "" {
			a.Final = []byte(fin)
		}
		return s.Substrings(s.AttributeType(attr), []byte(v), a)
	}
	for _, c := range []struct {
		attr, v, ini string
		any          []string
		fin          string
		want         Truth
	}{
		{"cn", "svc-web-stage", "svc-", nil, "-prod", False},
		{"cn", "svc-prod", "svc-", nil, "-prod", False}, // no overlap
		{"cn", "SVC-web-PROD", "svc-", nil, "-prod", True},
		{"cn", "foo  bar", "foo ", nil, " bar", True},
		{"cn", "foobar", "foo ", nil, " bar", False},
		{"cn", "foo bar", "", []string{"foo bar"}, "", True}, // erratum 1757
		{"cn", "a b c", "", []string{"b", "c"}, "", True},
		{"cn", "a b c", "", []string{"c", "b"}, "", False},
		{"cn", "abc", "x", nil, "", False},
		{"cn", "a\ufffd", "a", nil, "", Undefined},
		{"cn", "abc", "\ufffd", nil, "", Undefined},
		{"cn", "abc", "", nil, "\ufffd", Undefined},
		{"cn", "abc", "", []string{"\ufffd"}, "", Undefined},
		{"telephoneNumber", "+1 512-315-0280", "+1512", []string{"315"}, "280", True},
		{"x121Address", "123 456", "12", nil, "3 4 5 6", True},
		{"mail", "A@Example.org", "a@", nil, ".ORG", True},
		{"memberUid", "Alice", "al", nil, "", False}, // caseExactIA5SubstringsMatch
		{"memberUid", "alice", "al", nil, "", True},
		{"postalAddress", "1 Main$Springfield", "1 main", nil, "field", True},
		{"postalAddress", "1 Main$Springfield", "", []string{"mainspring"}, "", False}, // spans two lines
		{"postalAddress", "$", "", []string{"x"}, "", Undefined},
		{"uid", "x", "x", nil, "", True},
		{"objectClass", "person", "per", nil, "", Undefined}, // no SUBSTR rule
	} {
		if got := sub(c.attr, c.v, c.ini, c.any, c.fin); got != c.want {
			t.Errorf("%s %q ~ %q %q %q: %v, want %v", c.attr, c.v, c.ini, c.any, c.fin, got, c.want)
		}
	}
	// A rule that is not a substrings rule, as SUBSTR, is Undefined.
	if s.substrings(s.MatchingRule("caseIgnoreMatch"), []byte("a"), SubstringAssertion{}) != Undefined {
		t.Error("an equality rule as a substrings rule")
	}
}

func TestGeneralizedTime(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string // RFC 3339 in UTC, "" for invalid
	}{
		{"199412161032Z", "1994-12-16T10:32:00Z"},
		{"199412160532-0500", "1994-12-16T10:32:00Z"},
		{"1994121605+05", "1994-12-16T00:00:00Z"},
		{"1994121610.5Z", "1994-12-16T10:30:00Z"},
		{"199412161032,25Z", "1994-12-16T10:32:15Z"},
		{"19941216103230.123456789Z", "1994-12-16T10:32:30.123456789Z"},
		{"19981231235960Z", "1999-01-01T00:00:00Z"}, // a leap second
		{"19940229000000Z", ""},
		{"19941316000000Z", ""},
		{"19941200000000Z", ""},
		{"1994121624Z", ""},
		{"199412161060Z", ""},
		{"19941216106161Z", ""},
		{"19941216105961Z", ""},
		{"1994121610.Z", ""},
		{"1994121610", ""},
		{"1994121610X", ""},
		{"1994121610+24", ""},
		{"1994121610+0060", ""},
		{"1994121610+1", ""},
		{"1994121610ZZ", ""},
		{"199412", ""},
		{"19941216 0Z", ""},
	} {
		tm, ok := parseGeneralizedTime(c.in)
		got := ""
		if ok {
			got = tm.UTC().Format(time.RFC3339Nano)
		}
		if got != c.want {
			t.Errorf("%q: %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDNParsing(t *testing.T) {
	for _, c := range []struct {
		in   string
		ok   bool
		avas int
	}{
		{"", true, 0},
		{"uid=a,dc=example,dc=org", true, 3},
		{"uid = a , dc = b", true, 2},
		{"cn=a+sn=b;o=c", true, 3},
		{`cn=\"q\"\<\>,o=x`, true, 2},
		{"cn=#0401", false, 0},    // length says 1, has 0
		{"cn=#04", false, 0},      // too short
		{"cn=#0481", false, 0},    // long form with no octets
		{"cn=#048101ff", true, 1}, // long form
		{"cn=#2400", false, 0},    // constructed
		{"cn=#0g", false, 0},
		{"cn=#0400 ,o=x", true, 2},
		{"cn=#0400 x", false, 0}, // not hex
		{"cn=#0485000000000000", false, 0},
		{"cn=a\\", false, 0},
		{"cn=a\\q", false, 0},
		{`cn="a"`, false, 0},
		{"cn=a=b", true, 1}, // RFC 4514 2.4 does not require = to be escaped
		{"=a", false, 0},
		{"cn", false, 0},
		{"cn=a,", false, 0},
		{"1cn=a", false, 0},
		{"cn=a+", false, 0},
	} {
		avas := DNValues(c.in)
		_, err := parseDN(c.in)
		if (err == nil) != c.ok || len(avas) != c.avas {
			t.Errorf("%q: %v, %d AVAs", c.in, err, len(avas))
		}
	}
	if a := DNValues(`cn=Smith\, John  ,o=x`); string(a[0].Value) != "Smith, John" || a[0].Type != "cn" {
		t.Errorf("%q", a[0].Value)
	}
	if a := DNValues(`cn=a\20`); string(a[0].Value) != "a " {
		t.Errorf("an escaped trailing space is kept: %q", a[0].Value)
	}
	s := Standard()
	if s.MatchDN("CN=Subschema", "cn=subschema") != True || s.MatchDN("cn=Subschema", "cn=Sub") != False {
		t.Error("MatchDN")
	}
}
