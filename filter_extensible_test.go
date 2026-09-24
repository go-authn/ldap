// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// An extensible match carries four optional-ish fields, and every
// combination has to survive the wire -- including the ones this server
// refuses to EVALUATE. Refusing to evaluate is not the same as failing to
// parse: a server must be able to read the filter in order to say
// inappropriateMatching about it rather than protocolError, and those send a
// client to different places.
func TestAnExtensibleMatchSurvivesTheWireInEveryShape(t *testing.T) {
	for _, src := range []string{
		"(cn:=alice)",
		"(cn:dn:=alice)",
		"(cn:2.5.13.2:=alice)",
		"(cn:dn:2.5.13.2:=alice)",
		"(:2.5.13.2:=alice)",
		"(memberOf:1.2.840.113556.1.4.1941:=cn=admins,dc=example,dc=org)",
	} {
		f, err := ParseFilter(src)
		if err != nil {
			t.Errorf("%s: %v", src, err)
			continue
		}
		p, err := EncodeFilter(f)
		if err != nil {
			t.Errorf("%s: encoding: %v", src, err)
			continue
		}
		reread, err := ber.DecodePacketErr(p.Bytes())
		if err != nil {
			t.Errorf("%s: the bytes do not parse: %v", src, err)
			continue
		}
		back, err := DecodeFilter(reread)
		if err != nil {
			t.Errorf("%s: decoding: %v", src, err)
			continue
		}
		if back.String() != f.String() {
			t.Errorf("%s\n  went out as %s\n  came back as %s", src, f.String(), back.String())
		}
		got, want := back.(*ExtensibleMatch), f.(*ExtensibleMatch)
		if got.MatchingRule != want.MatchingRule || got.Attribute != want.Attribute ||
			got.DNAttributes != want.DNAttributes || got.Value != want.Value {
			t.Errorf("%s came back as %+v, want %+v", src, got, want)
		}
	}
}

// The extensible matches that are not extensible matches.
func TestMalformedExtensibleMatchesAreRefused(t *testing.T) {
	build := func(fields ...*ber.Packet) *ber.Packet {
		p := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagFilterExtensibleMatch, nil, "ext")
		for _, f := range fields {
			p.AppendChild(f)
		}
		return p
	}
	str := func(tag ber.Tag, v string) *ber.Packet {
		return ber.NewString(ber.ClassContext, ber.TypePrimitive, tag, v, "f")
	}

	// No matchValue at all: there is nothing to match against.
	if _, err := DecodeFilter(build(str(tagMatchType, "cn"))); err == nil {
		t.Error("an extensible match with no value was accepted")
	}
	// Neither a rule nor a type: RFC 4511 4.5.1.7.7 requires the type when
	// the rule is absent.
	if _, err := DecodeFilter(build(str(tagMatchValue, "alice"))); err == nil {
		t.Error("an extensible match with neither a rule nor a type was accepted")
	}
	// A rule alone IS legal -- it means "apply this rule to every attribute".
	if _, err := DecodeFilter(build(str(tagMatchingRule, "2.5.13.2"), str(tagMatchValue, "alice"))); err != nil {
		t.Errorf("a rule-only extensible match was refused: %v", err)
	}
	// dnAttributes present and false, which is the DEFAULT and so should not
	// normally be sent -- but must be read correctly if it is.
	f, err := DecodeFilter(build(
		str(tagMatchType, "cn"), str(tagMatchValue, "alice"),
		ber.NewBoolean(ber.ClassContext, ber.TypePrimitive, tagDNAttributes, false, "dn"),
	))
	if err != nil {
		t.Fatal(err)
	}
	if f.(*ExtensibleMatch).DNAttributes {
		t.Error("an explicit dnAttributes=FALSE was read as true")
	}
}

// ⛔ An error inside a nested filter must reach the caller, not be swallowed
// and turned into an empty conjunction -- an AND that lost a member matches
// MORE than it was asked to.
func TestAnErrorInsideAConjunctionIsNotSwallowed(t *testing.T) {
	// Encoding: a conjunction holding something that cannot be encoded.
	if _, err := EncodeFilter(&And{Filters: []Filter{nil}}); err == nil {
		t.Error("an AND holding an unencodable filter was encoded")
	}
	if _, err := EncodeFilter(&Or{Filters: []Filter{&Present{Attribute: "cn"}, nil}}); err == nil {
		t.Error("an OR holding an unencodable filter was encoded")
	}
	if _, err := EncodeFilter(&Not{Filter: nil}); err == nil {
		t.Error("a NOT holding an unencodable filter was encoded")
	}

	// Decoding: a conjunction holding a component with a tag that is not a
	// filter.
	bad := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagFilterAnd, nil, "and")
	bad.AppendChild(ber.Encode(ber.ClassContext, ber.TypeConstructed, ber.Tag(15), nil, "?"))
	if f, err := DecodeFilter(bad); err == nil {
		t.Errorf("an AND holding a non-filter decoded as %s", f.String())
	}
	deep := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagFilterNot, nil, "not")
	deep.AppendChild(bad)
	if _, err := DecodeFilter(deep); err == nil {
		t.Error("a NOT holding a broken AND decoded")
	}
}

// The substring string form, in each of its shapes -- the renderer has a
// branch per component and a filter that renders wrongly is one an audit
// cannot compare against the one that was asked.
func TestSubstringsRenderInEveryShape(t *testing.T) {
	for _, tc := range []struct {
		f    *Substrings
		want string
	}{
		{&Substrings{Attribute: "uid", Initial: "svc-", Final: "-prod"}, "(uid=svc-*-prod)"},
		{&Substrings{Attribute: "uid", Initial: "svc-"}, "(uid=svc-*)"},
		{&Substrings{Attribute: "uid", Final: "-prod"}, "(uid=*-prod)"},
		{&Substrings{Attribute: "uid", Any: []string{"web"}}, "(uid=*web*)"},
		{&Substrings{Attribute: "uid", Any: []string{"a", "b"}}, "(uid=*a*b*)"},
		{&Substrings{Attribute: "uid", Initial: "a", Any: []string{"b"}, Final: "c"}, "(uid=a*b*c)"},
		// A value carrying a character that IS syntax must come back escaped,
		// or the rendering means something else than the filter does.
		{&Substrings{Attribute: "cn", Initial: "O'Brien (", Final: ")"}, `(cn=O'Brien \28*\29)`},
	} {
		if got := tc.f.String(); got != tc.want {
			t.Errorf("rendered %q, want %q", got, tc.want)
		}
		// And it parses back to the same thing.
		back, err := ParseFilter(tc.want)
		if err != nil {
			t.Errorf("%s does not parse: %v", tc.want, err)
			continue
		}
		if back.String() != tc.want {
			t.Errorf("%s round-tripped to %s", tc.want, back.String())
		}
	}
}

// The escapes, both ways, including the ones that are refused.
func TestEscapesGoOutAndComeBack(t *testing.T) {
	for _, v := range []string{"", "plain", "star*", "paren(", "close)", `back\slash`, "\x00null", "all*()\\ of them"} {
		f := &Equality{Attribute: "cn", Value: v}
		back, err := ParseFilter(f.String())
		if err != nil {
			t.Errorf("%q rendered as %s, which does not parse: %v", v, f.String(), err)
			continue
		}
		if got := back.(*Equality).Value; got != v {
			t.Errorf("%q came back as %q", v, got)
		}
	}
	// Every hex digit case, upper and lower.
	f, err := ParseFilter(`(cn=\2A\2a\aB\Ab)`)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.(*Equality).Value; got != "**\xab\xab" {
		t.Errorf("mixed-case hex came back as %q", got)
	}
	// And a substring value with an escape inside a component.
	sub, err := ParseFilter(`(cn=a\2ab*c\29d)`)
	if err != nil {
		t.Fatal(err)
	}
	s := sub.(*Substrings)
	if s.Initial != "a*b" || s.Final != "c)d" {
		t.Errorf("components came back as %q / %q", s.Initial, s.Final)
	}
	// A bad escape inside each position is refused rather than half-read.
	for _, bad := range []string{`(cn=\zz*x)`, `(cn=x*\zz)`, `(cn=x*\zz*y)`, `(cn:=\zz)`, `(cn>=\zz)`, `(cn<=\zz)`, `(cn~=\zz)`} {
		if _, err := ParseFilter(bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

// An empty conjunction on the wire, which is RFC 4526's absolute-true and
// absolute-false filter.
func TestEmptyConjunctionsSurviveTheWire(t *testing.T) {
	for _, src := range []string{"(&)", "(|)"} {
		f, err := ParseFilter(src)
		if err != nil {
			t.Fatal(err)
		}
		p, err := EncodeFilter(f)
		if err != nil {
			t.Fatal(err)
		}
		reread, err := ber.DecodePacketErr(p.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		back, err := DecodeFilter(reread)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if back.String() != src {
			t.Errorf("%s came back as %s", src, back.String())
		}
	}
}

func TestTrailingRubbishAfterAFilterIsRefused(t *testing.T) {
	if _, err := ParseFilter("(cn=a)(cn=b)"); err == nil {
		t.Error("two filters side by side parsed as one")
	} else if !strings.Contains(err.Error(), "trailing") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// The last handful of paths, each one a refusal a client can provoke.
func TestTheRemainingRefusals(t *testing.T) {
	// A conjunction whose member is not parenthesised.
	if _, err := ParseFilter("(&cn=a)"); err == nil {
		t.Error("an AND with an unparenthesised member parsed")
	}
	// A conjunction that never closes.
	if _, err := ParseFilter("(|(cn=a)"); err == nil {
		t.Error("an unclosed OR parsed")
	}
	// An extensible match with no ':=' at all.
	if _, err := ParseFilter("(cn:dn)"); err == nil {
		t.Error("an extensible match with no ':=' parsed")
	}
	// A substrings packet whose component list holds something that is
	// neither initial, any nor final.
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagFilterSubstrings, nil, "sub")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "a"))
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Substrings")
	seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.Tag(7), "x", "?"))
	p.AppendChild(seq)
	if _, err := DecodeFilter(p); err == nil {
		t.Error("a substring component with an unknown tag decoded")
	}
}

// ⛔ A broken member inside a conjunction must abort the whole filter. An AND
// that quietly dropped an unparseable member would match MORE than it was
// asked to, which in a directory is disclosure -- the same failure shape as
// the substring bug, one level up.
func TestABrokenMemberAbortsItsConjunction(t *testing.T) {
	for _, bad := range []string{
		"(&(cn=a)(sn))",     // a member with no operator
		"(|(cn=a)(sn:dn))",  // a member with no ':='
		`(&(cn=a)(sn=\zz))`, // a member with a bad escape
		"(&(cn=a)(&(sn)))",  // nested two deep
		"(cn",               // ends inside the attribute, with no operator at all
	} {
		if f, err := ParseFilter(bad); err == nil {
			t.Errorf("%s parsed as %s", bad, f.String())
		}
	}
}
