// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// ⭐ The property that the three-way drift broke, asserted across the WIRE
// this time: a filter encoded and decoded again must mean the same thing
// about every entry, and must render to the same string.
//
// String and the wire form are two renderings of one tree. If they can
// disagree, a server answers a different question from the one a client
// asked -- which is exactly how `(uid=svc-*-prod)` became `(uid=svc-*)`.
func TestAFilterSurvivesTheWire(t *testing.T) {
	corpus := []*Entry{
		entry("a", "uid", "svc-web-prod", "mail", "a@example.org"),
		entry("b", "uid", "svc-prod"),
		entry("c", "uid", "APP-Web-Prod"),
		entry("d", "cn", "O'Brien (contractor)"),
		entry("e", "cn", "10*"),
	}
	for _, src := range []string{
		"(uid=svc-*-prod)", "(uid=*)", "(uid=*a*b*c*)",
		"(&(uid=svc-*)(mail=*))", "(|(uid=svc-prod)(cn=10\\2a))",
		"(!(mail=*))", "(cn=O'Brien \\28contractor\\29)",
		"(uid>=svc)", "(uid<=svc-z)", "(uid~=svc-prod)",
		"(&)", "(|)", "(uid=a*)", "(uid=*a)",
	} {
		f, err := ParseFilter(src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		p, err := EncodeFilter(f)
		if err != nil {
			t.Errorf("%s: encoding: %v", src, err)
			continue
		}
		// Through the actual bytes, not the packet object: a packet that has
		// never been serialised and re-read has not been tested.
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
		for _, e := range corpus {
			if f.Matches(e) != back.Matches(e) {
				t.Errorf("%s and its wire round trip disagree about %s", src, e.DN)
			}
		}
	}
}

// ⛔ A filter arrives from the network and is recursive. Nested far enough,
// decoding it overflows the goroutine stack -- and a stack overflow in Go is
// not a panic that recover can catch: it kills the PROCESS. One
// unauthenticated packet would take the directory down for everybody.
//
// Three bytes per level, so the packet that does it is tiny. The depth is
// what is bounded, not the size.
func TestADeeplyNestedFilterIsRefusedRatherThanRecursedInto(t *testing.T) {
	// Build (!(!(!(...)))) far past the limit, by hand.
	deep := ber.Encode(ber.ClassContext, ber.TypePrimitive, tagFilterPresent, nil, "Present")
	deep.Data.WriteString("cn")
	deep.Value = "cn"
	for i := 0; i < maxFilterDepth*4; i++ {
		outer := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagFilterNot, nil, "Not")
		outer.AppendChild(deep)
		deep = outer
	}
	if _, err := DecodeFilter(deep); err == nil {
		t.Fatal("a filter nested far past the limit was decoded")
	} else if !strings.Contains(err.Error(), "nests deeper") {
		t.Errorf("refused, but for the wrong reason: %v", err)
	}

	// And the control: something well within the limit still works, or the
	// test above would pass on a decoder that refuses everything.
	shallow := ber.Encode(ber.ClassContext, ber.TypePrimitive, tagFilterPresent, nil, "Present")
	shallow.Data.WriteString("cn")
	for i := 0; i < 10; i++ {
		outer := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagFilterNot, nil, "Not")
		outer.AppendChild(shallow)
		shallow = outer
	}
	if _, err := DecodeFilter(shallow); err != nil {
		t.Errorf("ten levels were refused: %v", err)
	}
}

// ⛔ Malformed packets are REFUSED, not panicked on. Every one of these is
// something a client can send, and the library this replaces indexed
// Children[0] without checking length in several of these positions.
func TestMalformedFiltersAreRefusedNotPanics(t *testing.T) {
	ctx := func(tag ber.Tag, desc string) *ber.Packet {
		return ber.Encode(ber.ClassContext, ber.TypeConstructed, tag, nil, desc)
	}
	for _, tc := range []struct {
		what string
		p    *ber.Packet
	}{
		{"an equality with no children", ctx(tagFilterEqualityMatch, "eq")},
		{"an equality with one child", func() *ber.Packet {
			p := ctx(tagFilterEqualityMatch, "eq")
			p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "a"))
			return p
		}()},
		{"a NOT with no children", ctx(tagFilterNot, "not")},
		{"a NOT with two children", func() *ber.Packet {
			p := ctx(tagFilterNot, "not")
			p.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagFilterPresent, "cn", "p"))
			p.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagFilterPresent, "sn", "p"))
			return p
		}()},
		{"substrings with no children", ctx(tagFilterSubstrings, "sub")},
		{"substrings with an empty component list", func() *ber.Packet {
			p := ctx(tagFilterSubstrings, "sub")
			p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "a"))
			p.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Substrings"))
			return p
		}()},
		{"an extensible match with no value", ctx(tagFilterExtensibleMatch, "ext")},
		{"a filter tag that is not one of the nine", ctx(ber.Tag(15), "?")},
		{"no packet at all", nil},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s PANICKED: %v", tc.what, r)
				}
			}()
			if f, err := DecodeFilter(tc.p); err == nil {
				t.Errorf("%s was decoded as %s", tc.what, f.String())
			}
		}()
	}
}

// ⛔ RFC 4511 4.5.1.7.2: `initial` can occur at most once and comes first,
// `final` at most once and comes last. A packet that puts them elsewhere is
// refused rather than reinterpreted -- reinterpreting silently answers a
// different question, which is the whole failure this package is built
// around.
func TestSubstringComponentsMustBeInTheirPlaces(t *testing.T) {
	build := func(tags ...ber.Tag) *ber.Packet {
		p := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagFilterSubstrings, nil, "sub")
		p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid", "a"))
		seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Substrings")
		for _, tag := range tags {
			seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tag, "x", "c"))
		}
		p.AppendChild(seq)
		return p
	}
	for _, tc := range []struct {
		what string
		tags []ber.Tag
		ok   bool
	}{
		{"initial, any, final", []ber.Tag{tagSubstringInitial, tagSubstringAny, tagSubstringFinal}, true},
		{"any alone", []ber.Tag{tagSubstringAny}, true},
		{"several anys", []ber.Tag{tagSubstringAny, tagSubstringAny, tagSubstringAny}, true},
		{"initial LAST", []ber.Tag{tagSubstringAny, tagSubstringInitial}, false},
		{"final FIRST", []ber.Tag{tagSubstringFinal, tagSubstringAny}, false},
		{"two initials", []ber.Tag{tagSubstringInitial, tagSubstringInitial}, false},
		{"two finals", []ber.Tag{tagSubstringFinal, tagSubstringFinal}, false},
	} {
		_, err := DecodeFilter(build(tc.tags...))
		if tc.ok && err != nil {
			t.Errorf("%s was refused: %v", tc.what, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s was accepted", tc.what)
		}
	}
}
