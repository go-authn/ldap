// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// The wire form of a filter (RFC 4511 4.5.1.7). It reads into the SAME tree
// the string form parses into -- see the comment on Filter.

// The context tags of the Filter CHOICE.
const (
	tagFilterAnd             = 0
	tagFilterOr              = 1
	tagFilterNot             = 2
	tagFilterEqualityMatch   = 3
	tagFilterSubstrings      = 4
	tagFilterGreaterOrEqual  = 5
	tagFilterLessOrEqual     = 6
	tagFilterPresent         = 7
	tagFilterApproxMatch     = 8
	tagFilterExtensibleMatch = 9
)

// The tags inside a SubstringFilter.
const (
	tagSubstringInitial = 0
	tagSubstringAny     = 1
	tagSubstringFinal   = 2
)

// The tags inside a MatchingRuleAssertion.
const (
	tagMatchingRule = 1
	tagMatchType    = 2
	tagMatchValue   = 3
	tagDNAttributes = 4
)

// maxFilterDepth bounds how deeply a filter may nest.
//
// ⛔ A filter is recursive and arrives from the network. `(!(!(!(...))))`
// nested far enough overflows the goroutine stack, and a stack overflow in
// Go is not a panic a recover can catch -- it kills the PROCESS, so one
// unauthenticated packet takes the directory down for everybody. The depth
// is bounded rather than the packet size, because the size that produces a
// given depth is tiny: three bytes per level.
const maxFilterDepth = 96

// DecodeFilter reads a Filter from its BER packet.
func DecodeFilter(p *ber.Packet) (Filter, error) { return decodeFilter(p, 0) }

func decodeFilter(p *ber.Packet, depth int) (Filter, error) {
	if p == nil {
		return nil, fmt.Errorf("ldap: a filter with no packet")
	}
	if depth > maxFilterDepth {
		return nil, fmt.Errorf("ldap: the filter nests deeper than %d", maxFilterDepth)
	}
	switch p.Tag {
	case tagFilterAnd, tagFilterOr:
		subs := make([]Filter, 0, len(p.Children))
		for _, c := range p.Children {
			sub, err := decodeFilter(c, depth+1)
			if err != nil {
				return nil, err
			}
			subs = append(subs, sub)
		}
		if p.Tag == tagFilterAnd {
			return &And{Filters: subs}, nil
		}
		return &Or{Filters: subs}, nil

	case tagFilterNot:
		// A NOT holds exactly one filter. Some encoders wrap it in a child
		// and some place it inline, so both are accepted -- but a NOT of
		// NOTHING is refused rather than treated as true or false, since
		// there is no defensible choice between them.
		if len(p.Children) == 1 {
			sub, err := decodeFilter(p.Children[0], depth+1)
			if err != nil {
				return nil, err
			}
			return &Not{Filter: sub}, nil
		}
		return nil, fmt.Errorf("ldap: a NOT filter with %d children, want 1", len(p.Children))

	case tagFilterEqualityMatch, tagFilterGreaterOrEqual, tagFilterLessOrEqual, tagFilterApproxMatch:
		attr, value, err := assertion(p)
		if err != nil {
			return nil, err
		}
		switch p.Tag {
		case tagFilterEqualityMatch:
			return &Equality{Attribute: attr, Value: value}, nil
		case tagFilterGreaterOrEqual:
			return &GreaterOrEqual{Attribute: attr, Value: value}, nil
		case tagFilterLessOrEqual:
			return &LessOrEqual{Attribute: attr, Value: value}, nil
		}
		return &Approx{Attribute: attr, Value: value}, nil

	case tagFilterPresent:
		// present is [7] AttributeDescription -- the octets ARE the name,
		// with no SEQUENCE around them.
		return &Present{Attribute: string(p.Data.Bytes())}, nil

	case tagFilterSubstrings:
		return decodeSubstrings(p)

	case tagFilterExtensibleMatch:
		return decodeExtensible(p)
	}
	return nil, fmt.Errorf("ldap: filter tag %d is not one of the nine", p.Tag)
}

// assertion reads an AttributeValueAssertion: two octet strings.
func assertion(p *ber.Packet) (attribute, value string, err error) {
	if len(p.Children) != 2 {
		return "", "", fmt.Errorf("ldap: an assertion with %d children, want 2", len(p.Children))
	}
	return string(p.Children[0].Data.Bytes()), string(p.Children[1].Data.Bytes()), nil
}

func decodeSubstrings(p *ber.Packet) (Filter, error) {
	if len(p.Children) != 2 {
		return nil, fmt.Errorf("ldap: a substrings filter with %d children, want 2", len(p.Children))
	}
	f := &Substrings{Attribute: string(p.Children[0].Data.Bytes())}
	parts := p.Children[1].Children
	if len(parts) == 0 {
		// RFC 4511 4.5.1.7.2: SIZE (1..MAX). An empty one asserts nothing,
		// and treating it as "matches everything" is how an empty filter
		// returns the directory.
		return nil, fmt.Errorf("ldap: a substrings filter with no components")
	}
	for i, c := range parts {
		v := string(c.Data.Bytes())
		switch c.Tag {
		case tagSubstringInitial:
			// "can occur at most once", and first.
			if f.Initial != "" || i != 0 {
				return nil, fmt.Errorf("ldap: an `initial` substring at position %d", i)
			}
			f.Initial = v
		case tagSubstringAny:
			f.Any = append(f.Any, v)
		case tagSubstringFinal:
			// "can occur at most once", and last.
			if f.Final != "" || i != len(parts)-1 {
				return nil, fmt.Errorf("ldap: a `final` substring at position %d of %d", i, len(parts))
			}
			f.Final = v
		default:
			return nil, fmt.Errorf("ldap: substring component tag %d is not initial, any or final", c.Tag)
		}
	}
	return f, nil
}

func decodeExtensible(p *ber.Packet) (Filter, error) {
	f := &ExtensibleMatch{}
	seen := false
	for _, c := range p.Children {
		switch c.Tag {
		case tagMatchingRule:
			f.MatchingRule = string(c.Data.Bytes())
		case tagMatchType:
			f.Attribute = string(c.Data.Bytes())
		case tagMatchValue:
			f.Value = string(c.Data.Bytes())
			seen = true
		case tagDNAttributes:
			b := c.Data.Bytes()
			f.DNAttributes = len(b) > 0 && b[0] != 0
		}
	}
	if !seen {
		return nil, fmt.Errorf("ldap: an extensible match with no matchValue")
	}
	if f.MatchingRule == "" && f.Attribute == "" {
		// RFC 4511 4.5.1.7.7: if matchingRule is absent, type MUST be
		// present. Neither leaves nothing to match against.
		return nil, fmt.Errorf("ldap: an extensible match with neither a rule nor an attribute")
	}
	return f, nil
}

// EncodeFilter writes a Filter as its BER packet.
func EncodeFilter(f Filter) (*ber.Packet, error) {
	switch t := f.(type) {
	case *And:
		return encodeSet(tagFilterAnd, "And", t.Filters)
	case *Or:
		return encodeSet(tagFilterOr, "Or", t.Filters)
	case *Not:
		p := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagFilterNot, nil, "Not")
		sub, err := EncodeFilter(t.Filter)
		if err != nil {
			return nil, err
		}
		p.AppendChild(sub)
		return p, nil
	case *Equality:
		return encodeAssertion(tagFilterEqualityMatch, "Equality", t.Attribute, t.Value), nil
	case *GreaterOrEqual:
		return encodeAssertion(tagFilterGreaterOrEqual, "GreaterOrEqual", t.Attribute, t.Value), nil
	case *LessOrEqual:
		return encodeAssertion(tagFilterLessOrEqual, "LessOrEqual", t.Attribute, t.Value), nil
	case *Approx:
		return encodeAssertion(tagFilterApproxMatch, "Approx", t.Attribute, t.Value), nil
	case *Present:
		return ber.NewString(ber.ClassContext, ber.TypePrimitive, tagFilterPresent, t.Attribute, "Present"), nil
	case *Substrings:
		return encodeSubstrings(t), nil
	case *ExtensibleMatch:
		return encodeExtensible(t), nil
	}
	return nil, fmt.Errorf("ldap: %T is not a filter this package can encode", f)
}

func encodeSet(tag ber.Tag, name string, subs []Filter) (*ber.Packet, error) {
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed, tag, nil, name)
	for _, s := range subs {
		c, err := EncodeFilter(s)
		if err != nil {
			return nil, err
		}
		p.AppendChild(c)
	}
	return p, nil
}

func encodeAssertion(tag ber.Tag, name, attribute, value string) *ber.Packet {
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed, tag, nil, name)
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attribute, "Attribute"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "Value"))
	return p
}

func encodeSubstrings(f *Substrings) *ber.Packet {
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagFilterSubstrings, nil, "Substrings")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, f.Attribute, "Attribute"))
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Substrings")
	if f.Initial != "" {
		seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagSubstringInitial, f.Initial, "Initial"))
	}
	for _, a := range f.Any {
		seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagSubstringAny, a, "Any"))
	}
	if f.Final != "" {
		seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagSubstringFinal, f.Final, "Final"))
	}
	p.AppendChild(seq)
	return p
}

func encodeExtensible(f *ExtensibleMatch) *ber.Packet {
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagFilterExtensibleMatch, nil, "ExtensibleMatch")
	if f.MatchingRule != "" {
		p.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagMatchingRule, f.MatchingRule, "MatchingRule"))
	}
	if f.Attribute != "" {
		p.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagMatchType, f.Attribute, "Type"))
	}
	p.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagMatchValue, f.Value, "Value"))
	if f.DNAttributes {
		p.AppendChild(ber.NewBoolean(ber.ClassContext, ber.TypePrimitive, tagDNAttributes, true, "DNAttributes"))
	}
	return p
}
