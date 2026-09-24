// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"fmt"
	"strings"
)

// ParseFilter reads the RFC 4515 string form into the tree.
//
// It is here for tests, for a configuration that writes a filter down, and
// for a log line that has to render one back. A SERVER does not parse
// strings off the wire -- DecodeFilter reads the BER directly -- and that is
// deliberate: a server that decoded a filter to a string and re-parsed it
// would be back to two representations that can disagree, which is the
// defect this whole file exists to prevent.
func ParseFilter(s string) (Filter, error) {
	p := &filterParser{s: s}
	f, err := p.parse()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.s) {
		return nil, fmt.Errorf("ldap: trailing %q after the filter", p.s[p.pos:])
	}
	return f, nil
}

type filterParser struct {
	s   string
	pos int
}

func (p *filterParser) parse() (Filter, error) {
	if p.pos >= len(p.s) || p.s[p.pos] != '(' {
		return nil, fmt.Errorf("ldap: a filter starts with '(', and this starts with %q", p.rest())
	}
	p.pos++
	if p.pos >= len(p.s) {
		return nil, fmt.Errorf("ldap: the filter ends after '('")
	}
	var f Filter
	var err error
	switch p.s[p.pos] {
	case '&':
		p.pos++
		var subs []Filter
		if subs, err = p.list(); err == nil {
			f = &And{Filters: subs}
		}
	case '|':
		p.pos++
		var subs []Filter
		if subs, err = p.list(); err == nil {
			f = &Or{Filters: subs}
		}
	case '!':
		p.pos++
		var sub Filter
		if sub, err = p.parse(); err == nil {
			f = &Not{Filter: sub}
		}
	default:
		f, err = p.item()
	}
	if err != nil {
		return nil, err
	}
	if p.pos >= len(p.s) || p.s[p.pos] != ')' {
		return nil, fmt.Errorf("ldap: the filter is missing a ')' at %q", p.rest())
	}
	p.pos++
	return f, nil
}

// list reads zero or more parenthesised filters. ZERO is legal: RFC 4526
// makes `(&)` the absolute-true filter and `(|)` the absolute-false one, and
// refusing them here would refuse two filters the specification defines.
func (p *filterParser) list() ([]Filter, error) {
	var out []Filter
	for p.pos < len(p.s) && p.s[p.pos] == '(' {
		f, err := p.parse()
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// item reads one `attr OP value` with no parentheses around it.
func (p *filterParser) item() (Filter, error) {
	start := p.pos
	for p.pos < len(p.s) && !strings.ContainsRune("=<>~():", rune(p.s[p.pos])) {
		p.pos++
	}
	attr := p.s[start:p.pos]
	if attr == "" {
		return nil, fmt.Errorf("ldap: a filter item with no attribute at %q", p.rest())
	}
	if p.pos >= len(p.s) {
		return nil, fmt.Errorf("ldap: the filter ends inside %q", attr)
	}

	if p.s[p.pos] == ':' {
		return p.extensible(attr)
	}

	var op string
	switch p.s[p.pos] {
	case '=':
		op, p.pos = "=", p.pos+1
	case '>', '<', '~':
		if p.pos+1 >= len(p.s) || p.s[p.pos+1] != '=' {
			return nil, fmt.Errorf("ldap: %q is not a filter operator", p.s[p.pos:])
		}
		op, p.pos = p.s[p.pos:p.pos+2], p.pos+2
	default:
		// `(uid)` -- an attribute and no assertion at all. Without this it
		// fell through as an equality against the empty string, which is a
		// DIFFERENT question and one that quietly matches nothing.
		return nil, fmt.Errorf("ldap: %q has no filter operator in it", attr)
	}

	raw := p.value()
	switch op {
	case ">=":
		v, err := unescapeValue(raw)
		return &GreaterOrEqual{Attribute: attr, Value: v}, err
	case "<=":
		v, err := unescapeValue(raw)
		return &LessOrEqual{Attribute: attr, Value: v}, err
	case "~=":
		v, err := unescapeValue(raw)
		return &Approx{Attribute: attr, Value: v}, err
	}

	// '=' is three different filters depending on the asterisks, and telling
	// them apart is done on the RAW text: an escaped `\2a` is a literal
	// asterisk in a value and must NOT split anything.
	if raw == "*" {
		return &Present{Attribute: attr}, nil
	}
	if !strings.Contains(raw, "*") {
		v, err := unescapeValue(raw)
		return &Equality{Attribute: attr, Value: v}, err
	}
	return substringsOf(attr, raw)
}

// substringsOf splits a raw assertion value on its UNESCAPED asterisks.
func substringsOf(attr, raw string) (Filter, error) {
	parts := strings.Split(raw, "*")
	f := &Substrings{Attribute: attr}
	for i, part := range parts {
		v, err := unescapeValue(part)
		if err != nil {
			return nil, err
		}
		switch {
		case i == 0:
			f.Initial = v
		case i == len(parts)-1:
			f.Final = v
		case v != "":
			// An empty interior component is what `a**b` produces. It asserts
			// nothing, and keeping it would make the filter demand an empty
			// string appear between two others -- which is always true and
			// costs a comparison.
			f.Any = append(f.Any, v)
		}
	}
	return f, nil
}

func (p *filterParser) extensible(attr string) (Filter, error) {
	f := &ExtensibleMatch{Attribute: attr}
	for p.pos < len(p.s) && p.s[p.pos] == ':' {
		p.pos++
		start := p.pos
		for p.pos < len(p.s) && p.s[p.pos] != ':' && p.s[p.pos] != '=' {
			p.pos++
		}
		token := p.s[start:p.pos]
		switch {
		case strings.EqualFold(token, "dn"):
			f.DNAttributes = true
		case token != "":
			f.MatchingRule = token
		}
	}
	if p.pos >= len(p.s) || p.s[p.pos] != '=' {
		return nil, fmt.Errorf("ldap: an extensible match needs ':=' at %q", p.rest())
	}
	p.pos++
	v, err := unescapeValue(p.value())
	f.Value = v
	return f, err
}

// value reads to the closing parenthesis, leaving escapes alone.
func (p *filterParser) value() string {
	start := p.pos
	for p.pos < len(p.s) && p.s[p.pos] != ')' {
		p.pos++
	}
	return p.s[start:p.pos]
}

func (p *filterParser) rest() string {
	if p.pos >= len(p.s) {
		return ""
	}
	return p.s[p.pos:]
}

// unescapeValue turns RFC 4515's `\XX` back into bytes.
//
// ⛔ A lone backslash, or one followed by something that is not two hex
// digits, is an ERROR and not a literal backslash. Accepting it would mean
// `\2` and `\29` could reach the same value by different routes, and a
// filter that can be written two ways is one an audit cannot compare.
func unescapeValue(s string) (string, error) {
	if !strings.Contains(s, "\\") {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", fmt.Errorf("ldap: the filter ends in an unfinished escape %q", s[i:])
		}
		hi, ok1 := unhex(s[i+1])
		lo, ok2 := unhex(s[i+2])
		if !ok1 || !ok2 {
			return "", fmt.Errorf("ldap: %q is not a hex escape", s[i:i+3])
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String(), nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
