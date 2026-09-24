// SPDX-License-Identifier: BSD-3-Clause

package ldap

import "strings"

// The RFC 4515 string form. It is the SAME tree String, Encode and Matches
// all read -- see the comment on Filter.

func (f *And) String() string { return group("&", f.Filters) }
func (f *Or) String() string  { return group("|", f.Filters) }

func (f *Not) String() string { return "(!" + f.Filter.String() + ")" }

func group(op string, subs []Filter) string {
	var b strings.Builder
	b.WriteByte('(')
	b.WriteString(op)
	for _, s := range subs {
		b.WriteString(s.String())
	}
	b.WriteByte(')')
	return b.String()
}

func (f *Equality) String() string {
	return "(" + f.Attribute + "=" + EscapeValue(f.Value) + ")"
}
func (f *GreaterOrEqual) String() string {
	return "(" + f.Attribute + ">=" + EscapeValue(f.Value) + ")"
}
func (f *LessOrEqual) String() string {
	return "(" + f.Attribute + "<=" + EscapeValue(f.Value) + ")"
}
func (f *Approx) String() string {
	return "(" + f.Attribute + "~=" + EscapeValue(f.Value) + ")"
}

// Present is the one place a bare '*' is not escaped, because there it is
// the syntax rather than a value.
func (f *Present) String() string { return "(" + f.Attribute + "=*)" }

func (f *Substrings) String() string {
	var b strings.Builder
	b.WriteByte('(')
	b.WriteString(f.Attribute)
	b.WriteByte('=')
	b.WriteString(EscapeValue(f.Initial))
	b.WriteByte('*')
	for _, a := range f.Any {
		b.WriteString(EscapeValue(a))
		b.WriteByte('*')
	}
	b.WriteString(EscapeValue(f.Final))
	b.WriteByte(')')
	return b.String()
}

func (f *ExtensibleMatch) String() string {
	var b strings.Builder
	b.WriteByte('(')
	b.WriteString(f.Attribute)
	if f.DNAttributes {
		b.WriteString(":dn")
	}
	if f.MatchingRule != "" {
		b.WriteString(":" + f.MatchingRule)
	}
	b.WriteString(":=")
	b.WriteString(EscapeValue(f.Value))
	b.WriteByte(')')
	return b.String()
}

// EscapeValue writes an assertion value the way RFC 4515 3 requires.
//
// ⛔ The five that MUST be escaped are `*`, `(`, `)`, `\` and NUL, and the
// reason is not cosmetic: an unescaped `*` in a value turns an equality
// filter into a substring one, and an unescaped `)` ends the filter early
// and leaves the rest of the value as syntax. A name containing either --
// `O'Brien (contractor)`, or a password reset token -- becomes a different
// question from the one that was asked.
func EscapeValue(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		switch c := v[i]; c {
		case '*', '(', ')', '\\', 0x00:
			b.WriteString(hexEscape(c))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func hexEscape(c byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{'\\', digits[c>>4], digits[c&0x0f]})
}
