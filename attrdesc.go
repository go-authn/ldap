// SPDX-License-Identifier: BSD-3-Clause

package ldap

import "fmt"

// validAttributeDescription is RFC 4512 2.5:
//
//	attributedescription = attributetype options
//	attributetype = oid
//	options = *( SEMI option )
//	option = 1*keychar
//
// RFC 4511 4.1.4 constrains every AttributeDescription on the wire to it.
func validAttributeDescription(s string) bool {
	typ, rest, more := cut(s, ';')
	if !validOID(typ) {
		return false
	}
	for more {
		var opt string
		opt, rest, more = cut(rest, ';')
		if opt == "" {
			return false
		}
		for i := 0; i < len(opt); i++ {
			if !keychar(opt[i]) {
				return false
			}
		}
	}
	return true
}

// validOID is RFC 4512 1.4:
//
//	oid = descr / numericoid
//	descr = keystring = leadkeychar *keychar
//	numericoid = number 1*( DOT number )
//	number = DIGIT / ( LDIGIT 1*DIGIT )
func validOID(s string) bool {
	if s == "" {
		return false
	}
	if alpha(s[0]) {
		for i := 1; i < len(s); i++ {
			if !keychar(s[i]) {
				return false
			}
		}
		return true
	}
	parts := 0
	for s != "" {
		var n string
		n, s, _ = cut(s, '.')
		if n == "" || (len(n) > 1 && n[0] == '0') {
			return false
		}
		for i := 0; i < len(n); i++ {
			if n[i] < '0' || n[i] > '9' {
				return false
			}
		}
		parts++
	}
	return parts >= 2
}

func alpha(c byte) bool   { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func keychar(c byte) bool { return alpha(c) || c >= '0' && c <= '9' || c == '-' }

// cut is strings.Cut over a byte, which also says whether the separator was
// there -- needed to tell "a;" (an empty option) from "a".
func cut(s string, sep byte) (before, after string, found bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// checkNames refuses a filter naming an attribute, or a matching rule, that
// is not one by RFC 4512.
//
// ⛔ The names were taken as octets and written back as they came, so a
// filter's string form could say something its tree did not: a present
// filter whose attribute was `!x` read back as a NOT. This package promises
// that the string form, the wire form and the matcher read one tree, and a
// consumer that logs a filter, or hands its string to another directory,
// relies on that promise. Found by FuzzMessage.
func checkNames(f Filter) error {
	bad := func(what, name string) error {
		return fmt.Errorf("ldap: %q is not %s (RFC 4512 2.5)", name, what)
	}
	attr := func(name string) error {
		if !validAttributeDescription(name) {
			return bad("an attribute description", name)
		}
		return nil
	}
	switch f := f.(type) {
	case *And:
		for _, s := range f.Filters {
			if err := checkNames(s); err != nil {
				return err
			}
		}
	case *Or:
		for _, s := range f.Filters {
			if err := checkNames(s); err != nil {
				return err
			}
		}
	case *Not:
		return checkNames(f.Filter)
	case *Equality:
		return attr(f.Attribute)
	case *GreaterOrEqual:
		return attr(f.Attribute)
	case *LessOrEqual:
		return attr(f.Attribute)
	case *Approx:
		return attr(f.Attribute)
	case *Present:
		return attr(f.Attribute)
	case *Substrings:
		return attr(f.Attribute)
	case *ExtensibleMatch:
		if f.Attribute != "" {
			if err := attr(f.Attribute); err != nil {
				return err
			}
		}
		if f.MatchingRule != "" && !validOID(f.MatchingRule) {
			return bad("a matching rule", f.MatchingRule)
		}
	}
	return nil
}
