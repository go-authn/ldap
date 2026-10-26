// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"strings"
	"unicode/utf8"
)

// The syntaxes whose values are checked (RFC 4517 3.3, and the schema
// description syntaxes of RFC 4512 4.1). A syntax not listed here is not
// checked: its values are accepted as they are, which is what RFC 4517 3
// allows ("Servers SHOULD recognize all the syntaxes ... but are not
// required to otherwise support them").
var syntaxCheck = map[string]func(*Schema, []byte) bool{
	"1.3.6.1.4.1.1466.115.121.1.3":  func(_ *Schema, v []byte) bool { _, err := ParseAttributeType(string(v)); return err == nil },
	"1.3.6.1.4.1.1466.115.121.1.6":  func(s *Schema, v []byte) bool { _, ok := bitStringKey(s, v, whole); return ok },
	"1.3.6.1.4.1.1466.115.121.1.7":  func(s *Schema, v []byte) bool { _, ok := booleanKey(s, v, whole); return ok },
	"1.3.6.1.4.1.1466.115.121.1.11": func(_ *Schema, v []byte) bool { return len(v) == 2 && printable(v) },
	"1.3.6.1.4.1.1466.115.121.1.12": func(_ *Schema, v []byte) bool { _, err := parseDN(string(v)); return err == nil },
	"1.3.6.1.4.1.1466.115.121.1.15": func(_ *Schema, v []byte) bool { return len(v) > 0 && utf8.Valid(v) },
	"1.3.6.1.4.1.1466.115.121.1.16": func(_ *Schema, v []byte) bool { _, err := ParseDITContentRule(string(v)); return err == nil },
	"1.3.6.1.4.1.1466.115.121.1.17": func(_ *Schema, v []byte) bool { _, err := ParseDITStructureRule(string(v)); return err == nil },
	"1.3.6.1.4.1.1466.115.121.1.24": func(s *Schema, v []byte) bool { _, ok := timeKey(s, v, whole); return ok },
	"1.3.6.1.4.1.1466.115.121.1.26": func(_ *Schema, v []byte) bool { return ia5(v) },
	"1.3.6.1.4.1.1466.115.121.1.27": func(_ *Schema, v []byte) bool { _, ok := parseInteger(string(v)); return ok },
	"1.3.6.1.4.1.1466.115.121.1.30": func(_ *Schema, v []byte) bool { _, err := ParseMatchingRule(string(v)); return err == nil },
	"1.3.6.1.4.1.1466.115.121.1.31": func(_ *Schema, v []byte) bool { _, err := ParseMatchingRuleUse(string(v)); return err == nil },
	"1.3.6.1.4.1.1466.115.121.1.34": func(s *Schema, v []byte) bool {
		dn := v
		if i := strings.LastIndex(string(v), "#'"); i >= 0 {
			if _, ok := bitStringKey(s, v[i+1:], whole); ok {
				dn = v[:i]
			}
		}
		_, err := parseDN(string(dn))
		return err == nil
	},
	"1.3.6.1.4.1.1466.115.121.1.35": func(_ *Schema, v []byte) bool { _, err := ParseNameForm(string(v)); return err == nil },
	"1.3.6.1.4.1.1466.115.121.1.36": func(_ *Schema, v []byte) bool {
		return len(v) > 0 && strings.Trim(string(v), "0123456789 ") == ""
	},
	"1.3.6.1.4.1.1466.115.121.1.37": func(_ *Schema, v []byte) bool { _, err := ParseObjectClass(string(v)); return err == nil },
	"1.3.6.1.4.1.1466.115.121.1.38": func(_ *Schema, v []byte) bool { return isOID(string(v)) },
	"1.3.6.1.4.1.1466.115.121.1.41": func(_ *Schema, v []byte) bool {
		_, ok := postalLines(string(v))
		return ok && utf8.Valid(v)
	},
	"1.3.6.1.4.1.1466.115.121.1.44": func(_ *Schema, v []byte) bool { return printable(v) },
	"1.3.6.1.4.1.1466.115.121.1.50": func(_ *Schema, v []byte) bool { return printable(v) },
	"1.3.6.1.4.1.1466.115.121.1.54": func(_ *Schema, v []byte) bool { _, err := ParseSyntax(string(v)); return err == nil },
	// RFC 3672 2.1. Only the shape is checked: a value of the Generic String
	// Encoding of a SEQUENCE is braced.
	"1.3.6.1.4.1.1466.115.121.1.45": func(_ *Schema, v []byte) bool {
		t := strings.TrimSpace(string(v))
		return strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}")
	},
}

// printable is PrintableString = 1*PrintableCharacter (RFC 4517 3.2).
func printable(v []byte) bool {
	if len(v) == 0 {
		return false
	}
	for _, c := range v {
		if !isAlpha(c) && !isDigit(c) && strings.IndexByte(`'()+,-.=/:? `, c) < 0 {
			return false
		}
	}
	return true
}

// ia5 is IA5String = *(%x00-7F).
func ia5(v []byte) bool {
	for _, c := range v {
		if c >= 0x80 {
			return false
		}
	}
	return true
}

// ValidValue reports whether a value conforms to t's syntax, as far as this
// package checks that syntax.
func (s *Schema) ValidValue(t *AttributeType, v []byte) bool {
	check, ok := syntaxCheck[t.syntax]
	return !ok || check(s, v)
}
