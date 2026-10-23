// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"fmt"
	"strings"
)

// OID macros are OpenLDAP's, not RFC 4512's. slapd.conf(5), objectidentifier:
//
//	objectidentifier <name> "{ <oid> | <name>[:<suffix>] }"
//	Define a string name that equates to the given OID. The string can be
//	used in place of the numeric OID in objectclass and attribute
//	definitions. The name can also be used with a suffix of the form ":xx"
//	in which case the value "oid.xx" will be used.
//
// slapd-config(5) says the same of olcObjectIdentifier. What the manual
// leaves out is read from the source, servers/slapd/oidm.c and
// schemaparse.c at OpenLDAP commit 0160e81d (2026-04-30):
//
//   - parse_oidm expands the VALUE once, when the macro is defined, with
//     oidm_find, and refuses one it does not recognise ("OID %s not
//     recognized"). A macro may therefore name another one -- they chain
//     -- but only one defined BEFORE it, in file order: a forward
//     reference is an error, and no cycle can be written.
//   - Defining a name twice is refused unless both expand to the same OID
//     ("Allow duplicate if the definition is identical").
//   - Names are compared by dscompare, byte for byte: they are
//     CASE-SENSITIVE, unlike every other name in a schema.
//   - oidm_find never looks up a value that starts with a digit, and copies
//     a suffix without checking it. This package checks both: an expansion
//     must be a numeric OID (RFC 4512 1.4), because what it expands is
//     published.
//   - at.c and oc.c expand the OID of an attribute type and of an object
//     class, and the SYNTAX of an attribute type -- in libldap's
//     ldap_str2attributetype the SYNTAX is the only term besides the OID
//     that takes a macro (LDAP_SCHEMA_ALLOW_OID_MACRO). SUP, EQUALITY, MUST
//     and MAY are oids, looked up by name, never expanded, and here too.
//     This package also expands the OID of an ldapsyntax, which
//     slapd.conf(5) lists, and of a matchingrule and its SYNTAX, the other
//     places RFC 4512 4.1 wants a numericoid.

// An ObjectIdentifier is one OID macro as it was written: OID is a numeric
// OID, another macro's name, or a name and a suffix, "supannOID:1".
type ObjectIdentifier struct {
	Name string
	OID  string
}

// OIDMacros is a table of OID macros, each expanded to its numeric OID.
// The zero value is empty and ready.
type OIDMacros struct {
	expanded map[string]string // name -> numeric OID
	order    []ObjectIdentifier
}

// A MacroError is a macro that cannot be defined or expanded.
type MacroError struct {
	// Name is the macro being defined, or the reference being expanded.
	Name string
	Msg  string
}

func (e *MacroError) Error() string { return fmt.Sprintf("schema: the OID macro %q %s", e.Name, e.Msg) }

// isMacroRef is name[:suffix], with the suffix one or more numbers joined
// by dots, which is what makes "oid.suffix" a numeric OID.
func isMacroRef(s string) (name, suffix string, ok bool) {
	name, suffix, hasSuffix := strings.Cut(s, ":")
	if !isKeystring(name) {
		return "", "", false
	}
	if hasSuffix && !isNumber(suffix) && !isNumericOID(suffix) {
		return "", "", false
	}
	return name, suffix, true
}

// Expand is oidm_find: a numeric OID as itself, "name" as the name's OID,
// and "name:suffix" as the name's OID, a dot, and the suffix.
func (m *OIDMacros) Expand(s string) (string, error) {
	if isNumericOID(s) {
		return s, nil
	}
	name, suffix, ok := isMacroRef(s)
	if !ok {
		return "", &MacroError{s, "is neither a numeric OID nor name[:suffix], with a suffix of numbers and dots (slapd.conf(5) objectidentifier)"}
	}
	oid, defined := m.expanded[name]
	if !defined {
		return "", &MacroError{name, "is not defined before it is used (names are case-sensitive)"}
	}
	if suffix != "" {
		oid += "." + suffix
	}
	return oid, nil
}

// Define adds a macro, expanding its value now, as parse_oidm does: the
// value may name only macros already defined. Defining a name again is
// allowed only to the same OID.
func (m *OIDMacros) Define(name, value string) error {
	if !isKeystring(name) {
		return &MacroError{name, "is not a descriptor (RFC 4512 1.4: a letter, then letters, digits and hyphens)"}
	}
	oid, err := m.Expand(value)
	if err != nil {
		return err
	}
	if prev, dup := m.expanded[name]; dup {
		if prev != oid {
			return &MacroError{name, fmt.Sprintf("is already defined as %s, and this makes it %s", prev, oid)}
		}
		return nil
	}
	if m.expanded == nil {
		m.expanded = map[string]string{}
	}
	m.expanded[name] = oid
	m.order = append(m.order, ObjectIdentifier{Name: name, OID: value})
	return nil
}

// Defined lists the macros in the order they were first defined, each as it
// was written.
func (m *OIDMacros) Defined() []ObjectIdentifier {
	return append([]ObjectIdentifier(nil), m.order...)
}

// Compress is Expand in reverse: a numeric OID written with the macro whose
// OID is the longest prefix of it, then ":" and the rest. Two macros of the
// same OID: the one defined first. An OID no macro covers is returned as it
// is.
func (m *OIDMacros) Compress(oid string) string {
	best, bestOID := "", ""
	for _, d := range m.order {
		v := m.expanded[d.Name]
		if (oid == v || strings.HasPrefix(oid, v+".")) && len(v) > len(bestOID) {
			best, bestOID = d.Name, v
		}
	}
	switch {
	case best == "":
		return oid
	case oid == bestOID:
		return best
	}
	return best + ":" + oid[len(bestOID)+1:]
}

// Macros defines a list of macros in its order, as slapd reads them; an
// error is an *IndexedMacroError that names the one at fault.
func Macros(ids []ObjectIdentifier) (*OIDMacros, error) {
	m := &OIDMacros{}
	for i, d := range ids {
		if err := m.Define(d.Name, d.OID); err != nil {
			return nil, &IndexedMacroError{i, err.(*MacroError)}
		}
	}
	return m, nil
}

// An IndexedMacroError is a MacroError in a list given to Macros.
type IndexedMacroError struct {
	Index int
	*MacroError
}

func (e *IndexedMacroError) Unwrap() error { return e.MacroError }
