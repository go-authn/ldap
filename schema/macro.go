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
//   - parse_oidm expands the VALUE when the macro is defined, with
//     oidm_find, and refuses one it does not recognise ("OID %s not
//     recognized"). A macro may therefore name another one -- they chain
//     -- but only one defined BEFORE it: a forward reference is an error,
//     and so a cycle cannot be written in a .schema file.
//   - Defining a name twice is refused unless both expand to the same OID
//     ("Allow duplicate if the definition is identical").
//   - Names are compared by dscompare, byte for byte: they are
//     CASE-SENSITIVE, unlike every other name in a schema.
//   - oidm_find returns a value that starts with a digit unchanged, without
//     checking it; this package checks that every expansion is a numeric
//     OID (RFC 4512 1.4), because what it expands is published.
//   - at.c and oc.c expand the OID of an attribute type and of an object
//     class, and the SYNTAX of an attribute type. This package expands every
//     place RFC 4512 4.1 wants a numericoid: those three, and the OID of an
//     ldapsyntax and a matchingrule and a matching rule's SYNTAX, which
//     slapd.conf(5) lists for ldapsyntax and which no slapd.conf can define
//     for a matching rule. Never a SUP, an EQUALITY or a MUST: those are oids,
//     where a descriptor already means something else.

// MaxMacroDepth bounds how deep one macro may be defined in terms of
// another. Read never needs it -- a .schema file expands each macro as it
// is defined -- but a set resolved out of order (Resolve, which HCL needs)
// follows chains, and a chain is input.
const MaxMacroDepth = 32

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
// by dots, which is what makes "name.suffix" a numeric OID.
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
		return "", &MacroError{s, "is neither a numeric OID nor name[:suffix] (slapd.conf(5) objectidentifier)"}
	}
	oid, defined := m.expanded[name]
	if !defined {
		return "", &MacroError{name, "is not defined (names are case-sensitive, and are defined before they are used)"}
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

// Compress is Expand in reverse: the shortest way to write a numeric OID
// with the macros defined, which is the macro whose OID is the longest
// prefix of it, then ":" and the rest. Two macros of the same OID: the one
// defined first. An OID no macro prefixes is returned as it is.
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

// Resolve defines a set of macros in any order, which is what a
// declarative format such as HCL needs: a macro may name one defined after
// it. A chain longer than MaxMacroDepth, a cycle and a name that nothing
// defines are refused; the error is an *IndexedMacroError naming the macro
// at fault by its index in ids.
func Resolve(ids []ObjectIdentifier) (*OIDMacros, error) {
	byName := map[string]int{}
	for i, d := range ids {
		if j, dup := byName[d.Name]; dup && ids[j].OID != d.OID {
			// Two spellings of a name: their expansions are compared once
			// both are known, below.
			continue
		}
		byName[d.Name] = i
	}
	m := &OIDMacros{}
	const (
		unvisited = iota
		visiting
		done
	)
	state := make([]int, len(ids))
	var visit func(i int, path []string) error
	visit = func(i int, path []string) error {
		switch state[i] {
		case done:
			return nil
		case visiting:
			return &IndexedMacroError{i, &MacroError{ids[i].Name, "is part of a cycle: " + strings.Join(append(path, ids[i].Name), " -> ")}}
		}
		if len(path) >= MaxMacroDepth {
			return &IndexedMacroError{i, &MacroError{ids[i].Name, fmt.Sprintf("is more than %d macros deep: %s ...", MaxMacroDepth, strings.Join(path[:4], " -> "))}}
		}
		state[i] = visiting
		if name, _, ok := isMacroRef(ids[i].OID); ok {
			if j, defined := byName[name]; defined {
				if err := visit(j, append(path, ids[i].Name)); err != nil {
					return err
				}
			}
		}
		state[i] = done
		if err := m.Define(ids[i].Name, ids[i].OID); err != nil {
			return &IndexedMacroError{i, err.(*MacroError)}
		}
		return nil
	}
	for i := range ids {
		if err := visit(i, nil); err != nil {
			return nil, err
		}
	}
	// Defined in dependency order; listed in the order given.
	m.order = m.order[:0]
	seen := map[string]bool{}
	for _, d := range ids {
		if !seen[d.Name] {
			seen[d.Name] = true
			m.order = append(m.order, d)
		}
	}
	return m, nil
}

// An IndexedMacroError is a MacroError in a list given to Resolve.
type IndexedMacroError struct {
	Index int
	*MacroError
}

func (e *IndexedMacroError) Unwrap() error { return e.MacroError }
