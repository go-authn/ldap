// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"errors"
	"strings"
	"testing"
)

func TestMacrosChainAndExpand(t *testing.T) {
	var m OIDMacros
	for _, d := range [][2]string{
		{"supann", "1.3.6.1.4.1.7135.1"},
		{"supannAttr", "supann:2.1"}, // chained, with a dotted suffix
		{"supannClass", "supann:2.2"},
		{"leaf", "supannAttr"}, // a bare name: the same OID
		{"supann", "1.3.6.1.4.1.7135.1"},
	} {
		if err := m.Define(d[0], d[1]); err != nil {
			t.Fatal(err)
		}
	}
	for in, want := range map[string]string{
		"supannAttr:14": "1.3.6.1.4.1.7135.1.2.1.14",
		"supannClass":   "1.3.6.1.4.1.7135.1.2.2",
		"leaf:1":        "1.3.6.1.4.1.7135.1.2.1.1",
		"2.5.4.3":       "2.5.4.3",
	} {
		if got, err := m.Expand(in); err != nil || got != want {
			t.Errorf("Expand(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	// The identical redefinition of supann is kept once, as written first.
	if d := m.Defined(); len(d) != 4 || d[1] != (ObjectIdentifier{"supannAttr", "supann:2.1"}) {
		t.Errorf("Defined() = %v", d)
	}
	for in, want := range map[string]string{
		"1.3.6.1.4.1.7135.1.2.1.14": "supannAttr:14", // the longest prefix wins
		"1.3.6.1.4.1.7135.1.2.1":    "supannAttr",    // defined before leaf
		"1.3.6.1.4.1.7135.1.9":      "supann:9",
		"1.3.6.1.4.1.71351":         "1.3.6.1.4.1.71351", // a prefix of digits is not a prefix of arcs
		"2.5.4.3":                   "2.5.4.3",
	} {
		if got := m.Compress(in); got != want {
			t.Errorf("Compress(%q) = %q, want %q", in, got, want)
		}
	}
}

// Each guard, and a break check that it is the guard that refuses.
func TestMacrosRefuse(t *testing.T) {
	var m OIDMacros
	if err := m.Define("base", "1.2"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, value, want string }{
		{"later", "notYet:1", `"notYet" is not defined before it is used`}, // a forward reference
		{"Base2", "BASE:1", `"BASE" is not defined`},                       // case-sensitive (dscompare)
		{"x", "base:", "neither a numeric OID"},                            // an empty suffix
		{"x", "base:1.", "neither a numeric OID"},                          // a trailing dot
		{"x", "base:01", "neither a numeric OID"},                          // RFC 4512 1.4: no leading zero
		{"x", "base:a", "neither a numeric OID"},                           // slapd would copy it unchecked
		{"x", "1.2.x", "neither a numeric OID"},                            // a digit first is never a macro
		{"1x", "1.2", "is not a descriptor"},
		{"x y", "1.2", "is not a descriptor"},
		{"base", "1.3", "is already defined as 1.2, and this makes it 1.3"},
	} {
		err := m.Define(c.name, c.value)
		var me *MacroError
		if !errors.As(err, &me) || !strings.Contains(err.Error(), c.want) || !strings.HasPrefix(err.Error(), "schema: the OID macro ") {
			t.Errorf("Define(%q, %q) = %v, want %q", c.name, c.value, err, c.want)
		}
	}
	// Break check: the same table with each value fixed is accepted.
	for _, c := range [][2]string{{"later", "base:1"}, {"Base2", "base:1"}, {"y", "base:1.0"}, {"z", "1.2.3"}} {
		if err := m.Define(c[0], c[1]); err != nil {
			t.Errorf("Define(%q, %q) = %v", c[0], c[1], err)
		}
	}
}

func TestMacrosIndexTheFault(t *testing.T) {
	ids := []ObjectIdentifier{{"a", "1.1"}, {"b", "a:2"}, {"c", "d:1"}, {"d", "1.3"}}
	_, err := Macros(ids)
	var ie *IndexedMacroError
	if !errors.As(err, &ie) || ie.Index != 2 || ie.Name != "d" || errors.Unwrap(err) != ie.MacroError {
		t.Fatalf("Macros = %v, want the forward reference at index 2", err)
	}
	if m, err := Macros(ids[:2]); err != nil || len(m.Defined()) != 2 {
		t.Fatalf("Macros(ok) = %v", err)
	}
}

// FuzzMacros: no panic, and every expansion is a numeric OID whose
// compression expands back to it.
func FuzzMacros(f *testing.F) {
	f.Add("a", "1.2", "b", "a:3", "b:4.5")
	f.Add("x", "x", "y", "y:1", "q")
	f.Add("a-1", "0.0", "B", "a-1:0", "B")
	f.Fuzz(func(t *testing.T, n1, v1, n2, v2, ref string) {
		var m OIDMacros
		_ = m.Define(n1, v1)
		_ = m.Define(n2, v2)
		oid, err := m.Expand(ref)
		if err != nil {
			return
		}
		if !isNumericOID(oid) {
			t.Fatalf("Expand(%q) = %q, not a numeric OID", ref, oid)
		}
		if back, err := m.Expand(m.Compress(oid)); err != nil || back != oid {
			t.Fatalf("Compress(%q) = %q, which expands to %q, %v", oid, m.Compress(oid), back, err)
		}
	})
}
