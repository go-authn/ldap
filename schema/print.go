// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"fmt"
	"strings"
)

// The printer writes the RFC 4512 4.1 form, which the parser reads back to
// the same value. It is the form a server publishes in the subschema
// subentry (RFC 4512 4.2), so it is written ONE way: terms in the ABNF's
// order, one space between them, and quotes escaped as RFC 4512 4.1 says.
//
// Format writes the same terms one to a line, for a .schema file: the
// reader joins a continuation line with one space, so what it reads is
// exactly what String writes.

type printer struct {
	b strings.Builder
	// nl puts each term on a line of its own, indented with a tab.
	nl bool
}

// gap is what comes before a term.
func (w *printer) gap() {
	if w.nl {
		w.b.WriteString("\n\t")
	} else {
		w.b.WriteString(" ")
	}
}

func (w *printer) open(oid string) { w.b.WriteString("( "); w.b.WriteString(oid) }

func (w *printer) close(exts []Extension) string {
	for _, e := range exts {
		w.gap()
		w.b.WriteString(e.Name)
		w.b.WriteString(" ")
		w.list(e.Values, quote, " ")
	}
	w.b.WriteString(" )")
	return w.b.String()
}

func (w *printer) flag(on bool, kw string) {
	if on {
		w.gap()
		w.b.WriteString(kw)
	}
}

func (w *printer) str(kw, v string, q bool) {
	if v == "" {
		return
	}
	w.gap()
	w.b.WriteString(kw)
	w.b.WriteString(" ")
	if q {
		v = quote(v)
	}
	w.b.WriteString(v)
}

// list writes one item bare and several in parentheses.
func (w *printer) list(items []string, each func(string) string, sep string) {
	if len(items) == 1 {
		w.b.WriteString(each(items[0]))
		return
	}
	w.b.WriteString("(")
	for i, it := range items {
		if i > 0 {
			w.b.WriteString(sep)
		} else {
			w.b.WriteString(" ")
		}
		w.b.WriteString(each(it))
	}
	w.b.WriteString(" )")
}

func (w *printer) names(names []string) {
	if len(names) == 0 {
		return
	}
	w.gap()
	w.b.WriteString("NAME ")
	w.list(names, quote, " ")
}

func (w *printer) oids(kw string, oids []string) {
	if len(oids) == 0 {
		return
	}
	w.gap()
	w.b.WriteString(kw)
	w.b.WriteString(" ")
	w.list(oids, func(s string) string { return s }, " $ ")
}

func (w *printer) common(names []string, desc string, obsolete bool) {
	w.names(names)
	w.str("DESC", desc, true)
	w.flag(obsolete, "OBSOLETE")
}

// quote is qdstring: SQUOTE dstring SQUOTE, with ' and \ escaped.
func quote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\5C`)
	s = strings.ReplaceAll(s, `'`, `\27`)
	return "'" + s + "'"
}

func (s *Syntax) String() string { return s.print(&printer{}) }

func (s *Syntax) print(w *printer) string {
	w.open(s.OID)
	w.str("DESC", s.Desc, true)
	return w.close(s.Extensions)
}

func (r *MatchingRule) String() string { return r.print(&printer{}) }

func (r *MatchingRule) print(w *printer) string {
	w.open(r.OID)
	w.common(r.Names, r.Desc, r.Obsolete)
	w.str("SYNTAX", r.Syntax, false)
	return w.close(r.Extensions)
}

func (u *MatchingRuleUse) String() string {
	var w printer
	w.open(u.OID)
	w.common(u.Names, u.Desc, u.Obsolete)
	w.oids("APPLIES", u.Applies)
	return w.close(u.Extensions)
}

func (t *AttributeType) String() string { return t.print(&printer{}) }

func (t *AttributeType) print(w *printer) string {
	w.open(t.OID)
	w.common(t.Names, t.Desc, t.Obsolete)
	w.str("SUP", t.Sup, false)
	w.str("EQUALITY", t.Equality, false)
	w.str("ORDERING", t.Ordering, false)
	w.str("SUBSTR", t.Substr, false)
	if t.Syntax != "" {
		syn := t.Syntax
		if t.SyntaxLen != "" {
			syn += "{" + t.SyntaxLen + "}"
		}
		w.str("SYNTAX", syn, false)
	}
	w.flag(t.SingleValue, "SINGLE-VALUE")
	w.flag(t.Collective, "COLLECTIVE")
	w.flag(t.NoUserModification, "NO-USER-MODIFICATION")
	if t.Usage != UserApplications {
		w.str("USAGE", t.Usage.String(), false)
	}
	return w.close(t.Extensions)
}

func (c *ObjectClass) String() string { return c.print(&printer{}) }

func (c *ObjectClass) print(w *printer) string {
	w.open(c.OID)
	w.common(c.Names, c.Desc, c.Obsolete)
	w.oids("SUP", c.Sup)
	w.gap()
	w.b.WriteString(c.Kind.String())
	w.oids("MUST", c.Must)
	w.oids("MAY", c.May)
	return w.close(c.Extensions)
}

// Format writes the definitions as an OpenLDAP .schema file
// (slapd.conf(5)), which Read reads back to the same Definitions: the
// macros first, in an order where each is defined before it is used, then
// the syntaxes, matching rules, attribute types and object classes, each
// in the order it has here.
//
// With macros, the OID of every definition and the SYNTAX of an attribute
// type -- the places slapd expands a macro (servers/slapd/at.c, oc.c) --
// are written with the macro that covers most of them, "supannAttr:14",
// as an OpenLDAP schema author writes them. Without, every OID is numeric.
//
// The macros must resolve (see Resolve); an error says which does not.
func (d *Definitions) Format(macros bool) ([]byte, error) {
	m, err := Resolve(d.ObjectIdentifiers)
	if err != nil {
		return nil, err
	}
	short := func(oid string) string { return oid }
	if macros {
		short = m.Compress
	}
	var b strings.Builder
	defined := map[string]bool{}
	for len(defined) < len(m.order) {
		for _, o := range m.order {
			name, _, _ := isMacroRef(o.OID)
			if defined[o.Name] || !(isNumericOID(o.OID) || defined[name]) {
				continue
			}
			defined[o.Name] = true
			b.WriteString("objectidentifier " + o.Name + " " + o.OID + "\n")
		}
	}
	var bad error
	def := func(kind string, x printed) {
		// A line break in a value cannot be written: the next line would
		// start a definition, or continue this one with a space in its
		// place (fp_getline, servers/slapd/config.c).
		if bad == nil && strings.ContainsAny(x.String(), "\r\n") {
			bad = fmt.Errorf("schema: the %s %s has a line break in a value, which a .schema file cannot hold", kind, x.print(&printer{})[2:])
		}
		b.WriteString("\n" + kind + " " + x.print(&printer{nl: true}) + "\n")
	}
	for _, x := range d.Syntaxes {
		c := *x
		c.OID = short(c.OID)
		def("ldapsyntax", &c)
	}
	for _, x := range d.MatchingRules {
		c := *x
		c.OID = short(c.OID)
		def("matchingrule", &c)
	}
	for _, x := range d.AttributeTypes {
		c := *x
		c.OID = short(c.OID)
		if c.Syntax != "" {
			c.Syntax = short(c.Syntax)
		}
		def("attributetype", &c)
	}
	for _, x := range d.ObjectClasses {
		c := *x
		c.OID = short(c.OID)
		def("objectclass", &c)
	}
	if bad != nil {
		return nil, bad
	}
	return []byte(b.String()), nil
}

type printed interface {
	String() string
	print(*printer) string
}
