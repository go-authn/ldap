// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"fmt"
	"strconv"
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

func (r *DITContentRule) String() string { return r.print(&printer{}) }

func (r *DITContentRule) print(w *printer) string {
	w.open(r.OID)
	w.common(r.Names, r.Desc, r.Obsolete)
	w.oids("AUX", r.Aux)
	w.oids("MUST", r.Must)
	w.oids("MAY", r.May)
	w.oids("NOT", r.Not)
	return w.close(r.Extensions)
}

func (f *NameForm) String() string { return f.print(&printer{}) }

func (f *NameForm) print(w *printer) string {
	w.open(f.OID)
	w.common(f.Names, f.Desc, f.Obsolete)
	w.str("OC", f.OC, false)
	w.oids("MUST", f.Must)
	w.oids("MAY", f.May)
	return w.close(f.Extensions)
}

func (r *DITStructureRule) String() string { return r.print(&printer{}) }

func (r *DITStructureRule) print(w *printer) string {
	w.open(strconv.Itoa(r.ID))
	w.common(r.Names, r.Desc, r.Obsolete)
	w.str("FORM", r.Form, false)
	if len(r.Sup) > 0 {
		ids := make([]string, len(r.Sup))
		for i, id := range r.Sup {
			ids[i] = strconv.Itoa(id)
		}
		w.gap()
		w.b.WriteString("SUP ")
		w.list(ids, func(s string) string { return s }, " ")
	}
	return w.close(r.Extensions)
}

// Format writes the definitions as an OpenLDAP .schema file
// (slapd.conf(5)), which Read reads back to the same Definitions: the
// macros first, in an order where each is defined before it is used, then
// the syntaxes, matching rules, attribute types and object classes, each
// in the order it has here, then the DIT content rules, name forms and DIT
// structure rules.
//
// ⛔ slapd.conf(5) has a ditcontentrule directive and NONE for name forms or
// structure rules (OpenLDAP implements neither), so a file that holds one
// is written with this package's own keywords, nameform and
// ditstructurerule, which Read reads and slapd refuses.
//
// With macros, the OID of every definition and the SYNTAX of an attribute
// type -- the places slapd expands a macro (servers/slapd/at.c, oc.c) --
// are written with the macro that covers most of them, "supannAttr:14",
// as an OpenLDAP schema author writes them. Without, every OID is numeric.
//
// The macros must define in their order (see Macros); an error says which
// does not.
func (d *Definitions) Format(macros bool) ([]byte, error) {
	m, err := Macros(d.ObjectIdentifiers)
	if err != nil {
		return nil, err
	}
	short := func(oid string) string { return oid }
	if macros {
		short = m.Compress
	}
	var b strings.Builder
	for _, o := range m.order {
		b.WriteString("objectidentifier " + o.Name + " " + o.OID + "\n")
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
	for _, x := range d.DITContentRules {
		c := *x
		c.OID = short(c.OID)
		def("ditcontentrule", &c)
	}
	for _, x := range d.NameForms {
		c := *x
		c.OID = short(c.OID)
		def("nameform", &c)
	}
	for _, x := range d.DITStructureRules {
		def("ditstructurerule", x)
	}
	if bad != nil {
		return nil, bad
	}
	return []byte(foldLong(b.String())), nil
}

// foldLong cuts every line of s longer than MaxLineLength, which Read
// refuses as slapd.conf(5) does, into pieces that end with a backslash.
// slapd's fp_getline (servers/slapd/config.c) joins a line that ends with a
// backslash not preceded by another to the next one with nothing between
// them, and so does Read, so the value is unchanged. A name or a string of
// more than 2000 bytes reads from LDIF, which has no such bound (found by
// FuzzRead: it formatted to a line that did not read back). A piece never
// ends with a backslash of its own, which would read as `\\`.
func foldLong(s string) string {
	long := false
	for rest := s; rest != "" && !long; {
		var line string
		line, rest, _ = strings.Cut(rest, "\n")
		long = len(line) > MaxLineLength
	}
	if !long {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + len(s)/MaxLineLength*2)
	for rest := s; rest != ""; {
		line, after, nl := strings.Cut(rest, "\n")
		for len(line) > MaxLineLength {
			k := MaxLineLength - 1 // and the backslash: MaxLineLength
			for k > 1 && line[k-1] == '\\' {
				k--
			}
			b.WriteString(line[:k])
			b.WriteString("\\\n")
			line = line[k:]
		}
		b.WriteString(line)
		if nl {
			b.WriteByte('\n')
		}
		rest = after
	}
	return b.String()
}

type printed interface {
	String() string
	print(*printer) string
}
