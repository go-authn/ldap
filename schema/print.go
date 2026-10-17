// SPDX-License-Identifier: BSD-3-Clause

package schema

import "strings"

// The printer writes the RFC 4512 4.1 form, which the parser reads back to
// the same value. It is the form a server publishes in the subschema
// subentry (RFC 4512 4.2), so it is written ONE way: terms in the ABNF's
// order, one space between them, and quotes escaped as RFC 4512 4.1 says.

type printer struct{ b strings.Builder }

func (w *printer) open(oid string) { w.b.WriteString("( "); w.b.WriteString(oid) }

func (w *printer) close(exts []Extension) string {
	for _, e := range exts {
		w.b.WriteString(" ")
		w.b.WriteString(e.Name)
		w.b.WriteString(" ")
		w.list(e.Values, quote, " ")
	}
	w.b.WriteString(" )")
	return w.b.String()
}

func (w *printer) flag(on bool, kw string) {
	if on {
		w.b.WriteString(" ")
		w.b.WriteString(kw)
	}
}

func (w *printer) str(kw, v string, q bool) {
	if v == "" {
		return
	}
	w.b.WriteString(" ")
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
	w.b.WriteString(" NAME ")
	w.list(names, quote, " ")
}

func (w *printer) oids(kw string, oids []string) {
	if len(oids) == 0 {
		return
	}
	w.b.WriteString(" ")
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

func (s *Syntax) String() string {
	var w printer
	w.open(s.OID)
	w.str("DESC", s.Desc, true)
	return w.close(s.Extensions)
}

func (r *MatchingRule) String() string {
	var w printer
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

func (t *AttributeType) String() string {
	var w printer
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

func (c *ObjectClass) String() string {
	var w printer
	w.open(c.OID)
	w.common(c.Names, c.Desc, c.Obsolete)
	w.oids("SUP", c.Sup)
	w.b.WriteString(" ")
	w.b.WriteString(c.Kind.String())
	w.oids("MUST", c.Must)
	w.oids("MAY", c.May)
	return w.close(c.Extensions)
}
