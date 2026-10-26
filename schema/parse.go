// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// The parser is RFC 4512 4.1's ABNF, and it is STRICT about it.
//
// ⛔ The terms come in the order the ABNF lists them, separated by SP (one
// or more SPACE, and nothing else -- not a tab, not a newline), and a term
// out of order is refused rather than accepted. A lenient parser is a parser
// whose output nobody can predict for input nobody has seen, and this one
// reads definitions that a server then PUBLISHES: what it accepted it will
// hand to every client that reads the subschema. The printer writes exactly
// this form, so that whatever is published reads back here.
//
// Keywords are matched without regard to case, because ABNF quoted strings
// are case-insensitive (RFC 4234 2.3), and printed in capitals.

// A ParseError is a definition refused, and where.
type ParseError struct {
	// Offset is the byte offset in the definition where reading stopped.
	Offset int
	// Msg says what was expected there.
	Msg string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("schema: at offset %d: %s", e.Offset, e.Msg)
}

type parser struct {
	s   string
	pos int
	// macros, when not nil, lets a numericoid be written as an OID macro
	// (slapd.conf(5) objectidentifier; see macro.go). The exported Parse
	// functions leave it nil: RFC 4512 has no macros.
	macros *OIDMacros
	// openldap relaxes the parser the way libldap relaxes it for slapd's
	// schema files, and only that far: tabs and newlines as white space,
	// and quotes around an OID. Read sets it; the Parse functions do not.
	openldap bool
}

func (p *parser) fail(format string, args ...any) error {
	return &ParseError{Offset: p.pos, Msg: fmt.Sprintf(format, args...)}
}

func (p *parser) peek() byte {
	if p.pos < len(p.s) {
		return p.s[p.pos]
	}
	return 0
}

// isSpace is SPACE, and in an OpenLDAP file also a tab or a newline:
// libldap's parse_whsp (libraries/libldap/schema.c) skips LDAP_SPACE, which
// is all three, and published .schema files indent with tabs.
func (p *parser) isSpace(c byte) bool {
	return c == ' ' || p.openldap && (c == '\t' || c == '\n')
}

// openQuote reads the SQUOTE OpenLDAP accepts around an OID in a file.
// libldap's ldap_int_parse_numericoid and parse_noidlen, under
// LDAP_SCHEMA_ALLOW_QUOTED: "Netscape puts the SYNTAX value in quotes
// (incorrectly)" -- and REFEDS's eduperson.ldif still does.
func (p *parser) openQuote() bool {
	if p.openldap && p.peek() == '\'' {
		p.pos++
		return true
	}
	return false
}

func (p *parser) closeQuote(open bool, v string, err error) (string, error) {
	if err == nil && open {
		err = p.expect('\'')
	}
	return v, err
}

// spaces skips WSP and says how many there were.
func (p *parser) spaces() int {
	n := 0
	for p.pos < len(p.s) && p.isSpace(p.s[p.pos]) {
		p.pos++
		n++
	}
	return n
}

// sp is SP: at least one space.
func (p *parser) sp() error {
	if p.spaces() == 0 {
		return p.fail("expected a space")
	}
	return nil
}

func (p *parser) expect(c byte) error {
	if p.peek() != c {
		return p.fail("expected %q, found %s", c, p.found())
	}
	p.pos++
	return nil
}

func (p *parser) found() string {
	if p.pos >= len(p.s) {
		return "the end"
	}
	r, _ := utf8.DecodeRuneInString(p.s[p.pos:])
	return fmt.Sprintf("%q", r)
}

// word reads up to the next space or parenthesis: a keyword, an oid, or a
// number. What it read is checked by the caller.
func (p *parser) word() string {
	start := p.pos
	for p.pos < len(p.s) {
		switch p.s[p.pos] {
		case '(', ')', '\'', '$', '{', '}':
			return p.s[start:p.pos]
		}
		if p.isSpace(p.s[p.pos]) {
			return p.s[start:p.pos]
		}
		p.pos++
	}
	return p.s[start:p.pos]
}

func (p *parser) numericoid() (string, error) {
	q := p.openQuote()
	v, err := p.bareNumericoid()
	return p.closeQuote(q, v, err)
}

func (p *parser) bareNumericoid() (string, error) {
	start := p.pos
	w := p.word()
	if isNumericOID(w) {
		return w, nil
	}
	if _, _, ok := isMacroRef(w); ok && p.macros != nil {
		oid, err := p.macros.Expand(w)
		if err != nil {
			p.pos = start
			return "", p.fail("expected a numeric OID, found %q, and the OID macro %q %s", w, err.(*MacroError).Name, err.(*MacroError).Msg)
		}
		return oid, nil
	}
	p.pos = start
	return "", p.fail("expected a numeric OID, found %q", w)
}

func (p *parser) oid() (string, error) {
	q := p.openQuote()
	v, err := p.bareOID()
	return p.closeQuote(q, v, err)
}

func (p *parser) bareOID() (string, error) {
	start := p.pos
	w := p.word()
	if !isOID(w) {
		p.pos = start
		return "", p.fail("expected an OID or a descriptor, found %q", w)
	}
	return w, nil
}

// listBuf is the stack room a list is gathered in before it is copied out
// at its exact length: one allocation per list, not one per growth. Eight
// holds every list in the embedded schemas but a handful of MAY lists.
const listBuf = 8

// exact copies a gathered list to the heap at its length; an empty list
// stays nil, as an append to a nil slice left it before.
func exact(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}

// oids = oid / ( LPAREN WSP oidlist WSP RPAREN )
// oidlist = oid *( WSP DOLLAR WSP oid )
func (p *parser) oids() ([]string, error) {
	if p.peek() != '(' {
		o, err := p.oid()
		if err != nil {
			return nil, err
		}
		return []string{o}, nil
	}
	p.pos++
	p.spaces()
	var buf [listBuf]string
	out := buf[:0]
	for {
		o, err := p.oid()
		if err != nil {
			return nil, err
		}
		out = append(out, o)
		p.spaces()
		if p.peek() == ')' {
			p.pos++
			return exact(out), nil
		}
		if err := p.expect('$'); err != nil {
			return nil, err
		}
		p.spaces()
	}
}

// qdescrs = qdescr / ( LPAREN WSP qdescrlist WSP RPAREN )
// qdescrlist = [ qdescr *( SP qdescr ) ]
func (p *parser) qdescrs() ([]string, error) {
	if p.peek() != '(' {
		d, err := p.qdescr()
		if err != nil {
			return nil, err
		}
		return []string{d}, nil
	}
	p.pos++
	p.spaces()
	var buf [listBuf]string
	out := buf[:0]
	for p.peek() != ')' {
		if len(out) > 0 && !p.isSpace(p.s[p.pos-1]) {
			return nil, p.fail("expected a space between two names")
		}
		d, err := p.qdescr()
		if err != nil {
			return nil, err
		}
		out = append(out, d)
		p.spaces()
	}
	p.pos++
	return exact(out), nil
}

// qdescr = SQUOTE descr SQUOTE
func (p *parser) qdescr() (string, error) {
	if err := p.expect('\''); err != nil {
		return "", err
	}
	start := p.pos
	for p.pos < len(p.s) && p.s[p.pos] != '\'' {
		p.pos++
	}
	d := p.s[start:p.pos]
	if !isKeystring(d) {
		p.pos = start
		return "", p.fail("%q is not a descriptor (RFC 4512 1.4: a letter, then letters, digits and hyphens)", d)
	}
	return d, p.expect('\'')
}

// qdstring = SQUOTE dstring SQUOTE
// dstring = 1*( QS / QQ / QUTF8 )
func (p *parser) qdstring() (string, error) {
	if err := p.expect('\''); err != nil {
		return "", err
	}
	// The common case has no escape, and its value is the input between
	// the quotes: a slice of it, copied nowhere. At the first backslash the
	// string is rebuilt from there on.
	start := p.pos
	for p.pos < len(p.s) {
		c := p.s[p.pos]
		switch {
		case c == '\'':
			if p.pos == start {
				return "", p.fail("a quoted string may not be empty (RFC 4512 4.1: dstring = 1*...)")
			}
			p.pos++
			return p.s[start : p.pos-1], nil
		case c == '\\':
			return p.qdstringEscaped(start)
		case c < utf8.RuneSelf:
			p.pos++
		default:
			r, n := utf8.DecodeRuneInString(p.s[p.pos:])
			if r == utf8.RuneError && n <= 1 {
				return "", p.fail("the quoted string is not UTF-8")
			}
			p.pos += n
		}
	}
	return "", p.fail("the quoted string is not closed")
}

// qdstringEscaped goes on with a qdstring from its first backslash, at
// p.pos; what came before it, from start, had nothing to unescape.
func (p *parser) qdstringEscaped(start int) (string, error) {
	var b strings.Builder
	b.Grow(p.pos - start + 16)
	b.WriteString(p.s[start:p.pos])
	for {
		if p.pos >= len(p.s) {
			return "", p.fail("the quoted string is not closed")
		}
		c := p.s[p.pos]
		switch {
		case c == '\'':
			// Not empty: the escape this began at wrote a byte, or failed.
			p.pos++
			return b.String(), nil
		case c == '\\':
			esc := p.s[p.pos:min(p.pos+3, len(p.s))]
			switch esc {
			case `\27`:
				b.WriteByte('\'')
			case `\5C`, `\5c`:
				b.WriteByte('\\')
			default:
				return "", p.fail(`a backslash in a quoted string is \27 or \5C, and this is %q`, esc)
			}
			p.pos += 3
		default:
			r, n := utf8.DecodeRuneInString(p.s[p.pos:])
			if r == utf8.RuneError && n <= 1 {
				return "", p.fail("the quoted string is not UTF-8")
			}
			b.WriteString(p.s[p.pos : p.pos+n])
			p.pos += n
		}
	}
}

// qdstrings = qdstring / ( LPAREN WSP qdstringlist WSP RPAREN )
func (p *parser) qdstrings() ([]string, error) {
	if p.peek() != '(' {
		s, err := p.qdstring()
		if err != nil {
			return nil, err
		}
		return []string{s}, nil
	}
	p.pos++
	p.spaces()
	var buf [listBuf]string
	out := buf[:0]
	for p.peek() != ')' {
		if len(out) > 0 && !p.isSpace(p.s[p.pos-1]) {
			return nil, p.fail("expected a space between two strings")
		}
		s, err := p.qdstring()
		if err != nil {
			return nil, err
		}
		out = append(out, s)
		p.spaces()
	}
	p.pos++
	return exact(out), nil
}

// noidlen = numericoid [ LCURLY len RCURLY ]
func (p *parser) noidlen() (oid, bound string, err error) {
	q := p.openQuote()
	if oid, err = p.bareNumericoid(); err != nil {
		return "", "", err
	}
	if p.peek() == '{' {
		p.pos++
		start := p.pos
		bound = p.word()
		if !isNumber(bound) {
			p.pos = start
			return "", "", p.fail("expected a number in braces, found %q", bound)
		}
		if err = p.expect('}'); err != nil {
			return "", "", err
		}
	}
	oid, err = p.closeQuote(q, oid, nil)
	return oid, bound, err
}

// A term is one of the keywords of a definition, in the order the ABNF
// gives them. Each kind of definition allows a subset, in this order.
type term int

const (
	tName term = iota
	tDesc
	tObsolete
	tSup
	tEquality
	tOrdering
	tSubstr
	tSyntax
	tSingleValue
	tCollective
	tNoUserMod
	tUsage
	tKind
	tMust
	tMay
	tApplies
)

// A grammar is the terms a kind of definition allows: grammar[t] is t's
// rank in the order the ABNF gives them, or -1 when t is not allowed. It
// is built once per kind, not per definition read.
type grammar [tApplies + 1]int8

func newGrammar(terms ...term) *grammar {
	g := new(grammar)
	for i := range g {
		g[i] = -1
	}
	for i, t := range terms {
		g[t] = int8(i)
	}
	return g
}

var (
	syntaxTerms          = newGrammar(tDesc)
	matchingRuleTerms    = newGrammar(tName, tDesc, tObsolete, tSyntax)
	matchingRuleUseTerms = newGrammar(tName, tDesc, tObsolete, tApplies)
	attributeTypeTerms   = newGrammar(tName, tDesc, tObsolete, tSup, tEquality, tOrdering, tSubstr,
		tSyntax, tSingleValue, tCollective, tNoUserMod, tUsage)
	objectClassTerms = newGrammar(tName, tDesc, tObsolete, tSup, tKind, tMust, tMay)
)

var termWords = map[string]term{
	"NAME": tName, "DESC": tDesc, "OBSOLETE": tObsolete, "SUP": tSup,
	"EQUALITY": tEquality, "ORDERING": tOrdering, "SUBSTR": tSubstr,
	"SYNTAX": tSyntax, "SINGLE-VALUE": tSingleValue, "COLLECTIVE": tCollective,
	"NO-USER-MODIFICATION": tNoUserMod, "USAGE": tUsage,
	"ABSTRACT": tKind, "STRUCTURAL": tKind, "AUXILIARY": tKind,
	"MUST": tMust, "MAY": tMay, "APPLIES": tApplies,
}

// definition reads LPAREN WSP numericoid, then each `SP term` in the order
// allowed, then extensions WSP RPAREN, calling each term's reader.
func (p *parser) definition(allowed *grammar, read func(t term, keyword string) error) (string, []Extension, error) {
	if err := p.expect('('); err != nil {
		return "", nil, err
	}
	p.spaces()
	oid, err := p.numericoid()
	if err != nil {
		return "", nil, err
	}
	next := int8(0)  // the rank of the first term still allowed
	var seen uint32 // the terms read, one bit each
	var exts []Extension
	for {
		n := p.spaces()
		if p.peek() == ')' {
			p.pos++
			if p.pos != len(p.s) {
				return "", nil, p.fail("trailing %q after the definition", p.s[p.pos:])
			}
			return oid, exts, nil
		}
		// libldap needs no white space between two terms: get_token stops
		// a word at a quote or a parenthesis (libraries/libldap/schema.c),
		// and samba.ldif, folded per RFC 2849, has "...Outgoing'DESC".
		if n == 0 && !p.openldap {
			return "", nil, p.fail("expected a space or ')', found %s", p.found())
		}
		start := p.pos
		kw := p.word()
		up := strings.ToUpper(kw)
		if isXString(kw) {
			if err := p.sp(); err != nil {
				return "", nil, err
			}
			vals, err := p.qdstrings()
			if err != nil {
				return "", nil, err
			}
			exts = append(exts, Extension{Name: kw, Values: vals})
			continue
		}
		t, known := termWords[up]
		r := allowed[t]
		if !known || r < 0 {
			p.pos = start
			if kw == "" {
				return "", nil, p.fail("expected a keyword, found %s", p.found())
			}
			return "", nil, p.fail("%q is not a term of this definition", kw)
		}
		switch {
		case p.openldap:
			// libldap, ldap_str2attributetype and the others: "Beyond this
			// point we will be liberal and accept the items in any order",
			// and a term seen twice is LDAP_SCHERR_DUPOPT.
			if seen&(1<<t) != 0 {
				p.pos = start
				return "", nil, p.fail("%s is repeated", up)
			}
			seen |= 1 << t
		case exts != nil:
			p.pos = start
			return "", nil, p.fail("%s after an extension: extensions come last (RFC 4512 4.1)", up)
		case r < next:
			p.pos = start
			return "", nil, p.fail("%s is out of order or repeated (RFC 4512 4.1 fixes the order of the terms)", up)
		}
		next = r + 1
		if err := read(t, up); err != nil {
			return "", nil, err
		}
	}
}

// arg reads the SP that separates a keyword from its value.
func (p *parser) arg() error { return p.sp() }

// ParseSyntax reads a SyntaxDescription (RFC 4512 4.1.5).
func ParseSyntax(s string) (*Syntax, error) { return parseSyntax(&parser{s: s}) }

func parseSyntax(p *parser) (*Syntax, error) {
	out := &Syntax{}
	oid, exts, err := p.definition(syntaxTerms, func(_ term, _ string) (err error) {
		if err = p.arg(); err == nil {
			out.Desc, err = p.qdstring()
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	out.OID, out.Extensions = oid, exts
	return out, nil
}

// common reads the three terms every named definition shares.
func (p *parser) common(t term, names *[]string, desc *string, obsolete *bool) (err error) {
	switch t {
	case tName:
		if err = p.arg(); err == nil {
			*names, err = p.qdescrs()
		}
	case tDesc:
		if err = p.arg(); err == nil {
			*desc, err = p.qdstring()
		}
	case tObsolete:
		*obsolete = true
	}
	return err
}

// ParseMatchingRule reads a MatchingRuleDescription (RFC 4512 4.1.3).
func ParseMatchingRule(s string) (*MatchingRule, error) { return parseMatchingRule(&parser{s: s}) }

func parseMatchingRule(p *parser) (*MatchingRule, error) {
	out := &MatchingRule{}
	oid, exts, err := p.definition(matchingRuleTerms, func(t term, _ string) (err error) {
		if t != tSyntax {
			return p.common(t, &out.Names, &out.Desc, &out.Obsolete)
		}
		if err = p.arg(); err == nil {
			out.Syntax, err = p.numericoid()
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if out.Syntax == "" {
		return nil, &ParseError{Offset: len(p.s), Msg: "a matching rule must name its SYNTAX (RFC 4512 4.1.3)"}
	}
	out.OID, out.Extensions = oid, exts
	return out, nil
}

// ParseMatchingRuleUse reads a MatchingRuleUseDescription (RFC 4512 4.1.4).
func ParseMatchingRuleUse(s string) (*MatchingRuleUse, error) {
	p := &parser{s: s}
	out := &MatchingRuleUse{}
	oid, exts, err := p.definition(matchingRuleUseTerms, func(t term, _ string) (err error) {
		if t != tApplies {
			return p.common(t, &out.Names, &out.Desc, &out.Obsolete)
		}
		if err = p.arg(); err == nil {
			out.Applies, err = p.oids()
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if out.Applies == nil {
		return nil, &ParseError{Offset: len(s), Msg: "a matching rule use must say what it APPLIES to (RFC 4512 4.1.4)"}
	}
	out.OID, out.Extensions = oid, exts
	return out, nil
}

var usages = map[string]Usage{
	"USERAPPLICATIONS": UserApplications, "DIRECTORYOPERATION": DirectoryOperation,
	"DISTRIBUTEDOPERATION": DistributedOperation, "DSAOPERATION": DSAOperation,
}

// ParseAttributeType reads an AttributeTypeDescription (RFC 4512 4.1.2).
func ParseAttributeType(s string) (*AttributeType, error) {
	return parseAttributeType(&parser{s: s})
}

func parseAttributeType(p *parser) (*AttributeType, error) {
	out := &AttributeType{}
	oid, exts, err := p.definition(attributeTypeTerms, func(t term, _ string) (err error) {
		switch t {
		case tSup, tEquality, tOrdering, tSubstr:
			if err = p.arg(); err != nil {
				return err
			}
			var o string
			if o, err = p.oid(); err == nil {
				switch t {
				case tSup:
					out.Sup = o
				case tEquality:
					out.Equality = o
				case tOrdering:
					out.Ordering = o
				default:
					out.Substr = o
				}
			}
		case tSyntax:
			if err = p.arg(); err == nil {
				out.Syntax, out.SyntaxLen, err = p.noidlen()
			}
		case tSingleValue:
			out.SingleValue = true
		case tCollective:
			out.Collective = true
		case tNoUserMod:
			out.NoUserModification = true
		case tUsage:
			if err = p.arg(); err != nil {
				return err
			}
			start := p.pos
			w := p.word()
			u, ok := usages[strings.ToUpper(w)]
			if !ok {
				p.pos = start
				return p.fail("%q is not a usage (RFC 4512 4.1.2)", w)
			}
			out.Usage = u
		default:
			return p.common(t, &out.Names, &out.Desc, &out.Obsolete)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	// RFC 4512 4.1.2: "Each attribute type description must contain at least
	// one of the SUP or SYNTAX fields."
	if out.Sup == "" && out.Syntax == "" {
		return nil, &ParseError{Offset: len(p.s), Msg: "an attribute type needs SUP or SYNTAX (RFC 4512 4.1.2)"}
	}
	out.OID, out.Extensions = oid, exts
	return out, nil
}

// ParseObjectClass reads an ObjectClassDescription (RFC 4512 4.1.1).
func ParseObjectClass(s string) (*ObjectClass, error) { return parseObjectClass(&parser{s: s}) }

func parseObjectClass(p *parser) (*ObjectClass, error) {
	out := &ObjectClass{}
	oid, exts, err := p.definition(objectClassTerms, func(t term, kw string) (err error) {
		switch t {
		case tSup:
			if err = p.arg(); err == nil {
				out.Sup, err = p.oids()
			}
		case tKind:
			// kw is one of the three: termWords maps nothing else to tKind.
			switch kw {
			case "ABSTRACT":
				out.Kind = Abstract
			case "STRUCTURAL":
				out.Kind = Structural
			default:
				out.Kind = Auxiliary
			}
		case tMust:
			if err = p.arg(); err == nil {
				out.Must, err = p.oids()
			}
		case tMay:
			if err = p.arg(); err == nil {
				out.May, err = p.oids()
			}
		default:
			return p.common(t, &out.Names, &out.Desc, &out.Obsolete)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	out.OID, out.Extensions = oid, exts
	return out, nil
}

// --- RFC 4512 1.4 ---------------------------------------------------------

// isNumericOID is numericoid = number 1*( DOT number ).
// It scans s once, number by number, without splitting it.
func isNumericOID(s string) bool {
	dots, start := 0, 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '.' {
			continue
		}
		if !isNumber(s[start:i]) {
			return false
		}
		if i < len(s) {
			dots++
		}
		start = i + 1
	}
	return dots > 0
}

// isNumber is number = DIGIT / ( LDIGIT 1*DIGIT ): no leading zero.
func isNumber(n string) bool {
	if n == "" || (len(n) > 1 && n[0] == '0') {
		return false
	}
	for i := 0; i < len(n); i++ {
		if n[i] < '0' || n[i] > '9' {
			return false
		}
	}
	return true
}

// isKeystring is keystring = leadkeychar *keychar.
func isKeystring(s string) bool {
	if s == "" || !isAlpha(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isAlpha(s[i]) && !isDigit(s[i]) && s[i] != '-' {
			return false
		}
	}
	return true
}

// isOID is oid = descr / numericoid.
func isOID(s string) bool { return isKeystring(s) || isNumericOID(s) }

// isXString is xstring = "X" HYPHEN 1*( ALPHA / HYPHEN / USCORE ).
func isXString(s string) bool {
	if len(s) < 3 || (s[0] != 'X' && s[0] != 'x') || s[1] != '-' {
		return false
	}
	for i := 2; i < len(s); i++ {
		if !isAlpha(s[i]) && s[i] != '-' && s[i] != '_' {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
