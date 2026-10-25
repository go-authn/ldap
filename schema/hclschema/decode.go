// SPDX-License-Identifier: BSD-3-Clause

// Package hclschema reads and writes LDAP schema definitions in HCL2: the
// same definitions package schema reads from OpenLDAP's .schema and LDIF
// files (schema.Definitions), for a server whose configuration is HCL.
//
// It is a package of its own so that package schema has no HCL
// dependency. Decode gives definitions that schema.BuildFrom links with
// every check schema.Build makes; Encode writes them back, one way.
//
// # The shape
//
//	object_identifier "supannAttr" {
//	  oid = "1.3.6.1.4.1.7135.1.2.1"
//	}
//
//	ldap_syntax "1.3.6.1.4.1.1466.115.121.1.15" {
//	  desc = "Directory String"
//	}
//
//	matching_rule "caseIgnoreMatch" {
//	  oid    = "2.5.13.2"
//	  syntax = "1.3.6.1.4.1.1466.115.121.1.15"
//	}
//
//	attribute_type "supannEtablissement" {
//	  oid        = "1.3.6.1.4.1.7135.1.2.1.14"
//	  desc       = "code d etablissement"
//	  equality   = "caseIgnoreMatch"
//	  substr     = "caseIgnoreSubstringsMatch"
//	  syntax     = "1.3.6.1.4.1.1466.115.121.1.15"
//	  syntax_len = 128
//	}
//
//	object_class "supannPerson" {
//	  oid        = "1.3.6.1.4.1.7135.1.2.2.1"
//	  sup        = ["top"]
//	  kind       = "auxiliary"
//	  may        = ["supannOrganisme", "supannCivilite"]
//	  extensions = { "X-ORIGIN" = ["SUPANN 2021"] }
//	}
//
// One block per definition, its kind the block type. The label is the
// definition's first NAME, and "names" lists the others. A definition with
// no NAME -- RFC 4512 4.1 makes NAME optional, and a syntax has none (RFC
// 4517 3.1) -- is labelled with its OID instead, and then has no "oid".
// Every term of RFC 4512 4.1 is an attribute named after it in lower case,
// with underscores: desc, obsolete, sup, equality, ordering, substr,
// syntax, single_value, collective, no_user_modification, usage, kind,
// must, may. The "{len}" after a SYNTAX is not part of the OID (RFC 4512
// 4.1.2: noidlen), so it is a number of its own, syntax_len. The "X-"
// terms are one map, extensions, from each name to its list of strings
// (RFC 4512 4.1: xstring SP qdstrings), kept in the order written.
//
// A term left out has RFC 4512's default: STRUCTURAL (4.1.1),
// userApplications (4.1.2), not OBSOLETE, not SINGLE-VALUE. Encode leaves
// defaults out.
//
// # Literals only
//
// An HCL string is a template ("${...}", "%{...}"). A schema file must not
// compute anything, so every value is a literal -- a quoted string with no
// interpolation, a number, true or false, a list of those, and the
// extensions map with literal keys -- and anything else is refused before
// it is evaluated. Encode escapes "${", "%{", quotes, backslashes and
// control characters, so that a DESC holding any of them reads back as it
// was.
//
// # OID macros
//
// An OID -- the label or "oid" of a definition, the "syntax" of an
// attribute type or a matching rule -- may be written with an OID macro,
// "supannAttr:14", as in an OpenLDAP .schema file (slapd.conf(5),
// objectidentifier), with slapd's rule: a macro is defined, and may be
// used, only after the object_identifier blocks before it, in the order of
// the files and of the blocks in them (servers/slapd/oidm.c, parse_oidm).
// A name used before it is defined is refused with its position.
//
// Encode writes numeric OIDs unless asked for macros (EncodeOptions): a
// numeric OID is what a client sees in the subschema, it can be searched
// for, and a block that carries one can be moved to another file on its
// own. The object_identifier blocks are written either way, so that
// nothing that was defined is lost.
package hclschema

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-authn/ldap/schema"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// An Error is a set of HCL diagnostics: each says what was refused, and
// where, as file:line:column.
type Error struct {
	Diagnostics hcl.Diagnostics
}

func (e *Error) Error() string {
	var b strings.Builder
	for i, d := range e.Diagnostics {
		if i > 0 {
			b.WriteString("\n")
		}
		if d.Subject != nil {
			fmt.Fprintf(&b, "%s:%d:%d: ", d.Subject.Filename, d.Subject.Start.Line, d.Subject.Start.Column)
		}
		b.WriteString(d.Summary)
		if d.Detail != "" {
			b.WriteString(": ")
			b.WriteString(d.Detail)
		}
	}
	return b.String()
}

// MaxNesting bounds how deeply brackets, braces and parentheses may nest in
// a file. The deepest a schema needs is 3 -- a list in a map in a block --
// and the HCL parser recurses on each level.
const MaxNesting = 64

var topSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{
	{Type: "object_identifier", LabelNames: []string{"name"}},
	{Type: "ldap_syntax", LabelNames: []string{"oid"}},
	{Type: "matching_rule", LabelNames: []string{"name"}},
	{Type: "attribute_type", LabelNames: []string{"name"}},
	{Type: "object_class", LabelNames: []string{"name"}},
}}

func attrs(names ...string) *hcl.BodySchema {
	s := &hcl.BodySchema{}
	for _, n := range names {
		s.Attributes = append(s.Attributes, hcl.AttributeSchema{Name: n})
	}
	return s
}

var kindSchemas = map[string]*hcl.BodySchema{
	"object_identifier": attrs("oid"),
	"ldap_syntax":       attrs("desc", "extensions"),
	"matching_rule":     attrs("oid", "names", "desc", "obsolete", "syntax", "extensions"),
	"attribute_type": attrs("oid", "names", "desc", "obsolete", "sup", "equality", "ordering", "substr",
		"syntax", "syntax_len", "single_value", "collective", "no_user_modification", "usage", "extensions"),
	"object_class": attrs("oid", "names", "desc", "obsolete", "sup", "kind", "must", "may", "extensions"),
}

// decoder carries what Decode has read so far.
type decoder struct {
	diags  hcl.Diagnostics
	defs   schema.Definitions
	macros schema.OIDMacros
	// seen finds a definition given twice: kind, then OID or lower-case
	// name, then where.
	seen map[string]map[string]hcl.Range
}

func (d *decoder) errorf(rng hcl.Range, summary, format string, args ...any) {
	r := rng
	d.diags = append(d.diags, &hcl.Diagnostic{Severity: hcl.DiagError, Summary: summary, Detail: fmt.Sprintf(format, args...), Subject: &r})
}

// Decode reads HCL files, in order, into definitions.
func Decode(files ...schema.File) (*schema.Definitions, error) {
	d := &decoder{seen: map[string]map[string]hcl.Range{}}
	var blocks []*hcl.Block
	for _, f := range files {
		if len(f.Data) > schema.MaxFileSize {
			d.errorf(hcl.Range{Filename: f.Name, Start: hcl.InitialPos, End: hcl.InitialPos}, "File too large",
				"the file is %d bytes, more than the %d a schema file may have", len(f.Data), schema.MaxFileSize)
			continue
		}
		if pos, deep := tooDeep(f.Data); deep {
			d.errorf(hcl.Range{Filename: f.Name, Start: pos, End: pos}, "Nested too deeply",
				"brackets nest more than %d deep", MaxNesting)
			continue
		}
		file, diags := hclsyntax.ParseConfig(f.Data, f.Name, hcl.InitialPos)
		d.diags = append(d.diags, diags...)
		if diags.HasErrors() {
			continue
		}
		content, diags := file.Body.Content(topSchema)
		d.diags = append(d.diags, diags...)
		blocks = append(blocks, content.Blocks...)
	}
	if !d.diags.HasErrors() {
		for _, b := range blocks {
			d.block(b)
		}
	}
	if d.diags.HasErrors() {
		return nil, &Error{d.diags}
	}
	d.defs.ObjectIdentifiers = d.macros.Defined()
	return &d.defs, nil
}

// tooDeep scans for brackets nested past MaxNesting, without telling a
// bracket in a string from one outside: it is a bound, not a parser.
func tooDeep(data []byte) (hcl.Pos, bool) {
	depth, line, col := 0, 1, 1
	for i, c := range data {
		switch c {
		case '(', '[', '{':
			depth++
			if depth > MaxNesting {
				return hcl.Pos{Line: line, Column: col, Byte: i}, true
			}
		case ')', ']', '}':
			depth--
		case '\n':
			line, col = line+1, 0
		}
		col++
	}
	return hcl.Pos{}, false
}

// literal reports whether an expression is a literal: no variable, no
// function, no interpolation, no operator.
func literal(e hcl.Expression) bool {
	switch e := e.(type) {
	case *hclsyntax.LiteralValueExpr:
		return true
	case *hclsyntax.TemplateExpr:
		// The text of a template is string literals; an interpolation,
		// even of a literal ("${2}"), is a part of another type or
		// another expression.
		for _, p := range e.Parts {
			l, ok := p.(*hclsyntax.LiteralValueExpr)
			if !ok || l.Val.Type() != cty.String {
				return false
			}
		}
		return true
	case *hclsyntax.TupleConsExpr:
		for _, x := range e.Exprs {
			if !literal(x) {
				return false
			}
		}
		return true
	}
	return false
}

// fields is a block's attributes, each checked to be a literal and
// evaluated.
type fields struct {
	d     *decoder
	block *hcl.Block
	attrs hcl.Attributes
	vals  map[string]cty.Value
}

func (d *decoder) fields(b *hcl.Block) *fields {
	content, diags := b.Body.Content(kindSchemas[b.Type])
	d.diags = append(d.diags, diags...)
	if diags.HasErrors() {
		return nil
	}
	f := &fields{d: d, block: b, attrs: content.Attributes, vals: map[string]cty.Value{}}
	n := len(d.diags)
	for name, a := range content.Attributes {
		if name == "extensions" {
			continue // a map, read item by item in its order
		}
		if !literal(a.Expr) {
			d.errorf(a.Expr.Range(), "Not a literal", "%s must be written as a literal: no variables, functions, operators or ${...} interpolation", name)
			continue
		}
		v, diags := a.Expr.Value(nil)
		d.diags = append(d.diags, diags...)
		f.vals[name] = v
	}
	if len(d.diags) > n {
		return nil
	}
	return f
}

func (f *fields) rangeOf(name string) hcl.Range { return f.attrs[name].Expr.Range() }

// str is a string attribute, or false when it is absent. A value of
// another type, or an empty string, is an error.
func (f *fields) str(name string) (string, bool) {
	v, ok := f.vals[name]
	if !ok {
		return "", false
	}
	if v.IsNull() || v.Type() != cty.String {
		f.d.errorf(f.rangeOf(name), "Incorrect type", "%s must be a string", name)
		return "", false
	}
	if v.AsString() == "" {
		f.d.errorf(f.rangeOf(name), "Empty value", "%s may not be empty; leave it out instead", name)
		return "", false
	}
	return v.AsString(), true
}

// strings is a list of strings, none empty; an empty list is none.
func (d *decoder) strings(v cty.Value, rng hcl.Range, name string) []string {
	if v.IsNull() || !v.Type().IsTupleType() {
		d.errorf(rng, "Incorrect type", "%s must be a list of strings", name)
		return nil
	}
	var out []string
	for it := v.ElementIterator(); it.Next(); {
		_, e := it.Element()
		if e.IsNull() || e.Type() != cty.String || e.AsString() == "" {
			d.errorf(rng, "Incorrect type", "%s must be a list of strings, none of them empty", name)
			return nil
		}
		out = append(out, e.AsString())
	}
	return out
}

func (f *fields) list(name string) []string {
	v, ok := f.vals[name]
	if !ok {
		return nil
	}
	return f.d.strings(v, f.rangeOf(name), name)
}

func (f *fields) flag(name string) bool {
	v, ok := f.vals[name]
	if !ok {
		return false
	}
	if v.IsNull() || v.Type() != cty.Bool {
		f.d.errorf(f.rangeOf(name), "Incorrect type", "%s must be true or false", name)
		return false
	}
	return v.True()
}

// unique files a definition under a key, and says whether it was new.
// RFC 4512 1.4: descriptors are case-insensitive.
func (d *decoder) unique(b *hcl.Block, kind, key string) bool {
	if d.seen[kind] == nil {
		d.seen[kind] = map[string]hcl.Range{}
	}
	key = strings.ToLower(key)
	if prev, dup := d.seen[kind][key]; dup {
		d.errorf(b.DefRange, "Duplicate definition", "%s %q is already defined at %s:%d", kind, key, prev.Filename, prev.Start.Line)
		return false
	}
	d.seen[kind][key] = b.DefRange
	return true
}

// isOIDLabel is a label that is an OID rather than a name: numeric, or an
// OID macro with a suffix. A bare macro name reads as a name.
func isOIDLabel(s string) bool {
	return s != "" && (s[0] >= '0' && s[0] <= '9' || strings.Contains(s, ":"))
}

// expand is a numericoid as written: a numeric OID or a macro reference.
func (f *fields) expand(v string, rng hcl.Range, what string) (string, bool) {
	oid, err := f.d.macros.Expand(v)
	if err != nil {
		f.d.errorf(rng, "Invalid "+what, "%s", strings.TrimPrefix(err.Error(), "schema: "))
		return "", false
	}
	return oid, true
}

// probe prints a definition and parses it back with package schema's
// strict RFC 4512 parser, so that HCL accepts exactly what RFC 4512 4.1
// does and no rule is written twice.
func probe(x fmt.Stringer) bool {
	var err error
	switch x := x.(type) {
	case *schema.Syntax:
		_, err = schema.ParseSyntax(x.String())
	case *schema.ObjectClass:
		_, err = schema.ParseObjectClass(x.String())
	case *schema.AttributeType:
		_, err = schema.ParseAttributeType(x.String())
	}
	return err == nil
}

// identity is the oid and names of a definition. The first name is the
// label, unless the label is the OID.
func (f *fields) identity(kind string) (oid string, names []string, ok bool) {
	label, lrng := f.block.Labels[0], f.block.LabelRanges[0]
	written, hasOID := f.str("oid")
	extra := f.list("names")
	switch {
	case isOIDLabel(label) && hasOID:
		f.d.errorf(f.rangeOf("oid"), "Redundant oid", "the label of this %s is its OID already", kind)
		return "", nil, false
	case isOIDLabel(label) && extra != nil:
		f.d.errorf(f.rangeOf("names"), "Names without a name", "a %s labelled with its OID has no names; label it with the first", kind)
		return "", nil, false
	case isOIDLabel(label):
		written = label
	case !hasOID:
		if _, given := f.vals["oid"]; !given {
			f.d.errorf(f.block.DefRange, "Missing oid", "a %s labelled with a name needs an oid", kind)
		}
		return "", nil, false
	default:
		lrng = f.rangeOf("oid")
		names = append([]string{label}, extra...)
	}
	if oid, ok = f.expand(written, lrng, "OID"); !ok {
		return "", nil, false
	}
	for i, n := range names {
		rng := f.block.LabelRanges[0]
		if i > 0 {
			rng = f.rangeOf("names")
		}
		if !probe(&schema.ObjectClass{OID: "1.1", Names: []string{n}}) {
			f.d.errorf(rng, "Invalid name", "%q is not a descriptor (RFC 4512 1.4: a letter, then letters, digits and hyphens)", n)
			return "", nil, false
		}
		if !f.d.unique(f.block, kind+" name", n) {
			return "", nil, false
		}
	}
	return oid, names, f.d.unique(f.block, kind, oid)
}

// isOID is RFC 4512 1.4's oid: a descriptor or a numeric OID. Macros are
// not expanded here, as slapd does not expand them in SUP, EQUALITY, MUST
// or MAY.
func isOID(v string) bool { return probe(&schema.AttributeType{OID: "1.1", Syntax: "1.1", Sup: v}) }

// oidField is an oid-valued attribute, such as sup or equality.
func (f *fields) oidField(name string) string {
	v, ok := f.str(name)
	if ok && !isOID(v) {
		f.d.errorf(f.rangeOf(name), "Invalid "+name, "%q is not an OID or a descriptor (RFC 4512 1.4)", v)
		return ""
	}
	return v
}

func (f *fields) oidList(name string) []string {
	l := f.list(name)
	for _, v := range l {
		if !isOID(v) {
			f.d.errorf(f.rangeOf(name), "Invalid "+name, "%q is not an OID or a descriptor (RFC 4512 1.4)", v)
			return nil
		}
	}
	return l
}

func (f *fields) desc() string {
	v, _ := f.str("desc")
	return v
}

// syntax is a numericoid, perhaps written with a macro.
func (f *fields) syntax() string {
	v, given := f.str("syntax")
	if !given {
		return ""
	}
	oid, _ := f.expand(v, f.rangeOf("syntax"), "syntax")
	return oid
}

// syntaxLen is the len of noidlen: a whole number, written as RFC 4512
// 1.4's number is, with no leading zero.
func (f *fields) syntaxLen() string {
	v, ok := f.vals["syntax_len"]
	if !ok {
		return ""
	}
	if !v.IsNull() && v.Type() == cty.Number {
		s := v.AsBigFloat().Text('f', -1)
		if probe(&schema.AttributeType{OID: "1.1", Syntax: "1.1", SyntaxLen: s}) {
			return s
		}
	}
	f.d.errorf(f.rangeOf("syntax_len"), "Invalid syntax_len", "syntax_len must be a whole number, 0 or more")
	return ""
}

// extensions reads the map item by item, so that the order written is
// the order kept: RFC 4512 does not say extensions may be reordered.
func (f *fields) extensions() []schema.Extension {
	a, ok := f.attrs["extensions"]
	if !ok {
		return nil
	}
	obj, isObj := a.Expr.(*hclsyntax.ObjectConsExpr)
	if !isObj {
		f.d.errorf(a.Expr.Range(), "Incorrect type", "extensions must be a map, { \"X-NAME\" = [\"value\", ...] }")
		return nil
	}
	var out []schema.Extension
	seen := map[string]bool{}
	for _, it := range obj.Items {
		key := it.KeyExpr.(*hclsyntax.ObjectConsKeyExpr)
		name := hcl.ExprAsKeyword(key.Wrapped)
		if name == "" {
			if t, isT := key.Wrapped.(*hclsyntax.TemplateExpr); isT && literal(t) {
				v, _ := t.Value(nil)
				name = v.AsString()
			}
		}
		if !probe(&schema.Syntax{OID: "1.1", Extensions: []schema.Extension{{Name: name}}}) {
			f.d.errorf(key.Range(), "Invalid extension", "%q is not an extension name (RFC 4512 4.1: \"X-\", then letters, hyphens and underscores)", name)
			continue
		}
		if seen[name] {
			f.d.errorf(key.Range(), "Duplicate extension", "%s is given twice", name)
			continue
		}
		seen[name] = true
		if !literal(it.ValueExpr) {
			f.d.errorf(it.ValueExpr.Range(), "Not a literal", "the values of %s must be a list of literal strings", name)
			continue
		}
		v, _ := it.ValueExpr.Value(nil)
		vals := f.d.strings(v, it.ValueExpr.Range(), name)
		out = append(out, schema.Extension{Name: name, Values: vals})
	}
	return out
}

var kinds = map[string]schema.Kind{"structural": schema.Structural, "abstract": schema.Abstract, "auxiliary": schema.Auxiliary}

var usages = map[string]schema.Usage{
	"userapplications": schema.UserApplications, "directoryoperation": schema.DirectoryOperation,
	"distributedoperation": schema.DistributedOperation, "dsaoperation": schema.DSAOperation,
}

func (d *decoder) block(b *hcl.Block) {
	f := d.fields(b)
	if f == nil {
		return
	}
	n := len(d.diags)
	switch b.Type {
	case "object_identifier":
		oid, ok := f.str("oid")
		if !ok {
			if _, given := f.vals["oid"]; !given {
				d.errorf(b.DefRange, "Missing oid", "an object_identifier needs an oid: a numeric OID, or a macro defined before it and a suffix")
			}
			return
		}
		if err := d.macros.Define(b.Labels[0], oid); err != nil {
			rng := f.rangeOf("oid")
			var me *schema.MacroError
			if errors.As(err, &me) && me.Name == b.Labels[0] {
				rng = b.LabelRanges[0]
			}
			d.errorf(rng, "Invalid object identifier", "%s", strings.TrimPrefix(err.Error(), "schema: "))
		}
	case "ldap_syntax":
		label := b.Labels[0]
		if !isOIDLabel(label) {
			d.errorf(b.LabelRanges[0], "Invalid OID", "an ldap_syntax is labelled with its OID: syntaxes have no names (RFC 4517 3.1)")
			return
		}
		oid, ok := f.expand(label, b.LabelRanges[0], "OID")
		if !ok || !d.unique(b, b.Type, oid) {
			return
		}
		x := &schema.Syntax{OID: oid, Desc: f.desc(), Extensions: f.extensions(), Pos: position(b)}
		if len(d.diags) == n {
			d.defs.Syntaxes = append(d.defs.Syntaxes, x)
		}
	case "matching_rule":
		oid, names, ok := f.identity(b.Type)
		if !ok {
			return
		}
		x := &schema.MatchingRule{OID: oid, Names: names, Desc: f.desc(), Obsolete: f.flag("obsolete"), Syntax: f.syntax(), Extensions: f.extensions(), Pos: position(b)}
		if len(d.diags) == n && x.Syntax == "" {
			d.errorf(b.DefRange, "Missing syntax", "a matching rule must name its syntax (RFC 4512 4.1.3)")
		}
		if len(d.diags) == n {
			d.defs.MatchingRules = append(d.defs.MatchingRules, x)
		}
	case "attribute_type":
		d.attributeType(f, n)
	case "object_class":
		oid, names, ok := f.identity(b.Type)
		if !ok {
			return
		}
		x := &schema.ObjectClass{OID: oid, Names: names, Desc: f.desc(), Obsolete: f.flag("obsolete"),
			Sup: f.oidList("sup"), Must: f.oidList("must"), May: f.oidList("may"), Extensions: f.extensions(), Pos: position(b)}
		if k, given := f.str("kind"); given {
			kind, known := kinds[k]
			if !known {
				d.errorf(f.rangeOf("kind"), "Invalid kind", "%q is not structural, abstract or auxiliary (RFC 4512 4.1.1)", k)
			}
			x.Kind = kind
		}
		if len(d.diags) == n {
			d.defs.ObjectClasses = append(d.defs.ObjectClasses, x)
		}
	}
}

// position is where a block starts -- its type keyword -- which is where an
// error schema.BuildFrom returns about its definition points.
func position(b *hcl.Block) schema.Position {
	return schema.Position{File: b.DefRange.Filename, Line: b.DefRange.Start.Line, Column: b.DefRange.Start.Column}
}

func (d *decoder) attributeType(f *fields, n int) {
	b := f.block
	oid, names, ok := f.identity(b.Type)
	if !ok {
		return
	}
	x := &schema.AttributeType{OID: oid, Names: names, Desc: f.desc(), Obsolete: f.flag("obsolete"),
		Sup: f.oidField("sup"), Equality: f.oidField("equality"), Ordering: f.oidField("ordering"), Substr: f.oidField("substr"),
		Syntax: f.syntax(), SyntaxLen: f.syntaxLen(), SingleValue: f.flag("single_value"), Collective: f.flag("collective"),
		NoUserModification: f.flag("no_user_modification"), Extensions: f.extensions(), Pos: position(b)}
	if u, given := f.str("usage"); given {
		usage, known := usages[strings.ToLower(u)]
		if !known {
			d.errorf(f.rangeOf("usage"), "Invalid usage", "%q is not userApplications, directoryOperation, distributedOperation or dSAOperation (RFC 4512 4.1.2)", u)
		}
		x.Usage = usage
	}
	if len(d.diags) > n {
		return
	}
	switch {
	case x.Sup == "" && x.Syntax == "":
		d.errorf(b.DefRange, "Missing sup or syntax", "an attribute type needs sup or syntax (RFC 4512 4.1.2)")
	case x.SyntaxLen != "" && x.Syntax == "":
		d.errorf(f.rangeOf("syntax_len"), "syntax_len without syntax", "syntax_len bounds the syntax given here (RFC 4512 4.1.2 noidlen)")
	case x.Collective && x.Usage != schema.UserApplications:
		d.errorf(f.rangeOf("collective"), "Collective and operational", "COLLECTIVE requires usage userApplications (RFC 4512 4.1.2)")
	case x.NoUserModification && x.Usage == schema.UserApplications:
		d.errorf(f.rangeOf("no_user_modification"), "No-user-modification for a user attribute", "NO-USER-MODIFICATION requires an operational usage (RFC 4512 4.1.2)")
	default:
		d.defs.AttributeTypes = append(d.defs.AttributeTypes, x)
	}
}
