// SPDX-License-Identifier: BSD-3-Clause

package hclschema

import (
	"fmt"

	"github.com/go-authn/ldap/schema"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// EncodeOptions say how Encode writes.
type EncodeOptions struct {
	// Macros writes each OID that a macro covers with the macro,
	// "supannAttr:14", the way the .schema file it came from probably
	// did. Off, every OID is numeric.
	Macros bool
}

// Encode writes definitions as HCL that Decode reads back to the same
// definitions. It writes ONE way, so that two encodings of the same
// definitions are the same bytes: the object identifiers, then the
// syntaxes, matching rules, attribute types and object classes, each in
// the order it has in d (which is the order of the files it was read
// from); in a block, the attributes in RFC 4512 4.1's order of terms, and
// a term only when it says something -- no "obsolete = false", no "usage"
// for userApplications, no "kind" for structural.
//
// Strings are NFC-normalised, as every HCL string is (cty.StringVal), and
// escaped by hclwrite: "${" as "$${", "%{" as "%%{", quotes, backslashes
// and control characters.
//
// Two extensions of the same name in one definition, which RFC 4512
// allows and one map cannot hold, are refused.
func Encode(d *schema.Definitions, opt EncodeOptions) ([]byte, error) {
	m, err := schema.Macros(d.ObjectIdentifiers)
	if err != nil {
		return nil, err
	}
	short := func(oid string) string { return oid }
	if opt.Macros {
		short = m.Compress
	}
	f := hclwrite.NewEmptyFile()
	root := f.Body()
	block := func(kind, label string) *hclwrite.Body {
		if len(root.Blocks()) > 0 {
			root.AppendNewline()
		}
		return root.AppendNewBlock(kind, []string{label}).Body()
	}
	for _, o := range m.Defined() {
		block("object_identifier", o.Name).SetAttributeValue("oid", cty.StringVal(o.OID))
	}
	for _, x := range d.Syntaxes {
		b := block("ldap_syntax", short(x.OID))
		str(b, "desc", x.Desc)
		if err := extensions(b, "syntax "+x.OID, x.Extensions); err != nil {
			return nil, err
		}
	}
	for _, x := range d.MatchingRules {
		b := identity(block, "matching_rule", short(x.OID), x.Names)
		str(b, "desc", x.Desc)
		flag(b, "obsolete", x.Obsolete)
		str(b, "syntax", short(x.Syntax))
		if err := extensions(b, "matching rule "+x.Name(), x.Extensions); err != nil {
			return nil, err
		}
	}
	for _, x := range d.AttributeTypes {
		if err := attributeType(identity(block, "attribute_type", short(x.OID), x.Names), x, short); err != nil {
			return nil, err
		}
	}
	for _, x := range d.ObjectClasses {
		b := identity(block, "object_class", short(x.OID), x.Names)
		str(b, "desc", x.Desc)
		flag(b, "obsolete", x.Obsolete)
		list(b, "sup", x.Sup)
		str(b, "kind", map[schema.Kind]string{schema.Abstract: "abstract", schema.Auxiliary: "auxiliary"}[x.Kind])
		list(b, "must", x.Must)
		list(b, "may", x.May)
		if err := extensions(b, "object class "+x.Name(), x.Extensions); err != nil {
			return nil, err
		}
	}
	return hclwrite.Format(f.Bytes()), nil
}

func attributeType(b *hclwrite.Body, x *schema.AttributeType, short func(string) string) error {
	str(b, "desc", x.Desc)
	flag(b, "obsolete", x.Obsolete)
	str(b, "sup", x.Sup)
	str(b, "equality", x.Equality)
	str(b, "ordering", x.Ordering)
	str(b, "substr", x.Substr)
	if x.Syntax != "" {
		str(b, "syntax", short(x.Syntax))
	}
	if x.SyntaxLen != "" {
		n, err := cty.ParseNumberVal(x.SyntaxLen)
		if err != nil {
			return fmt.Errorf("hclschema: the attribute type %s has the syntax bound %q, which is not a number", x.Name(), x.SyntaxLen)
		}
		b.SetAttributeValue("syntax_len", n)
	}
	flag(b, "single_value", x.SingleValue)
	flag(b, "collective", x.Collective)
	flag(b, "no_user_modification", x.NoUserModification)
	if x.Usage != schema.UserApplications {
		str(b, "usage", x.Usage.String())
	}
	return extensions(b, "attribute type "+x.Name(), x.Extensions)
}

// identity opens a block labelled with the first name, or with the OID
// when there is no name.
func identity(block func(kind, label string) *hclwrite.Body, kind, oid string, names []string) *hclwrite.Body {
	if len(names) == 0 {
		return block(kind, oid)
	}
	b := block(kind, names[0])
	b.SetAttributeValue("oid", cty.StringVal(oid))
	list(b, "names", names[1:])
	return b
}

func str(b *hclwrite.Body, name, v string) {
	if v != "" {
		b.SetAttributeValue(name, cty.StringVal(v))
	}
}

func flag(b *hclwrite.Body, name string, on bool) {
	if on {
		b.SetAttributeValue(name, cty.True)
	}
}

// listInline is how many items a list holds on one line.
const listInline = 4

var (
	newline = &hclwrite.Token{Type: hclsyntax.TokenNewline, Bytes: []byte("\n")}
	comma   = &hclwrite.Token{Type: hclsyntax.TokenComma, Bytes: []byte(",")}
)

func listTokens(items []string) hclwrite.Tokens {
	elems := make([]hclwrite.Tokens, len(items))
	for i, s := range items {
		elems[i] = hclwrite.TokensForValue(cty.StringVal(s))
	}
	if len(items) <= listInline {
		return hclwrite.TokensForTuple(elems)
	}
	toks := hclwrite.Tokens{{Type: hclsyntax.TokenOBrack, Bytes: []byte("[")}, newline}
	for _, e := range elems {
		toks = append(toks, e...)
		toks = append(toks, comma, newline)
	}
	return append(toks, &hclwrite.Token{Type: hclsyntax.TokenCBrack, Bytes: []byte("]")})
}

func list(b *hclwrite.Body, name string, items []string) {
	if len(items) > 0 {
		b.SetAttributeRaw(name, listTokens(items))
	}
}

// extensions is one map, its items in the order of the definition, one
// to a line.
func extensions(b *hclwrite.Body, what string, exts []schema.Extension) error {
	if len(exts) == 0 {
		return nil
	}
	seen := map[string]bool{}
	toks := hclwrite.Tokens{{Type: hclsyntax.TokenOBrace, Bytes: []byte("{")}, newline}
	for _, e := range exts {
		if seen[e.Name] {
			return fmt.Errorf("hclschema: the %s has the extension %s twice, which one map cannot hold", what, e.Name)
		}
		seen[e.Name] = true
		toks = append(toks, hclwrite.TokensForValue(cty.StringVal(e.Name))...)
		toks = append(toks, &hclwrite.Token{Type: hclsyntax.TokenEqual, Bytes: []byte("=")})
		toks = append(toks, listTokens(e.Values)...)
		toks = append(toks, newline)
	}
	b.SetAttributeRaw("extensions", append(toks, &hclwrite.Token{Type: hclsyntax.TokenCBrace, Bytes: []byte("}")}))
	return nil
}
