// SPDX-License-Identifier: BSD-3-Clause

package hclschema

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/go-authn/ldap/schema"
	"github.com/hashicorp/hcl/v2"
)

// blk is a block of HCL, one attribute to a line.
func blk(head string, lines ...string) string {
	return head + " {\n" + strings.Join(lines, "\n") + "\n}"
}

func decode(src ...string) (*schema.Definitions, error) {
	var fs []schema.File
	for i, s := range src {
		fs = append(fs, schema.File{Name: []string{"a.hcl", "b.hcl"}[i], Data: []byte(s)})
	}
	return Decode(fs...)
}

// unplaced is d without the positions Decode gives each definition: what the
// definitions SAY, for comparing two decodings of different text.
func unplaced(d *schema.Definitions) *schema.Definitions {
	out := &schema.Definitions{ObjectIdentifiers: d.ObjectIdentifiers}
	for _, x := range d.Syntaxes {
		c := *x
		c.Pos = schema.Position{}
		out.Syntaxes = append(out.Syntaxes, &c)
	}
	for _, x := range d.MatchingRules {
		c := *x
		c.Pos = schema.Position{}
		out.MatchingRules = append(out.MatchingRules, &c)
	}
	for _, x := range d.AttributeTypes {
		c := *x
		c.Pos = schema.Position{}
		out.AttributeTypes = append(out.AttributeTypes, &c)
	}
	for _, x := range d.ObjectClasses {
		c := *x
		c.Pos = schema.Position{}
		out.ObjectClasses = append(out.ObjectClasses, &c)
	}
	for _, x := range d.DITContentRules {
		c := *x
		c.Pos = schema.Position{}
		out.DITContentRules = append(out.DITContentRules, &c)
	}
	for _, x := range d.NameForms {
		c := *x
		c.Pos = schema.Position{}
		out.NameForms = append(out.NameForms, &c)
	}
	for _, x := range d.DITStructureRules {
		c := *x
		c.Pos = schema.Position{}
		out.DITStructureRules = append(out.DITStructureRules, &c)
	}
	return out
}

// rules are authnd's tree in HCL: a DIT content rule, name forms and DIT
// structure rules, on top of the standard schema.
const rules = `
dit_content_rule "accountRule" {
  oid  = "0.9.2342.19200300.100.4.5"
  aux  = ["posixAccount", "shadowAccount"]
  must = ["description"]
  not  = ["seeAlso"]
}

name_form "domainForm" {
  oid  = "1.3.6.1.4.1.32473.1.2.1"
  oc   = "domain"
  must = ["dc"]
}

name_form "1.3.6.1.4.1.32473.1.2.2" {
  oc   = "organizationalUnit"
  must = ["ou"]
}

dit_structure_rule "suffix" {
  id   = 1
  form = "domainForm"
}

dit_structure_rule "2" {
  form = "1.3.6.1.4.1.32473.1.2.2"
  sup  = [1, 2]
}
`

// The rules decode to what package schema reads, build on the standard
// schema, govern the tree, and encode back to the same definitions; a
// BuildError about one points at its block.
func TestDecodeTheRules(t *testing.T) {
	d, err := decode(rules)
	if err != nil {
		t.Fatal(err)
	}
	want := &schema.Definitions{
		DITContentRules: []*schema.DITContentRule{{OID: "0.9.2342.19200300.100.4.5", Names: []string{"accountRule"},
			Aux: []string{"posixAccount", "shadowAccount"}, Must: []string{"description"}, Not: []string{"seeAlso"}}},
		NameForms: []*schema.NameForm{{OID: "1.3.6.1.4.1.32473.1.2.1", Names: []string{"domainForm"}, OC: "domain", Must: []string{"dc"}},
			{OID: "1.3.6.1.4.1.32473.1.2.2", OC: "organizationalUnit", Must: []string{"ou"}}},
		DITStructureRules: []*schema.DITStructureRule{{ID: 1, Names: []string{"suffix"}, Form: "domainForm"},
			{ID: 2, Form: "1.3.6.1.4.1.32473.1.2.2", Sup: []int{1, 2}}},
	}
	if !reflect.DeepEqual(unplaced(d), want) {
		t.Fatalf("decoded %+v %+v %+v", d.DITContentRules, d.NameForms, d.DITStructureRules)
	}
	if d.DITStructureRules[1].Pos != (schema.Position{File: "a.hcl", Line: 25, Column: 1}) {
		t.Errorf("position %v", d.DITStructureRules[1].Pos)
	}
	std, _ := schema.Read(schema.StandardFiles()...)
	s, err := schema.BuildFrom(std, d)
	if err != nil {
		t.Fatal(err)
	}
	suffix := schema.Entry{DN: "dc=example,dc=org", Attributes: []schema.Attribute{
		{Description: "objectClass", Values: [][]byte{[]byte("top"), []byte("domain")}}, {Description: "dc", Values: [][]byte{[]byte("example")}}}}
	if r, err := s.GoverningStructureRule(suffix, nil); err != nil || r.ID != 1 {
		t.Errorf("the suffix: %v %v", r, err)
	}
	out, err := Encode(d, EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`dit_structure_rule "suffix" {` + "\n  id   = 1\n", `dit_structure_rule "2" {`, `sup  = [1, 2]`, `name_form "1.3.6.1.4.1.32473.1.2.2" {`} {
		if !strings.Contains(string(out), s) {
			t.Errorf("no %q in\n%s", s, out)
		}
	}
	back, err := Decode(schema.File{Name: "x.hcl", Data: out})
	if err != nil || !reflect.DeepEqual(unplaced(back), want) {
		t.Errorf("round trip: %v\n%s", err, out)
	}

	bad, err := decode("\n\ndit_structure_rule \"x\" {\n  id   = 9\n  form = \"nope\"\n}\n")
	if err != nil {
		t.Fatal(err)
	}
	_, err = schema.BuildFrom(std, bad)
	if err == nil || err.Error() != "a.hcl:3:1: schema: the DIT structure rule x has FORM nope, which is not a defined name form" {
		t.Errorf("%v", err)
	}
}

// example is the README's.
const example = `
object_identifier "supann" {
  oid = "1.3.6.1.4.1.7135.1"
}

object_identifier "supannAttr" {
  oid = "supann:2.1"
}

ldap_syntax "1.3.6.1.4.1.1466.115.121.1.15" {
  desc = "Directory String"
}

matching_rule "caseIgnoreMatch" {
  oid    = "2.5.13.2"
  syntax = "1.3.6.1.4.1.1466.115.121.1.15"
}

attribute_type "supannEtablissement" {
  oid        = "supannAttr:14"
  desc       = "code d etablissement"
  equality   = "caseIgnoreMatch"
  syntax     = "1.3.6.1.4.1.1466.115.121.1.15"
  syntax_len = 128
}

object_class "supannPerson" {
  oid        = "supann:2.2.1"
  sup        = ["top"]
  kind       = "auxiliary"
  may        = ["supannEtablissement"]
  extensions = { "X-ORIGIN" = ["SUPANN 2021"] }
}
`

func TestDecodeTheExample(t *testing.T) {
	d, err := decode(example)
	if err != nil {
		t.Fatal(err)
	}
	want := &schema.Definitions{
		ObjectIdentifiers: []schema.ObjectIdentifier{{Name: "supann", OID: "1.3.6.1.4.1.7135.1"}, {Name: "supannAttr", OID: "supann:2.1"}},
		Syntaxes:          []*schema.Syntax{{OID: "1.3.6.1.4.1.1466.115.121.1.15", Desc: "Directory String", Pos: schema.Position{File: "a.hcl", Line: 10, Column: 1}}},
		MatchingRules: []*schema.MatchingRule{{OID: "2.5.13.2", Names: []string{"caseIgnoreMatch"}, Syntax: "1.3.6.1.4.1.1466.115.121.1.15",
			Pos: schema.Position{File: "a.hcl", Line: 14, Column: 1}}},
		AttributeTypes: []*schema.AttributeType{{OID: "1.3.6.1.4.1.7135.1.2.1.14", Names: []string{"supannEtablissement"},
			Desc: "code d etablissement", Equality: "caseIgnoreMatch", Syntax: "1.3.6.1.4.1.1466.115.121.1.15", SyntaxLen: "128",
			Pos: schema.Position{File: "a.hcl", Line: 19, Column: 1}}},
		ObjectClasses: []*schema.ObjectClass{{OID: "1.3.6.1.4.1.7135.1.2.2.1", Names: []string{"supannPerson"}, Sup: []string{"top"},
			Kind: schema.Auxiliary, May: []string{"supannEtablissement"}, Extensions: []schema.Extension{{Name: "X-ORIGIN", Values: []string{"SUPANN 2021"}}},
			Pos: schema.Position{File: "a.hcl", Line: 27, Column: 1}}},
	}
	if !reflect.DeepEqual(d, want) {
		t.Fatalf("decoded %+v", d)
	}
	// The same checks as Build: on top of the standard schema, it builds.
	// (Its syntax and rule are the standard schema's own, so they are left
	// out: Build refuses a definition given twice.)
	std, _ := schema.Read(schema.StandardFiles()...)
	s, err := schema.BuildFrom(std, &schema.Definitions{AttributeTypes: d.AttributeTypes, ObjectClasses: d.ObjectClasses})
	if err != nil {
		t.Fatal(err)
	}
	if s.AttributeType("supannEtablissement").EqualityRule().OID != "2.5.13.2" {
		t.Error("not linked")
	}

	plain, err := Encode(d, EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plain), `oid        = "1.3.6.1.4.1.7135.1.2.1.14"`) {
		t.Errorf("without macros:\n%s", plain)
	}
	short, _ := Encode(d, EncodeOptions{Macros: true})
	if !strings.Contains(string(short), `oid        = "supannAttr:14"`) || !strings.Contains(string(short), `oid  = "supann:2.2.1"`) {
		t.Errorf("with macros:\n%s", short)
	}
	for _, out := range [][]byte{plain, short} {
		back, err := Decode(schema.File{Name: "x.hcl", Data: out})
		if err != nil || !reflect.DeepEqual(unplaced(back), unplaced(d)) {
			t.Errorf("round trip: %v\n%s", err, out)
		}
	}
}

// What a DESC can hold that HCL would read as a template or an escape.
func TestEncodeEscapesTemplates(t *testing.T) {
	d := &schema.Definitions{AttributeTypes: []*schema.AttributeType{{
		OID: "1.1", Names: []string{"a", "b", "c", "d", "e", "f"}, Syntax: "1.1",
		Desc: `${x} %{ if } \ " \27 ` + "\ttab\nline",
		Extensions: []schema.Extension{
			{Name: "X-A", Values: []string{"${y}", "%{z}"}},
			{Name: "X-EMPTY"},
			{Name: "X-MANY", Values: []string{"1", "2", "3", "4", "5"}},
		},
	}}}
	out, err := Encode(d, EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`$${x}`, `%%{ if }`, `\\`, `\"`, `\t`, `\n`, `"X-EMPTY" = []`} {
		if !strings.Contains(string(out), s) {
			t.Errorf("no %s in\n%s", s, out)
		}
	}
	back, err := Decode(schema.File{Name: "x.hcl", Data: out})
	if err != nil {
		t.Fatal(err)
	}
	d.AttributeTypes[0].Extensions[1].Values = nil
	if !reflect.DeepEqual(unplaced(back), d) {
		t.Errorf("read back %+v\n%s", back.AttributeTypes[0], out)
	}
}

func TestEncodeEverything(t *testing.T) {
	d := &schema.Definitions{
		Syntaxes:      []*schema.Syntax{{OID: "1.2", Extensions: []schema.Extension{{Name: "X-NOT-HUMAN-READABLE", Values: []string{"TRUE"}}}}},
		MatchingRules: []*schema.MatchingRule{{OID: "1.3", Syntax: "1.2", Obsolete: true, Desc: "r", Extensions: []schema.Extension{{Name: "X-O", Values: []string{"x"}}}}},
		AttributeTypes: []*schema.AttributeType{
			{OID: "1.4", Names: []string{"op"}, Sup: "x", Ordering: "o", Substr: "s", SingleValue: true, NoUserModification: true, Usage: schema.DSAOperation, Obsolete: true},
			{OID: "1.5", Syntax: "1.2", Collective: true},
		},
		ObjectClasses: []*schema.ObjectClass{
			{OID: "1.6", Names: []string{"c", "c2"}, Kind: schema.Abstract, Must: []string{"op"}, Obsolete: true},
			{OID: "1.7", Kind: schema.Structural},
		},
		DITContentRules: []*schema.DITContentRule{
			{OID: "1.7", Names: []string{"r", "r2"}, Desc: "d", Obsolete: true, Aux: []string{"a"}, Must: []string{"op"}, May: []string{"m", "n"},
				Not: []string{"x"}, Extensions: []schema.Extension{{Name: "X-O", Values: []string{"y"}}}},
		},
		NameForms: []*schema.NameForm{
			{OID: "1.8", Names: []string{"f"}, Desc: "d", Obsolete: true, OC: "c", Must: []string{"op"}, May: []string{"a", "b", "c", "d", "e"},
				Extensions: []schema.Extension{{Name: "X-O", Values: []string{"y"}}}},
		},
		DITStructureRules: []*schema.DITStructureRule{
			{ID: 0, Form: "f"},
			{ID: schema.MaxRuleID, Names: []string{"s", "s2"}, Desc: "d", Obsolete: true, Form: "1.8", Sup: []int{0, schema.MaxRuleID},
				Extensions: []schema.Extension{{Name: "X-O", Values: []string{"y"}}}},
		},
	}
	out, err := Encode(d, EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(schema.File{Name: "x.hcl", Data: out})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !reflect.DeepEqual(unplaced(back), d) {
		t.Errorf("read back differently:\n%s", out)
	}
	if strings.Contains(string(out), "structural") || strings.Contains(string(out), "userApplications") || strings.Contains(string(out), "false") {
		t.Errorf("a default was written:\n%s", out)
	}

	twice := []schema.Extension{{Name: "X-A"}, {Name: "X-A"}}
	for _, bad := range []*schema.Definitions{
		{ObjectIdentifiers: []schema.ObjectIdentifier{{Name: "a", OID: "b"}}},
		{Syntaxes: []*schema.Syntax{{OID: "1.1", Extensions: twice}}},
		{MatchingRules: []*schema.MatchingRule{{OID: "1.1", Syntax: "1.1", Extensions: twice}}},
		{AttributeTypes: []*schema.AttributeType{{OID: "1.1", Syntax: "1.1", Extensions: twice}}},
		{ObjectClasses: []*schema.ObjectClass{{OID: "1.1", Extensions: twice}}},
		{DITContentRules: []*schema.DITContentRule{{OID: "1.1", Extensions: twice}}},
		{NameForms: []*schema.NameForm{{OID: "1.1", OC: "c", Must: []string{"a"}, Extensions: twice}}},
		{DITStructureRules: []*schema.DITStructureRule{{ID: 1, Form: "f", Extensions: twice}}},
		{AttributeTypes: []*schema.AttributeType{{OID: "1.1", Syntax: "1.1", SyntaxLen: "x"}}},
	} {
		if _, err := Encode(bad, EncodeOptions{}); err == nil {
			t.Errorf("Encode(%+v) did not refuse", bad)
		}
	}
}

// Each guard of the decoder, with the position it reports. A break check
// for each: the "ok" form of the same input decodes.
func TestDecodeRefuses(t *testing.T) {
	const at = `attribute_type "a" {` + "\n"
	for _, c := range []struct{ src, want, ok string }{
		{at + `oid = "1.1"` + "\n" + `syntax = "1.1"` + "\n" + `desc = <<EOT` + "\nheredoc $${x}\nEOT\n}", ``, ``},
		{`bogus "x" {}`, `a.hcl:1:1: Unsupported block type`, ``},
		{`attribute_type "a" {`, `a.hcl:1:20: Unclosed configuration block`, ``},
		{at + `oid = "1.1"` + "\n" + `syntax = "1.1"` + "\n" + `nonsense = 1` + "\n}", `a.hcl:4:1: Unsupported argument`, at + `oid = "1.1"` + "\n" + `syntax = "1.1"` + "\n}"},
		{at + `oid = "1.${2}"` + "\n}", `a.hcl:2:7: Not a literal`, at + `oid = "1.2"` + "\nsyntax=\"1.1\"\n}"},
		{at + `oid = upper("x")` + "\n}", `Not a literal`, ``},
		{at + `oid = 1` + "\n}", `a.hcl:2:7: Incorrect type: oid must be a string`, ``},
		{at + `oid = ""` + "\n}", `Empty value`, ``},
		{at + `oid = "1.1"` + "\n" + `names = "b"` + "\nsyntax=\"1.1\"\n}", `names must be a list of strings`, ``},
		{at + `oid = "1.1"` + "\n" + `names = [1]` + "\nsyntax=\"1.1\"\n}", `none of them empty`, ``},
		{at + `oid = "1.1"` + "\n" + `single_value = "yes"` + "\nsyntax=\"1.1\"\n}", `single_value must be true or false`, ``},
		{at + `syntax = "1.1"` + "\n}", `a.hcl:1:1: Missing oid`, ``},
		{`attribute_type "1.1" {` + "\n" + `oid = "1.1"` + "\n}", `Redundant oid`, `attribute_type "1.1" { syntax = "1.1" }`},
		{`attribute_type "1.1" {` + "\n" + `names = ["x"]` + "\n}", `Names without a name`, ``},
		{at + `oid = "x:1"` + "\n}", `a.hcl:2:7: Invalid OID: the OID macro "x" is not defined before it is used`, ``},
		{at + `oid = "1.1.x"` + "\n}", `is neither a numeric OID nor name[:suffix]`, ``},
		{`attribute_type "a_b" {` + "\n" + `oid = "1.1"` + "\n" + `syntax = "1.1"` + "\n}", `a.hcl:1:16: Invalid name: "a_b" is not a descriptor`, ``},
		{at + `oid = "1.1"` + "\n" + `names = ["9"]` + "\nsyntax=\"1.1\"\n}", `a.hcl:3:9: Invalid name`, ``},
		{at + `oid = "1.1"` + "\n" + `names = ["A"]` + "\nsyntax=\"1.1\"\n}", `Duplicate definition: attribute_type name "a"`, ``},
		{at + `oid = "1.1"` + "\n" + `sup = "a b"` + "\n}", `Invalid sup: "a b" is not an OID`, ``},
		{at + `oid = "1.1"` + "\n" + `syntax = "1.1{3}"` + "\n}", `Invalid syntax`, at + `oid = "1.1"` + "\n" + `syntax = "1.1"` + "\nsyntax_len = 3\n}"},
		{at + `oid = "1.1"` + "\n" + `syntax = "1.1"` + "\n" + `syntax_len = 1.5` + "\n}", `syntax_len must be a whole number`, ``},
		{at + `oid = "1.1"` + "\n" + `syntax = "1.1"` + "\n" + `syntax_len = "3"` + "\n}", `syntax_len must be a whole number`, ``},
		{at + `oid = "1.1"` + "\n" + `sup = "b"` + "\n" + `syntax_len = 3` + "\n}", `syntax_len without syntax`, ``},
		{at + `oid = "1.1"` + "\n}", `Missing sup or syntax`, ``},
		{at + `oid = "1.1"` + "\n" + `sup = "b"` + "\n" + `usage = "nobody"` + "\n}", `Invalid usage`, at + `oid = "1.1"` + "\n" + `sup = "b"` + "\n" + `usage = "DSAOPERATION"` + "\n}"},
		{at + `oid = "1.1"` + "\n" + `sup = "b"` + "\n" + `collective = true` + "\n" + `usage = "dSAOperation"` + "\n}", `COLLECTIVE requires usage userApplications`, ``},
		{at + `oid = "1.1"` + "\n" + `sup = "b"` + "\n" + `no_user_modification = true` + "\n}", `NO-USER-MODIFICATION requires an operational usage`, ``},
		{at + `oid = "1.1"` + "\n" + `sup = "b"` + "\n" + `extensions = ["X-A"]` + "\n}", `extensions must be a map`, ``},
		{at + `oid = "1.1"` + "\n" + `sup = "b"` + "\n" + `extensions = { "Y-A" = [] }` + "\n}", `a.hcl:4:16: Invalid extension: "Y-A" is not an extension name`, at + `oid = "1.1"` + "\n" + `sup = "b"` + "\n" + `extensions = { X-A = [] }` + "\n}"},
		{at + `oid = "1.1"` + "\n" + `sup = "b"` + "\n" + `extensions = { "X-${a}" = [] }` + "\n}", `is not an extension name`, ``},
		{at + `oid = "1.1"` + "\n" + `sup = "b"` + "\n" + `extensions = { X-A = [], "X-A" = [] }` + "\n}", `Duplicate extension: X-A is given twice`, ``},
		{at + `oid = "1.1"` + "\n" + `sup = "b"` + "\n" + `extensions = { X-A = ["${x}"] }` + "\n}", `the values of X-A must be a list of literal strings`, ``},
		{at + `oid = "1.1"` + "\n" + `sup = "b"` + "\n" + `extensions = { X-A = "x" }` + "\n}", `X-A must be a list of strings`, ``},
		{`object_identifier "a" {}`, `Missing oid`, `object_identifier "a" { oid = "1.2" }`},
		{`object_identifier "a" { oid = 7 }`, `oid must be a string`, ``},
		{`object_identifier "a" { oid = "b:1" }`, `a.hcl:1:31: Invalid object identifier: the OID macro "b" is not defined before it is used`, ``},
		{`object_identifier "a b" { oid = "1.2" }`, `a.hcl:1:19: Invalid object identifier: the OID macro "a b" is not a descriptor`, ``},
		{`object_identifier "a" { oid = "1.2" }` + "\n" + `object_identifier "a" { oid = "1.3" }`, `is already defined as 1.2, and this makes it 1.3`, `object_identifier "a" { oid = "1.2" }` + "\n" + `object_identifier "a" { oid = "1.2" }`},
		{`ldap_syntax "name" {}`, `an ldap_syntax is labelled with its OID`, `ldap_syntax "1.1" {}`},
		{`ldap_syntax "x:1" {}`, `Invalid OID`, ``},
		{`ldap_syntax "1.1" {}` + "\n" + `ldap_syntax "1.1" {}`, `a.hcl:2:1: Duplicate definition: ldap_syntax "1.1" is already defined at a.hcl:1`, ``},
		{`matching_rule "m" { oid = "1.1" }`, `a matching rule must name its syntax`, "matching_rule \"m\" {\noid = \"1.1\"\nsyntax = \"1.2\"\n}"},
		{at + `oid = "1.1"` + "\n" + `syntax = "1.${"2"}"` + "\n}", `Not a literal`, ``},
		{at + `oid = "1.1"` + "\n" + `syntax = "1.%{ if true }2%{ endif }"` + "\n}", `Not a literal`, ``},
		{at + `oid = "1.1"` + "\n" + `syntax = "1.1"` + "\n" + `names = ["${b}"]` + "\n}", `Not a literal`, ``},
		{at + `oid = "1.1"` + "\n" + `syntax = "1.1"` + "\n" + `desc = <<EOT` + "\nheredoc $${x}\nEOT\n}", ``, ``},
		{`matching_rule "m" {}`, `Missing oid`, ``},
		{"object_class \"c\" {\noid = \"1.1\"\nkind = \"STRUCTURAL\"\n}", `Invalid kind`, "object_class \"c\" {\noid = \"1.1\"\nkind = \"structural\"\n}"},
		{"object_class \"c\" {\noid = \"1.1\"\nmust = [\"a$b\"]\n}", `Invalid must`, ``},
		{`object_class "c" {}`, `Missing oid`, ``},
		{`object_class "c" { oid = "1.1" }` + "\n" + `object_class "d" { oid = "1.1" }`, `object_class "1.1" is already defined`, ``},
		{strings.Repeat("[", MaxNesting+1), `a.hcl:1:65: Nested too deeply`, strings.Repeat("\n", 3)},

		// Found by FuzzDecode: a string that is not UTF-8 decoded, and
		// encoded to another (cty.StringVal replaces what is not UTF-8).
		{"ldap_syntax \"0.0\" { desc = \"$00005\xc1\x87\" }", `a.hcl:1:28: Invalid UTF-8: desc is not UTF-8`, `ldap_syntax "0.0" { desc = "$00005é" }`},
		{blk(`object_class "c"`, `oid = "1.1"`, "extensions = { X-A = [\"\xc1\x87\"] }"), `Invalid UTF-8: X-A holds a string that is not UTF-8`, ``},

		// The rules.
		{`dit_content_rule "r" {}`, `Missing oid`, `dit_content_rule "r" { oid = "2.5.6.6" }`},
		{blk(`dit_content_rule "r"`, `oid = "2.5.6.6"`, `aux = ["a b"]`), `a.hcl:3:7: Invalid aux`, blk(`dit_content_rule "r"`, `oid = "2.5.6.6"`, `aux = ["a"]`)},
		{blk(`dit_content_rule "r"`, `oid = "2.5.6.6"`, `not = "a"`), `not must be a list of strings`, ``},
		{blk(`dit_content_rule "r"`, `oid = "2.5.6.6"`, `oc = "a"`), `Unsupported argument`, ``},
		{`dit_content_rule "2.5.6.6" {}` + "\n" + `dit_content_rule "2.5.6.6" {}`, `dit_content_rule "2.5.6.6" is already defined`, ``},
		{blk(`name_form "f"`, `oid = "1.2"`, `oc = "c"`), `a.hcl:1:1: Missing oc or must`, blk(`name_form "f"`, `oid = "1.2"`, `oc = "c"`, `must = ["a"]`)},
		{blk(`name_form "f"`, `oid = "1.2"`, `must = ["a"]`), `Missing oc or must`, ``},
		{blk(`name_form "f"`, `oid = "1.2"`, `oc = "c d"`, `must = ["a"]`), `a.hcl:3:6: Invalid oc`, ``},
		{`name_form "f" {}`, `Missing oid`, ``},
		{`dit_structure_rule "r" { form = "f" }`, `a.hcl:1:1: Missing id`, blk(`dit_structure_rule "r"`, `id = 1`, `form = "f"`)},
		{blk(`dit_structure_rule "r"`, `id = 1`), `a.hcl:1:1: Missing form`, ``},
		{blk(`dit_structure_rule "1"`, `id = 1`, `form = "f"`), `a.hcl:2:6: Redundant id`, `dit_structure_rule "1" { form = "f" }`},
		{blk(`dit_structure_rule "1"`, `names = ["r"]`, `form = "f"`), `Names without a name`, ``},
		{`dit_structure_rule "01" { form = "f" }`, `a.hcl:1:20: Invalid rule ID: "01" is not a rule ID: a number from 0 to 2147483647`, ``},
		{`dit_structure_rule "2147483648" { form = "f" }`, `Invalid rule ID`, `dit_structure_rule "2147483647" { form = "f" }`},
		{blk(`dit_structure_rule "r"`, `id = 2147483648`, `form = "f"`), `a.hcl:2:6: Invalid id: id must be a rule ID, a whole number from 0 to 2147483647`, ``},
		{blk(`dit_structure_rule "r"`, `id = 1.5`, `form = "f"`), `Invalid id`, ``},
		{blk(`dit_structure_rule "r"`, `id = -1`, `form = "f"`), `a.hcl:2:6: Not a literal`, ``},
		{blk(`dit_structure_rule "r"`, `id = "1"`, `form = "f"`), `Invalid id`, ``},
		{blk(`dit_structure_rule "r"`, `id = 1`, `form = "f"`, `sup = [1, "2"]`), `a.hcl:4:7: Invalid sup`, blk(`dit_structure_rule "r"`, `id = 1`, `form = "f"`, `sup = [1, 2]`)},
		{blk(`dit_structure_rule "r"`, `id = 1`, `form = "f"`, `sup = []`), `sup must be a list of rule IDs`, ``},
		{blk(`dit_structure_rule "r"`, `id = 1`, `form = "f"`, `sup = 2`), `sup must be a list of rule IDs`, ``},
		{blk(`dit_structure_rule "r"`, `id = 1`, `form = "f a"`), `Invalid form`, ``},
		{blk(`dit_structure_rule "r_s"`, `id = 1`, `form = "f"`), `a.hcl:1:20: Invalid name`, ``},
		{blk(`dit_structure_rule "r"`, `id = 1`, `names = ["9"]`, `form = "f"`), `a.hcl:3:9: Invalid name`, ``},
		{blk(`dit_structure_rule "r"`, `id = 1`, `form = "f"`) + "\n" + blk(`dit_structure_rule "R"`, `id = 2`, `form = "f"`), `Duplicate definition: dit_structure_rule name "r"`, ``},
		{`dit_structure_rule "1" { form = "f" }` + "\n" + blk(`dit_structure_rule "r"`, `id = 1`, `form = "f"`), `a.hcl:2:1: Duplicate definition: dit_structure_rule "1" is already defined at a.hcl:1`, ``},
	} {
		_, err := decode(c.src)
		var he *Error
		if c.want == "" {
			if err != nil {
				t.Errorf("%s\n  -> %v", c.src, err)
			}
			continue
		}
		if !errors.As(err, &he) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s\n  -> %v\n  want %q", c.src, err, c.want)
		}
		if c.ok != "" {
			if _, err := decode(c.ok); err != nil {
				t.Errorf("break check %s: %v", c.ok, err)
			}
		}
	}
	big := make([]byte, schema.MaxFileSize+1)
	if _, err := Decode(schema.File{Name: "big.hcl", Data: big}); err == nil || !strings.Contains(err.Error(), "big.hcl:1:1: File too large") {
		t.Errorf("an oversized file: %v", err)
	}
	// A macro may be used in a later file, not in an earlier one.
	if _, err := decode(`object_identifier "a" { oid = "1.2" }`, `object_identifier "b" { oid = "a:1" }`); err != nil {
		t.Error(err)
	}
	if _, err := decode(`object_identifier "b" { oid = "a:1" }`, `object_identifier "a" { oid = "1.2" }`); err == nil {
		t.Error("a macro was used before it was defined")
	}
}

// A definition decoded from HCL carries its block's position, column
// included, so a schema.BuildError about it points at the block -- here an
// indented one after another definition -- and so does the first definition
// of a duplicate.
func TestBuildErrorPointsAtTheBlock(t *testing.T) {
	std, err := schema.Read(schema.StandardFiles()...)
	if err != nil {
		t.Fatal(err)
	}
	d, err := decode("# site\nattribute_type \"ok\" {\n  oid = \"1.9.1\"\n  sup = \"name\"\n}\n\n  attribute_type \"bad\" {\n    oid = \"1.9.2\"\n    sup = \"nope\"\n  }\n")
	if err != nil {
		t.Fatal(err)
	}
	_, err = schema.BuildFrom(std, d)
	var be *schema.BuildError
	if !errors.As(err, &be) || be.Kind != schema.UnknownReference || be.Field != "SUP" || be.Ref != "nope" ||
		be.Pos != (schema.Position{File: "a.hcl", Line: 7, Column: 3}) ||
		err.Error() != "a.hcl:7:3: schema: the attribute type bad has the supertype nope, which is not defined" {
		t.Errorf("%#v: %v", be, err)
	}
	// Decode refuses a duplicate among the files it is given; two decodings
	// are built together, as authnd builds its schema blocks.
	one, err := decode(`attribute_type "x" {` + "\n" + `oid = "1.9.1"` + "\n" + `sup = "name"` + "\n}\n")
	if err != nil {
		t.Fatal(err)
	}
	two, err := Decode(schema.File{Name: "b.hcl", Data: []byte(`object_class "y" { oid = "1.9.1" }` + "\n" + `attribute_type "x2" {` + "\n" + `oid = "1.9.1"` + "\n" + `sup = "name"` + "\n}\n")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = schema.BuildFrom(std, one, two)
	if !errors.As(err, &be) || be.Kind != schema.DuplicateOID || be.Pos != (schema.Position{File: "b.hcl", Line: 2, Column: 1}) ||
		be.RefPos != (schema.Position{File: "a.hcl", Line: 1, Column: 1}) || be.Ref != "x" ||
		!strings.HasSuffix(err.Error(), "is defined twice (first defined at a.hcl:1:1)") {
		t.Errorf("%#v: %v", be, err)
	}
}

func TestErrorFormat(t *testing.T) {
	e := &Error{hcl.Diagnostics{{Summary: "One"}, {Summary: "Two", Detail: "why", Subject: &hcl.Range{Filename: "f", Start: hcl.Pos{Line: 2, Column: 3}}}}}
	if got := e.Error(); got != "One\nf:2:3: Two: why" {
		t.Errorf("%q", got)
	}
}

// FuzzDecode: no panic, and what decodes encodes to HCL that decodes to
// the same definitions, and encodes to the same bytes.
func FuzzDecode(f *testing.F) {
	f.Add([]byte(example))
	f.Add([]byte(`attribute_type "a" { oid = "1.1"` + "\n" + `syntax = "1.2"` + "\n" + `extensions = { X-A = ["${"$"}"] } }`))
	f.Add([]byte(`ldap_syntax "1.2" { desc = "%%{x}" }`))
	f.Add([]byte(rules))
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := Decode(schema.File{Name: "fuzz.hcl", Data: data})
		if err != nil {
			return
		}
		out, err := Encode(d, EncodeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		back, err := Decode(schema.File{Name: "encoded.hcl", Data: out})
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if !reflect.DeepEqual(unplaced(d), unplaced(back)) {
			t.Fatalf("decoded differently:\n%s", out)
		}
		again, _ := Encode(back, EncodeOptions{})
		if string(again) != string(out) {
			t.Fatalf("two encodings differ:\n%s\n%s", out, again)
		}
	})
}
