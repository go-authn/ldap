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

func decode(src ...string) (*schema.Definitions, error) {
	var fs []schema.File
	for i, s := range src {
		fs = append(fs, schema.File{Name: []string{"a.hcl", "b.hcl"}[i], Data: []byte(s)})
	}
	return Decode(fs...)
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
		Syntaxes:          []*schema.Syntax{{OID: "1.3.6.1.4.1.1466.115.121.1.15", Desc: "Directory String"}},
		MatchingRules:     []*schema.MatchingRule{{OID: "2.5.13.2", Names: []string{"caseIgnoreMatch"}, Syntax: "1.3.6.1.4.1.1466.115.121.1.15"}},
		AttributeTypes: []*schema.AttributeType{{OID: "1.3.6.1.4.1.7135.1.2.1.14", Names: []string{"supannEtablissement"},
			Desc: "code d etablissement", Equality: "caseIgnoreMatch", Syntax: "1.3.6.1.4.1.1466.115.121.1.15", SyntaxLen: "128"}},
		ObjectClasses: []*schema.ObjectClass{{OID: "1.3.6.1.4.1.7135.1.2.2.1", Names: []string{"supannPerson"}, Sup: []string{"top"},
			Kind: schema.Auxiliary, May: []string{"supannEtablissement"}, Extensions: []schema.Extension{{Name: "X-ORIGIN", Values: []string{"SUPANN 2021"}}}}},
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
		if err != nil || !reflect.DeepEqual(back, d) {
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
	if !reflect.DeepEqual(back, d) {
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
	}
	out, err := Encode(d, EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(schema.File{Name: "x.hcl", Data: out})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !reflect.DeepEqual(back, d) {
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
		if !reflect.DeepEqual(d, back) {
			t.Fatalf("decoded differently:\n%s", out)
		}
		again, _ := Encode(back, EncodeOptions{})
		if string(again) != string(out) {
			t.Fatalf("two encodings differ:\n%s\n%s", out, again)
		}
	})
}
