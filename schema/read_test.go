// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func read(t *testing.T, text string) *Definitions {
	t.Helper()
	d, err := Read(File{Name: "f", Data: []byte(text)})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func readErr(text string) error {
	_, err := Read(File{Name: "f", Data: []byte(text)})
	return err
}

// The two forms continue a line differently, and a DESC folded inside a
// word shows it: slapd.conf(5) keeps a continuation line after its first
// white space character, RFC 2849 removes exactly one space.
func TestFoldingMidWordInBothForms(t *testing.T) {
	d := read(t, "attributetype ( 1.1 NAME 'a' DESC 'ab\n\t  cd' SYNTAX 1.1 )\n")
	if got := d.AttributeTypes[0].Desc; got != "ab   cd" {
		t.Errorf(".schema: DESC %q, want %q (fp_getline: the first white space becomes one space, the rest stays)", got, "ab   cd")
	}
	// "SYN" / " TAX" is two words in a .schema file, so this is refused.
	if err := readErr("attributetype ( 1.1 NAME 'a' SYN\n TAX 1.1 )\n"); err == nil {
		t.Error(".schema: a keyword split by a continuation line was read")
	}
	d = read(t, "dn: cn=x,cn=schema,cn=config\nolcAttributeTypes: ( 1.1 NAME 'a' DES\n C 'ab\n cd' SYN\n TAX 1.1 )\n")
	if got := d.AttributeTypes[0].Desc; got != "abcd" {
		t.Errorf("LDIF: DESC %q, want %q (RFC 2849: one space removed)", got, "abcd")
	}
	d = read(t, "attributetype ( 1.1 NAME 'a' DES\\\nC 'x' SYNTAX 1.1 )\n")
	if got := d.AttributeTypes[0].Desc; got != "x" {
		t.Errorf("a trailing backslash joins with nothing between: DESC %q", got)
	}
}

func TestReadSchemaFormAsSlapdDoes(t *testing.T) {
	d := read(t, strings.Join([]string{
		"# a comment",
		" attributetype ( continued comment, unwrapped before comment processing",
		"",
		"   ",
		"objectIdentifier base 1.3.6",
		"objectidentifier attrs base:1",
		"ObjectIdentifier attrs base:1", // the identical redefinition slapd allows
		"attributetype ( attrs:7",
		"\tSYNTAX '1.3.6.1.4.1.1466.115.121.1.15{32}'", // quoted, as libldap allows
		"\tNAME ( 'x'\t'y' ) EQUALITY caseIgnoreMatch", // any order, tabs as space
		"\tDESC 'd'SINGLE-VALUE )",                     // no space after a quote
		"objectclass ( base:2 NAME 'c' MAY 'x' AUXILIARY SUP top )",
		"ldapsyntax ( base:3 DESC 's' )",
		"matchingrule ( base:4 NAME 'm' SYNTAX base:3 )",
		"",
	}, "\n"))
	at := d.AttributeTypes[0]
	want := &AttributeType{OID: "1.3.6.1.7", Names: []string{"x", "y"}, Desc: "d", Equality: "caseIgnoreMatch",
		Syntax: "1.3.6.1.4.1.1466.115.121.1.15", SyntaxLen: "32", SingleValue: true}
	if want.Pos = (Position{"f", 8, 1}); !reflect.DeepEqual(at, want) {
		t.Errorf("attribute type %+v, want %+v", at, want)
	}
	if c := d.ObjectClasses[0]; c.OID != "1.3.6.2" || c.Kind != Auxiliary || c.May[0] != "x" || c.Sup[0] != "top" {
		t.Errorf("object class %+v", c)
	}
	if d.Syntaxes[0].OID != "1.3.6.3" || d.MatchingRules[0].Syntax != "1.3.6.3" {
		t.Errorf("syntax %+v, rule %+v", d.Syntaxes[0], d.MatchingRules[0])
	}
	if want := []ObjectIdentifier{{"base", "1.3.6"}, {"attrs", "base:1"}}; !reflect.DeepEqual(d.ObjectIdentifiers, want) {
		t.Errorf("ObjectIdentifiers %v, want %v", d.ObjectIdentifiers, want)
	}
	// The strict parser, for what a server publishes, still refuses all of
	// it: the order, the tab, the quotes, the missing space.
	for _, s := range []string{
		"( 1.1 SYNTAX 1.1 NAME 'a' )",
		"( 1.1 NAME 'a'\tSYNTAX 1.1 )",
		"( 1.1 SYNTAX '1.1' )",
		"( 1.1 NAME 'a'SYNTAX 1.1 )",
		"( a:1 SYNTAX 1.1 )",
	} {
		if _, err := ParseAttributeType(s); err == nil {
			t.Errorf("ParseAttributeType(%q) accepted it", s)
		}
	}
}

func TestReadRefusesWithAPosition(t *testing.T) {
	long := "attributetype ( 1.1 DESC '" + strings.Repeat("x", MaxLineLength) + "' SYNTAX 1.1 )"
	for _, c := range []struct{ text, want string }{
		{" ( 1.1 )", "f:1: a continuation line with no definition before it"},
		{long, "f:1: the line is 2040 bytes, more than the 2000 slapd.conf(5) allows"},
		{"bogus ( 1.1 )", `f:1: "bogus" is not a kind of definition`},
		{"objectidentifier a", "f:1: objectidentifier takes a name and an OID, and has 1 arguments"},
		{"objectidentifier a b:1", `f:1: schema: the OID macro "b" is not defined before it is used`},
		{"objectidentifier a 1.2\nattributetype ( a:1\n\tNAME 'x' SYNTAX zz:1 )", `f:3:18: schema: at offset 22: expected a numeric OID, found "zz:1", and the OID macro "zz" is not defined`},
		{"attributetype ( 1.1 NAME 'a' NAME 'b' SYNTAX 1.1 )", "f:1:30: schema: at offset 15: NAME is repeated"},
		{"attributetype ( '1.1 NAME 'a' SYNTAX 1.1 )", `f:1:21: schema: at offset 6: expected '\'', found ' '`},
		{"attributetype ( 1.1 SYNTAX '1.1{x}' )", `expected a number in braces, found "x"`},
		{"attributetype ( 1.1 SYNTAX '1.1{3' )", `expected '}'`},
		{"attributetype ( 1.1 SYNTAX '1.1{3} )", `expected '\''`},
		{"attributetype ( 1.1 SYNTAX 'x' )", "expected a numeric OID"},
		{"attributetype", `f:1:14: schema: at offset 0: expected '('`},
	} {
		err := readErr(c.text)
		var fe *FileError
		if !errors.As(err, &fe) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.text, err, c.want)
		}
	}
	if err := readErr(strings.Repeat("#", MaxFileSize+1)); err == nil || !strings.Contains(err.Error(), "more than the 4194304") {
		t.Errorf("an oversized file: %v", err)
	}
}

func TestReadLDIF(t *testing.T) {
	def := "( 1.1 NAME 'a' DESC 'café ${x}' SYNTAX 1.1 )"
	b64 := base64.StdEncoding.EncodeToString([]byte(def))
	d := read(t, strings.Join([]string{
		"# a comment",
		" folded into the comment",
		"version: 1",
		"",
		"dn: cn=x,cn=schema,cn=config",
		"changetype: modify",
		"add: olcAttributeTypes",
		"olcAttributeTypes:: " + b64[:20],
		" " + b64[20:],
		"-",
		"replace: description",
		"description: kept out",
		"-",
		"",
		"dn: cn=Subschema",
		"changetype: add",
		"objectClass: subschema",
		"ldapSyntaxes: ( 1.2 DESC 's' )",
		"matchingRules: ( 1.3 NAME 'm' SYNTAX 1.2 )",
		"matchingRuleUse: ( 1.3 APPLIES a )",
		"attributeTypes;x-option: {3}( 1.4 NAME 'b' SUP a )",
		"objectClasses: ( 1.5 NAME 'c' MAY a )",
		"olcObjectIdentifier: {0}base 1.6",
		"olcObjectClasses:{1}( base:1 NAME 'd' )",
		"olcDitContentRules: {0}( base:1 NAME 'd' MUST a )",
		"dITContentRules: ( 1.5 NAME 'c' NOT a )",
		"nameForms: ( 1.7 NAME 'f' OC c MUST a )",
		"dITStructureRules: ( 1 NAME 'r' FORM f SUP ( 1 2 ) )",
		"",
	}, "\r\n"))
	if got := d.AttributeTypes[0].Desc; got != "café ${x}" {
		t.Errorf("base64: DESC %q", got)
	}
	if len(d.DITContentRules) != 2 || d.DITContentRules[0].OID != "1.6.1" || d.DITContentRules[1].Not[0] != "a" ||
		len(d.NameForms) != 1 || d.NameForms[0].OC != "c" ||
		len(d.DITStructureRules) != 1 || !reflect.DeepEqual(d.DITStructureRules[0].Sup, []int{1, 2}) {
		t.Errorf("the rules: %+v %+v %+v", d.DITContentRules, d.NameForms, d.DITStructureRules)
	}
	if len(d.Syntaxes) != 1 || len(d.MatchingRules) != 1 || len(d.AttributeTypes) != 2 || len(d.ObjectClasses) != 2 ||
		d.AttributeTypes[1].Sup != "a" || d.ObjectClasses[1].OID != "1.6.1" {
		t.Errorf("read %+v", d)
	}

	b64bad := base64.StdEncoding.EncodeToString([]byte("( 1.1 NAME )"))
	for _, c := range []struct{ text, want string }{
		{"dn: x\n continued\n", ""},
		{"dn: x\n\n continued", "f:3: a continuation line with no line before it"},
		{"dn: x\nnot a line", `f:2: "not" is not "name: value"`},
		{"dn: x\nattributeTypes:: !!", "f:2: the base64 value of attributeTypes"},
		{"dn: x\nattributeTypes:: " + b64bad, "f:2: schema: at offset"},
		{"dn: x\nattributeTypes:< file:///etc/passwd", "f:2: attributeTypes is a URL"},
		{"dn: x\nchangetype: delete", "f:2: changetype delete: only definitions that are added"},
		{"dn: x\nchangetype: modify\ndelete: olcAttributeTypes", "f:3: delete: olcAttributeTypes: only definitions"},
		{"dn: x\nchangetype: modify\nreplace: olcDitContentRules", "f:3: replace: olcDitContentRules"},
		{"dn: x\nnameForms: ( 1.1 )", "f:2:19: schema: at offset 7: a name form must name its OC and its MUST"},
		{"dn: x\nchangetype: modify\ndelete: nameForms", "f:3: delete: nameForms: only definitions"},
		{"dn: x\nolcAttributeTypes: {0}( 1.1 NAME 'a' SYN\n TAX zz:1 )", `f:3:6: schema: at offset`},
		{"dn: x\nolcObjectIdentifier: a", "f:2: objectidentifier takes a name and an OID"},
		{"dn: x\nolcAttributeTypes: {x}( 1.1 SYNTAX 1.1 )", `f:2:20: schema: at offset 0: expected '('`},
	} {
		err := readErr(c.text)
		if c.want == "" {
			if err != nil {
				t.Errorf("%q: %v", c.text, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.text, err, c.want)
		}
	}
	// base64: the error has a line and no column.
	var fe *FileError
	if err := readErr("dn: x\nattributeTypes:: " + b64bad); !errors.As(err, &fe) || fe.Column != 0 {
		t.Errorf("a base64 value's error: %#v", err)
	}
}

func TestFormatReadsBackToTheSameDefinitions(t *testing.T) {
	std, err := Read(StandardFiles()...)
	if err != nil {
		t.Fatal(err)
	}
	src := "objectidentifier base 1.3.6\nobjectidentifier attrs base:1\n" +
		"attributetype ( attrs:7 NAME 'x' DESC 'a \\27quote\\27 and \\5C' SYNTAX 1.3.6.9{4} X-ORIGIN ( 'one' 'two' ) X-E ( ) )\n" +
		"attributetype ( 1.9 SUP x )\n"
	mine := read(t, src)
	for _, d := range []*Definitions{std, mine} {
		for _, macros := range []bool{false, true} {
			out, err := d.Format(macros)
			if err != nil {
				t.Fatal(err)
			}
			back, err := Read(File{Name: "formatted", Data: out})
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if !reflect.DeepEqual(unplaced(d), unplaced(back)) {
				t.Errorf("macros=%v: the formatted definitions read back differently:\n%s", macros, out)
			}
		}
	}
	out, _ := mine.Format(true)
	if !strings.Contains(string(out), "attributetype ( attrs:7\n\tNAME 'x'\n") || !strings.Contains(string(out), "\tSYNTAX base:9{4}\n") {
		t.Errorf("with macros:\n%s", out)
	}

	bad := &Definitions{AttributeTypes: []*AttributeType{{OID: "1.1", Desc: "two\nlines", Syntax: "1.1"}}}
	if _, err := bad.Format(false); err == nil || !strings.Contains(err.Error(), "line break") {
		t.Errorf("a line break in a value: %v", err)
	}
	bad = &Definitions{ObjectIdentifiers: []ObjectIdentifier{{"a", "b:1"}}}
	if _, err := bad.Format(false); err == nil {
		t.Error("an undefined macro was formatted")
	}
}

// BuildFrom copies: the same Definitions build twice, and so do elements
// taken from a built Schema.
func TestBuildFromCopies(t *testing.T) {
	d, err := Read(StandardFiles()...)
	if err != nil {
		t.Fatal(err)
	}
	a, err := BuildFrom(d)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildFrom(d)
	if err != nil {
		t.Fatal(err)
	}
	if a.AttributeType("cn") == b.AttributeType("cn") || a.AttributeType("cn").Superior() == b.AttributeType("cn").Superior() {
		t.Error("two builds share elements")
	}
	again := &Definitions{Syntaxes: a.Syntaxes(), MatchingRules: a.MatchingRules(), AttributeTypes: a.AttributeTypes(), ObjectClasses: a.ObjectClasses()}
	c, err := BuildFrom(again)
	if err != nil {
		t.Fatal(err)
	}
	if c.ObjectClass("person").MustTypes()[0] == a.ObjectClass("person").MustTypes()[0] {
		t.Error("a build from built elements links to the old schema")
	}
}

// FuzzRead: no panic, and what reads formats and reads back the same.
func FuzzRead(f *testing.F) {
	for _, s := range []string{
		"objectidentifier a 1.2\nattributetype ( a:1 NAME 'x' SYNTAX 1.1{3} X-O 'y' )\nobjectclass ( a:2 NAME 'c' MAY x )\n",
		"dn: cn=x\nolcAttributeTypes: {0}( 1.1 NAME 'a' DES\n C 'b' SUP c )\n",
		"ldapsyntax ( 1.2 DESC 'x' )\nmatchingrule ( 1.3 NAME 'm' SYNTAX 1.2 )\n",
		"objectidentifier e 1.9\nditcontentrule ( e:1 NOT a AUX b )\nnameform ( e:2 MUST a OC c )\nditstructurerule ( 3 SUP ( 1 2 ) FORM e:2 )\n",
		"dn: x\ndITContentRules: ( 1.1 MUST a )\nnameForms: ( 1.2 OC c MUST a )\ndITStructureRules: ( 0 FORM 1.2 SUP 0 )\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := Read(File{Name: "fuzz", Data: data})
		if err != nil {
			return
		}
		out, err := d.Format(false)
		if err != nil {
			return // a line break in a value, which .schema cannot hold
		}
		back, err := Read(File{Name: "formatted", Data: out})
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if !reflect.DeepEqual(unplaced(d), unplaced(back)) {
			t.Fatalf("read back differently:\n%s", out)
		}
	})
}
