// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// buildErr is the BuildError a build of base and extra returns, or fails.
func buildErr(t *testing.T, extra string) *BuildError {
	t.Helper()
	_, err := build(extra)
	var be *BuildError
	if !errors.As(err, &be) {
		t.Fatalf("%q: %v is not a *BuildError", extra, err)
	}
	return be
}

// Every kind of BuildError, each from a real input, with everything it says.
// Each refused definition starts on line 3 of "extra", after a comment and a
// blank line, and is folded over two lines: its position is the line it
// starts on. base (schema_test.go) defines, on its lines 2 to 5, the syntax
// 1.1.1, the rule eq, the type a and the abstract class top.
func TestEveryBuildErrorKind(t *testing.T) {
	at := func(file string, line int) Position { return Position{file, line, 1} }
	for _, c := range []struct {
		extra                 string
		kind                  BuildErrorKind
		el                    Element
		oid, name, field, ref string
		refOID                string
		pos, refPos           Position
		says                  string
	}{
		{"ldapsyntax ( 1.1.1\n DESC 'again' )", DuplicateOID, ElementSyntax, "1.1.1", "", "", "1.1.1", "1.1.1", at("extra", 3), at("base", 2),
			"extra:3:1: schema: the syntax 1.1.1 is defined twice (first defined at base:2:1)"},
		{"matchingrule ( 1.1.2 NAME 'other'\n SYNTAX 1.1.1 )", DuplicateOID, ElementMatchingRule, "1.1.2", "other", "", "eq", "1.1.2", at("extra", 3), at("base", 3),
			"extra:3:1: schema: the matching rule 1.1.2 is defined twice (first defined at base:3:1)"},
		{"attributetype ( 1.1.3\n SUP a )", DuplicateOID, ElementAttributeType, "1.1.3", "", "", "a", "1.1.3", at("extra", 3), at("base", 4),
			"schema: the attribute type 1.1.3 is defined twice"},
		{"objectclass ( 1.1.4\n SUP top )", DuplicateOID, ElementObjectClass, "1.1.4", "", "", "top", "1.1.4", at("extra", 3), at("base", 5),
			"schema: the object class 1.1.4 is defined twice"},
		{"matchingrule ( 1.9 NAME 'EQ'\n SYNTAX 1.1.1 )", DuplicateName, ElementMatchingRule, "1.9", "EQ", "NAME", "EQ", "1.1.2", at("extra", 3), at("base", 3),
			`extra:3:1: schema: the name "EQ" is given to two matching rules (first defined at base:3:1)`},
		{"attributetype ( 1.9 NAME ( 'x' 'A' )\n SUP a )", DuplicateName, ElementAttributeType, "1.9", "x", "NAME", "A", "1.1.3", at("extra", 3), at("base", 4),
			`name "A" is given to two attribute types`},
		{"objectclass ( 1.9 NAME 'TOP'\n SUP top )", DuplicateName, ElementObjectClass, "1.9", "TOP", "NAME", "TOP", "1.1.4", at("extra", 3), at("base", 5),
			`name "TOP" is given to two object classes`},
		{"matchingrule ( 1.9 NAME 'm'\n SYNTAX 9.9 )", UnknownReference, ElementMatchingRule, "1.9", "m", "SYNTAX", "9.9", "", at("extra", 3), Position{},
			"extra:3:1: schema: the matching rule m has the syntax 9.9, which is not defined"},
		{"attributetype ( 1.9 NAME 'x'\n EQUALITY nope SYNTAX 1.1.1 )", UnknownReference, ElementAttributeType, "1.9", "x", "EQUALITY", "nope", "", at("extra", 3), Position{},
			"EQUALITY rule nope, which is not defined"},
		{"attributetype ( 1.9\n ORDERING nope SYNTAX 1.1.1 )", UnknownReference, ElementAttributeType, "1.9", "", "ORDERING", "nope", "", at("extra", 3), Position{},
			"extra:3:1: schema: the attribute type 1.9 has the ORDERING rule nope"},
		{"attributetype ( 1.9\n SUBSTR nope SYNTAX 1.1.1 )", UnknownReference, ElementAttributeType, "1.9", "", "SUBSTR", "nope", "", at("extra", 3), Position{},
			"SUBSTR rule nope"},
		{"attributetype ( 1.9\n SYNTAX 9.9 )", UnknownReference, ElementAttributeType, "1.9", "", "SYNTAX", "9.9", "", at("extra", 3), Position{},
			"has the syntax 9.9, which is not defined"},
		{"attributetype ( 1.9\n SUP nope )", UnknownReference, ElementAttributeType, "1.9", "", "SUP", "nope", "", at("extra", 3), Position{},
			"supertype nope, which is not defined"},
		{"objectclass ( 1.9\n SUP nope )", UnknownReference, ElementObjectClass, "1.9", "", "SUP", "nope", "", at("extra", 3), Position{},
			"superclass nope, which is not defined"},
		{"objectclass ( 1.9\n MUST nope )", UnknownReference, ElementObjectClass, "1.9", "", "MUST", "nope", "", at("extra", 3), Position{},
			"has MUST nope, which is not a defined attribute type"},
		{"objectclass ( 1.9\n MAY nope )", UnknownReference, ElementObjectClass, "1.9", "", "MAY", "nope", "", at("extra", 3), Position{},
			"has MAY nope, which is not a defined attribute type"},
		{"attributetype ( 1.9 NAME 'x'\n SUP y )\nattributetype ( 1.8 NAME 'y' SUP x )", SuperiorCycle, ElementAttributeType, "1.9", "x", "SUP", "", "", at("extra", 3), Position{},
			"extra:3:1: schema: the attribute type x is its own supertype"},
		{"objectclass ( 1.9 NAME 'x'\n SUP y )\nobjectclass ( 1.8 NAME 'y' SUP x )", SuperiorCycle, ElementObjectClass, "1.9", "x", "SUP", "", "", at("extra", 3), Position{},
			"its own superclass"},
		{"objectclass ( 1.8 SUP s\n ABSTRACT )\nobjectclass ( 1.9 NAME 's' SUP top )", KindViolation, ElementObjectClass, "1.8", "", "SUP", "s", "1.9", at("extra", 3), at("extra", 5),
			"extra:3:1: schema: the abstract class 1.8 derives from the structural class s (RFC 4512 2.4.1)"},
		{"objectclass ( 1.8\n SUP x )\nobjectclass ( 1.9 NAME 'x' SUP top AUXILIARY )", KindViolation, ElementObjectClass, "1.8", "", "SUP", "x", "1.9", at("extra", 3), at("extra", 5),
			"structural class 1.8 derives from the auxiliary class x (RFC 4512 2.4.2)"},
		{"objectclass ( 1.8 SUP s\n AUXILIARY )\nobjectclass ( 1.9 NAME 's' SUP top )", KindViolation, ElementObjectClass, "1.8", "", "SUP", "s", "1.9", at("extra", 3), at("extra", 5),
			"auxiliary class 1.8 derives from the structural class s (RFC 4512 2.4.3)"},
		{"attributetype ( 1.9 SUP a\n USAGE dSAOperation )", UsageMismatch, ElementAttributeType, "1.9", "", "SUP", "a", "1.1.3", at("extra", 3), at("base", 4),
			"extra:3:1: schema: the attribute type 1.9 is dSAOperation and its supertype a is userApplications (RFC 4512 2.5.1)"},
		{"attributetype ( 1.8\n SUP c )\nattributetype ( 1.9 NAME 'c' SYNTAX 1.1.1 COLLECTIVE )", CollectiveMismatch, ElementAttributeType, "1.8", "", "SUP", "c", "1.9", at("extra", 3), at("extra", 5),
			"must be COLLECTIVE like its supertype c"},
		{"attributetype ( 1.9 SYNTAX 1.1.1\n COLLECTIVE USAGE directoryOperation )", UsageViolation, ElementAttributeType, "1.9", "", "COLLECTIVE", "", "", at("extra", 3), Position{},
			"extra:3:1: schema: the attribute type 1.9 is COLLECTIVE and directoryOperation (RFC 4512 4.1.2)"},
		{"attributetype ( 1.9 SYNTAX 1.1.1\n NO-USER-MODIFICATION )", UsageViolation, ElementAttributeType, "1.9", "", "NO-USER-MODIFICATION", "", "", at("extra", 3), Position{},
			"NO-USER-MODIFICATION and a user attribute"},

		// DIT content rules (RFC 4512 4.1.6). 's' is structural, on line 5.
		{"ditcontentrule ( 1.9\n NAME 'r' )", UnknownReference, ElementDITContentRule, "1.9", "r", "", "1.9", "", at("extra", 3), Position{},
			"extra:3:1: schema: the DIT content rule r is for the object class 1.9, which is not defined"},
		{"ditcontentrule ( 1.1.4\n NAME 'r' )", KindViolation, ElementDITContentRule, "1.1.4", "r", "", "top", "1.1.4", at("extra", 3), at("base", 5),
			"the DIT content rule r is for the abstract class top, and a content rule is for a structural class (RFC 4512 4.1.6)"},
		{"ditcontentrule ( 1.8\n AUX nope )\nobjectclass ( 1.8 NAME 's' SUP top )", UnknownReference, ElementDITContentRule, "1.8", "", "AUX", "nope", "", at("extra", 3), Position{},
			"the DIT content rule 1.8 has AUX nope, which is not a defined object class"},
		{"ditcontentrule ( 1.8\n AUX s )\nobjectclass ( 1.8 NAME 's' SUP top )", KindViolation, ElementDITContentRule, "1.8", "", "AUX", "s", "1.8", at("extra", 3), at("extra", 5),
			"has AUX s, which is structural, not auxiliary (RFC 4512 4.1.6)"},
		{"ditcontentrule ( 1.8\n AUX ( x $ X ) )\nobjectclass ( 1.8 NAME 's' SUP top )\nobjectclass ( 1.7 NAME 'x' SUP top AUXILIARY )", DuplicateMember, ElementDITContentRule, "1.8", "", "AUX", "X", "1.7", at("extra", 3), at("extra", 6),
			"the DIT content rule 1.8 lists the class x twice"},
		{"ditcontentrule ( 1.8\n MUST nope )\nobjectclass ( 1.8 NAME 's' SUP top )", UnknownReference, ElementDITContentRule, "1.8", "", "MUST", "nope", "", at("extra", 3), Position{},
			"the DIT content rule 1.8 has MUST nope, which is not a defined attribute type"},
		{"ditcontentrule ( 1.8\n MAY nope )\nobjectclass ( 1.8 NAME 's' SUP top )", UnknownReference, ElementDITContentRule, "1.8", "", "MAY", "nope", "", at("extra", 3), Position{},
			"has MAY nope"},
		{"ditcontentrule ( 1.8\n NOT nope )\nobjectclass ( 1.8 NAME 's' SUP top )", UnknownReference, ElementDITContentRule, "1.8", "", "NOT", "nope", "", at("extra", 3), Position{},
			"has NOT nope"},
		{"ditcontentrule ( 1.8\n MUST a NOT A )\nobjectclass ( 1.8 NAME 's' SUP top )", DuplicateMember, ElementDITContentRule, "1.8", "", "NOT", "A", "1.1.3", at("extra", 3), at("base", 4),
			"the DIT content rule 1.8 lists the attribute type a twice"},
		{"ditcontentrule ( 1.8\n NOT a )\nobjectclass ( 1.8 NAME 's' SUP top )", PrecludedRequired, ElementDITContentRule, "1.8", "", "NOT", "a", "1.1.3", at("extra", 3), at("base", 4),
			"extra:3:1: schema: the DIT content rule 1.8 precludes a, which the class s requires (RFC 4512 4.1.6)"},
		{"ditcontentrule ( 1.8\n NAME 'r2' )\nobjectclass ( 1.8 NAME 's' SUP top )\nditcontentrule ( 1.8 NAME 'r1' )", DuplicateOID, ElementDITContentRule, "1.8", "r1", "", "r2", "1.8", at("extra", 6), at("extra", 3),
			"extra:6:1: schema: the DIT content rule 1.8 is defined twice (first defined at extra:3:1)"},
		{"ditcontentrule ( 1.8\n NAME 'R' )\nobjectclass ( 1.8 NAME 's' SUP top )\nobjectclass ( 1.7 NAME 't' SUP top )\nditcontentrule ( 1.7 NAME 'r' )", DuplicateName, ElementDITContentRule, "1.7", "r", "NAME", "r", "1.8", at("extra", 7), at("extra", 3),
			`the name "r" is given to two DIT content rules`},

		// Name forms (RFC 4512 4.1.7.2).
		{"nameform ( 1.9 NAME 'f'\n OC nope MUST a )", UnknownReference, ElementNameForm, "1.9", "f", "OC", "nope", "", at("extra", 3), Position{},
			"extra:3:1: schema: the name form f has OC nope, which is not a defined object class"},
		{"nameform ( 1.9\n OC top MUST a )", KindViolation, ElementNameForm, "1.9", "", "OC", "top", "1.1.4", at("extra", 3), at("base", 5),
			"the name form 1.9 names the abstract class top, and a name form names a structural class (X.501 13.7.2)"},
		{"nameform ( 1.9\n OC s MUST nope )\nobjectclass ( 1.8 NAME 's' SUP top )", UnknownReference, ElementNameForm, "1.9", "", "MUST", "nope", "", at("extra", 3), Position{},
			"the name form 1.9 has MUST nope, which is not a defined attribute type"},
		{"nameform ( 1.9\n OC s MUST a MAY A )\nobjectclass ( 1.8 NAME 's' SUP top )", DuplicateMember, ElementNameForm, "1.9", "", "MAY", "A", "1.1.3", at("extra", 3), at("base", 4),
			"the name form 1.9 lists the attribute type a twice"},
		{"nameform ( 1.9\n OC s MUST a )\nobjectclass ( 1.8 NAME 's' SUP top )\nnameform ( 1.9 OC s MUST a )", DuplicateOID, ElementNameForm, "1.9", "", "", "1.9", "1.9", at("extra", 6), at("extra", 3),
			"the name form 1.9 is defined twice"},

		// DIT structure rules (RFC 4512 4.1.7.1). The OID is the rule ID.
		{"ditstructurerule ( 7 NAME 'r'\n FORM nope )", UnknownReference, ElementDITStructureRule, "7", "r", "FORM", "nope", "", at("extra", 3), Position{},
			"extra:3:1: schema: the DIT structure rule r has FORM nope, which is not a defined name form"},
		{"ditstructurerule ( 7\n FORM f SUP 8 )\nobjectclass ( 1.8 NAME 's' SUP top )\nnameform ( 1.9 NAME 'f' OC s MUST a )", UnknownReference, ElementDITStructureRule, "7", "", "SUP", "8", "", at("extra", 3), Position{},
			"the DIT structure rule 7 has the superior rule 8, which is not defined"},
		{"ditstructurerule ( 7\n FORM f SUP ( 7 7 ) )\nobjectclass ( 1.8 NAME 's' SUP top )\nnameform ( 1.9 NAME 'f' OC s MUST a )", DuplicateMember, ElementDITStructureRule, "7", "", "SUP", "7", "7", at("extra", 3), at("extra", 3),
			"the DIT structure rule 7 lists the superior rule 7 twice"},
		{"ditstructurerule ( 7\n FORM f )\nobjectclass ( 1.8 NAME 's' SUP top )\nnameform ( 1.9 NAME 'f' OC s MUST a )\nditstructurerule ( 7 NAME 'again' FORM f )", DuplicateOID, ElementDITStructureRule, "7", "again", "", "7", "7", at("extra", 7), at("extra", 3),
			"extra:7:1: schema: the DIT structure rule 7 is defined twice (X.501 13.7.5: a rule ID is unique in a subschema) (first defined at extra:3:1)"},
		{"ditstructurerule ( 7 NAME 'r'\n FORM f )\nobjectclass ( 1.8 NAME 's' SUP top )\nnameform ( 1.9 NAME 'f' OC s MUST a )\nditstructurerule ( 8 NAME 'R' FORM f )", DuplicateName, ElementDITStructureRule, "8", "R", "NAME", "R", "7", at("extra", 7), at("extra", 3),
			`the name "R" is given to two DIT structure rules`},
	} {
		be := buildErr(t, "# refused below\n\n"+c.extra)
		got := *be
		got.msg = ""
		want := BuildError{Kind: c.kind, Element: c.el, OID: c.oid, Name: c.name, Pos: c.pos, Field: c.field, Ref: c.ref, RefOID: c.refOID, RefPos: c.refPos}
		if got != want {
			t.Errorf("%q:\n got %+v\nwant %+v", c.extra, got, want)
		}
		if !strings.Contains(be.Error(), c.says) {
			t.Errorf("%q: %q, want %q", c.extra, be.Error(), c.says)
		}
	}
}

// The README's example, on the embedded files: the first definition is
// named where the standard schema has it.
func TestBuildErrorTheREADMEShows(t *testing.T) {
	site := File{"site.schema", []byte(strings.Repeat("\n", 11) + "attributetype ( 2.5.4.3 NAME 'myCn' SUP name )\n")}
	_, err := Build(append(StandardFiles(), site)...)
	if want := "site.schema:12:1: schema: the attribute type 2.5.4.3 is defined twice (first defined at rfc4519.schema:42:1)"; err == nil || err.Error() != want {
		t.Errorf("%v\nwant %s", err, want)
	}
}

// Every kind and element is named, and an unknown one says what it is.
func TestBuildErrorNames(t *testing.T) {
	want := map[BuildErrorKind]string{UnknownReference: "unknown reference", DuplicateOID: "duplicate OID", DuplicateName: "duplicate name",
		SuperiorCycle: "superior cycle", KindViolation: "kind violation", UsageMismatch: "usage mismatch",
		CollectiveMismatch: "collective mismatch", UsageViolation: "usage violation", DuplicateMember: "duplicate member",
		PrecludedRequired: "precluded required", 0: "BuildErrorKind(0)", 99: "BuildErrorKind(99)"}
	for k, s := range want {
		if k.String() != s {
			t.Errorf("%d: %q, want %q", k, k.String(), s)
		}
	}
	for e, s := range map[Element]string{ElementSyntax: "syntax", ElementMatchingRule: "matching rule",
		ElementAttributeType: "attribute type", ElementObjectClass: "object class", ElementDITContentRule: "DIT content rule",
		ElementNameForm: "name form", ElementDITStructureRule: "DIT structure rule", 0: "Element(0)"} {
		if e.String() != s {
			t.Errorf("%d: %q, want %q", e, e.String(), s)
		}
	}
	for p, s := range map[Position]string{{}: "", {"f", 0, 4}: "", {"f", 3, 0}: "f:3", {"f", 3, 7}: "f:3:7"} {
		if p.String() != s || p.IsValid() != (s != "") {
			t.Errorf("%+v: %q %v, want %q", p, p.String(), p.IsValid(), s)
		}
	}
}

// What has no position -- definitions built in code -- reads as Build has
// always worded it; a definition that gives one name twice is its own first
// definition, and the message does not point at itself.
func TestBuildErrorWithoutAPosition(t *testing.T) {
	_, err := BuildFrom(&Definitions{AttributeTypes: []*AttributeType{{OID: "1.1", Sup: "x"}}})
	var be *BuildError
	if !errors.As(err, &be) || err.Error() != "schema: the attribute type 1.1 has the supertype x, which is not defined" || be.Pos.IsValid() {
		t.Errorf("%v", err)
	}
	_, err = BuildFrom(&Definitions{Syntaxes: []*Syntax{{OID: "1.1"}, {OID: "1.1"}}})
	if !errors.As(err, &be) || err.Error() != "schema: the syntax 1.1 is defined twice" {
		t.Errorf("%v", err)
	}
	be = buildErr(t, "\nattributetype ( 1.9 NAME ( 'z' 'Z' ) SUP a )")
	if be.Kind != DuplicateName || be.RefPos != be.Pos || be.RefOID != "1.9" ||
		be.Error() != `extra:2:1: schema: the name "Z" is given to two attribute types` {
		t.Errorf("%+v: %v", be, be)
	}
}

// The position is the line a definition STARTS on in the original file, in
// both forms and in HCL, however the definition is folded: slapd.conf(5)
// continuation lines and backslash joins, RFC 2849 note 2 continuation lines
// ("Any line that begins with a single space MUST be treated as a
// continuation of the previous (non-empty) line"), and a base64 value folded
// the same way. A definition before it that is folded too must not shift it.
func TestBuildErrorPositionsInEveryForm(t *testing.T) {
	def := "( 1.9 NAME 'x' DESC 'folded' SUP nope )"
	b64 := base64.StdEncoding.EncodeToString([]byte(def))
	for _, c := range []struct {
		name, text string
		line       int
	}{
		{"schema", "# a comment\n continued comment\n\nattributetype ( 1.8 NAME 'ok'\n\tSUP a )\nattributetype ( 1.9\n\tNAME 'x'\n\tSUP nope )\n", 6},
		{"schema backslash", "attributetype ( 1.8 NAME 'ok' \\\nSUP a )\n\nattributetype ( 1.9 NAME \\\n'x' SUP \\\nnope )\n", 4},
		{"schema CRLF", "attributetype ( 1.8 NAME 'ok'\r\n SUP a )\r\nattributetype ( 1.9\r\n SUP nope )\r\n", 3},
		{"LDIF", "dn: cn=x,cn=schema,cn=config\nolcAttributeTypes: {0}( 1.8 NAME 'ok' S\n UP a )\nolcAttributeTypes: {1}( 1.9 NAME 'x' DE\n SC 'folded'\n  SUP nope )\n", 4},
		{"LDIF base64", "dn: cn=Subschema\n# attributeTypes: ( 1.7 )\nattributeTypes: ( 1.8 NAME 'ok'\n  SUP a )\nattributeTypes:: " + b64[:12] + "\n " + b64[12:30] + "\n " + b64[30:] + "\n", 5},
	} {
		be := buildErr(t, c.text)
		if be.Pos != (Position{"extra", c.line, 1}) || be.OID != "1.9" || be.Kind != UnknownReference {
			t.Errorf("%s: %+v, want extra:%d", c.name, be, c.line)
		}
		if !strings.HasPrefix(be.Error(), be.Pos.String()+": schema: ") {
			t.Errorf("%s: %q", c.name, be.Error())
		}
	}
}

// FuzzBuildErrorPosition: whatever reads and does not build, the BuildError
// points into the input -- a line that exists, and that starts a record (not
// a continuation line, not a comment) -- and so does the first definition of
// a duplicate.
func FuzzBuildErrorPosition(f *testing.F) {
	for _, s := range []string{
		"attributetype ( 1.9\n SUP nope )\n",
		"ldapsyntax ( 1.1 )\n\nldapsyntax ( 1.1\n DESC 'x' )\n",
		"attributetype ( 1.1 NAME 'a' SYNTAX 1.1 )\nldapsyntax ( 1.1 )\nattributetype ( 1.2 NAME 'A' SUP a )\n",
		"dn: x\nattributeTypes: ( 1.1 NAME 'a' SY\n NTAX 1.1 )\nldapSyntaxes: ( 1.1 )\nobjectClasses: ( 1.2 NAME 'c' MUST b )\n",
		"objectclass ( 1.1 NAME 'x' SUP y )\nobjectclass ( 1.2 NAME 'y' SUP x )\n",
		"ldapsyntax ( 1.1 )\nattributetype ( 1.2 NAME 'a' SYNTAX 1.1 \\\nCOLLECTIVE USAGE dSAOperation )\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, err := Build(File{Name: "fuzz", Data: data})
		var be *BuildError
		if !errors.As(err, &be) {
			return
		}
		ls := lines(data)
		check := func(what string, p Position) {
			if p.File != "fuzz" || p.Line < 1 || p.Line > len(ls) || p.Column != 1 {
				t.Fatalf("%s position %+v is not in the input (%d lines): %v", what, p, len(ls), err)
			}
			if l := ls[p.Line-1]; l == "" || isBlank(l[0]) || l[0] == '#' {
				t.Fatalf("%s position %+v is on %q, which starts no record: %v", what, p, l, err)
			}
		}
		check("the refused definition's", be.Pos)
		if be.RefPos.IsValid() {
			check("the other definition's", be.RefPos)
		}
	})
}
