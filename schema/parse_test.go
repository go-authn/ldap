// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// strip clears what Build resolves, so that a parsed element can be
// compared with one that came out of a Schema.
func strip(x any) any {
	switch v := x.(type) {
	case *AttributeType:
		c := *v
		c.sup, c.equality, c.ordering, c.sub, c.syntax, c.linked = nil, nil, nil, nil, "", false
		return &c
	case *ObjectClass:
		c := *v
		c.sup, c.must, c.may = nil, nil, nil
		return &c
	}
	return x
}

// ⛔ The printer writes what the server PUBLISHES, so every embedded
// definition must survive print -> parse unchanged, and printing must be a
// fixed point. A definition that read back differently would be cached
// differently by every client that read the subschema.
func TestEveryEmbeddedDefinitionRoundTrips(t *testing.T) {
	s := Standard()
	n := 0
	check := func(orig any, printed string, parse func(string) (any, error)) {
		t.Helper()
		n++
		back, err := parse(printed)
		if err != nil {
			t.Errorf("%s does not read back: %v", printed, err)
			return
		}
		if !reflect.DeepEqual(strip(orig), back) {
			t.Errorf("%s reads back as something else:\n got %#v\nwant %#v", printed, back, strip(orig))
		}
		if again := back.(interface{ String() string }).String(); again != printed {
			t.Errorf("printing is not a fixed point:\n%s\n%s", printed, again)
		}
	}
	for _, x := range s.Syntaxes() {
		check(x, x.String(), func(p string) (any, error) { return ParseSyntax(p) })
	}
	for _, x := range s.MatchingRules() {
		check(x, x.String(), func(p string) (any, error) { return ParseMatchingRule(p) })
	}
	for _, x := range s.MatchingRuleUses() {
		check(x, x.String(), func(p string) (any, error) { return ParseMatchingRuleUse(p) })
	}
	for _, x := range s.AttributeTypes() {
		check(x, x.String(), func(p string) (any, error) { return ParseAttributeType(p) })
	}
	for _, x := range s.ObjectClasses() {
		check(x, x.String(), func(p string) (any, error) { return ParseObjectClass(p) })
	}
	if n < 300 {
		t.Errorf("only %d definitions were checked", n)
	}
}

func TestTheParserReadsEveryTerm(t *testing.T) {
	at, err := ParseAttributeType(`( 1.2.3 NAME ( 'a' 'b-2' ) DESC 'it\27s a \5C and \5c' OBSOLETE SUP name EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64} SINGLE-VALUE COLLECTIVE NO-USER-MODIFICATION USAGE dSAOperation X-ORIGIN ( 'RFC 1' 'RFC 2' ) X-ONE 'x' )`)
	if err != nil {
		t.Fatal(err)
	}
	want := &AttributeType{OID: "1.2.3", Names: []string{"a", "b-2"}, Desc: `it's a \ and \`, Obsolete: true,
		Sup: "name", Equality: "caseIgnoreMatch", Ordering: "caseIgnoreOrderingMatch", Substr: "caseIgnoreSubstringsMatch",
		Syntax: "1.3.6.1.4.1.1466.115.121.1.15", SyntaxLen: "64", SingleValue: true, Collective: true, NoUserModification: true,
		Usage: DSAOperation, Extensions: []Extension{{"X-ORIGIN", []string{"RFC 1", "RFC 2"}}, {"X-ONE", []string{"x"}}}}
	if !reflect.DeepEqual(at, want) {
		t.Errorf("got %#v", at)
	}
	if got := at.String(); got != `( 1.2.3 NAME ( 'a' 'b-2' ) DESC 'it\27s a \5C and \5C' OBSOLETE SUP name EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64} SINGLE-VALUE COLLECTIVE NO-USER-MODIFICATION USAGE dSAOperation X-ORIGIN ( 'RFC 1' 'RFC 2' ) X-ONE 'x' )` {
		t.Errorf("printed as %s", got)
	}
	// Keywords are ABNF quoted strings, so case does not matter (RFC 4234
	// 2.3), and WSP may be empty inside parentheses.
	oc, err := ParseObjectClass(`(1.2.4 name 'c' sup (top$ x) auxiliary must (a $b) may c x-e ())`)
	if err != nil {
		t.Fatal(err)
	}
	if oc.Kind != Auxiliary || len(oc.Sup) != 2 || len(oc.Must) != 2 || oc.May[0] != "c" || oc.Extensions[0].Values != nil {
		t.Errorf("got %#v", oc)
	}
	for _, k := range []string{"ABSTRACT", "STRUCTURAL"} {
		if oc, err := ParseObjectClass("( 1.2 " + k + " )"); err != nil || oc.Kind.String() != k {
			t.Errorf("%s: %v %v", k, oc, err)
		}
	}
	mru, err := ParseMatchingRuleUse(`( 2.5.13.2 NAME 'x' DESC 'd' OBSOLETE APPLIES ( cn $ sn ) )`)
	if err != nil || !mru.Obsolete || len(mru.Applies) != 2 {
		t.Errorf("%v %v", mru, err)
	}
	if got := mru.String(); got != `( 2.5.13.2 NAME 'x' DESC 'd' OBSOLETE APPLIES ( cn $ sn ) )` {
		t.Error(got)
	}
	if _, err := ParseAttributeType(`( 1.2 NAME ( ) SUP x )`); err != nil {
		t.Errorf("an empty qdescrlist is allowed by the ABNF: %v", err)
	}
	for _, u := range []Usage{UserApplications, DirectoryOperation, DistributedOperation, DSAOperation} {
		at, err := ParseAttributeType("( 1.2 SUP x USAGE " + u.String() + " )")
		if err != nil || at.Usage != u || u.Operational() != (u != UserApplications) {
			t.Errorf("%s: %v %v", u, at, err)
		}
	}
}

// ⛔ A malformed definition is refused, and the error says WHERE. Each case
// names the offset the parser stopped at, so that a change which moved the
// reported position -- and so pointed somebody at the wrong character --
// fails here.
func TestTheParserRefusesMalformedInputWithAPosition(t *testing.T) {
	for _, c := range []struct {
		in     string
		parse  func(string) error
		offset int
		says   string
	}{
		{"", at, 0, `expected '('`},
		{"1.2 )", at, 0, `expected '('`},
		{"( cn SUP x )", at, 2, "numeric OID"},
		{"( 1.02 SUP x )", at, 2, "numeric OID"},
		{"( 1 SUP x )", at, 2, "numeric OID"},
		{"( 1.2 SUP x", at, 11, "expected a space or ')'"},
		{"( 1.2 SUP x ) x", at, 13, "trailing"},
		{"( 1.2 SUP x\tSYNTAX 1.2 )", at, 10, "OID or a descriptor"},
		{"( 1.2 SYNTAX 1.2 SUP x )", at, 17, "out of order"},
		{"( 1.2 SUP x SUP y )", at, 12, "out of order or repeated"},
		{"( 1.2 SUP x X-A 'b' SYNTAX 1.2 )", at, 20, "extensions come last"},
		{"( 1.2 BOGUS )", at, 6, `"BOGUS" is not a term`},
		{"( 1.2 'x' )", at, 6, "expected a keyword"},
		{"( 1.2 MUST x )", at, 6, `"MUST" is not a term`},
		{"( 1.2 SUP )", at, 10, "OID or a descriptor"},
		{"( 1.2 SUP(x) )", at, 9, "expected a space"},
		{"( 1.2 SYNTAX 1.2{x} )", at, 17, "number in braces"},
		{"( 1.2 SYNTAX 1.2{1 )", at, 18, `expected '}'`},
		{"( 1.2 SYNTAX cn )", at, 13, "numeric OID"},
		{"( 1.2 USAGE everybody SUP x )", at, 12, "not a usage"},
		{"( 1.2 NAME '1a' SUP x )", at, 12, "not a descriptor"},
		{"( 1.2 NAME ('a''b') SUP x )", at, 15, "space between two names"},
		{"( 1.2 NAME ( 'a' SUP x )", at, 17, `expected '\''`},
		{"( 1.2 NAME a SUP x )", at, 11, `expected '\''`},
		{"( 1.2 DESC '' SUP x )", at, 12, "may not be empty"},
		{"( 1.2 DESC 'abc", at, 15, "not closed"},
		{`( 1.2 DESC 'a\41' SUP x )`, at, 13, `\27 or \5C`},
		{"( 1.2 DESC 'a\xff' SUP x )", at, 13, "not UTF-8"},
		{"( 1.2 X-A ('a''b') SUP x )", at, 14, "space between two strings"},
		{"( 1.2 X-A )", at, 10, `expected '\''`},
		{"( 1.2 X-A ( 'a' '' ) )", at, 17, "may not be empty"},
		{"( 1.2 X-A1 'b' )", at, 6, `"X-A1" is not a term`},
		{"( 1.2 SUP x USAGE)", at, 17, "expected a space"},
		{"( 1.2 X-A('a') )", at, 9, "expected a space"},
		{"( 1.2 X-A ( 'a' )", at, 17, "expected a space or ')'"},
		{"( 1.2 NAME 'a' )", at, 16, "needs SUP or SYNTAX"},
		{"( 1.2 SUP ( a $ b ) )", at, 10, "OID or a descriptor"},
		{"( 1.2 MUST ( a b ) )", oc, 15, `expected '$'`},
		{"( 1.2 MUST ( a $ ) )", oc, 17, "OID or a descriptor"},
		{"( 1.2 MUST ( a $ b )", oc, 20, "expected a space or ')'"},
		{"( 1.2 SUP x STRUCTURAL ABSTRACT )", oc, 23, "out of order or repeated"},
		{"( 1.2 NAME 'a' )", mr, 16, "must name its SYNTAX"},
		{"( 1.2 SYNTAX 1.2.x )", mr, 13, "numeric OID"},
		{"( 1.2 NAME 'a' )", mru, 16, "APPLIES"},
		{"( 1.2 APPLIES )", mru, 14, "OID or a descriptor"},
		{"( 1.2 NAME 'a' )", syn, 6, `"NAME" is not a term`},
		{"( 1.2 DESC x )", syn, 11, `expected '\''`},
	} {
		err := c.parse(c.in)
		var pe *ParseError
		if !errors.As(err, &pe) {
			t.Errorf("%q: %v is not a *ParseError", c.in, err)
			continue
		}
		if pe.Offset != c.offset || !strings.Contains(pe.Msg, c.says) {
			t.Errorf("%q: got offset %d %q, want offset %d and %q", c.in, pe.Offset, pe.Msg, c.offset, c.says)
		}
		if !strings.HasPrefix(err.Error(), "schema: at offset ") {
			t.Errorf("%q: %v", c.in, err)
		}
	}
}

func at(s string) error  { _, err := ParseAttributeType(s); return err }
func oc(s string) error  { _, err := ParseObjectClass(s); return err }
func mr(s string) error  { _, err := ParseMatchingRule(s); return err }
func mru(s string) error { _, err := ParseMatchingRuleUse(s); return err }
func syn(s string) error { _, err := ParseSyntax(s); return err }

// FuzzDefinition: nothing may panic, and anything accepted must print to a
// form that reads back to the same value and prints the same again.
//
// The seeds run with every `go test`; `go test -fuzz FuzzDefinition ./schema`
// explores.
func FuzzDefinition(f *testing.F) {
	s := Standard()
	for _, x := range s.AttributeTypes()[:20] {
		f.Add(x.String())
	}
	for _, x := range s.ObjectClasses()[:20] {
		f.Add(x.String())
	}
	for _, x := range s.MatchingRules()[:5] {
		f.Add(x.String())
	}
	f.Add(`( 1.2 NAME ( 'a' 'b' ) DESC 'q\27\5c' SUP x X-A ( 'p' 'q' ) )`)
	f.Add(`( 1.2 SYNTAX 1.2{64} )`)
	f.Add(`( 1.2 APPLIES ( a $ b ) )`)
	f.Fuzz(func(t *testing.T, in string) {
		for _, p := range []func(string) (interface{ String() string }, error){
			func(s string) (interface{ String() string }, error) { return ParseAttributeType(s) },
			func(s string) (interface{ String() string }, error) { return ParseObjectClass(s) },
			func(s string) (interface{ String() string }, error) { return ParseMatchingRule(s) },
			func(s string) (interface{ String() string }, error) { return ParseMatchingRuleUse(s) },
			func(s string) (interface{ String() string }, error) { return ParseSyntax(s) },
		} {
			x, err := p(in)
			if err != nil {
				continue
			}
			printed := x.String()
			y, err := p(printed)
			if err != nil {
				t.Fatalf("%q was accepted and its printed form %q is not: %v", in, printed, err)
			}
			if !reflect.DeepEqual(x, y) {
				t.Fatalf("%q -> %q reads back as something else:\n%#v\n%#v", in, printed, x, y)
			}
			if y.String() != printed {
				t.Fatalf("printing %q is not a fixed point", in)
			}
		}
	})
}
