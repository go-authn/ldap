// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

const base = `# a comment
ldapsyntax ( 1.1.1 DESC 's' )
matchingrule ( 1.1.2 NAME 'eq' SYNTAX 1.1.1 )
attributetype ( 1.1.3 NAME 'a' EQUALITY eq SYNTAX 1.1.1 )
objectclass ( 1.1.4 NAME 'top' ABSTRACT MUST a )
`

func build(extra string) (*Schema, error) {
	return Build(File{"base", []byte(base)}, File{"extra", []byte(extra)})
}

func TestStandardBuildsAndHasWhatTheRFCsDefine(t *testing.T) {
	files := StandardFiles()
	if len(files) != len(standardFiles) {
		t.Fatalf("%d files", len(files))
	}
	for _, f := range files {
		if len(f.Data) == 0 {
			t.Errorf("%s is empty", f.Name)
		}
	}
	s := Standard()
	if Standard() != s {
		t.Error("Standard is built more than once")
	}
	for _, name := range []string{"cn", "2.5.4.3", "CN", "uidNumber", "sshPublicKey", "subschemaSubentry", "vendorName", "userCertificate", "subtreeSpecification", "memberUid"} {
		if s.AttributeType(name) == nil {
			t.Errorf("no attribute type %s", name)
		}
	}
	for _, name := range []string{"top", "person", "inetOrgPerson", "posixAccount", "posixGroup", "shadowAccount", "ldapPublicKey", "subschema", "subentry", "extensibleObject", "OpenLDAProotDSE", "account", "pkiUser"} {
		if s.ObjectClass(name) == nil {
			t.Errorf("no object class %s", name)
		}
	}
	if s.MatchingRule("caseIgnoreMatch") == nil || s.MatchingRule("2.5.13.14") == nil || s.MatchingRule("algorithmIdentifierMatch") == nil {
		t.Error("a matching rule is missing")
	}
	if s.Syntax("1.3.6.1.4.1.1466.115.121.1.27") == nil || s.Syntax("1.3.6.1.4.1.1466.115.121.1.45") == nil {
		t.Error("a syntax is missing")
	}
	if len(s.Syntaxes()) < 40 || len(s.MatchingRules()) < 35 || len(s.AttributeTypes()) < 140 || len(s.ObjectClasses()) < 50 || len(s.MatchingRuleUses()) < 30 {
		t.Errorf("%d syntaxes, %d rules, %d types, %d classes, %d uses", len(s.Syntaxes()), len(s.MatchingRules()), len(s.AttributeTypes()), len(s.ObjectClasses()), len(s.MatchingRuleUses()))
	}
}

func TestMustPanicsOnABrokenBuild(t *testing.T) {
	defer func() {
		if r := recover(); r == nil || !strings.Contains(r.(string), "do not build") {
			t.Errorf("recovered %v", r)
		}
	}()
	must(nil, errors.New("x"))
}

// RFC 4512 4.1.2: EQUALITY, ORDERING, SUBSTR and SYNTAX are inherited
// through SUP when a definition does not give them.
func TestAttributeTypesInheritThroughSUP(t *testing.T) {
	s := Standard()
	cn, name := s.AttributeType("cn"), s.AttributeType("name")
	if cn.Superior() != name || cn.EqualityRule() != s.MatchingRule("caseIgnoreMatch") ||
		cn.SubstringRule() != s.MatchingRule("caseIgnoreSubstringsMatch") ||
		cn.EffectiveSyntax() != "1.3.6.1.4.1.1466.115.121.1.15" || cn.OrderingRule() != nil {
		t.Errorf("cn: %v %v %v %v", cn.Superior(), cn.EqualityRule(), cn.SubstringRule(), cn.EffectiveSyntax())
	}
	if !cn.IsA(name) || name.IsA(cn) || cn.Name() != "cn" {
		t.Error("IsA is wrong")
	}
	if s.AttributeType("uidNumber").OrderingRule() != nil {
		t.Error("RFC 2307 gives uidNumber no ORDERING rule")
	}
	if (&AttributeType{OID: "1.2"}).Name() != "1.2" || (&ObjectClass{OID: "1.3"}).Name() != "1.3" || s.MatchingRule("2.5.13.2").Name() != "caseIgnoreMatch" {
		t.Error("Name")
	}
}

// RFC 4512 2.4: a class inherits its superclasses' MUST and MAY, and an
// attribute in both is required.
func TestObjectClassesInheritMustAndMay(t *testing.T) {
	s := Standard()
	iop := s.ObjectClass("inetOrgPerson")
	op := s.ObjectClass("organizationalPerson")
	if !slices.Contains(iop.Superiors(), op) || !iop.IsA(s.ObjectClass("top")) || op.IsA(iop) {
		t.Error("superclasses")
	}
	names := func(ts []*AttributeType) []string {
		var out []string
		for _, t := range ts {
			out = append(out, t.Name())
		}
		slices.Sort(out)
		return out
	}
	if got := names(iop.MustTypes()); !slices.Equal(got, []string{"cn", "objectClass", "sn"}) {
		t.Errorf("inetOrgPerson MUST %v", got)
	}
	for _, want := range []string{"telephoneNumber", "mail", "uid", "displayName", "userPassword"} {
		if !slices.Contains(names(iop.MayTypes()), want) {
			t.Errorf("inetOrgPerson does not MAY %s", want)
		}
	}
	// RFC 2307 lists description in both MUST and MAY of ipProtocol.
	ip := s.ObjectClass("ipProtocol")
	if !slices.Contains(names(ip.MustTypes()), "description") || slices.Contains(names(ip.MayTypes()), "description") {
		t.Error("an attribute in MUST and MAY is required, and only required")
	}
}

func TestMatchingRuleUseIsDerived(t *testing.T) {
	s := Standard()
	u := s.MatchingRuleUse("integerOrderingMatch")
	if u == nil || !slices.Contains(u.Applies, "uidNumber") {
		t.Fatalf("integerOrderingMatch does not apply to uidNumber: %v", u)
	}
	if !s.Applies(s.MatchingRule("caseIgnoreMatch"), s.AttributeType("cn")) {
		t.Error("caseIgnoreMatch does not apply to cn")
	}
	if s.Applies(s.MatchingRule("integerMatch"), s.AttributeType("cn")) {
		t.Error("integerMatch applies to cn")
	}
	if s.MatchingRuleUse("nonsense") != nil || s.MatchingRuleUse("certificateMatch") != nil {
		t.Error("a use for a rule with no attribute type")
	}
}

func TestBuildRefusesWhatDoesNotLink(t *testing.T) {
	if _, err := build(""); err != nil {
		t.Fatalf("the base does not build: %v", err)
	}
	for _, c := range []struct{ extra, says string }{
		{" ( 1.2 )", "continuation line with no definition"},
		{"attribute ( 1.2 SUP a )", "is not a kind of definition"},
		{"ldapsyntax ( x )", "numeric OID"},
		{"matchingrule ( x )", "numeric OID"},
		{"attributetype ( x )", "numeric OID"},
		{"objectclass ( x )", "numeric OID"},
		{"ldapsyntax ( 1.1.1 )", "syntax 1.1.1 is defined twice"},
		{"matchingrule ( 1.1.2 SYNTAX 1.1.1 )", "matching rule 1.1.2 is defined twice"},
		{"matchingrule ( 1.9 NAME 'EQ' SYNTAX 1.1.1 )", `name "EQ" is given to two matching rules`},
		{"attributetype ( 1.1.3 SUP a )", "attribute type 1.1.3 is defined twice"},
		{"objectclass ( 1.1.4 SUP top )", "object class 1.1.4 is defined twice"},
		{"matchingrule ( 1.9 SYNTAX 9.9 )", "syntax 9.9, which is not defined"},
		{"attributetype ( 1.9 EQUALITY nope SYNTAX 1.1.1 )", "EQUALITY rule nope"},
		{"attributetype ( 1.9 ORDERING nope SYNTAX 1.1.1 )", "ORDERING rule nope"},
		{"attributetype ( 1.9 SUBSTR nope SYNTAX 1.1.1 )", "SUBSTR rule nope"},
		{"attributetype ( 1.9 SYNTAX 9.9 )", "syntax 9.9"},
		{"attributetype ( 1.9 SUP nope )", "supertype nope"},
		{"attributetype ( 1.9 NAME 'x' SUP y )\nattributetype ( 1.8 NAME 'y' SUP x )", "its own supertype"},
		{"attributetype ( 1.9 SUP a USAGE dSAOperation )", "(RFC 4512 2.5.1)"},
		{"attributetype ( 1.9 NAME 'c' SYNTAX 1.1.1 COLLECTIVE )\nattributetype ( 1.8 SUP c )", "must be COLLECTIVE"},
		{"attributetype ( 1.9 SYNTAX 1.1.1 COLLECTIVE USAGE directoryOperation )", "COLLECTIVE and directoryOperation"},
		{"attributetype ( 1.9 SYNTAX 1.1.1 NO-USER-MODIFICATION )", "NO-USER-MODIFICATION and a user attribute"},
		{"objectclass ( 1.9 SUP nope )", "superclass nope"},
		{"objectclass ( 1.9 NAME 'x' SUP y )\nobjectclass ( 1.8 NAME 'y' SUP x )", "its own superclass"},
		{"objectclass ( 1.9 NAME 's' SUP top )\nobjectclass ( 1.8 SUP s ABSTRACT )", "abstract class 1.8 derives from the structural class s"},
		{"objectclass ( 1.9 NAME 'x' SUP top AUXILIARY )\nobjectclass ( 1.8 SUP x )", "structural class 1.8 derives from the auxiliary class x"},
		{"objectclass ( 1.9 NAME 's' SUP top )\nobjectclass ( 1.8 SUP s AUXILIARY )", "auxiliary class 1.8 derives from the structural class s"},
		{"objectclass ( 1.9 MUST nope )", "MUST nope"},
		{"objectclass ( 1.9 MAY nope )", "MAY nope"},
	} {
		_, err := build(c.extra)
		if err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%q: got %v, want %q", c.extra, err, c.says)
		}
	}
	var fe *FileError
	if _, err := build("\n\nbogus ( 1.2 )"); !errors.As(err, &fe) || fe.Line != 3 || fe.File != "extra" || !strings.HasPrefix(err.Error(), "extra:3: ") || errors.Unwrap(err) == nil {
		t.Errorf("a file error says where: %v", err)
	}
}

// A deployment adds its own definitions to the standard ones.
func TestADeploymentExtendsTheStandardSchema(t *testing.T) {
	mine := File{"samba", []byte("attributetype ( 1.3.6.1.4.1.7165.2.1.25 NAME 'sambaNTPassword'\n\tEQUALITY caseIgnoreIA5Match\n\tSYNTAX 1.3.6.1.4.1.1466.115.121.1.26{32} SINGLE-VALUE )\n")}
	s, err := Build(append(StandardFiles(), mine)...)
	if err != nil {
		t.Fatal(err)
	}
	if s.AttributeType("sambaNTPassword") == nil || Standard().AttributeType("sambaNTPassword") != nil {
		t.Error("the extension leaked into, or missed, a schema")
	}
}

// RFC 4517 4.2.26: a descriptor means the OID it names; RFC 4512 1.4: one
// used for two different OIDs is unrecognized.
func TestResolveOID(t *testing.T) {
	s, err := build("objectclass ( 1.9 NAME 'a' SUP top AUXILIARY )")
	if err != nil {
		t.Fatal(err)
	}
	for in, want := range map[string]string{"1.1.3": "1.1.3", "top": "1.1.4", "TOP": "1.1.4", "eq": "1.1.2", "a": "", "nope": "", "1.": ""} {
		got, ok := s.resolveOID(in)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
}
