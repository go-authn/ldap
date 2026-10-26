// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// rulesFile is a DIT content rule, name form and structure rule for each
// kind of entry of the tree go-authn/authnd serves -- the suffix, the
// containers ou=people and ou=groups, the accounts and the groups -- and the
// cases the tests below need: an OBSOLETE rule of each kind, a content rule
// for a class with a subclass, and a structural subclass no rule names. The
// OIDs are under 1.3.6.1.4.1.32473, the example enterprise number (RFC 5612).
const rulesFile = `# rules
objectclass ( 1.3.6.1.4.1.32473.1.1 NAME 'localUnit' SUP organizationalUnit STRUCTURAL )

ditcontentrule ( 0.9.2342.19200300.100.4.5 NAME 'accountRule'
	AUX ( posixAccount $ shadowAccount $ extensibleObject )
	MUST description
	MAY mail
	NOT seeAlso )
ditcontentrule ( 1.3.6.1.1.1.2.2 NAME 'groupRule' OBSOLETE MUST description )
ditcontentrule ( 2.5.6.6 NAME 'personRule' MUST description )

nameform ( 1.3.6.1.4.1.32473.1.2.1 NAME 'domainForm' OC domain MUST dc )
nameform ( 1.3.6.1.4.1.32473.1.2.2 NAME 'ouForm' OC organizationalUnit MUST ou )
nameform ( 1.3.6.1.4.1.32473.1.2.3 NAME 'accountForm' OC account MUST uid MAY cn )
nameform ( 1.3.6.1.4.1.32473.1.2.4 NAME 'groupForm' OC posixGroup MUST cn )
nameform ( 1.3.6.1.4.1.32473.1.2.5 NAME 'gidForm' OBSOLETE OC posixGroup MUST gidNumber )

ditstructurerule ( 1 NAME 'suffix' FORM domainForm )
ditstructurerule ( 2 NAME 'container' FORM ouForm SUP ( 1 2 ) )
ditstructurerule ( 3 NAME 'people' FORM accountForm SUP 2 )
ditstructurerule ( 4 NAME 'groups' FORM groupForm SUP 2 )
ditstructurerule ( 5 NAME 'retired' OBSOLETE FORM groupForm SUP 1 )
ditstructurerule ( 6 NAME 'oldGids' FORM gidForm SUP 2 )
`

func rulesSchema(t testing.TB) *Schema {
	t.Helper()
	s, err := Build(append(StandardFiles(), File{"rules.schema", []byte(rulesFile)})...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// kinds lists the problems of a Validate or GoverningStructureRule error,
// "Kind:Attribute:Class" each, so a test says exactly what it expects.
func kinds(t *testing.T, err error) []string {
	t.Helper()
	var out []string
	for _, p := range problems(t, err).Problems {
		out = append(out, fmt.Sprintf("%d:%s:%s", p.Kind, p.Attribute, p.Class))
	}
	return out
}

func kind(k ProblemKind, attr, class string) string { return fmt.Sprintf("%d:%s:%s", k, attr, class) }

// alice is an account of authnd's tree, valid under accountRule.
func alice(extra ...string) Entry {
	return entry("uid=alice,ou=people,dc=example,dc=org", append([]string{
		"objectClass: top", "objectClass: account", "objectClass: posixAccount", "objectClass: shadowAccount",
		"uid: alice", "cn: Alice", "uidNumber: 1000", "gidNumber: 100", "homeDirectory: /home/alice",
		"description: an account"}, extra...)...)
}

func without(e Entry, desc string) Entry {
	e.Attributes = slices.DeleteFunc(slices.Clone(e.Attributes), func(a Attribute) bool { return a.Description == desc })
	return e
}

// Each clause of a DIT content rule refuses the entry that breaks it, and
// only that entry (RFC 4512 4.1.6). The witness of each: the same entry is
// valid, or refused for another reason, under the standard schema, which
// has no rule.
func TestEachClauseOfADITContentRuleIsEnforced(t *testing.T) {
	s, std := rulesSchema(t), Standard()
	for _, c := range []struct {
		name      string
		e         Entry
		opt       ValidateOptions
		want, std []string
	}{
		{"valid", alice(), ValidateOptions{}, nil, nil},
		// AUX: "An entry may only belong to auxiliary object classes listed
		// in the governing content rule."
		{"AUX", alice("objectClass: ldapPublicKey"), ValidateOptions{},
			[]string{kind(AuxiliaryNotAllowed, "objectClass", "ldapPublicKey")}, nil},
		// MUST: "all attributes required by the governing content rule."
		{"MUST", without(alice(), "description"), ValidateOptions{},
			[]string{kind(MissingRequired, "description", "accountRule")}, nil},
		// NOT: "An entry cannot include any attribute precluded by the
		// governing content rule" -- account itself allows seeAlso.
		{"NOT", alice("seeAlso: cn=x"), ValidateOptions{},
			[]string{kind(Precluded, "seeAlso", "accountRule")}, nil},
		// NOT holds even in an extensibleObject, which allows any type.
		{"NOT and extensibleObject", alice("objectClass: extensibleObject", "seeAlso: cn=x"), ValidateOptions{},
			[]string{kind(Precluded, "seeAlso", "accountRule")}, nil},
		// MAY: "as well as all attributes allowed by the governing content
		// rule" -- no class of the entry allows mail.
		{"MAY", alice("mail: alice@example.org"), ValidateOptions{},
			nil, []string{kind(NotAllowed, "mail", "")}},
		// StrictAuxiliary is RFC 4512 2.4.3: no rule, no auxiliary class.
		{"no rule, strict", entry("cn=x,dc=org", "objectClass: top", "objectClass: device", "objectClass: extensibleObject", "cn: x"),
			ValidateOptions{StrictAuxiliary: true},
			[]string{kind(AuxiliaryNotAllowed, "objectClass", "extensibleObject")},
			[]string{kind(AuxiliaryNotAllowed, "objectClass", "extensibleObject")}},
		// An OBSOLETE rule is not active: posixGroup is governed as if it
		// had none, and needs no description.
		{"OBSOLETE", entry("cn=staff,ou=groups,dc=example,dc=org", "objectClass: top", "objectClass: posixGroup", "cn: staff", "gidNumber: 100"),
			ValidateOptions{}, nil, nil},
		{"OBSOLETE, strict", entry("cn=staff,ou=groups,dc=example,dc=org", "objectClass: top", "objectClass: posixGroup", "objectClass: extensibleObject", "cn: staff", "gidNumber: 100"),
			ValidateOptions{StrictAuxiliary: true},
			[]string{kind(AuxiliaryNotAllowed, "objectClass", "extensibleObject")},
			[]string{kind(AuxiliaryNotAllowed, "objectClass", "extensibleObject")}},
		// "DIT content rules for superclasses of the structural object class
		// of an entry are not applicable to that entry": personRule wants a
		// description of a person, not of an inetOrgPerson.
		{"superclass", entry("cn=b,dc=org", "objectClass: top", "objectClass: person", "objectClass: organizationalPerson", "objectClass: inetOrgPerson", "cn: b", "sn: j"),
			ValidateOptions{}, nil, nil},
		{"the class itself", entry("cn=b,dc=org", "objectClass: top", "objectClass: person", "cn: b", "sn: j"),
			ValidateOptions{}, []string{kind(MissingRequired, "description", "personRule")}, nil},
		// Two chains: no structural class, so no rule; strict refuses the
		// auxiliary class all the same.
		{"no structural class, strict", entry("cn=b,dc=org", "objectClass: top", "objectClass: extensibleObject", "cn: b"),
			ValidateOptions{StrictAuxiliary: true},
			[]string{kind(NoStructuralClass, "objectClass", ""), kind(AuxiliaryNotAllowed, "objectClass", "extensibleObject")},
			[]string{kind(NoStructuralClass, "objectClass", ""), kind(AuxiliaryNotAllowed, "objectClass", "extensibleObject")}},
	} {
		if got := kinds(t, s.ValidateWith(c.e, c.opt)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
		if got := kinds(t, std.ValidateWith(c.e, c.opt)); !reflect.DeepEqual(got, c.std) {
			t.Errorf("%s, without rules: %v, want %v", c.name, got, c.std)
		}
	}
	err := s.Validate(alice("objectClass: ldapPublicKey", "seeAlso: cn=x"))
	for _, says := range []string{"the auxiliary class ldapPublicKey is not in the AUX of the DIT content rule accountRule (RFC 4512 4.1.6)",
		"seeAlso is precluded by the DIT content rule accountRule (RFC 4512 4.1.6)"} {
		if err == nil || !strings.Contains(err.Error(), says) {
			t.Errorf("%v, want %q", err, says)
		}
	}
	if err := s.Validate(without(alice(), "description")); err == nil || !strings.Contains(err.Error(), "description is required by the DIT content rule accountRule and is missing") {
		t.Errorf("%v", err)
	}
}

// RFC 4512 4.1.7.2: "Entries governed by the form must be named using a
// value from each required attribute type and zero or more values from the
// allowed attribute types." Each way to break it is refused; the witness is
// the standard schema, which has no name forms and takes every one.
func TestNameFormsGovernTheRDN(t *testing.T) {
	s, std := rulesSchema(t), Standard()
	group := func(dn string) Entry {
		return entry(dn, "objectClass: top", "objectClass: posixGroup", "cn: staff", "gidNumber: 100")
	}
	renamed := func(dn string, e Entry) Entry { e.DN = dn; return e }
	for _, c := range []struct {
		name     string
		e        Entry
		badClass string // the class whose name forms refuse the RDN, or ""
	}{
		{"MUST", alice(), ""},
		{"MUST and MAY", renamed("uid=alice+cn=Alice,dc=org", alice()), ""},
		{"MUST missing", renamed("cn=Alice,dc=org", alice()), "account"},
		{"a type outside MUST and MAY", renamed("uid=alice+uidNumber=1000,dc=org", alice()), "account"},
		{"an OBSOLETE form allows nothing", group("gidNumber=100,dc=org"), "posixGroup"},
		{"the active form", group("cn=staff,dc=org"), ""},
		{"the root DSE has no RDN", entry("", "objectClass: top", "objectClass: OpenLDAProotDSE"), ""},
	} {
		var want []string
		if c.badClass != "" {
			want = []string{kind(NameFormViolation, "", c.badClass)}
		}
		if got := kinds(t, s.Validate(c.e)); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %v, want %v", c.name, got, want)
		}
		if err := std.Validate(c.e); err != nil {
			t.Errorf("%s, without name forms: %v", c.name, err)
		}
	}
	err := s.Validate(renamed("cn=Alice,dc=org", alice()))
	if want := "the RDN (cn) is allowed by no name form of account: accountForm needs uid and allows cn"; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%v, want %q", err, want)
	}
}

// The tree authnd serves, from its root down, gets a structure rule at
// every entry; an entry anywhere else, or of a class no rule names, or
// named otherwise, gets none (X.501 13.7.5).
func TestGoverningStructureRule(t *testing.T) {
	s := rulesSchema(t)
	suffix := entry("dc=example,dc=org", "objectClass: top", "objectClass: domain", "dc: example")
	people := entry("ou=people,dc=example,dc=org", "objectClass: top", "objectClass: organizationalUnit", "ou: people")
	sub := entry("ou=staff,ou=people,dc=example,dc=org", "objectClass: top", "objectClass: organizationalUnit", "ou: staff")
	group := entry("cn=staff,ou=groups,dc=example,dc=org", "objectClass: top", "objectClass: posixGroup", "cn: staff", "gidNumber: 100")
	rule := func(id int) *DITStructureRule { return s.DITStructureRule(id) }

	for _, c := range []struct {
		name     string
		e        Entry
		superior *DITStructureRule
		want     int
	}{
		{"the suffix", suffix, nil, 1},
		{"a container under the suffix", people, rule(1), 2},
		{"a container under a container", sub, rule(2), 2},
		{"an account", alice(), rule(2), 3},
		{"a group", group, rule(2), 4},
	} {
		got, err := s.GoverningStructureRule(c.e, c.superior)
		if err != nil || got == nil || got.ID != c.want {
			t.Errorf("%s: %v %v, want rule %d", c.name, got, err, c.want)
		}
	}

	localUnit := entry("ou=x,dc=example,dc=org", "objectClass: top", "objectClass: organizationalUnit", "objectClass: localUnit", "ou: x")
	for _, c := range []struct {
		name     string
		e        Entry
		superior *DITStructureRule
		want     []string
		says     string
	}{
		{"an account under the suffix", alice(), rule(1), []string{kind(NoStructureRule, "", "account")},
			"no DIT structure rule allows account under an entry governed by the rule suffix (X.501 13.7.5)"},
		{"a container as the root", people, nil, []string{kind(NoStructureRule, "", "organizationalUnit")},
			"no DIT structure rule allows organizationalUnit as a subschema administrative point"},
		// "It does not permit entries belonging to any of the subclasses of
		// the structural object class."
		{"a subclass of the named class", localUnit, rule(1), []string{kind(NoStructureRule, "", "localUnit")},
			"no active DIT structure rule has a name form for localUnit"},
		{"named by no form of a rule placed here", Entry{"cn=Alice,ou=people,dc=example,dc=org", alice().Attributes}, rule(2),
			[]string{kind(NameFormViolation, "", "account")},
			"the RDN (cn) is allowed by the name form of no DIT structure rule that places account under an entry governed by the rule container: accountForm needs uid and allows cn"},
		// Rule 5 is OBSOLETE; rule 6's name form is.
		{"an OBSOLETE rule", group, rule(1), []string{kind(NoStructureRule, "", "posixGroup")}, "allows posixGroup under"},
		{"a rule of an OBSOLETE form", Entry{"gidNumber=100,ou=groups,dc=example,dc=org", group.Attributes}, rule(2),
			[]string{kind(NameFormViolation, "", "posixGroup")}, "groupForm needs cn"},
		{"the root DSE", entry("", "objectClass: top", "objectClass: OpenLDAProotDSE"), nil,
			[]string{kind(NoStructureRule, "", "")}, "the root DSE is governed by no DIT structure rule"},
		{"a DN that is none", entry("not a dn", "objectClass: top", "objectClass: domain"), nil,
			[]string{kind(BadDN, "", "")}, "is not a DN"},
		{"no structural class", entry("dc=x", "objectClass: top", "dc: x"), nil,
			[]string{kind(NoStructuralClass, "objectClass", ""), kind(AbstractAlone, "objectClass", "top")}, "no structural object class"},
	} {
		got, err := s.GoverningStructureRule(c.e, c.superior)
		if got != nil || !reflect.DeepEqual(kinds(t, err), c.want) || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v %v, want %v %q", c.name, got, err, c.want, c.says)
		}
	}

	// No structure rule, or only OBSOLETE ones: nothing governs, and
	// nothing is refused.
	for _, extra := range []string{"", "nameform ( 1.9 OC domain MUST dc )\nditstructurerule ( 1 OBSOLETE FORM 1.9 )\n"} {
		s, err := Build(append(StandardFiles(), File{"x", []byte(extra)})...)
		if err != nil {
			t.Fatal(err)
		}
		if r, err := s.GoverningStructureRule(alice(), nil); r != nil || err != nil {
			t.Errorf("%q: %v %v", extra, r, err)
		}
	}
}

// The rules are found by every name and listed in order; an element knows
// what it resolved to.
func TestRulesAreLinked(t *testing.T) {
	s := rulesSchema(t)
	account, top := s.ObjectClass("account"), s.ObjectClass("top")
	r := s.DITContentRule("ACCOUNTRULE")
	if r == nil || r != s.DITContentRule("0.9.2342.19200300.100.4.5") || r != s.DITContentRuleOf(account) || s.DITContentRuleOf(top) != nil ||
		r.Class() != account || len(r.AuxiliaryClasses()) != 3 || r.AuxiliaryClasses()[0] != s.ObjectClass("posixAccount") ||
		r.MustTypes()[0] != s.AttributeType("description") || r.MayTypes()[0] != s.AttributeType("mail") || r.NotTypes()[0] != s.AttributeType("seeAlso") ||
		r.Name() != "accountRule" || (&DITContentRule{OID: "1.2"}).Name() != "1.2" {
		t.Errorf("content rule %+v", r)
	}
	f := s.NameForm("accountform")
	if f == nil || f != s.NameForm("1.3.6.1.4.1.32473.1.2.3") || f.Class() != account || f.MustTypes()[0] != s.AttributeType("uid") ||
		f.MayTypes()[0] != s.AttributeType("cn") || f.Name() != "accountForm" || (&NameForm{OID: "1.2"}).Name() != "1.2" {
		t.Errorf("name form %+v", f)
	}
	d := s.DITStructureRule(3)
	if d == nil || d.NameForm() != f || d.Name() != "people" || s.DITStructureRule(99) != nil || (&DITStructureRule{ID: 7}).Name() != "7" {
		t.Errorf("structure rule %+v", d)
	}
	if len(s.DITContentRules()) != 3 || len(s.NameForms()) != 5 || len(s.DITStructureRules()) != 6 || s.DITStructureRules()[5].ID != 6 {
		t.Errorf("%d %d %d", len(s.DITContentRules()), len(s.NameForms()), len(s.DITStructureRules()))
	}
	// A content rule's names are descriptors of its OID, for
	// objectIdentifierMatch, as an object class's are.
	if oid, ok := s.resolveOID("accountRule"); !ok || oid != "0.9.2342.19200300.100.4.5" {
		t.Errorf("accountRule resolves to %q %v", oid, ok)
	}
}

// Every value of the three syntaxes is checked by its parser (RFC 4517
// 3.3.7, 3.3.8, 3.3.22), so the subschema attributes are validated.
func TestTheRuleSyntaxesAreChecked(t *testing.T) {
	s := Standard()
	for _, c := range []struct {
		attr, good, bad string
	}{
		{"dITContentRules", "( 2.5.6.4 DESC 'content rule for organization' NOT ( x121Address $ telexNumber ) )", "( 2.5.6.4 FORM x )"},
		{"dITStructureRules", "( 2 DESC 'organization structure rule' FORM 2.5.15.3 )", "( 2.5 FORM x )"},
		{"nameForms", "( 2.5.15.3 OC organization MUST o )", "( 2.5.15.3 OC organization )"},
	} {
		t.Run(c.attr, func(t *testing.T) {
			a := s.AttributeType(c.attr)
			if !s.ValidValue(a, []byte(c.good)) || s.ValidValue(a, []byte(c.bad)) {
				t.Errorf("%q should be valid, %q not", c.good, c.bad)
			}
		})
	}
}

// The three parsers read every term, in the ABNF's order, print it back the
// same, and refuse what RFC 4512 does not allow, saying where.
func TestTheRuleParsers(t *testing.T) {
	for _, c := range []struct {
		text  string
		parse func(string) (fmt.Stringer, error)
		want  any
	}{
		{"( 2.5.6.6 NAME ( 'a' 'b' ) DESC 'd' OBSOLETE AUX ( x $ y ) MUST m MAY ( n $ o ) NOT p X-ORIGIN 'z' )", parseCR,
			&DITContentRule{OID: "2.5.6.6", Names: []string{"a", "b"}, Desc: "d", Obsolete: true, Aux: []string{"x", "y"}, Must: []string{"m"},
				May: []string{"n", "o"}, Not: []string{"p"}, Extensions: []Extension{{"X-ORIGIN", []string{"z"}}}}},
		{"( 2.5.6.6 )", parseCR, &DITContentRule{OID: "2.5.6.6"}},
		{"( 1.2.3 NAME 'f' DESC 'd' OBSOLETE OC person MUST ( cn $ sn ) MAY uid X-A ( 'b' 'c' ) )", parseNF,
			&NameForm{OID: "1.2.3", Names: []string{"f"}, Desc: "d", Obsolete: true, OC: "person", Must: []string{"cn", "sn"}, May: []string{"uid"},
				Extensions: []Extension{{"X-A", []string{"b", "c"}}}}},
		{"( 0 NAME 'r' DESC 'd' OBSOLETE FORM f SUP ( 0 2147483647 ) X-A 'b' )", parseSR,
			&DITStructureRule{ID: 0, Names: []string{"r"}, Desc: "d", Obsolete: true, Form: "f", Sup: []int{0, MaxRuleID}, Extensions: []Extension{{"X-A", []string{"b"}}}}},
		{"( 2147483647 FORM 1.2.3 SUP 7 )", parseSR, &DITStructureRule{ID: MaxRuleID, Form: "1.2.3", Sup: []int{7}}},
		// ruleidlist WSP RPAREN: no space is needed inside the parentheses.
		{"( 1 form f sup (2 3) )", parseSR, &DITStructureRule{ID: 1, Form: "f", Sup: []int{2, 3}}},
	} {
		got, err := c.parse(c.text)
		if err != nil {
			t.Errorf("%s: %v", c.text, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %#v\nwant %#v", c.text, got, c.want)
		}
		again, err := c.parse(got.String())
		if err != nil || !reflect.DeepEqual(again, got) || again.String() != got.String() {
			t.Errorf("%s printed as %s, which reads back as %v %v", c.text, got, again, err)
		}
	}
	for _, c := range []struct {
		text  string
		parse func(string) (fmt.Stringer, error)
		says  string
	}{
		{"( 2.5.6.6 MUST a AUX b )", parseCR, "AUX is out of order or repeated"},
		{"( 2.5.6.6 OC x )", parseCR, `"OC" is not a term of this definition`},
		{"( person AUX b )", parseCR, `expected a numeric OID, found "person"`},
		{"( 1.2 MUST a OC p )", parseNF, "OC is out of order"},
		{"( 1.2 MUST a )", parseNF, "a name form must name its OC and its MUST (RFC 4512 4.1.7.2)"},
		{"( 1.2 OC p )", parseNF, "a name form must name its OC and its MUST"},
		{"( 1.2 OC p MUST a NOT b )", parseNF, `"NOT" is not a term`},
		{"( 1 NAME 'r' )", parseSR, "a DIT structure rule must name its FORM (RFC 4512 4.1.7.1)"},
		{"( 1 SUP 2 FORM f )", parseSR, "FORM is out of order"},
		{"( 1.2 FORM f )", parseSR, `at offset 2: expected a rule ID, a number (RFC 4512 4.1.7.1), found "1.2"`},
		{"( 01 FORM f )", parseSR, `found "01"`},
		{"( -1 FORM f )", parseSR, `found "-1"`},
		{"( 2147483648 FORM f )", parseSR, "at offset 2: the rule ID 2147483648 is more than 2147483647"},
		{"( 99999999999999999999 FORM f )", parseSR, "is more than 2147483647"},
		{"( 1 FORM f SUP 2147483648 )", parseSR, "at offset 15: the rule ID 2147483648 is more than"},
		{"( 1 FORM f SUP ( ) )", parseSR, `expected a rule ID, a number (RFC 4512 4.1.7.1), found ')'`},
		{"( 1 FORM f SUP ( 2 $ 3 ) )", parseSR, `at offset 19: expected a rule ID, a number (RFC 4512 4.1.7.1), found '$'`},
		{"( 1 FORM f SUP", parseSR, `at offset 14: expected a space`},
		{"( 1 FORM f SUP ", parseSR, `found the end`},
		{"( 1 FORM f SUP ( 2$3 ) )", parseSR, `at offset 18: expected a space or ')' after a rule ID, found '$'`},
		{"( 1 FORM f SUP ( 2", parseSR, "after a rule ID, found the end"},
		{"( 1 FORM 'f' )", parseSR, "expected an OID or a descriptor"},
		{"( 1 FORM f SUP x )", parseSR, `found "x"`},
	} {
		if _, err := c.parse(c.text); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v, want %q", c.text, err, c.says)
		}
	}
}

func parseCR(s string) (fmt.Stringer, error) { return nilIfErr(ParseDITContentRule(s)) }
func parseNF(s string) (fmt.Stringer, error) { return nilIfErr(ParseNameForm(s)) }
func parseSR(s string) (fmt.Stringer, error) { return nilIfErr(ParseDITStructureRule(s)) }

func nilIfErr[T fmt.Stringer](x T, err error) (fmt.Stringer, error) {
	if err != nil {
		return nil, err
	}
	return x, nil
}

// In a file the terms come in any order, as libldap reads them
// (ldap_str2contentrule and the two others, libraries/libldap/schema.c), but
// not twice; the .schema keywords and the LDIF attributes read alike.
func TestTheRulesReadFromFilesInAnyOrder(t *testing.T) {
	d, err := Read(File{"r.schema", []byte("objectidentifier ex 1.3.6.1.4.1.32473\n" +
		"ditcontentrule ( 2.5.6.6\n\tNOT p\n\tAUX x )\n" +
		"NameForm ( ex:1 MUST a OC p )\n" +
		"ditStructureRule ( 7\tSUP 1 FORM 1.3.6.1.4.1.32473.1 )\n")})
	if err != nil {
		t.Fatal(err)
	}
	if d.DITContentRules[0].Not[0] != "p" || d.NameForms[0].OID != "1.3.6.1.4.1.32473.1" || d.DITStructureRules[0].Sup[0] != 1 {
		t.Errorf("%+v %+v %+v", d.DITContentRules[0], d.NameForms[0], d.DITStructureRules[0])
	}
	// The macros are expanded where slapd expands them, in the OID, and
	// Format writes them back.
	out, err := d.Format(true)
	if err != nil || !strings.Contains(string(out), "nameform ( ex:1\n\tOC p\n\tMUST a )") ||
		!strings.Contains(string(out), "ditstructurerule ( 7\n\tFORM 1.3.6.1.4.1.32473.1\n\tSUP 1 )") {
		t.Errorf("%v\n%s", err, out)
	}
	for _, c := range []struct{ text, says string }{
		{"ditcontentrule ( 2.5.6.6 AUX x AUX y )", "r.schema:1:32: schema: at offset 16: AUX is repeated"},
		{"nameform ( 1.2 OC p MUST a OC q )", "OC is repeated"},
		{"ditstructurerule ( 1 FORM f FORM g )", "FORM is repeated"},
		{"ditstructurerule ( x FORM f )", "r.schema:1:20: schema: at offset 2: expected a rule ID"},
		{"dn: x\ndITStructureRules: ( 1 )", "r.schema:2:25: schema: at offset 5: a DIT structure rule must name its FORM"},
		{"dn: x\ndITContentRules: ( 1.1 FORM f )", `"FORM" is not a term of this definition`},
		{"nameforms ( 1.1 )", `"nameforms" is not a kind of definition`},
	} {
		if _, err := Read(File{"r.schema", []byte(c.text)}); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%q: %v, want %q", c.text, err, c.says)
		}
	}
}

// ⛔ A rule ID is an int on every architecture, so the bound is the same on
// 32-bit ones (GOARCH=386 runs this test too): MaxRuleID reads, one more
// does not, and a rule ID is never a negative number or another rule.
func TestRuleIDsAreBoundedTheSameOn32Bit(t *testing.T) {
	if strconv.IntSize == 32 && MaxRuleID != int(^uint32(0)>>1) {
		t.Fatal("MaxRuleID is not the largest int32")
	}
	for _, c := range []struct {
		id string
		ok bool
	}{{"0", true}, {"2147483647", true}, {"2147483648", false}, {"4294967296", false}, {"4294967297", false}, {"18446744073709551617", false}} {
		r, err := ParseDITStructureRule("( " + c.id + " FORM f SUP " + c.id + " )")
		if (err == nil) != c.ok || err == nil && (strconv.Itoa(r.ID) != c.id || strconv.Itoa(r.Sup[0]) != c.id) {
			t.Errorf("%s: %+v %v", c.id, r, err)
		}
	}
}

// A long list in a rule is built in linear time: its members go through
// maps, not through a list searched once per member. 20000 types in a NOT,
// 20000 auxiliary classes in an AUX: a search per member would be 4e8 steps.
func TestLongRuleListsBuild(t *testing.T) {
	const n = 20000
	// LDIF, whose lines have no bound: a .schema line has 2000 bytes.
	var b strings.Builder
	b.WriteString("dn: cn=Subschema\nobjectClasses: ( 1.1.9 NAME 's' SUP top )\n")
	var aux, not, sup []string
	for i := range n {
		fmt.Fprintf(&b, "attributeTypes: ( 1.2.%d NAME 't%d' SUP a )\nobjectClasses: ( 1.3.%d NAME 'x%d' SUP top AUXILIARY )\n", i, i, i, i)
		fmt.Fprintf(&b, "dITStructureRules: ( %d FORM f SUP 0 )\n", i)
		aux, not, sup = append(aux, "x"+strconv.Itoa(i)), append(not, "t"+strconv.Itoa(i)), append(sup, strconv.Itoa(i))
	}
	// The AUX classes require a (through top), and NOT may not name it.
	fmt.Fprintf(&b, "dITContentRules: ( 1.1.9 AUX ( %s ) NOT ( %s ) )\n", strings.Join(aux, " $ "), strings.Join(not, " $ "))
	fmt.Fprintf(&b, "nameForms: ( 1.4 NAME 'f' OC s MUST a )\ndITStructureRules: ( %d FORM f SUP ( %s ) )\n", n, strings.Join(sup, " "))
	s, err := build(b.String())
	if err != nil {
		t.Fatal(err)
	}
	if r := s.DITContentRule("1.1.9"); len(r.AuxiliaryClasses()) != n || len(r.NotTypes()) != n || len(s.DITStructureRule(n).Sup) != n {
		t.Error("the lists were not linked")
	}
}

// The errors of Validate name a class problem as the class does; a
// BuildError of a rule is found by errors.As like any other.
func TestARuleBuildErrorIsABuildError(t *testing.T) {
	_, err := Build(append(StandardFiles(), File{"x", []byte("nameform ( 1.9 OC top MUST cn )")})...)
	var be *BuildError
	if !errors.As(err, &be) || be.Kind != KindViolation || be.Element != ElementNameForm || be.Field != "OC" {
		t.Errorf("%#v", err)
	}
}
