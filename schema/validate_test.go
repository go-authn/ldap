// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"errors"
	"strings"
	"testing"
)

// entry builds an Entry from "description: value" lines.
func entry(dn string, lines ...string) Entry {
	e := Entry{DN: dn}
	for _, l := range lines {
		d, v, _ := strings.Cut(l, ": ")
		found := false
		for i := range e.Attributes {
			if e.Attributes[i].Description == d {
				e.Attributes[i].Values = append(e.Attributes[i].Values, []byte(v))
				found = true
			}
		}
		if !found {
			e.Attributes = append(e.Attributes, Attribute{Description: d, Values: [][]byte{[]byte(v)}})
		}
	}
	return e
}

func problems(t *testing.T, err error) *ValidationError {
	t.Helper()
	if err == nil {
		return &ValidationError{}
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("%v is not a *ValidationError", err)
	}
	return ve
}

// An entry as RFC 2798 section 4 prints it, adapted to the attributes this
// schema defines, and the RFC 2307 account and group: these are valid.
func TestValidEntriesPass(t *testing.T) {
	s := Standard()
	for _, e := range []Entry{
		entry("cn=Barbara Jensen,ou=Product Development,dc=siroe,dc=com",
			"objectClass: top", "objectClass: person", "objectClass: organizationalPerson", "objectClass: inetOrgPerson",
			"cn: Barbara Jensen", "cn: Babs Jensen", "displayName: Babs Jensen", "sn: Jensen", "givenName: Barbara",
			"initials: BJJ", "title: manager, product development", "uid: bjensen", "mail: bjensen@siroe.com",
			"telephoneNumber: +1 408 555 1862", "facsimileTelephoneNumber: +1 408 555 1992", "mobile: +1 408 555 1941",
			"roomNumber: 0209", "carLicense: 6ABC246", "o: Siroe", "ou: Product Development", "departmentNumber: 2604",
			"employeeNumber: 42", "employeeType: full time", "preferredLanguage: fr, en-gb;q=0.8, en;q=0.7",
			"labeledURI: http://www.siroe.com/users/bjensen My Home Page", "cn;lang-fr: Barbara"),
		entry("uid=alice,ou=people,dc=example,dc=org",
			"objectClass: top", "objectClass: account", "objectClass: posixAccount", "objectClass: shadowAccount", "objectClass: ldapPublicKey",
			"uid: alice", "cn: Alice", "uidNumber: 1000", "gidNumber: 100", "homeDirectory: /home/alice", "loginShell: /bin/sh",
			"shadowLastChange: 19000", "sshPublicKey: ssh-ed25519 AAAAC3Nz alice@host", "createTimestamp: 20261012000000Z"),
		entry("cn=staff,ou=groups,dc=example,dc=org",
			"objectClass: top", "objectClass: posixGroup", "cn: staff", "gidNumber: 100", "memberUid: alice", "memberUid: bob"),
		entry("dc=example,dc=org", "objectClass: top", "objectClass: domain", "dc: example"),
		// RFC 4512 4.3: an extensibleObject may hold any user attribute.
		entry("cn=x,dc=org", "objectClass: top", "objectClass: device", "objectClass: extensibleObject", "cn: x", "mail: x@y", "uidNumber: 7"),
		// the root DSE has no RDN to check
		entry("", "objectClass: top", "objectClass: OpenLDAProotDSE", "supportedLDAPVersion: 3"),
	} {
		if err := s.Validate(e); err != nil {
			t.Errorf("%v", err)
		}
	}
}

// What authnd publishes today (go-authn/authnd server.go, peopleEntries and
// groupEntries): every problem is named.
func TestWhatAuthndPublishesTodayIsRefusedForEveryReason(t *testing.T) {
	s := Standard()
	err := s.Validate(entry("uid=alice,ou=people,dc=example,dc=org",
		"objectClass: top", "objectClass: person", "objectClass: posixAccount",
		"uid: alice", "cn: alice", "sshPublicKey: ssh-ed25519 AAAA", "sambaNTPassword: 0123456789ABCDEF0123456789ABCDEF"))
	ve := problems(t, err)
	for _, want := range []string{
		"sn is required by person",
		"uidNumber is required by posixAccount",
		"gidNumber is required by posixAccount",
		"homeDirectory is required by posixAccount",
		"sshPublicKey is not allowed",
		`"sambaNTPassword" is not defined`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("no %q in %v", want, err)
		}
	}
	if len(ve.Problems) != 6 || !ve.Has(MissingRequired) || !ve.Has(NotAllowed) || !ve.Has(UnknownAttribute) || ve.Has(BadDN) {
		t.Errorf("%d problems: %v", len(ve.Problems), err)
	}
	if !strings.HasPrefix(err.Error(), `schema: "uid=alice,ou=people,dc=example,dc=org": `) || ve.Problems[0].String() != ve.Problems[0].Msg {
		t.Error(err)
	}
	// posixGroup as authnd publishes it is fine except for gidNumber.
	err = s.Validate(entry("cn=staff,ou=groups,dc=example,dc=org", "objectClass: top", "objectClass: posixGroup", "cn: staff", "memberUid: alice"))
	if ve := problems(t, err); len(ve.Problems) != 1 || ve.Problems[0].Attribute != "gidNumber" || ve.Problems[0].Class != "posixGroup" {
		t.Errorf("%v", err)
	}
}

func TestEachProblemIsNamed(t *testing.T) {
	s := Standard()
	person := []string{"objectClass: top", "objectClass: person", "cn: a", "sn: b"}
	with := func(extra ...string) []string { return append(append([]string{}, person...), extra...) }
	for _, c := range []struct {
		name string
		e    Entry
		kind ProblemKind
		says string
	}{
		{"no objectClass", entry("cn=a", "cn: a"), NoObjectClass, "no objectClass"},
		{"unknown class", entry("cn=a", with("objectClass: shoe")...), UnknownClass, `"shoe" is not defined`},
		{"superclass missing", entry("cn=a", "objectClass: person", "cn: a", "sn: b"), MissingSuperclass, "top is a superclass of person"},
		{"no structural class", entry("cn=a", "objectClass: top", "objectClass: posixAccount", "cn: a", "uid: a", "uidNumber: 1", "gidNumber: 1", "homeDirectory: /"), NoStructuralClass, "no structural object class"},
		{"two chains", entry("cn=a", with("objectClass: device")...), SeveralStructural, "2 structural chains, person and device"},
		{"abstract alone", entry("cn=a", "objectClass: top", "cn: a"), AbstractAlone, "abstract class top"},
		{"unknown attribute", entry("cn=a", with("shoeSize: 12")...), UnknownAttribute, `"shoeSize" is not defined`},
		{"unknown option", entry("cn=a", with("description;x-secret: s")...), UnknownAttribute, "option"},
		{"MUST missing", entry("cn=a", "objectClass: top", "objectClass: person", "cn: a"), MissingRequired, "sn is required by person"},
		{"not allowed", entry("cn=a", with("mail: a@b")...), NotAllowed, "mail is not allowed"},
		{"MAY name is not met by a subtype", entry("cn=a", "objectClass: top", "objectClass: device", "cn: a", "o: x", "name: y"), NotAllowed, "name is not allowed"},
		{"single value", entry("cn=a", with("objectClass: posixAccount", "uid: a", "uidNumber: 1", "uidNumber: 2", "gidNumber: 1", "homeDirectory: /")...), SingleValued, "uidNumber is SINGLE-VALUE and has 2"},
		{"repeated description", Entry{DN: "cn=a", Attributes: append(entry("", person...).Attributes, Attribute{"CN", [][]byte{[]byte("z")}})}, DuplicateDescription, "appears twice"},
		{"no values", Entry{DN: "cn=a", Attributes: append(entry("", person...).Attributes, Attribute{"description", nil})}, NoValues, "has no values"},
		{"equivalent values", entry("cn=a", with("cn: A  ")...), DuplicateValue, "cn has the value"},
		{"identical values with no EQUALITY", entry("cn=a", "objectClass: top", "objectClass: person", "objectClass: inetOrgPerson", "objectClass: organizationalPerson", "cn: a", "sn: b", "jpegPhoto: x", "jpegPhoto: x"), DuplicateValue, "jpegPhoto has the value"},
		{"bad syntax", entry("cn=a", with("objectClass: posixAccount", "uid: a", "uidNumber: one", "gidNumber: 1", "homeDirectory: /")...), InvalidValue, `"one" of uidNumber`},
		{"bad DN", entry("cn=a,", person...), BadDN, "is not a DN"},
		{"RDN value absent", entry("cn=z,o=x", person...), RDNNotPresent, "cn=z"},
		{"RDN type unknown", entry("shoe=z,o=x", person...), RDNNotPresent, "shoe, which is not defined"},
	} {
		err := s.Validate(c.e)
		ve := problems(t, err)
		if !ve.Has(c.kind) || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v, want kind %d and %q", c.name, err, c.kind, c.says)
		}
	}
}

// Every syntax checked, with one good value and one bad.
func TestSyntaxChecks(t *testing.T) {
	s := Standard()
	for _, c := range []struct {
		attr, good, bad string
	}{
		{"attributeTypes", "( 1.2 SUP cn )", "( cn )"},
		{"objectClasses", "( 1.2 SUP top )", "(1.2"},
		{"matchingRules", "( 1.2 SYNTAX 1.3 )", "( 1.2 )"},
		{"matchingRuleUse", "( 1.2 APPLIES cn )", "( 1.2 )"},
		{"ldapSyntaxes", "( 1.2 DESC 'x' )", "( 1.2 NAME 'x' )"},
		{"c", "FR", "FRA"},
		{"member", "cn=a,o=b", "cn=a,"},
		{"cn", "x", ""},
		{"createTimestamp", "20261012000000Z", "2026"},
		{"mail", "a@b", "\u00e9@b"},
		{"uidNumber", "-12", "012"},
		{"uniqueMember", "cn=a#'01'B", "cn=a,#'01'B"},
		{"x121Address", "12 34", "12a"},
		{"objectClass", "2.5.6.6", "pers on"},
		{"postalAddress", "a$b", "a$$b"},
		{"serialNumber", "AB-12", "AB_12"},
		{"telephoneNumber", "+1 555", "+1 555 #2"},
		{"subtreeSpecification", "{}", "x"},
		{"x500UniqueIdentifier", "'0101'B", "0101"},
	} {
		at := s.AttributeType(c.attr)
		if !s.ValidValue(at, []byte(c.good)) {
			t.Errorf("%s: %q is refused", c.attr, c.good)
		}
		if s.ValidValue(at, []byte(c.bad)) {
			t.Errorf("%s: %q is accepted", c.attr, c.bad)
		}
	}
	// No standard type has the Boolean syntax; a deployment's may.
	b, err := Build(append(StandardFiles(), File{"x", []byte("attributetype ( 1.9.9 NAME 'flag' EQUALITY booleanMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )")})...)
	if err != nil {
		t.Fatal(err)
	}
	if flag := b.AttributeType("flag"); !b.ValidValue(flag, []byte("TRUE")) || b.ValidValue(flag, []byte("yes")) || b.Equal(flag, []byte("FALSE"), []byte("false")) != True {
		t.Error("Boolean")
	}
	if !s.ValidValue(s.AttributeType("jpegPhoto"), []byte{0xff, 0xd8}) {
		t.Error("an unchecked syntax refuses a value")
	}
	if s.ValidValue(s.AttributeType("c"), []byte("F_")) || s.ValidValue(s.AttributeType("telephoneNumber"), nil) {
		t.Error("printable")
	}
}

func TestDescribe(t *testing.T) {
	s := Standard()
	at, opts, ok := s.Describe("CN;Lang-FR;binary;lang-fr")
	if !ok || at.Name() != "cn" || strings.Join(opts, ",") != "binary,lang-fr" {
		t.Errorf("%v %v %v", at, opts, ok)
	}
	for _, d := range []string{"cn;lang-", "cn;x-foo", "shoe", "cn;"} {
		if _, _, ok := s.Describe(d); ok {
			t.Errorf("%q is recognized", d)
		}
	}
}

// RFC 4512 2.5.3: "a 'MUST name' specification is fulfilled by 'name' or
// 'name;x-tag-option', but is not fulfilled by 'CN'", and likewise for MAY.
func TestMustAndMayNameTheTypeNotItsSubtypes(t *testing.T) {
	s, err := Build(append(StandardFiles(), File{"x", []byte("objectclass ( 1.9.9 NAME 'named' SUP top STRUCTURAL MUST name MAY description )")})...)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Validate(entry("cn=a", "objectClass: top", "objectClass: named", "cn: a", "name;lang-fr: b"))
	if ve := problems(t, err); !ve.Has(NotAllowed) || ve.Has(MissingRequired) || !strings.Contains(err.Error(), "cn is not allowed") {
		t.Errorf("%v", err)
	}
	err = s.Validate(entry("cn=a", "objectClass: top", "objectClass: named", "cn: a"))
	if ve := problems(t, err); !ve.Has(MissingRequired) {
		t.Errorf("MUST name was met by cn: %v", err)
	}
}
