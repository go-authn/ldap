// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// refGoverningStructureRule is GoverningStructureRule as it was at v0.11.2,
// built on the reference validation of validate_ref_test.go: the oracle the
// current code must equal, rule for rule and message for message.
func refGoverningStructureRule(s *Schema, e Entry, superior *DITStructureRule) (*DITStructureRule, error) {
	if s.activeStructureRules == 0 {
		return nil, nil
	}
	v := &refValidation{s: s}
	v.classes(e)
	v.rdn(e)
	if v.structural == nil || !v.rdnRead {
		if !v.rdnRead && !slices.ContainsFunc(v.problems, func(p Problem) bool { return p.Kind == BadDN }) {
			v.add(NoStructureRule, "", "", "the root DSE is governed by no DIT structure rule")
		}
		return nil, &ValidationError{DN: e.DN, Problems: v.problems}
	}
	var named, placed []*DITStructureRule
	for _, r := range s.structureRulesOf[v.structural] {
		if r.Obsolete || r.form.Obsolete {
			continue
		}
		named = append(named, r)
		if superior == nil && len(r.sup) == 0 || superior != nil && r.sup[superior.ID] {
			placed = append(placed, r)
		}
	}
	for _, r := range placed {
		if v.names(r.form) {
			return r, nil
		}
	}
	where := "as a subschema administrative point"
	if superior != nil {
		where = "under an entry governed by the rule " + superior.Name()
	}
	v.problems = nil
	switch {
	case len(named) == 0:
		v.add(NoStructureRule, "", v.structural.Name(), "no active DIT structure rule has a name form for %s (X.501 13.7.5)", v.structural.Name())
	case len(placed) == 0:
		v.add(NoStructureRule, "", v.structural.Name(), "no DIT structure rule allows %s %s (X.501 13.7.5)", v.structural.Name(), where)
	default:
		forms := make([]*NameForm, len(placed))
		for i, r := range placed {
			forms[i] = r.form
		}
		v.add(NameFormViolation, "", v.structural.Name(), "the RDN (%s) is allowed by the name form of no DIT structure rule that places %s %s: %s", typeNames(v.rdnTypes), v.structural.Name(), where, formNeeds(forms))
	}
	return nil, &ValidationError{DN: e.DN, Problems: v.problems}
}

func checkStructure(t testing.TB, s *Schema, e Entry, sup *DITStructureRule) {
	t.Helper()
	got, gerr := s.GoverningStructureRule(e, sup)
	want, werr := refGoverningStructureRule(s, e, sup)
	if got != want || !reflect.DeepEqual(gerr, werr) {
		t.Fatalf("GoverningStructureRule(%#v, %v) = (%v, %v), reference (%v, %v)", e, sup, got, gerr, want, werr)
	}
}

// structureEntry is randomEntry with the DNs and classes of the structure
// rules of rulesFile pushed up, so that rules are found as often as refused.
func structureEntry(r *rand.Rand) Entry {
	e := randomEntry(r)
	dns := []string{
		"dc=example", "ou=people,dc=example", "uid=alice,ou=people,dc=example", "cn=g,ou=groups,dc=example",
		"gidNumber=100,ou=groups,dc=example", "cn=g+gidNumber=100,ou=groups", "uid=alice+cn=Alice,ou=people", "ou=x", "", "bad", "dc=a+dc=b",
	}
	if r.Intn(3) > 0 {
		e.DN = dns[r.Intn(len(dns))]
	}
	return e
}

func TestGoverningStructureRuleMatchesReference(t *testing.T) {
	s := rulesSchema(t)
	sups := append([]*DITStructureRule{nil}, s.DITStructureRules()...)
	r := rand.New(rand.NewSource(2))
	for range 30000 {
		checkStructure(t, s, structureEntry(r), sups[r.Intn(len(sups))])
	}
	// The standard schema has no structure rule: nothing governs.
	std := Standard()
	for range 200 {
		checkStructure(t, std, structureEntry(r), nil)
	}
	// Every shape the rules test names, against every superior.
	for _, e := range []Entry{
		alice(), without(alice(), "uid"),
		entry("dc=example,dc=org", "objectClass: top", "objectClass: domain", "objectClass: dcObject", "dc: example"),
		entry("ou=people,dc=example,dc=org", "objectClass: top", "objectClass: organizationalUnit", "ou: people"),
		entry("cn=staff,ou=groups,dc=example,dc=org", "objectClass: top", "objectClass: posixGroup", "cn: staff", "gidNumber: 100"),
		entry("", "objectClass: top"),
	} {
		for _, sup := range sups {
			checkStructure(t, s, e, sup)
		}
	}
}

func FuzzGoverningStructureRuleMatchesReference(f *testing.F) {
	f.Add("uid=alice,ou=people,dc=example,dc=org\nobjectClass: top\nobjectClass: account\nuid: alice", uint8(0))
	f.Add("dc=example\nobjectClass: domain\ndc: example", uint8(1))
	f.Add("cn=g,ou=groups\nobjectClass: posixGroup\ncn: g\ngidNumber: 1", uint8(4))
	f.Add("", uint8(2))
	s := rulesSchema(f)
	sups := append([]*DITStructureRule{nil}, s.DITStructureRules()...)
	f.Fuzz(func(t *testing.T, text string, which uint8) {
		lines := strings.Split(text, "\n")
		checkStructure(t, s, entry(lines[0], lines[1:]...), sups[int(which)%len(sups)])
	})
}
