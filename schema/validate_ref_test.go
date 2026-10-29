// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
)

// refValidation is validation, and refValidate is ValidateWith, as they were
// at v0.11.1, before the allocation work: the oracle the current code must
// equal, problem for problem and message for message. It reads the same
// *Schema, so the lookups it uses are the exported ones.
type refValidation struct {
	s          *Schema
	opt        ValidateOptions
	problems   []Problem
	listed     []*ObjectClass
	structural *ObjectClass
	rule       *DITContentRule
	rdnTypes   []*AttributeType
	rdnRead    bool
}

func refValidate(s *Schema, e Entry, o ValidateOptions) error {
	v := &refValidation{s: s, opt: o}
	v.classes(e)
	v.content()
	v.attributes(e)
	v.rdn(e)
	v.naming()
	if len(v.problems) == 0 {
		return nil
	}
	return &ValidationError{DN: e.DN, Problems: v.problems}
}

func refDescribe(s *Schema, desc string) (description, bool) {
	parts := strings.Split(desc, ";")
	t := s.typeBy[strings.ToLower(parts[0])]
	if t == nil {
		return description{}, false
	}
	options := parts[1:]
	for i, o := range options {
		o = strings.ToLower(o)
		if o != "binary" && !(strings.HasPrefix(o, "lang-") && len(o) > 5) {
			return description{}, false
		}
		options[i] = o
	}
	slices.Sort(options)
	return description{t: t, options: strings.Join(slices.Compact(options), ";")}, true
}

func (v *refValidation) add(k ProblemKind, attr, class, format string, args ...any) {
	v.problems = append(v.problems, Problem{Kind: k, Attribute: attr, Class: class, Msg: fmt.Sprintf(format, args...)})
}

func (v *refValidation) classes(e Entry) {
	oc := v.s.typeBy["objectclass"]
	var values [][]byte
	for _, a := range e.Attributes {
		if d, ok := refDescribe(v.s, a.Description); ok && d.t == oc {
			values = append(values, a.Values...)
		}
	}
	if len(values) == 0 {
		v.add(NoObjectClass, "objectClass", "", "it has no objectClass (RFC 4512 3.3)")
		return
	}
	for _, val := range values {
		c := v.s.classBy[strings.ToLower(string(val))]
		if c == nil {
			v.add(UnknownClass, "objectClass", string(val), "the object class %q is not defined", val)
			continue
		}
		if !slices.Contains(v.listed, c) {
			v.listed = append(v.listed, c)
		}
	}
	for _, c := range v.listed {
		var walk func(*ObjectClass)
		walk = func(x *ObjectClass) {
			for _, sup := range x.sup {
				if !slices.Contains(v.listed, sup) {
					v.add(MissingSuperclass, "objectClass", sup.Name(), "%s is a superclass of %s and is not listed (RFC 4512 3.3)", sup.Name(), c.Name())
				}
				walk(sup)
			}
		}
		walk(c)
	}
	var structural, leaves []*ObjectClass
	for _, c := range v.listed {
		if c.Kind == Structural {
			structural = append(structural, c)
		}
	}
	for _, c := range structural {
		if !slices.ContainsFunc(structural, func(o *ObjectClass) bool { return o != c && o.IsA(c) }) {
			leaves = append(leaves, c)
		}
	}
	switch len(leaves) {
	case 0:
		v.add(NoStructuralClass, "objectClass", "", "it has no structural object class (RFC 4512 2.4.2)")
	case 1:
		v.structural = leaves[0]
	default:
		names := make([]string, len(leaves))
		for i, l := range leaves {
			names[i] = l.Name()
		}
		v.add(SeveralStructural, "objectClass", names[0], "it has %d structural chains, %s, and an entry has exactly one (RFC 4512 2.4.2)", len(leaves), strings.Join(names, " and "))
	}
	for _, c := range v.listed {
		if c.Kind != Abstract {
			continue
		}
		if !slices.ContainsFunc(v.listed, func(o *ObjectClass) bool { return o.Kind != Abstract && o.IsA(c) }) {
			v.add(AbstractAlone, "objectClass", c.Name(), "the abstract class %s is not the superclass of any structural or auxiliary class it has (RFC 4512 2.4.1)", c.Name())
		}
	}
}

func (v *refValidation) content() {
	if v.structural != nil {
		if r := v.s.contentRuleOf[v.structural]; r != nil && !r.Obsolete {
			v.rule = r
		}
	}
	if v.rule == nil && !v.opt.StrictAuxiliary {
		return
	}
	for _, c := range v.listed {
		if c.Kind != Auxiliary {
			continue
		}
		switch {
		case v.rule == nil && v.structural == nil:
			v.add(AuxiliaryNotAllowed, "objectClass", c.Name(), "the auxiliary class %s is allowed by no DIT content rule (RFC 4512 2.4.3)", c.Name())
		case v.rule == nil:
			v.add(AuxiliaryNotAllowed, "objectClass", c.Name(), "the auxiliary class %s is allowed by no DIT content rule: %s has none (RFC 4512 2.4.3)", c.Name(), v.structural.Name())
		case !v.rule.auxSet[c]:
			v.add(AuxiliaryNotAllowed, "objectClass", c.Name(), "the auxiliary class %s is not in the AUX of the DIT content rule %s (RFC 4512 4.1.6)", c.Name(), v.rule.Name())
		}
	}
}

func (v *refValidation) attributes(e Entry) {
	s := v.s
	extensible := slices.ContainsFunc(v.listed, func(c *ObjectClass) bool { return c.OID == extensibleObjectOID })
	var must, allowed []*AttributeType
	for _, c := range v.listed {
		for _, t := range c.must {
			if !slices.Contains(must, t) {
				must = append(must, t)
			}
		}
		allowed = append(allowed, c.must...)
		allowed = append(allowed, c.may...)
	}
	var precluded map[*AttributeType]bool
	if v.rule != nil {
		allowed = append(allowed, v.rule.must...)
		allowed = append(allowed, v.rule.may...)
		precluded = v.rule.notSet
	}
	seen := map[description]bool{}
	present := map[*AttributeType]bool{}
	for _, a := range e.Attributes {
		d, ok := refDescribe(s, a.Description)
		if !ok {
			v.add(UnknownAttribute, a.Description, "", "the attribute %q is not defined, or has an option this server does not recognize (RFC 4512 2.5)", a.Description)
			continue
		}
		name := d.t.Name()
		if seen[d] {
			v.add(DuplicateDescription, a.Description, "", "the attribute %s appears twice (RFC 4512 2.5: descriptions are distinct)", a.Description)
		}
		seen[d] = true
		present[d.t] = true
		if len(a.Values) == 0 {
			v.add(NoValues, a.Description, "", "the attribute %s has no values (RFC 4512 2.2)", a.Description)
		}
		if d.t.SingleValue && len(a.Values) > 1 {
			v.add(SingleValued, a.Description, "", "%s is SINGLE-VALUE and has %d values", name, len(a.Values))
		}
		if !d.t.Usage.Operational() && !slices.Contains(allowed, d.t) && !extensible {
			v.add(NotAllowed, a.Description, "", "%s is not allowed by any of the entry's object classes", name)
		}
		if precluded[d.t] {
			v.add(Precluded, a.Description, v.rule.Name(), "%s is precluded by the DIT content rule %s (RFC 4512 4.1.6)", name, v.rule.Name())
		}
		for i, val := range a.Values {
			if !s.ValidValue(d.t, val) {
				v.add(InvalidValue, a.Description, "", "the value %q of %s is not of its syntax %s", val, name, d.t.syntax)
				continue
			}
			for _, other := range a.Values[:i] {
				same := string(val) == string(other)
				if d.t.equality != nil {
					same = s.Equal(d.t, val, other) == True
				}
				if same {
					v.add(DuplicateValue, a.Description, "", "%s has the value %q twice, or two values that are equal by its EQUALITY rule (RFC 4512 2.2)", name, val)
					break
				}
			}
		}
	}
	for _, t := range must {
		if !present[t] {
			var by []string
			for _, c := range v.listed {
				if slices.Contains(c.must, t) {
					by = append(by, c.Name())
				}
			}
			v.add(MissingRequired, t.Name(), by[0], "%s is required by %s and is missing", t.Name(), strings.Join(by, ", "))
		}
	}
	if v.rule != nil {
		for _, t := range v.rule.must {
			if !present[t] && !slices.Contains(must, t) {
				v.add(MissingRequired, t.Name(), v.rule.Name(), "%s is required by the DIT content rule %s and is missing (RFC 4512 4.1.6)", t.Name(), v.rule.Name())
			}
		}
	}
}

func (v *refValidation) naming() {
	if v.structural == nil || !v.rdnRead {
		return
	}
	var forms []*NameForm
	for _, f := range v.s.nameFormsOf[v.structural] {
		if !f.Obsolete {
			forms = append(forms, f)
		}
	}
	if len(forms) == 0 || slices.ContainsFunc(forms, v.names) {
		return
	}
	v.add(NameFormViolation, "", v.structural.Name(), "the RDN (%s) is allowed by no name form of %s: %s", typeNames(v.rdnTypes), v.structural.Name(), formNeeds(forms))
}

func (v *refValidation) names(f *NameForm) bool {
	for _, t := range f.must {
		if !slices.Contains(v.rdnTypes, t) {
			return false
		}
	}
	for _, t := range v.rdnTypes {
		if !slices.Contains(f.must, t) && !slices.Contains(f.may, t) {
			return false
		}
	}
	return true
}

func (v *refValidation) rdn(e Entry) {
	rdns, err := parseDN(e.DN)
	if err != nil {
		v.add(BadDN, "", "", "the DN %q is not a DN (RFC 4514)", e.DN)
		return
	}
	if len(rdns) == 0 {
		return
	}
	v.rdnRead = true
	for _, a := range rdns[0] {
		t := v.s.typeBy[strings.ToLower(a.typ)]
		if t == nil {
			v.add(RDNNotPresent, a.typ, "", "the RDN names %s, which is not defined", a.typ)
			continue
		}
		if !slices.Contains(v.rdnTypes, t) {
			v.rdnTypes = append(v.rdnTypes, t)
		}
		found := false
		for _, attr := range e.Attributes {
			if v.s.typeBy[strings.ToLower(attr.Description)] != t {
				continue
			}
			for _, val := range attr.Values {
				if v.s.Equal(t, val, a.value) == True {
					found = true
				}
			}
		}
		if !found {
			v.add(RDNNotPresent, t.Name(), "", "the RDN says %s=%s and the entry has no such value (RFC 4512 2.3.1)", a.typ, a.value)
		}
	}
}

// randomEntry draws an entry from pools that hit every branch of Validate:
// known and unknown classes and types in any case, options, repeated
// descriptions, values good and bad for their syntax, equal values, and DNs
// that match, differ, or do not parse.
func randomEntry(r *rand.Rand) Entry {
	pick := func(xs []string) string { return xs[r.Intn(len(xs))] }
	dns := []string{
		"uid=alice,ou=people,dc=example,dc=org", "UID=Alice,ou=people,dc=example,dc=org", "cn=Alice+uid=alice,dc=x",
		"dc=example", "ou=people,dc=example", "cn=g,ou=groups,dc=example", "gidNumber=100,ou=groups", "", "nonsense", "x=y,dc=z", "uid=bob,dc=x",
	}
	classes := []string{
		"top", "TOP", "account", "Account", "posixAccount", "posixaccount", "shadowAccount", "extensibleObject", "organizationalUnit",
		"domain", "posixGroup", "person", "inetOrgPerson", "organizationalPerson", "localUnit", "nosuchclass", "1.3.6.1.1.1.2.0", "dcObject", "",
	}
	types := []string{
		"objectClass", "OBJECTCLASS", "objectclass;lang-fr", "uid", "UID", "userid", "cn", "commonName", "sn", "uidNumber", "gidNumber", "homeDirectory",
		"description", "description;lang-en", "description;LANG-EN", "description;binary", "description;x-bad", "mail", "seeAlso", "userPassword", "dc", "ou",
		"member", "createTimestamp", "nosuchattr", "telephoneNumber", "1.3.6.1.1.1.1.0", "cn;lang-de;lang-de",
	}
	values := []string{
		"alice", "Alice", " alice ", "ALICE", "1000", "0", "-5", "007", "12x", "/home/alice", "an account", "a@b.c", "uid=alice,dc=x", "uid=bad", "",
		"20260101000000Z", "TRUE", "FALSE", "maybe", "cn=Alice", "é", "\xff", "a  b", "A B",
	}
	e := Entry{DN: pick(dns)}
	n := r.Intn(9)
	if r.Intn(10) == 0 {
		n = 17 + r.Intn(20) // past the 16 a smallSet keeps in place
	}
	for i := 0; i < n; i++ {
		var vals [][]byte
		switch r.Intn(6) {
		case 0:
		case 1, 2, 3:
			vals = [][]byte{[]byte(pick(values))}
		default:
			for j, m := 0, 1+r.Intn(3); j < m; j++ {
				vals = append(vals, []byte(pick(values)))
			}
		}
		e.Attributes = append(e.Attributes, Attribute{Description: pick(types), Values: vals})
	}
	if r.Intn(4) > 0 {
		var vals [][]byte
		for j, m := 0, 1+r.Intn(4); j < m; j++ {
			vals = append(vals, []byte(pick(classes)))
		}
		e.Attributes = append(e.Attributes, Attribute{Description: pick([]string{"objectClass", "objectclass", "OBJECTCLASS", "objectClass;lang-x"}), Values: vals})
	}
	r.Shuffle(len(e.Attributes), func(i, j int) { e.Attributes[i], e.Attributes[j] = e.Attributes[j], e.Attributes[i] })
	return e
}

func checkValidate(t testing.TB, name string, s *Schema, e Entry) {
	t.Helper()
	for _, o := range []ValidateOptions{{}, {StrictAuxiliary: true}} {
		got := s.ValidateWith(e, o)
		want := refValidate(s, e, o)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s %+v: ValidateWith(%#v) = %v, reference %v", name, o, e, got, want)
		}
	}
}

func TestValidateMatchesReference(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for name, s := range map[string]*Schema{"standard": Standard(), "rules": rulesSchema(t)} {
		for range 15000 {
			checkValidate(t, name, s, randomEntry(r))
		}
	}
}

func TestDescribeMatchesReference(t *testing.T) {
	s := Standard()
	for _, d := range []string{"cn", "CN", "commonName", "cn;lang-en", "cn;LANG-EN;binary", "cn;binary;binary", "cn;", "cn;;", "cn;lang-", "cn;x", ";", "", "nosuch", "nosuch;binary", "objectClass", "uidNumber;lang-fr;lang-de;lang-fr", "é", "1.3.6.1.4.1.1466.115.121.1.15"} {
		want, wok := refDescribe(s, d)
		got, gok := s.describe(d)
		if got != want || gok != wok {
			t.Errorf("describe(%q) = (%v, %v), reference (%v, %v)", d, got, gok, want, wok)
		}
	}
}

func TestLookupsAreCaseInsensitiveLikeToLower(t *testing.T) {
	s := Standard()
	for _, n := range []string{"cn", "CN", "cOmMoNnAmE", "uidnumber", "UIDNUMBER", "É", "ǅ", "K", "K", "cn\x00", strings.Repeat("A", 100), strings.Repeat("a", 64), strings.Repeat("a", 65), ""} {
		if got, want := s.AttributeType(n), s.typeBy[strings.ToLower(n)]; got != want {
			t.Errorf("AttributeType(%q) = %v, want %v", n, got, want)
		}
		if got, want := s.ObjectClass(n), s.classBy[strings.ToLower(n)]; got != want {
			t.Errorf("ObjectClass(%q) = %v, want %v", n, got, want)
		}
		if got, want := s.MatchingRule(n), s.ruleBy[strings.ToLower(n)]; got != want {
			t.Errorf("MatchingRule(%q) = %v, want %v", n, got, want)
		}
	}
}

func FuzzValidateMatchesReference(f *testing.F) {
	f.Add("uid=alice,ou=people,dc=example,dc=org\nobjectClass: top\nobjectClass: account\nuid: alice\ncn: Alice\ndescription: x")
	f.Add("cn=a\nobjectClass: person\ncn: a\nsn: b\nOBJECTCLASS: Person\ncn;lang-fr: c")
	f.Add("")
	std, rules := Standard(), rulesSchema(f)
	f.Fuzz(func(t *testing.T, text string) {
		lines := strings.Split(text, "\n")
		e := entry(lines[0], lines[1:]...)
		checkValidate(t, "standard", std, e)
		checkValidate(t, "rules", rules, e)
	})
}

// A built Schema is read-only: many goroutines validate through one (run with
// -race).
func TestConcurrentValidateIsRaceFree(t *testing.T) {
	s := rulesSchema(t)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := rand.New(rand.NewSource(int64(g)))
			for range 500 {
				e := randomEntry(r)
				_ = s.Validate(e)
				_, _ = s.GoverningStructureRule(e, nil)
			}
		}()
	}
	wg.Wait()
}

func BenchmarkValidate(b *testing.B) {
	for name, s := range map[string]*Schema{"standard": Standard(), "rules": rulesSchema(b)} {
		e := alice()
		b.Run(name, func(b *testing.B) {
			if err := s.Validate(e); err != nil && name == "rules" {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				_ = s.Validate(e)
			}
		})
	}
}
