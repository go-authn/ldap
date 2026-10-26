// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"fmt"
	"slices"
	"strings"
)

// An Attribute is one attribute of an entry as Validate reads it: an
// attribute description (RFC 4512 2.5) and its values.
type Attribute struct {
	Description string
	Values      [][]byte
}

// An Entry is what Validate checks: a DN and its attributes.
type Entry struct {
	DN         string
	Attributes []Attribute
}

// A ProblemKind is which rule an entry breaks.
type ProblemKind uint8

const (
	NoObjectClass        ProblemKind = iota + 1 // RFC 4512 3.3: every entry has one
	UnknownClass                                // a class this schema does not define
	MissingSuperclass                           // RFC 4512 3.3: superclasses are present too
	NoStructuralClass                           // RFC 4512 2.4.2: exactly one structural chain
	SeveralStructural                           // RFC 4512 2.4.2: exactly one structural chain
	AbstractAlone                               // RFC 4512 2.4.1
	UnknownAttribute                            // RFC 4512 2.5: an unrecognized type or option
	MissingRequired                             // a MUST that is not there
	NotAllowed                                  // neither MUST nor MAY of any class
	SingleValued                                // more than one value of a SINGLE-VALUE type
	DuplicateDescription                        // RFC 4512 2.5: descriptions are distinct
	NoValues                                    // RFC 4512 2.2: one or more values
	DuplicateValue                              // RFC 4512 2.2: no two equivalent values
	InvalidValue                                // not of the type's syntax
	BadDN                                       // the DN does not parse (RFC 4514)
	RDNNotPresent                               // RFC 4512 2.3.1: the RDN's values are the entry's
	AuxiliaryNotAllowed                         // RFC 4512 4.1.6: an auxiliary class the content rule does not list
	Precluded                                   // RFC 4512 4.1.6: a type the content rule's NOT names
	NameFormViolation                           // RFC 4512 4.1.7.2: an RDN no name form of the class allows
	NoStructureRule                             // X.501 13.7.5: no structure rule allows the entry where it is
)

// A Problem is one way an entry breaks the schema. Attribute and Class name
// what it is about, when it is about one.
type Problem struct {
	Kind      ProblemKind
	Attribute string
	Class     string
	Msg       string
}

func (p Problem) String() string { return p.Msg }

// A ValidationError is every problem Validate found, not only the first: a
// directory being brought into line with its schema needs the whole list.
type ValidationError struct {
	DN       string
	Problems []Problem
}

func (e *ValidationError) Error() string {
	msgs := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		msgs[i] = p.Msg
	}
	return fmt.Sprintf("schema: %q: %s", e.DN, strings.Join(msgs, "; "))
}

// Has reports whether one of the problems is of this kind.
func (e *ValidationError) Has(k ProblemKind) bool {
	return slices.ContainsFunc(e.Problems, func(p Problem) bool { return p.Kind == k })
}

// extensibleObject is RFC 4512 4.3's class, which allows any user attribute.
const extensibleObjectOID = "1.3.6.1.4.1.1466.101.120.111"

// description is an attribute description read against a schema.
type description struct {
	t       *AttributeType
	options string // sorted, lower case, ';'-joined: the identity of the set
}

// Describe reads an attribute description, "type;opt;opt" (RFC 4512 2.5),
// into its type and its options: lower case, sorted, without repeats. ok is
// false for an unknown type or an option this package does not recognize.
//
// ⛔ The options recognized are the language tags of RFC 3866 ("lang-...")
// and the transfer option "binary" of RFC 4522. RFC 4512 2.5: "Servers SHALL
// treat an attribute description with an unrecognized attribute option as
// unrecognized." A server that ignored an option it did not understand would
// answer for "cn;x-secret" with the values of cn.
func (s *Schema) Describe(desc string) (t *AttributeType, options []string, ok bool) {
	parts := strings.Split(desc, ";")
	if t = s.AttributeType(parts[0]); t == nil {
		return nil, nil, false
	}
	options = parts[1:]
	for i, o := range options {
		o = strings.ToLower(o)
		if o != "binary" && !(strings.HasPrefix(o, "lang-") && len(o) > 5) {
			return nil, nil, false
		}
		options[i] = o
	}
	slices.Sort(options)
	return t, slices.Compact(options), true
}

func (s *Schema) describe(desc string) (description, bool) {
	t, opts, ok := s.Describe(desc)
	return description{t: t, options: strings.Join(opts, ";")}, ok
}

// Validate checks an entry against RFC 4512: its object classes form
// exactly one structural chain (2.4.2) with every superclass present (3.3);
// every MUST of every class is there, and nothing outside the MUSTs and MAYs
// (2.4, 2.5.3) unless the entry is an extensibleObject (4.3); SINGLE-VALUE
// is kept (4.1.2); every type, option and class is known (2.5); no
// description is repeated (2.5) and no two values are equivalent (2.2);
// values are of their syntax; and the RDN's values are the entry's own
// (2.3.1).
//
// When the entry's structural class has an active DIT content rule (4.1.6),
// the entry belongs to no auxiliary class the rule does not list in AUX,
// holds every type of its MUST, none of its NOT -- even an extensibleObject
// -- and may hold its MAY. A rule for a superclass does not apply (4.1.6).
// Types are the rule's own and not their subtypes (X.501 13.8.2, NOTE).
//
// When the class has active name forms (4.1.7.2), the RDN is made of the
// types one of them allows: all its MUST, and nothing outside its MUST and
// MAY. Where in the DIT the entry may be is not Validate's business: it
// needs the entry's superior (see GoverningStructureRule).
//
// It returns nil or a *ValidationError naming every problem.
//
// ⛔ ONE deliberate departure, which ValidateOptions.StrictAuxiliary takes
// back. RFC 4512 2.4.3: "If no DIT content rule is associated with the
// structural object class of the entry, the entry cannot belong to any
// auxiliary object class", and X.501 13.8.1 says the same. Read literally,
// that refuses every posixAccount, every shadowAccount and every
// ldapPublicKey -- all three are auxiliary -- in a schema with no content
// rules. slapd allows auxiliary classes when there is no rule: its check
// (servers/slapd/schema_check.c, SLAP_DISALLOW_AUX_WO_CR) is behind a flag
// that no "disallow" verb of slapd.conf(5) sets. So does Validate.
func (s *Schema) Validate(e Entry) error { return s.ValidateWith(e, ValidateOptions{}) }

// ValidateOptions are the choices Validate makes where RFC 4512 and the
// servers in use part.
type ValidateOptions struct {
	// StrictAuxiliary refuses an auxiliary class on an entry whose
	// structural class has no active DIT content rule, as RFC 4512 2.4.3
	// says.
	StrictAuxiliary bool
}

// ValidateWith is Validate, with options.
func (s *Schema) ValidateWith(e Entry, o ValidateOptions) error {
	v := &validation{s: s, opt: o}
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

type validation struct {
	s        *Schema
	opt      ValidateOptions
	problems []Problem
	listed   []*ObjectClass
	// structural is the entry's structural class, when it has exactly one
	// structural chain (RFC 4512 2.4.2).
	structural *ObjectClass
	// rule is the active DIT content rule of that class, or nil.
	rule *DITContentRule
	// rdnTypes are the types of the RDN's AVAs that this schema defines;
	// rdnRead is whether the RDN was read (a root DSE has none).
	rdnTypes []*AttributeType
	rdnRead  bool
}

func (v *validation) add(k ProblemKind, attr, class, format string, args ...any) {
	v.problems = append(v.problems, Problem{Kind: k, Attribute: attr, Class: class, Msg: fmt.Sprintf(format, args...)})
}

// classes checks objectClass and records the classes the entry lists.
func (v *validation) classes(e Entry) {
	oc := v.s.AttributeType("objectClass")
	var values [][]byte
	for _, a := range e.Attributes {
		if d, ok := v.s.describe(a.Description); ok && d.t == oc {
			values = append(values, a.Values...)
		}
	}
	if len(values) == 0 {
		v.add(NoObjectClass, "objectClass", "", "it has no objectClass (RFC 4512 3.3)")
		return
	}
	for _, val := range values {
		c := v.s.ObjectClass(string(val))
		if c == nil {
			v.add(UnknownClass, "objectClass", string(val), "the object class %q is not defined", val)
			continue
		}
		if !slices.Contains(v.listed, c) {
			v.listed = append(v.listed, c)
		}
	}
	// RFC 4512 3.3: "all superclasses of the named classes SHALL be
	// implicitly added as well if not already present".
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
	// RFC 4512 2.4.2: "precisely one structural object class superclass
	// chain which has a single structural object class as the most
	// subordinate object class".
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
	// RFC 4512 2.4.1: "An entry cannot belong to an abstract object class
	// unless it belongs to a structural or auxiliary class that inherits
	// from that abstract class."
	for _, c := range v.listed {
		if c.Kind != Abstract {
			continue
		}
		if !slices.ContainsFunc(v.listed, func(o *ObjectClass) bool { return o.Kind != Abstract && o.IsA(c) }) {
			v.add(AbstractAlone, "objectClass", c.Name(), "the abstract class %s is not the superclass of any structural or auxiliary class it has (RFC 4512 2.4.1)", c.Name())
		}
	}
}

// content finds the active DIT content rule of the entry's structural class
// and checks the auxiliary classes against it (RFC 4512 4.1.6: "An entry
// may only belong to auxiliary object classes listed in the governing
// content rule"). Every auxiliary class the entry belongs to is checked,
// an auxiliary superclass of another as well, as slapd does
// (servers/slapd/schema_check.c, entry_schema_check).
func (v *validation) content() {
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
			// No structural class, already a problem: no rule to name.
			v.add(AuxiliaryNotAllowed, "objectClass", c.Name(), "the auxiliary class %s is allowed by no DIT content rule (RFC 4512 2.4.3)", c.Name())
		case v.rule == nil:
			v.add(AuxiliaryNotAllowed, "objectClass", c.Name(), "the auxiliary class %s is allowed by no DIT content rule: %s has none (RFC 4512 2.4.3)", c.Name(), v.structural.Name())
		case !v.rule.auxSet[c]:
			v.add(AuxiliaryNotAllowed, "objectClass", c.Name(), "the auxiliary class %s is not in the AUX of the DIT content rule %s (RFC 4512 4.1.6)", c.Name(), v.rule.Name())
		}
	}
}

// attributes checks every attribute against its type and the classes.
func (v *validation) attributes(e Entry) {
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
	// RFC 4512 4.1.6: "An entry may contain any non-precluded attributes
	// allowed by the object classes the entry belongs to as well as all
	// attributes allowed by the governing content rule."
	var precluded map[*AttributeType]bool
	if v.rule != nil {
		allowed = append(allowed, v.rule.must...)
		allowed = append(allowed, v.rule.may...)
		precluded = v.rule.notSet
	}
	seen := map[description]bool{}
	present := map[*AttributeType]bool{}
	for _, a := range e.Attributes {
		d, ok := s.describe(a.Description)
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
		// RFC 4512 2.5.3: MAY name is satisfied by name and name;x, NOT by
		// a subtype such as cn. Operational attributes are not the classes'
		// business (RFC 4512 3.4).
		if !d.t.Usage.Operational() && !slices.Contains(allowed, d.t) && !extensible {
			v.add(NotAllowed, a.Description, "", "%s is not allowed by any of the entry's object classes", name)
		}
		// Precluded even in an extensibleObject: slapd checks NOT before it
		// looks at the classes (servers/slapd/schema_check.c).
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

// naming checks the RDN against the active name forms of the entry's
// structural class, when it has any: one of them must allow it (X.501
// 13.7.2: "a name form shall be specified for each distinct set of
// attributes to be used for naming").
func (v *validation) naming() {
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

// names reports whether the RDN is one the name form allows (RFC 4512
// 4.1.7.2: "named using a value from each required attribute type and zero
// or more values from the allowed attribute types").
func (v *validation) names(f *NameForm) bool {
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

func typeNames(ts []*AttributeType) string {
	names := make([]string, len(ts))
	for i, t := range ts {
		names[i] = t.Name()
	}
	return strings.Join(names, "+")
}

// formNeeds says what each form wants, for a message.
func formNeeds(forms []*NameForm) string {
	out := make([]string, len(forms))
	for i, f := range forms {
		out[i] = fmt.Sprintf("%s needs %s", f.Name(), typeNames(f.must))
		if len(f.may) > 0 {
			out[i] += fmt.Sprintf(" and allows %s", typeNames(f.may))
		}
	}
	return strings.Join(out, "; ")
}

// GoverningStructureRule is the DIT structure rule that governs e when it
// is placed under an entry governed by superior -- or, with superior nil,
// when e is a subschema administrative point, the root of the subtree the
// schema controls, such as a server's suffix (X.501 13.7.5).
//
// The rule is one whose name form is for e's structural class itself, not
// a superclass of it (X.501 13.7.5: "It does not permit entries belonging
// to any of the subclasses"), allows e's RDN, and either lists superior in
// SUP or, for an administrative point, has no SUP. When several do, the
// first defined governs. OBSOLETE rules and rules of an OBSOLETE name form
// are not active and govern nothing.
//
// With no active structure rule in the schema there is nothing to govern
// by, and the result is nil and no error: RFC 4512 7.1 makes structure
// rules optional. Otherwise every entry has a governing rule (X.501 13.7.5:
// "Each object and alias entry is governed by a single DIT structure
// rule"), and an entry that has none is refused with a *ValidationError
// whose problems are NoStructureRule or NameFormViolation, or the class or
// DN problems that keep the rule from being found.
//
// A server checks a tree from its root down: the rule each entry gets is
// the superior of its subordinates.
//
//	root, err := s.GoverningStructureRule(suffix, nil)
//	people, err := s.GoverningStructureRule(ouPeople, root)
//	_, err = s.GoverningStructureRule(alice, people)
func (s *Schema) GoverningStructureRule(e Entry, superior *DITStructureRule) (*DITStructureRule, error) {
	if s.activeStructureRules == 0 {
		return nil, nil
	}
	v := &validation{s: s}
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
	v.problems = nil // the class and RDN problems are Validate's to report
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

// rdn checks that each AVA of the RDN is a value of the entry (RFC 4512
// 2.3.1: "These AVAs are chosen to match attribute values (each a
// distinguished value) of the entry.")
func (v *validation) rdn(e Entry) {
	rdns, err := parseDN(e.DN)
	if err != nil {
		v.add(BadDN, "", "", "the DN %q is not a DN (RFC 4514)", e.DN)
		return
	}
	if len(rdns) == 0 {
		return // the root DSE
	}
	v.rdnRead = true
	for _, a := range rdns[0] {
		t := v.s.AttributeType(a.typ)
		if t == nil {
			v.add(RDNNotPresent, a.typ, "", "the RDN names %s, which is not defined", a.typ)
			continue
		}
		if !slices.Contains(v.rdnTypes, t) {
			v.rdnTypes = append(v.rdnTypes, t)
		}
		found := false
		for _, attr := range e.Attributes {
			// The distinguished value is one of the attribute with no
			// options: an RDN's AVAs have none (RFC 4512 2.3.1).
			if v.s.AttributeType(attr.Description) != t {
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
