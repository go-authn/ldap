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
	NoObjectClass         ProblemKind = iota + 1 // RFC 4512 3.3: every entry has one
	UnknownClass                                 // a class this schema does not define
	MissingSuperclass                            // RFC 4512 3.3: superclasses are present too
	NoStructuralClass                            // RFC 4512 2.4.2: exactly one structural chain
	SeveralStructural                            // RFC 4512 2.4.2: exactly one structural chain
	AbstractAlone                                // RFC 4512 2.4.1
	UnknownAttribute                             // RFC 4512 2.5: an unrecognized type or option
	MissingRequired                              // a MUST that is not there
	NotAllowed                                   // neither MUST nor MAY of any class
	SingleValued                                 // more than one value of a SINGLE-VALUE type
	DuplicateDescription                         // RFC 4512 2.5: descriptions are distinct
	NoValues                                     // RFC 4512 2.2: one or more values
	DuplicateValue                               // RFC 4512 2.2: no two equivalent values
	InvalidValue                                 // not of the type's syntax
	BadDN                                        // the DN does not parse (RFC 4514)
	RDNNotPresent                                // RFC 4512 2.3.1: the RDN's values are the entry's
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

// describe reads "type;opt;opt". ok is false for an unknown type or an
// option this package does not recognize.
//
// ⛔ The options recognized are the language tags of RFC 3866 ("lang-...")
// and the transfer option "binary" of RFC 4522. RFC 4512 2.5: "Servers SHALL
// treat an attribute description with an unrecognized attribute option as
// unrecognized." A server that ignored an option it did not understand would
// answer for "cn;x-secret" with the values of cn.
func (s *Schema) describe(desc string) (description, bool) {
	parts := strings.Split(desc, ";")
	t := s.AttributeType(parts[0])
	if t == nil {
		return description{}, false
	}
	opts := parts[1:]
	for i, o := range opts {
		o = strings.ToLower(o)
		if o != "binary" && !(strings.HasPrefix(o, "lang-") && len(o) > 5) {
			return description{}, false
		}
		opts[i] = o
	}
	slices.Sort(opts)
	return description{t: t, options: strings.Join(slices.Compact(opts), ";")}, true
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
// It returns nil or a *ValidationError naming every problem.
//
// ⛔ ONE deliberate departure. RFC 4512 2.4.3: "If no DIT content rule is
// associated with the structural object class of the entry, the entry cannot
// belong to any auxiliary object class." Nothing here implements DIT content
// rules, so read literally that would refuse every posixAccount, every
// shadowAccount and every ldapPublicKey -- all three are auxiliary. Every
// directory server in use allows auxiliary classes when there are no DIT
// content rules, and so does this. It is said here so that nobody believes
// the RFC was followed to the letter.
func (s *Schema) Validate(e Entry) error {
	v := &validation{s: s}
	v.classes(e)
	v.attributes(e)
	v.rdn(e)
	if len(v.problems) == 0 {
		return nil
	}
	return &ValidationError{DN: e.DN, Problems: v.problems}
}

type validation struct {
	s        *Schema
	problems []Problem
	listed   []*ObjectClass
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
	for _, a := range rdns[0] {
		t := v.s.AttributeType(a.typ)
		if t == nil {
			v.add(RDNNotPresent, a.typ, "", "the RDN names %s, which is not defined", a.typ)
			continue
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
