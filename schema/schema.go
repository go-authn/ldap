// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"slices"
	"strings"
)

// A Schema is a set of definitions that refer to one another and have been
// checked to: every SUP, rule, syntax, MUST and MAY names something that is
// there.
//
// It is read-only once built, so one Schema serves every connection of a
// server without a lock. The elements it hands out belong to it and must not
// be changed.
type Schema struct {
	syntaxes []*Syntax
	rules    []*MatchingRule
	types    []*AttributeType
	classes  []*ObjectClass
	uses     []*MatchingRuleUse

	syntaxByOID map[string]*Syntax
	ruleBy      map[string]*MatchingRule
	typeBy      map[string]*AttributeType
	classBy     map[string]*ObjectClass
	useBy       map[string]*MatchingRuleUse
	// appliesTo is each rule's matchingRuleUse as a set, by the rule's OID.
	appliesTo map[string]map[*AttributeType]bool
	// oidOf resolves a descriptor of any kind to its OID, for
	// objectIdentifierMatch, or to "" when it names two different OIDs.
	oidOf map[string]string
}

// Build reads the files, in order, into one Schema, and checks that every
// definition refers only to definitions that are there. It is Read, then
// BuildFrom.
//
// A definition may refer to one later in the same file or in a later file:
// the RFCs list attribute types alphabetically, so 'cn' (SUP name) comes
// before 'name' in RFC 4519.
func Build(files ...File) (*Schema, error) {
	d, err := Read(files...)
	if err != nil {
		return nil, err
	}
	return BuildFrom(d)
}

// BuildFrom links definitions already read -- by Read, or decoded from
// another form such as HCL (package schema/hclschema) -- into one Schema,
// with every check Build makes. The definitions are copied, so the same
// Definitions may be built again, or into several schemas.
func BuildFrom(defs ...*Definitions) (*Schema, error) {
	d := &Definitions{}
	for _, x := range defs {
		for _, e := range x.Syntaxes {
			c := *e
			d.Syntaxes = append(d.Syntaxes, &c)
		}
		for _, e := range x.MatchingRules {
			c := *e
			d.MatchingRules = append(d.MatchingRules, &c)
		}
		for _, e := range x.AttributeTypes {
			c := *e
			c.sup, c.equality, c.ordering, c.sub, c.syntax, c.linked = nil, nil, nil, nil, "", false
			d.AttributeTypes = append(d.AttributeTypes, &c)
		}
		for _, e := range x.ObjectClasses {
			c := *e
			c.sup, c.must, c.may = nil, nil, nil
			d.ObjectClasses = append(d.ObjectClasses, &c)
		}
	}
	s := &Schema{
		syntaxByOID: map[string]*Syntax{},
		ruleBy:      map[string]*MatchingRule{},
		typeBy:      map[string]*AttributeType{},
		classBy:     map[string]*ObjectClass{},
		useBy:       map[string]*MatchingRuleUse{},
		appliesTo:   map[string]map[*AttributeType]bool{},
		oidOf:       map[string]string{},
	}
	for _, x := range d.Syntaxes {
		if first := s.syntaxByOID[x.OID]; first != nil {
			return nil, buildError(DuplicateOID, x, "", first.OID, first, "the syntax %s is defined twice", x.OID)
		}
		s.syntaxByOID[x.OID] = x
		s.syntaxes = append(s.syntaxes, x)
	}
	for _, x := range d.MatchingRules {
		if err := index(s, s.ruleBy, x, x.OID, x.Names, "matching rule"); err != nil {
			return nil, err
		}
		s.rules = append(s.rules, x)
	}
	for _, x := range d.AttributeTypes {
		if err := index(s, s.typeBy, x, x.OID, x.Names, "attribute type"); err != nil {
			return nil, err
		}
		s.types = append(s.types, x)
	}
	for _, x := range d.ObjectClasses {
		if err := index(s, s.classBy, x, x.OID, x.Names, "object class"); err != nil {
			return nil, err
		}
		s.classes = append(s.classes, x)
	}
	for _, r := range s.rules {
		if s.syntaxByOID[r.Syntax] == nil {
			return nil, buildError(UnknownReference, r, "SYNTAX", r.Syntax, nil, "the matching rule %s has the syntax %s, which is not defined", r.Name(), r.Syntax)
		}
	}
	for _, t := range s.types {
		if err := s.linkType(t, nil); err != nil {
			return nil, err
		}
	}
	for _, c := range s.classes {
		if err := s.linkClass(c, nil); err != nil {
			return nil, err
		}
	}
	s.deriveUses()
	return s, nil
}

// index files an element under its OID and each of its names, refusing an
// OID defined twice and remembering a name two OIDs claim.
func index[T interface {
	definition
	Name() string
}](s *Schema, by map[string]T, x T, oid string, names []string, what string) error {
	if first, dup := by[oid]; dup {
		return buildError(DuplicateOID, x, "", first.Name(), first, "the %s %s is defined twice", what, oid)
	}
	by[oid] = x
	for _, n := range names {
		k := strings.ToLower(n)
		if first, dup := by[k]; dup {
			// RFC 4512 1.4: "Implementations SHOULD treat short names
			// (descriptors) used in an ambiguous manner ... as
			// unrecognized." Refused here rather than resolved one way or
			// the other, because which one wins would depend on the order
			// the files were given in.
			plural := what + "s"
			if strings.HasSuffix(what, "s") {
				plural = what + "es" // "object classes", not "object classs"
			}
			return buildError(DuplicateName, x, "NAME", n, first, "the name %q is given to two %s", n, plural)
		}
		by[k] = x
		if o, seen := s.oidOf[k]; seen && o != oid {
			s.oidOf[k] = "" // the same name for two different things
		} else {
			s.oidOf[k] = oid
		}
	}
	return nil
}

func (s *Schema) linkType(t *AttributeType, seen []*AttributeType) error {
	if slices.Contains(seen, t) {
		return buildError(SuperiorCycle, t, "SUP", "", nil, "the attribute type %s is its own supertype", t.Name())
	}
	if t.linked {
		return nil
	}
	t.linked = true
	rule := func(name, what string) (*MatchingRule, error) {
		if name == "" {
			return nil, nil
		}
		r := s.ruleBy[strings.ToLower(name)]
		if r == nil {
			return nil, buildError(UnknownReference, t, what, name, nil, "the attribute type %s has the %s rule %s, which is not defined", t.Name(), what, name)
		}
		return r, nil
	}
	var err error
	if t.equality, err = rule(t.Equality, "EQUALITY"); err != nil {
		return err
	}
	if t.ordering, err = rule(t.Ordering, "ORDERING"); err != nil {
		return err
	}
	if t.sub, err = rule(t.Substr, "SUBSTR"); err != nil {
		return err
	}
	if t.Syntax != "" && s.syntaxByOID[t.Syntax] == nil {
		return buildError(UnknownReference, t, "SYNTAX", t.Syntax, nil, "the attribute type %s has the syntax %s, which is not defined", t.Name(), t.Syntax)
	}
	t.syntax = t.Syntax
	if t.Sup != "" {
		sup := s.typeBy[strings.ToLower(t.Sup)]
		if sup == nil {
			return buildError(UnknownReference, t, "SUP", t.Sup, nil, "the attribute type %s has the supertype %s, which is not defined", t.Name(), t.Sup)
		}
		if err := s.linkType(sup, append(seen, t)); err != nil {
			return err
		}
		t.sup = sup
		// RFC 4512 4.1.2: "If no SYNTAX field is provided, the attribute
		// type description takes its value from the supertype", and "the
		// EQUALITY, ORDERING, and SUBSTRING fields, if not specified, take
		// their value from the supertype."
		if t.syntax == "" {
			t.syntax = sup.syntax
		}
		if t.equality == nil {
			t.equality = sup.equality
		}
		if t.ordering == nil {
			t.ordering = sup.ordering
		}
		if t.sub == nil {
			t.sub = sup.sub
		}
		// RFC 4512 2.5.1: "a subtype must have the same usage as its direct
		// supertype" and "must be collective if its supertype is".
		if t.Usage != sup.Usage {
			return buildError(UsageMismatch, t, "SUP", sup.Name(), sup, "the attribute type %s is %s and its supertype %s is %s (RFC 4512 2.5.1)", t.Name(), t.Usage, sup.Name(), sup.Usage)
		}
		if sup.Collective && !t.Collective {
			return buildError(CollectiveMismatch, t, "SUP", sup.Name(), sup, "the attribute type %s must be COLLECTIVE like its supertype %s (RFC 4512 2.5.1)", t.Name(), sup.Name())
		}
	}
	// RFC 4512 4.1.2: "COLLECTIVE requires usage userApplications" and
	// "NO-USER-MODIFICATION requires an operational usage."
	if t.Collective && t.Usage != UserApplications {
		return buildError(UsageViolation, t, "COLLECTIVE", "", nil, "the attribute type %s is COLLECTIVE and %s (RFC 4512 4.1.2)", t.Name(), t.Usage)
	}
	if t.NoUserModification && t.Usage == UserApplications {
		return buildError(UsageViolation, t, "NO-USER-MODIFICATION", "", nil, "the attribute type %s is NO-USER-MODIFICATION and a user attribute (RFC 4512 4.1.2)", t.Name())
	}
	return nil
}

func (s *Schema) linkClass(c *ObjectClass, seen []*ObjectClass) error {
	if c.must != nil {
		return nil // already linked
	}
	if slices.Contains(seen, c) {
		return buildError(SuperiorCycle, c, "SUP", "", nil, "the object class %s is its own superclass", c.Name())
	}
	var must, may []*AttributeType
	add := func(list *[]*AttributeType, t *AttributeType) {
		if !slices.Contains(*list, t) {
			*list = append(*list, t)
		}
	}
	for _, name := range c.Sup {
		sup := s.classBy[strings.ToLower(name)]
		if sup == nil {
			return buildError(UnknownReference, c, "SUP", name, nil, "the object class %s has the superclass %s, which is not defined", c.Name(), name)
		}
		if err := s.linkClass(sup, append(seen, c)); err != nil {
			return err
		}
		// RFC 4512 2.4.1-2.4.3: what may derive from what.
		switch {
		case c.Kind == Abstract && sup.Kind != Abstract:
			return buildError(KindViolation, c, "SUP", sup.Name(), sup, "the abstract class %s derives from the %s class %s (RFC 4512 2.4.1)", c.Name(), strings.ToLower(sup.Kind.String()), sup.Name())
		case c.Kind == Structural && sup.Kind == Auxiliary:
			return buildError(KindViolation, c, "SUP", sup.Name(), sup, "the structural class %s derives from the auxiliary class %s (RFC 4512 2.4.2)", c.Name(), sup.Name())
		case c.Kind == Auxiliary && sup.Kind == Structural:
			return buildError(KindViolation, c, "SUP", sup.Name(), sup, "the auxiliary class %s derives from the structural class %s (RFC 4512 2.4.3)", c.Name(), sup.Name())
		}
		c.sup = append(c.sup, sup)
		for _, t := range sup.must {
			add(&must, t)
		}
		for _, t := range sup.may {
			add(&may, t)
		}
	}
	for _, list := range []struct {
		names []string
		into  *[]*AttributeType
		what  string
	}{{c.Must, &must, "MUST"}, {c.May, &may, "MAY"}} {
		for _, name := range list.names {
			t := s.typeBy[strings.ToLower(name)]
			if t == nil {
				return buildError(UnknownReference, c, list.what, name, nil, "the object class %s has %s %s, which is not a defined attribute type", c.Name(), list.what, name)
			}
			add(list.into, t)
		}
	}
	// RFC 4512 2.4: "If an attribute is a member of both sets, it is
	// required to be present."
	may = slices.DeleteFunc(may, func(t *AttributeType) bool { return slices.Contains(must, t) })
	if must == nil {
		must = []*AttributeType{}
	}
	if may == nil {
		may = []*AttributeType{}
	}
	c.must, c.may = must, may
	return nil
}

// deriveUses builds the matchingRuleUse values (RFC 4512 4.1.4): which
// attribute types each rule may be used with in an extensible match.
//
// A rule applies to a type when it is one of the type's own rules, or when
// its assertion syntax is the type's syntax -- RFC 4517 4.1: servers "SHOULD
// allow matching rules to be used with all attribute types known to the
// server, where the assertion syntax of the matching rule is the same as the
// value syntax of the attribute."
func (s *Schema) deriveUses() {
	for _, r := range s.rules {
		var applies []string
		set := map[*AttributeType]bool{}
		for _, t := range s.types {
			if t.equality == r || t.ordering == r || t.sub == r || t.syntax == r.Syntax {
				applies = append(applies, t.Name())
				set[t] = true
			}
		}
		if applies == nil {
			continue
		}
		u := &MatchingRuleUse{OID: r.OID, Names: r.Names, Applies: applies}
		s.uses = append(s.uses, u)
		s.useBy[r.OID] = u
		s.appliesTo[r.OID] = set
	}
}

// AttributeType finds a type by any of its names or its OID, without regard
// to case, or returns nil.
func (s *Schema) AttributeType(name string) *AttributeType { return s.typeBy[strings.ToLower(name)] }

// ObjectClass finds a class by any of its names or its OID, or returns nil.
func (s *Schema) ObjectClass(name string) *ObjectClass { return s.classBy[strings.ToLower(name)] }

// MatchingRule finds a rule by any of its names or its OID, or returns nil.
func (s *Schema) MatchingRule(name string) *MatchingRule { return s.ruleBy[strings.ToLower(name)] }

// Syntax finds a syntax by its OID, or returns nil. Syntaxes have no names
// (RFC 4517 3.1).
func (s *Schema) Syntax(oid string) *Syntax { return s.syntaxByOID[oid] }

// MatchingRuleUse is the use of a rule, by the rule's name or OID, or nil
// when the rule applies to no attribute type here.
func (s *Schema) MatchingRuleUse(rule string) *MatchingRuleUse {
	if r := s.MatchingRule(rule); r != nil {
		return s.useBy[r.OID]
	}
	return nil
}

// Applies reports whether a rule may be used with an attribute type in an
// extensible match: whether the type, or one of its supertypes, is in the
// rule's matchingRuleUse.
func (s *Schema) Applies(r *MatchingRule, t *AttributeType) bool {
	set := s.appliesTo[r.OID]
	for x := t; x != nil; x = x.sup {
		if set[x] {
			return true
		}
	}
	return false
}

// Syntaxes, MatchingRules, AttributeTypes, ObjectClasses and
// MatchingRuleUses list everything, in the order it was defined.
func (s *Schema) Syntaxes() []*Syntax                  { return slices.Clone(s.syntaxes) }
func (s *Schema) MatchingRules() []*MatchingRule       { return slices.Clone(s.rules) }
func (s *Schema) AttributeTypes() []*AttributeType     { return slices.Clone(s.types) }
func (s *Schema) ObjectClasses() []*ObjectClass        { return slices.Clone(s.classes) }
func (s *Schema) MatchingRuleUses() []*MatchingRuleUse { return slices.Clone(s.uses) }

// resolveOID is objectIdentifierMatch's reading of a value (RFC 4517
// 4.2.26): a numeric OID as itself, a descriptor as the OID it names. The
// second result is false for a descriptor nothing here defines, or one that
// names two different OIDs, which the rule makes Undefined.
func (s *Schema) resolveOID(v string) (string, bool) {
	if isNumericOID(v) {
		return v, true
	}
	if !isKeystring(v) {
		return "", false
	}
	o := s.oidOf[strings.ToLower(v)]
	return o, o != ""
}
