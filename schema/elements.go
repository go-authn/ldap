// SPDX-License-Identifier: BSD-3-Clause

// Package schema is the LDAP directory schema of RFC 4512 section 4: the
// definitions of syntaxes, matching rules, attribute types and object
// classes, what an entry must and may contain, and how two values are
// compared.
//
// A Schema is built once, from text, and is read-only afterwards, so that one
// can be shared by every connection of a server without a lock. Standard
// returns the schemas the RFCs define; Build adds a deployment's own.
//
// ⛔ Every definition embedded here is COPIED from the RFC that defines it,
// and each file names the RFC and the section. A definition typed from
// memory is one whose mistakes nobody can check, and an LDAP client caches
// what a server publishes: a wrong SINGLE-VALUE or EQUALITY is then wrong on
// every machine that read it.
package schema

import "strconv"

// A Kind is what an object class is for (RFC 4512 2.4).
type Kind uint8

const (
	// Structural is the default when a definition names no kind (RFC 4512
	// 4.1.1), which is why it is the zero value.
	Structural Kind = iota
	Abstract
	Auxiliary
)

func (k Kind) String() string {
	switch k {
	case Abstract:
		return "ABSTRACT"
	case Auxiliary:
		return "AUXILIARY"
	}
	return "STRUCTURAL"
}

// A Usage says whether an attribute holds user information or is kept by
// the directory (RFC 4512 4.1.2).
type Usage uint8

const (
	// UserApplications is the default, and the only usage of a USER
	// attribute. The other three are operational.
	UserApplications Usage = iota
	DirectoryOperation
	DistributedOperation
	DSAOperation
)

func (u Usage) String() string {
	switch u {
	case DirectoryOperation:
		return "directoryOperation"
	case DistributedOperation:
		return "distributedOperation"
	case DSAOperation:
		return "dSAOperation"
	}
	return "userApplications"
}

// Operational reports whether attributes of this usage are operational:
// returned only when asked for by name or with "+" (RFC 4512 3.4, RFC 3673).
func (u Usage) Operational() bool { return u != UserApplications }

// An Extension is an "X-" term (RFC 4512 4.1): a name and its strings.
type Extension struct {
	Name   string
	Values []string
}

// A Syntax is an LDAP syntax description (RFC 4512 4.1.5).
type Syntax struct {
	OID        string
	Desc       string
	Extensions []Extension
	// Pos is where the definition was read from, if it was (see Position).
	// It is not part of the definition: String and Format leave it out.
	Pos Position
}

// A MatchingRule is a matching rule description (RFC 4512 4.1.3). Syntax is
// the syntax of the ASSERTION value, which is not always the syntax of the
// attributes the rule applies to.
type MatchingRule struct {
	OID        string
	Names      []string
	Desc       string
	Obsolete   bool
	Syntax     string
	Extensions []Extension
	// Pos is where the definition was read from, if it was.
	Pos Position
}

// A MatchingRuleUse lists the attribute types a matching rule may be used
// with in an extensible match (RFC 4512 4.1.4).
type MatchingRuleUse struct {
	OID        string
	Names      []string
	Desc       string
	Obsolete   bool
	Applies    []string
	Extensions []Extension
}

// An AttributeType is an attribute type description (RFC 4512 4.1.2).
//
// The fields are what the definition SAYS. What it MEANS -- the rules and the
// syntax it inherits through SUP -- is asked of the methods, which answer
// only for a type that belongs to a Schema.
type AttributeType struct {
	OID      string
	Names    []string
	Desc     string
	Obsolete bool
	Sup      string
	Equality string
	Ordering string
	Substr   string
	Syntax   string
	// SyntaxLen is the suggested minimum upper bound after the syntax, the
	// "64" of "1.3.6.1.4.1.1466.115.121.1.15{64}", or empty for none. It is a
	// suggestion (RFC 4512 4.1.2) and nothing here enforces it.
	SyntaxLen          string
	SingleValue        bool
	Collective         bool
	NoUserModification bool
	Usage              Usage
	Extensions         []Extension
	// Pos is where the definition was read from, if it was.
	Pos Position

	// Resolved by Build.
	sup                     *AttributeType
	equality, ordering, sub *MatchingRule
	syntax                  string
	linked                  bool
}

// An ObjectClass is an object class description (RFC 4512 4.1.1).
type ObjectClass struct {
	OID        string
	Names      []string
	Desc       string
	Obsolete   bool
	Sup        []string
	Kind       Kind
	Must       []string
	May        []string
	Extensions []Extension
	// Pos is where the definition was read from, if it was.
	Pos Position

	// Resolved by Build.
	sup       []*ObjectClass
	must, may []*AttributeType
}

// A DITContentRule is a DIT content rule description (RFC 4512 4.1.6): what
// entries of ONE structural object class may hold beyond what their classes
// say. Its OID is the structural class's (RFC 4512 4.1.6: "Each content rule
// is identified by the object identifier ... of the structural object class
// it applies to").
//
// Aux are the auxiliary classes such an entry may belong to; Must and May
// add required and allowed attribute types; Not precludes types its classes
// would allow. An OBSOLETE rule is not active (RFC 4512 4.1), and an entry
// is then governed as if there were none (RFC 4512 4.1.6: "If no active
// rule is present ...").
type DITContentRule struct {
	OID        string
	Names      []string
	Desc       string
	Obsolete   bool
	Aux        []string
	Must       []string
	May        []string
	Not        []string
	Extensions []Extension
	// Pos is where the definition was read from, if it was.
	Pos Position

	// Resolved by Build.
	class          *ObjectClass
	aux            []*ObjectClass
	must, may, not []*AttributeType
	// auxSet and notSet are aux and not as sets, so that checking an entry
	// costs one lookup per class and attribute, however long the lists.
	auxSet map[*ObjectClass]bool
	notSet map[*AttributeType]bool
}

// A NameForm is a name form description (RFC 4512 4.1.7.2): the attribute
// types the RDN of an entry of one structural class is made of. Every type
// of Must is in the RDN, and nothing that is in neither Must nor May.
type NameForm struct {
	OID        string
	Names      []string
	Desc       string
	Obsolete   bool
	OC         string
	Must       []string
	May        []string
	Extensions []Extension
	// Pos is where the definition was read from, if it was.
	Pos Position

	// Resolved by Build.
	class     *ObjectClass
	must, may []*AttributeType
}

// MaxRuleID is the largest rule identifier a DIT structure rule may have.
// RFC 4512 4.1.7.1's ruleid is a number, and X.501 13.7.6's RuleIdentifier
// an INTEGER, neither bounded; this one fits an int on every architecture
// Go has, 32-bit ones included, so that no rule reads as another.
const MaxRuleID = 1<<31 - 1

// A DITStructureRule is a DIT structure rule description (RFC 4512
// 4.1.7.1): entries named by the name form Form -- and so of its structural
// class -- may be placed under entries governed by one of the rules Sup.
// A rule with no Sup governs a subschema administrative point, the root of
// the subtree the subschema controls (X.501 13.7.5).
//
// A rule is identified by its ID, not by an OID (RFC 4512 4.1.7.1: "ruleid
// = number"). A rule may name itself in Sup: organizationalUnits under
// organizationalUnits is one rule.
type DITStructureRule struct {
	ID         int
	Names      []string
	Desc       string
	Obsolete   bool
	Form       string
	Sup        []int
	Extensions []Extension
	// Pos is where the definition was read from, if it was.
	Pos Position

	// Resolved by Build.
	form *NameForm
	sup  map[int]bool
}

// Name is the first short name, or the OID when there is none.
func (r *DITContentRule) Name() string { return firstName(r.Names, r.OID) }

// Name is the first short name, or the OID when there is none.
func (f *NameForm) Name() string { return firstName(f.Names, f.OID) }

// Name is the first short name, or the rule ID when there is none.
func (r *DITStructureRule) Name() string { return firstName(r.Names, strconv.Itoa(r.ID)) }

// Class is the structural object class the rule governs.
func (r *DITContentRule) Class() *ObjectClass { return r.class }

// AuxiliaryClasses are the auxiliary classes the rule allows.
func (r *DITContentRule) AuxiliaryClasses() []*ObjectClass { return r.aux }

// MustTypes, MayTypes and NotTypes are the rule's MUST, MAY and NOT.
func (r *DITContentRule) MustTypes() []*AttributeType { return r.must }
func (r *DITContentRule) MayTypes() []*AttributeType  { return r.may }
func (r *DITContentRule) NotTypes() []*AttributeType  { return r.not }

// Class is the structural object class the name form names.
func (f *NameForm) Class() *ObjectClass { return f.class }

// MustTypes and MayTypes are the name form's required and allowed naming
// attribute types.
func (f *NameForm) MustTypes() []*AttributeType { return f.must }
func (f *NameForm) MayTypes() []*AttributeType  { return f.may }

// NameForm is the rule's name form.
func (r *DITStructureRule) NameForm() *NameForm { return r.form }

// Name is the first short name, or the OID when there is none: what a
// message about this element calls it.
func (t *AttributeType) Name() string { return firstName(t.Names, t.OID) }

// Name is the first short name, or the OID when there is none.
func (c *ObjectClass) Name() string { return firstName(c.Names, c.OID) }

// Name is the first short name, or the OID when there is none.
func (r *MatchingRule) Name() string { return firstName(r.Names, r.OID) }

func firstName(names []string, oid string) string {
	if len(names) > 0 {
		return names[0]
	}
	return oid
}

// Superior is the direct supertype, or nil.
func (t *AttributeType) Superior() *AttributeType { return t.sup }

// EqualityRule is the EQUALITY rule, inherited through SUP when the
// definition names none (RFC 4512 4.1.2), or nil when there is none at all.
// An attribute with no equality rule cannot be matched in a filter: RFC 4511
// 4.5.1.7 makes such an assertion Undefined.
func (t *AttributeType) EqualityRule() *MatchingRule { return t.equality }

// OrderingRule is the ORDERING rule, inherited through SUP, or nil.
func (t *AttributeType) OrderingRule() *MatchingRule { return t.ordering }

// SubstringRule is the SUBSTR rule, inherited through SUP, or nil.
func (t *AttributeType) SubstringRule() *MatchingRule { return t.sub }

// EffectiveSyntax is the syntax OID, inherited through SUP when the
// definition names none.
func (t *AttributeType) EffectiveSyntax() string { return t.syntax }

// IsA reports whether t is other or one of its subtypes, which is what a
// filter on other matches (RFC 4511 4.5.1.7.1: "the attribute type or
// subtype").
func (t *AttributeType) IsA(other *AttributeType) bool {
	for x := t; x != nil; x = x.sup {
		if x == other {
			return true
		}
	}
	return false
}

// Superiors are the direct superclasses.
func (c *ObjectClass) Superiors() []*ObjectClass { return c.sup }

// MustTypes are the attribute types the class requires, its own and its
// superclasses', without duplicates.
func (c *ObjectClass) MustTypes() []*AttributeType { return c.must }

// MayTypes are the attribute types the class allows and does not require,
// its own and its superclasses', without duplicates.
func (c *ObjectClass) MayTypes() []*AttributeType { return c.may }

// IsA reports whether c is other or inherits from it.
func (c *ObjectClass) IsA(other *ObjectClass) bool {
	if c == other {
		return true
	}
	for _, s := range c.sup {
		if s.IsA(other) {
			return true
		}
	}
	return false
}
