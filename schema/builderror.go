// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"fmt"
	"strconv"
)

// A Position is where a definition starts in the text it was read from.
//
// Read sets it on every syntax, matching rule, attribute type and object
// class: the file's name, the line its record starts on -- the line of the
// .schema keyword (attributetype, objectclass ...) or of the LDIF
// "attributeTypes:" line, before any continuation line is joined to it
// (slapd.conf(5); RFC 2849 note 2) -- and column 1, where that record
// starts. Package schema/hclschema sets it to the block's own position. A
// definition built in code, or parsed by the Parse functions, has none.
type Position struct {
	File string
	// Line is 1-based; 0 is no position.
	Line int
	// Column is the 1-based byte column, or 0 when it is not known.
	Column int
}

// IsValid reports whether p is a position: whether it has a line.
func (p Position) IsValid() bool { return p.Line > 0 }

// String is "file:line:column", what an editor jumps to, or "file:line"
// without a column, or "" for no position.
func (p Position) String() string {
	switch {
	case !p.IsValid():
		return ""
	case p.Column > 0:
		return fmt.Sprintf("%s:%d:%d", p.File, p.Line, p.Column)
	}
	return fmt.Sprintf("%s:%d", p.File, p.Line)
}

// An Element is a kind of definition a Schema holds.
type Element uint8

const (
	ElementSyntax Element = iota + 1
	ElementMatchingRule
	ElementAttributeType
	ElementObjectClass
	ElementDITContentRule
	ElementNameForm
	ElementDITStructureRule
)

// String is the element as messages call it: "syntax", "matching rule",
// "attribute type", "object class", "DIT content rule", "name form" or
// "DIT structure rule".
func (e Element) String() string {
	switch e {
	case ElementSyntax:
		return "syntax"
	case ElementMatchingRule:
		return "matching rule"
	case ElementAttributeType:
		return "attribute type"
	case ElementObjectClass:
		return "object class"
	case ElementDITContentRule:
		return "DIT content rule"
	case ElementNameForm:
		return "name form"
	case ElementDITStructureRule:
		return "DIT structure rule"
	}
	return fmt.Sprintf("Element(%d)", uint8(e))
}

// A BuildErrorKind is why a definition did not build. These are every check
// Build and BuildFrom make, and no other.
type BuildErrorKind uint8

const (
	// UnknownReference: a term names something not defined. Field is the
	// term (SUP, EQUALITY, ORDERING, SUBSTR, SYNTAX, MUST, MAY, AUX, NOT, OC
	// or FORM) and Ref the name or OID it gives -- or, for the SUP of a DIT
	// structure rule, the rule ID. Field is "" for a DIT content rule whose
	// OID is no object class, and Ref is that OID.
	UnknownReference BuildErrorKind = iota + 1
	// DuplicateOID: the OID is defined twice for one element -- for a DIT
	// content rule, two rules for one class (X.501 13.8.1: "at most one DIT
	// content rule for each structural object class"); for a DIT structure
	// rule, the rule ID twice (X.501 13.7.5: "unique within the scope of the
	// subschema"). The BuildError is about the second definition; Ref,
	// RefOID and RefPos are the first.
	DuplicateOID
	// DuplicateName: one NAME is given to two definitions of one element
	// (RFC 4512 1.4: an ambiguous descriptor). The BuildError is about the
	// second; Field is NAME, Ref the name as the second spells it, and
	// RefOID and RefPos are the first definition's.
	DuplicateName
	// SuperiorCycle: an attribute type is its own supertype, or an object
	// class its own superclass, through SUP. Field is SUP.
	SuperiorCycle
	// KindViolation: an object class derives from a class of a kind it may
	// not (RFC 4512 2.4.1-2.4.3), and Field is SUP; or a rule names a class
	// of the wrong kind: a DIT content rule for a class that is not
	// structural (Field "", RFC 4512 4.1.6) or with a class in AUX that is
	// not auxiliary (Field AUX), a name form for a class that is not
	// structural (Field OC, X.501 13.7.2: "Only structural object classes
	// are used in name forms"). Ref, RefOID and RefPos are the class.
	KindViolation
	// UsageMismatch: an attribute type's usage is not its supertype's (RFC
	// 4512 2.5.1). Field is SUP; Ref, RefOID and RefPos are the supertype.
	UsageMismatch
	// CollectiveMismatch: an attribute type is not COLLECTIVE and its
	// supertype is (RFC 4512 2.5.1). Field is SUP; Ref, RefOID and RefPos
	// are the supertype.
	CollectiveMismatch
	// UsageViolation: COLLECTIVE without usage userApplications, or
	// NO-USER-MODIFICATION with it (RFC 4512 4.1.2). Field is COLLECTIVE or
	// NO-USER-MODIFICATION.
	UsageViolation
	// DuplicateMember: a rule lists one attribute type twice: in one of the
	// MUST, MAY and NOT of a DIT content rule or in two of them (slapd
	// refuses it, servers/slapd/cr.c, SLAP_SCHERR_CR_BAD_AT), or in the MUST
	// and MAY of a name form (RFC 4512 4.1.7.2: "All attribute types in the
	// required ("MUST") and allowed ("MAY") lists shall be different") -- or
	// one class twice in AUX, or one rule ID twice in SUP. Field is the
	// second list, Ref the name as it is written there; RefOID and RefPos
	// are the type's or class's.
	DuplicateMember
	// PrecludedRequired: a DIT content rule's NOT names a type that its MUST,
	// its structural class or one of its AUX classes requires (RFC 4512
	// 4.1.6: "The list of precluded attributes cannot include any attribute
	// listed as mandatory in the rule, the structural object class, or any
	// of the allowed auxiliary object classes"). Field is NOT; Ref, RefOID
	// and RefPos are the type.
	PrecludedRequired
)

func (k BuildErrorKind) String() string {
	switch k {
	case UnknownReference:
		return "unknown reference"
	case DuplicateOID:
		return "duplicate OID"
	case DuplicateName:
		return "duplicate name"
	case SuperiorCycle:
		return "superior cycle"
	case KindViolation:
		return "kind violation"
	case UsageMismatch:
		return "usage mismatch"
	case CollectiveMismatch:
		return "collective mismatch"
	case UsageViolation:
		return "usage violation"
	case DuplicateMember:
		return "duplicate member"
	case PrecludedRequired:
		return "precluded required"
	}
	return fmt.Sprintf("BuildErrorKind(%d)", uint8(k))
}

// A BuildError is a definition Build or BuildFrom refused, why, and where
// it was read from. Build stops at the first definition it refuses, so it
// returns one BuildError; errors.As finds it.
type BuildError struct {
	Kind    BuildErrorKind
	Element Element
	// OID and Name are the refused definition's: Name is its first NAME, or
	// "" when it has none (a syntax never has one).
	OID  string
	Name string
	// Pos is where the refused definition starts, when it was read from a
	// file (see Position).
	Pos Position
	// Field is the term of the definition the error is about, as RFC 4512
	// 4.1 spells it, or "" when it is the definition as a whole.
	Field string
	// Ref is what the error refers to: the undefined name or OID, or the
	// other definition (see each Kind). RefOID and RefPos are that other
	// definition's OID and position, when there is one.
	Ref    string
	RefOID string
	RefPos Position

	msg string
}

// Error is the message Build has always returned, after the position of the
// refused definition as a FileError puts it ("file:line:column: schema:
// ..."), and, for a duplicate, with the position of the first definition.
func (e *BuildError) Error() string {
	msg := "schema: " + e.msg
	if (e.Kind == DuplicateOID || e.Kind == DuplicateName) && e.RefPos.IsValid() && e.RefPos != e.Pos {
		msg += " (first defined at " + e.RefPos.String() + ")"
	}
	if e.Pos.IsValid() {
		return e.Pos.String() + ": " + msg
	}
	return msg
}

// definition is what a BuildError says about an element.
type definition interface {
	identity() (Element, string, []string, Position)
}

func (x *Syntax) identity() (Element, string, []string, Position) {
	return ElementSyntax, x.OID, nil, x.Pos
}

func (x *MatchingRule) identity() (Element, string, []string, Position) {
	return ElementMatchingRule, x.OID, x.Names, x.Pos
}

func (x *AttributeType) identity() (Element, string, []string, Position) {
	return ElementAttributeType, x.OID, x.Names, x.Pos
}

func (x *ObjectClass) identity() (Element, string, []string, Position) {
	return ElementObjectClass, x.OID, x.Names, x.Pos
}

func (x *DITContentRule) identity() (Element, string, []string, Position) {
	return ElementDITContentRule, x.OID, x.Names, x.Pos
}

func (x *NameForm) identity() (Element, string, []string, Position) {
	return ElementNameForm, x.OID, x.Names, x.Pos
}

// The OID of a DIT structure rule, in a BuildError, is its rule ID.
func (x *DITStructureRule) identity() (Element, string, []string, Position) {
	return ElementDITStructureRule, strconv.Itoa(x.ID), x.Names, x.Pos
}

// buildError is the error about x, with the message as Build has always
// worded it, without the "schema: " prefix.
func buildError(kind BuildErrorKind, x definition, field, ref string, other definition, format string, args ...any) *BuildError {
	el, oid, names, pos := x.identity()
	e := &BuildError{Kind: kind, Element: el, OID: oid, Pos: pos, Field: field, Ref: ref, msg: fmt.Sprintf(format, args...)}
	if len(names) > 0 {
		e.Name = names[0]
	}
	if other != nil {
		_, e.RefOID, _, e.RefPos = other.identity()
	}
	return e
}
