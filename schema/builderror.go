// SPDX-License-Identifier: BSD-3-Clause

package schema

import "fmt"

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
)

// String is the element as messages call it: "syntax", "matching rule",
// "attribute type" or "object class".
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
	}
	return fmt.Sprintf("Element(%d)", uint8(e))
}

// A BuildErrorKind is why a definition did not build. These are every check
// Build and BuildFrom make, and no other.
type BuildErrorKind uint8

const (
	// UnknownReference: a term names something not defined. Field is the
	// term (SUP, EQUALITY, ORDERING, SUBSTR, SYNTAX, MUST or MAY) and Ref
	// the name or OID it gives.
	UnknownReference BuildErrorKind = iota + 1
	// DuplicateOID: the OID is defined twice for one element. The
	// BuildError is about the second definition; Ref, RefOID and RefPos are
	// the first.
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
	// not (RFC 4512 2.4.1-2.4.3). Field is SUP; Ref, RefOID and RefPos are
	// the superclass.
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
