// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"fmt"
	"strings"
)

// A Filter is the question a search asked (RFC 4511 4.5.1.7, and its string
// form in RFC 4515).
//
// ⛔ ONE representation, three renderings. The library this replaces had
// three separate implementations -- one that decoded a filter off the wire
// into a string, one that encoded a string onto the wire, and one that
// matched an entry against the wire form -- and they drifted apart. The
// result was that `(uid=svc-*-prod)` was decoded as `(uid=svc-*)`, encoded as
// an equality match on a literal '*', and matched on its first component
// alone. Three answers to one question, all different, and a directory
// answering a BROADER question than it was asked is disclosure.
//
// So a filter is parsed or decoded ONCE into this tree, and String, Encode
// and Matches all read the same tree. They cannot disagree about what a
// filter means, because there is only one thing that means it.
type Filter interface {
	// Matches reports whether an entry satisfies this filter.
	Matches(e *Entry) bool
	// String is the RFC 4515 form, parenthesised.
	String() string

	// filter keeps the set closed: a Filter from outside this package could
	// not be encoded, and a search that cannot be encoded cannot be answered.
	filter()
}

// And is `(&(a)(b))`. An EMPTY And is TRUE -- RFC 4526: the "absolute true"
// filter `(&)` matches every entry.
type And struct{ Filters []Filter }

// Or is `(|(a)(b))`. An EMPTY Or is FALSE -- RFC 4526's "absolute false"
// filter `(|)` matches nothing. The asymmetry is the specification's and is
// the identity element of each operation; getting it backwards turns a filter
// that should match nothing into one that matches the directory.
type Or struct{ Filters []Filter }

// Not is `(!(a))`.
type Not struct{ Filter Filter }

// Equality is `(type=value)`.
type Equality struct{ Attribute, Value string }

// GreaterOrEqual is `(type>=value)`.
type GreaterOrEqual struct{ Attribute, Value string }

// LessOrEqual is `(type<=value)`.
type LessOrEqual struct{ Attribute, Value string }

// Approx is `(type~=value)`. Nothing here does phonetic matching, so it is
// answered as an equality -- which RFC 4511 4.5.1.7.6 permits: "the
// semantics of the approxMatch are implementation defined", and equality is
// an implementation of "approximately".
type Approx struct{ Attribute, Value string }

// Present is `(type=*)`.
type Present struct{ Attribute string }

// Substrings is `(type=ini*any*any*fin)`.
//
// ⛔ Initial and Final are at most one each and Any is any number of them, in
// order, which is what RFC 4511 4.5.1.7.2 says and what the three-way drift
// above got wrong. They are separate fields rather than a list of components
// so that "at most once" is a thing the type says rather than a thing a
// check has to remember.
type Substrings struct {
	Attribute string
	Initial   string // empty means absent
	Any       []string
	Final     string // empty means absent
}

// ExtensibleMatch is `(type:dn:=value)` and its relatives (RFC 4511
// 4.5.1.7.7). Nothing here implements a matching rule, so one that NAMES a
// rule is refused rather than guessed at -- see Matches.
type ExtensibleMatch struct {
	Attribute    string
	MatchingRule string
	Value        string
	DNAttributes bool
}

func (*And) filter()             {}
func (*Or) filter()              {}
func (*Not) filter()             {}
func (*Equality) filter()        {}
func (*GreaterOrEqual) filter()  {}
func (*LessOrEqual) filter()     {}
func (*Approx) filter()          {}
func (*Present) filter()         {}
func (*Substrings) filter()      {}
func (*ExtensibleMatch) filter() {}

// --- Matching -------------------------------------------------------------
//
// ⛔ Every comparison here is case-insensitive on the VALUE as well as the
// attribute name. That is not universally right -- an attribute's matching
// rule decides, and RFC 4517 has caseExactMatch too -- but this server has no
// schema, so it has no way to know which rule applies. Case-insensitive is
// what caseIgnoreMatch does, which is the default for the attribute types a
// directory of people is made of (cn, uid, mail), and it is the SAFER
// default here only for reading: it never hides an entry a case-exact
// comparison would have found. A deployment that needs exact matching needs a
// schema, which is a larger thing than this.

func (f *And) Matches(e *Entry) bool {
	for _, sub := range f.Filters {
		if !sub.Matches(e) {
			return false
		}
	}
	// An empty And is true: RFC 4526.
	return true
}

func (f *Or) Matches(e *Entry) bool {
	for _, sub := range f.Filters {
		if sub.Matches(e) {
			return true
		}
	}
	// An empty Or is false: RFC 4526.
	return false
}

func (f *Not) Matches(e *Entry) bool { return !f.Filter.Matches(e) }

func (f *Equality) Matches(e *Entry) bool {
	return e.anyValue(f.Attribute, func(v string) bool {
		return strings.EqualFold(v, f.Value)
	})
}

func (f *Approx) Matches(e *Entry) bool {
	return (&Equality{Attribute: f.Attribute, Value: f.Value}).Matches(e)
}

func (f *GreaterOrEqual) Matches(e *Entry) bool {
	return e.anyValue(f.Attribute, func(v string) bool {
		return strings.Compare(strings.ToLower(v), strings.ToLower(f.Value)) >= 0
	})
}

func (f *LessOrEqual) Matches(e *Entry) bool {
	return e.anyValue(f.Attribute, func(v string) bool {
		return strings.Compare(strings.ToLower(v), strings.ToLower(f.Value)) <= 0
	})
}

// Present is about the ATTRIBUTE, not its values: `(mail=*)` asks whether
// this entry has a mail at all.
func (f *Present) Matches(e *Entry) bool {
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, f.Attribute) && len(a.Values) > 0 {
			return true
		}
	}
	return false
}

// Matches walks the components in order and WITHOUT OVERLAP, which is the
// whole of the defect this type exists to prevent.
//
// `(uid=svc-*-prod)` is initial "svc-", final "-prod": the value must start
// with one, end with the other, and they must not overlap -- "svc-prod" is 8
// characters and the two components need 9, so it does not match, and a
// check that tested them independently would say it does.
func (f *Substrings) Matches(e *Entry) bool {
	return e.anyValue(f.Attribute, func(v string) bool {
		rest := strings.ToLower(v)
		if f.Initial != "" {
			ini := strings.ToLower(f.Initial)
			if !strings.HasPrefix(rest, ini) {
				return false
			}
			rest = rest[len(ini):]
		}
		if f.Final != "" {
			fin := strings.ToLower(f.Final)
			if !strings.HasSuffix(rest, fin) {
				return false
			}
			rest = rest[:len(rest)-len(fin)]
		}
		// Each `any` must appear after the one before it, in what is LEFT --
		// so the same characters are never spent twice.
		for _, a := range f.Any {
			i := strings.Index(rest, strings.ToLower(a))
			if i < 0 {
				return false
			}
			rest = rest[i+len(a):]
		}
		return true
	})
}

// Matches an extensible match, or refuses to.
//
// ⛔ A filter naming a matching rule this server does not implement matches
// NOTHING, and says so through Unsupported rather than falling back to
// equality. RFC 4511 4.5.1.7.7 is explicit: a server that does not recognise
// the rule returns inappropriateMatching. Falling back would answer a
// different question -- `(memberOf:1.2.840.113556.1.4.1941:=cn=admins,...)`
// asks for a TRANSITIVE group search, and answering it as an equality would
// quietly say "not a member" about people who are.
func (f *ExtensibleMatch) Matches(e *Entry) bool {
	if f.MatchingRule != "" || f.DNAttributes {
		return false
	}
	if f.Attribute == "" {
		return false
	}
	return (&Equality{Attribute: f.Attribute, Value: f.Value}).Matches(e)
}

// Unsupported reports whether this filter asks for something this server
// cannot do, so a search can answer inappropriateMatching instead of
// silently returning fewer entries than the client asked about.
func Unsupported(f Filter) error {
	switch t := f.(type) {
	case *And:
		for _, sub := range t.Filters {
			if err := Unsupported(sub); err != nil {
				return err
			}
		}
	case *Or:
		for _, sub := range t.Filters {
			if err := Unsupported(sub); err != nil {
				return err
			}
		}
	case *Not:
		return Unsupported(t.Filter)
	case *ExtensibleMatch:
		if t.MatchingRule != "" {
			return fmt.Errorf("no matching rule %q here", t.MatchingRule)
		}
		if t.DNAttributes {
			return fmt.Errorf("the dnAttributes flag is not implemented here")
		}
		if t.Attribute == "" {
			return fmt.Errorf("an extensible match with no attribute needs a schema to resolve")
		}
	}
	return nil
}
