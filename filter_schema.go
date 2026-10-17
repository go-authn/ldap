// SPDX-License-Identifier: BSD-3-Clause

package ldap

import "github.com/go-authn/ldap/schema"

// Evaluate answers a filter about an entry with a schema's matching rules,
// in RFC 4511 4.5.1.7's three-valued logic: True, False or Undefined. An
// entry is returned by a search only for True.
//
// With a nil schema it is Matches, exactly: True or False, every value
// compared as Matches compares it. A server that has no schema behaves as it
// always did.
//
// With a schema:
//
//   - equality, approximate, ordering and substrings use the attribute
//     type's EQUALITY, ORDERING and SUBSTR rules, inherited through SUP, so
//     (uidNumber=01000) is Undefined (not an Integer) and (cn=Alice  Smith)
//     matches "alice smith";
//   - a filter on a type also matches its subtypes: (name=x) asks about cn,
//     sn, ou and the rest (RFC 4511 4.5.1.7.1);
//   - an unknown type, an unrecognized option, a type with no rule for the
//     kind of match asked, a rule not implemented and an assertion value
//     that is not of the rule's syntax are all Undefined, never an error
//     (RFC 4511 4.5.1.7: "Servers MUST NOT return errors if attribute
//     descriptions or matching rule ids are not recognized");
//   - an extensible match may name any implemented rule that applies to
//     the type, may omit the type, and may set dnAttributes.
func Evaluate(f Filter, e *Entry, s *schema.Schema) schema.Truth {
	if s == nil {
		if f.Matches(e) {
			return schema.True
		}
		return schema.False
	}
	switch f := f.(type) {
	case *And:
		r := schema.True
		for _, sub := range f.Filters {
			r = schema.And(r, Evaluate(sub, e, s))
		}
		return r
	case *Or:
		r := schema.False
		for _, sub := range f.Filters {
			r = schema.Or(r, Evaluate(sub, e, s))
		}
		return r
	case *Not:
		return schema.Not(Evaluate(f.Filter, e, s))
	case *Equality:
		return eachValue(e, s, f.Attribute, func(t *schema.AttributeType, v []byte) schema.Truth {
			return s.Equal(t, v, []byte(f.Value))
		})
	case *Approx:
		// RFC 4511 4.5.1.7.6: "If approximate matching is not supported
		// for the attribute, this filter item should be treated as an
		// equalityMatch."
		return Evaluate(&Equality{Attribute: f.Attribute, Value: f.Value}, e, s)
	case *GreaterOrEqual:
		// RFC 4511 4.5.1.7.3: TRUE "when the ORDERING rule returns FALSE".
		return eachValue(e, s, f.Attribute, func(t *schema.AttributeType, v []byte) schema.Truth {
			return schema.Not(s.Less(t, v, []byte(f.Value)))
		})
	case *LessOrEqual:
		// RFC 4511 4.5.1.7.4: "when either the ORDERING or EQUALITY rule
		// returns TRUE". Without an ORDERING rule it is Undefined.
		return eachValue(e, s, f.Attribute, func(t *schema.AttributeType, v []byte) schema.Truth {
			less := s.Less(t, v, []byte(f.Value))
			if less == schema.Undefined {
				return less
			}
			return schema.Or(less, s.Equal(t, v, []byte(f.Value)))
		})
	case *Substrings:
		a := schema.SubstringAssertion{Any: make([][]byte, len(f.Any))}
		if f.Initial != "" {
			a.Initial = []byte(f.Initial)
		}
		if f.Final != "" {
			a.Final = []byte(f.Final)
		}
		for i, x := range f.Any {
			a.Any[i] = []byte(x)
		}
		return eachValue(e, s, f.Attribute, func(t *schema.AttributeType, v []byte) schema.Truth {
			return s.Substrings(t, v, a)
		})
	case *Present:
		// RFC 4511 4.5.1.7.5: TRUE when an attribute of the type or a
		// subtype is present, FALSE when none is, Undefined otherwise --
		// and "(shoeSize=*)" for an unknown shoeSize is Undefined.
		want, ok := describe(s, f.Attribute)
		if !ok {
			return schema.Undefined
		}
		for _, a := range e.Attributes {
			if d, ok := describe(s, a.Name); ok && d.covers(want) && len(a.Values) > 0 {
				return schema.True
			}
		}
		return schema.False
	default:
		// Filter is sealed, and this is the last of its ten types.
		return evaluateExtensible(f.(*ExtensibleMatch), e, s)
	}
}

// desc is an attribute description read against a schema.
type desc struct {
	t       *schema.AttributeType
	options []string
}

// covers reports whether an attribute with this description answers a
// filter on want: its type is want's or a subtype of it, and it has every
// option want names (RFC 4512 2.5.2.1: cn;lang-de is a subtype of cn).
func (d desc) covers(want desc) bool {
	if !d.t.IsA(want.t) {
		return false
	}
	for _, o := range want.options {
		found := false
		for _, mine := range d.options {
			found = found || mine == o
		}
		if !found {
			return false
		}
	}
	return true
}

// describe reads "type;opt;opt" as schema.Describe does.
func describe(s *schema.Schema, d string) (desc, bool) {
	t, opts, ok := s.Describe(d)
	return desc{t: t, options: opts}, ok
}

// eachValue applies a rule to every value of every attribute the filter's
// description covers: TRUE if any value is, else Undefined if any value is,
// else FALSE.
func eachValue(e *Entry, s *schema.Schema, attr string, rule func(*schema.AttributeType, []byte) schema.Truth) schema.Truth {
	want, ok := describe(s, attr)
	if !ok {
		return schema.Undefined
	}
	r := schema.False
	for _, a := range e.Attributes {
		d, ok := describe(s, a.Name)
		if !ok || !d.covers(want) {
			continue
		}
		for _, v := range a.Values {
			// The rule is the FILTER type's: (name=x) compares cn by name's
			// EQUALITY, which RFC 4512 4.1.2 makes cn's too unless cn
			// says otherwise.
			r = schema.Or(r, rule(want.t, v))
		}
	}
	return r
}

// evaluateExtensible is RFC 4511 4.5.1.7.7.
func evaluateExtensible(f *ExtensibleMatch, e *Entry, s *schema.Schema) schema.Truth {
	if f.MatchingRule == "" {
		// "If the matchingRule field is absent, the type field MUST be
		// present, and an equality match is performed for that type."
		eq := Evaluate(&Equality{Attribute: f.Attribute, Value: f.Value}, e, s)
		if !f.DNAttributes {
			return eq
		}
		want, ok := describe(s, f.Attribute)
		if !ok {
			return schema.Undefined
		}
		return schema.Or(eq, eachAVA(e, s, func(t *schema.AttributeType, v []byte) schema.Truth {
			if !t.IsA(want.t) {
				return schema.False
			}
			return s.Equal(want.t, v, []byte(f.Value))
		}))
	}
	r := s.MatchingRule(f.MatchingRule)
	if r == nil || !schema.Implemented(r) {
		// "Undefined if the matchingRule is not recognized"
		return schema.Undefined
	}
	apply := func(t *schema.AttributeType, v []byte) schema.Truth {
		if !s.Applies(r, t) {
			// "the matchingRule is unsuitable for use with the specified
			// type"
			return schema.Undefined
		}
		return s.Rule(r, v, []byte(f.Value))
	}
	var result schema.Truth
	if f.Attribute != "" {
		// "compared against the specified attribute type and its subtypes"
		want, ok := describe(s, f.Attribute)
		if !ok {
			return schema.Undefined
		}
		result = schema.False
		for _, a := range e.Attributes {
			if d, ok := describe(s, a.Name); ok && d.covers(want) {
				for _, v := range a.Values {
					result = schema.Or(result, apply(d.t, v))
				}
			}
		}
		if f.DNAttributes {
			result = schema.Or(result, eachAVA(e, s, func(t *schema.AttributeType, v []byte) schema.Truth {
				if !t.IsA(want.t) {
					return schema.False
				}
				return apply(t, v)
			}))
		}
		return result
	}
	// "compared against all attributes in an entry that support that
	// matchingRule"
	result = schema.False
	for _, a := range e.Attributes {
		if d, ok := describe(s, a.Name); ok && s.Applies(r, d.t) {
			for _, v := range a.Values {
				result = schema.Or(result, s.Rule(r, v, []byte(f.Value)))
			}
		}
	}
	if f.DNAttributes {
		result = schema.Or(result, eachAVA(e, s, func(t *schema.AttributeType, v []byte) schema.Truth {
			if !s.Applies(r, t) {
				return schema.False
			}
			return s.Rule(r, v, []byte(f.Value))
		}))
	}
	return result
}

// eachAVA applies a rule to every AVA of the entry's DN whose type the
// schema knows, for dnAttributes.
func eachAVA(e *Entry, s *schema.Schema, rule func(*schema.AttributeType, []byte) schema.Truth) schema.Truth {
	r := schema.False
	for _, a := range schema.DNValues(e.DN) {
		if t := s.AttributeType(a.Type); t != nil {
			r = schema.Or(r, rule(t, a.Value))
		}
	}
	return r
}

// Matches reports whether an entry answers this search: Evaluate with the
// server's schema, or Filter.Matches when the server has none.
//
// ⛔ A handler should call this rather than req.Filter.Matches. With a
// schema, the server also re-checks every entry a handler sends and drops
// the ones that are not True -- but it cannot bring back an entry the handler
// left out, and Filter.Matches compares as strings: "10000" >= "9999" is
// false to it.
func (r *SearchRequest) Matches(e *Entry) bool {
	return Evaluate(r.Filter, e, r.schema) == schema.True
}

// Validate checks the entry against a schema (schema.Schema.Validate): its
// classes, its MUSTs and MAYs, SINGLE-VALUE, syntaxes and RDN. It returns
// nil or a *schema.ValidationError naming every problem.
func (e *Entry) Validate(s *schema.Schema) error {
	se := schema.Entry{DN: e.DN, Attributes: make([]schema.Attribute, len(e.Attributes))}
	for i, a := range e.Attributes {
		se.Attributes[i] = schema.Attribute{Description: a.Name, Values: a.Values}
	}
	return s.Validate(se)
}
