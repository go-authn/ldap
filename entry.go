// SPDX-License-Identifier: BSD-3-Clause

package ldap

import "strings"

// An Attribute is a PartialAttribute: a type and its values (RFC 4511 4.1.7).
//
// ⛔ Values are [][]byte and not []string. An attribute value is an OCTET
// STRING, and several that a directory carries are not text at all --
// userCertificate;binary, jpegPhoto, objectSid, and the NT hash a Samba
// deployment reads. Typing them as string works until the first byte that is
// not valid UTF-8, which Go replaces with U+FFFD on conversion: the value
// that reaches the client is then not the value the directory holds, and
// nothing anywhere reports an error.
type Attribute struct {
	Name   string
	Values [][]byte

	// Operational marks an attribute the directory maintains rather than a
	// person (RFC 4512 4.1.3): createTimestamp, entryUUID, and everything on
	// the root DSE.
	//
	// ⛔ It changes what a search RETURNS, which is why it is on the model
	// and not a detail of one server. RFC 4512 5.1: operational attributes
	// "are not returned in search requests unless requested by name" -- so
	// `*` (or an empty selection) brings the user attributes only, and `+`
	// (RFC 3673) brings these. A server that cannot tell them apart either
	// hides an attribute a client asked for or hands out one it did not.
	Operational bool
}

// OperationalAttribute is StringAttribute for an attribute the directory
// maintains.
func OperationalAttribute(name string, values ...string) *Attribute {
	a := StringAttribute(name, values...)
	a.Operational = true
	return a
}

// StringAttribute is the common case spelled once, since most attributes ARE
// text and writing the conversion at every call site is how one of them ends
// up different.
func StringAttribute(name string, values ...string) *Attribute {
	a := &Attribute{Name: name, Values: make([][]byte, 0, len(values))}
	for _, v := range values {
		a.Values = append(a.Values, []byte(v))
	}
	return a
}

// An Entry is a SearchResultEntry: a DN and what is published about it.
type Entry struct {
	DN         string
	Attributes []*Attribute
}

// Attribute returns the named attribute, or nil. The name is matched without
// regard to case, as RFC 4512 2.5 requires of an attribute description.
func (e *Entry) Attribute(name string) *Attribute {
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, name) {
			return a
		}
	}
	return nil
}

// Values returns the named attribute's values as strings, for the callers
// that know their attribute is text.
func (e *Entry) Values(name string) []string {
	a := e.Attribute(name)
	if a == nil {
		return nil
	}
	out := make([]string, 0, len(a.Values))
	for _, v := range a.Values {
		out = append(out, string(v))
	}
	return out
}

// anyValue reports whether any value of the named attribute satisfies pred.
//
// ⛔ It walks EVERY attribute with that name, not the first. An entry may
// legitimately carry the same description twice -- options make `mail` and
// `mail;lang-fr` different descriptions that both answer to `mail` in a
// filter -- and stopping at the first is how a value that matches is missed.
func (e *Entry) anyValue(name string, pred func(string) bool) bool {
	for _, a := range e.Attributes {
		if !strings.EqualFold(a.Name, name) && !strings.EqualFold(baseName(a.Name), name) {
			continue
		}
		for _, v := range a.Values {
			if pred(string(v)) {
				return true
			}
		}
	}
	return false
}

// baseName strips attribute options: "mail;lang-fr" answers to "mail"
// (RFC 4512 2.5).
func baseName(description string) string {
	if i := strings.IndexByte(description, ';'); i >= 0 {
		return description[:i]
	}
	return description
}

// A Scope is a search scope (RFC 4511 4.5.1.2).
type Scope uint8

const (
	ScopeBaseObject   Scope = 0
	ScopeSingleLevel  Scope = 1
	ScopeWholeSubtree Scope = 2
)

func (s Scope) String() string {
	switch s {
	case ScopeBaseObject:
		return "base"
	case ScopeSingleLevel:
		return "one"
	case ScopeWholeSubtree:
		return "sub"
	}
	return "scope(?)"
}

// A DerefAliases says what to do with alias entries (RFC 4511 4.5.1.3).
//
// Nothing here creates aliases, so nothing here dereferences them. The value
// is carried and reported rather than ignored, because a client that asked
// for dereferencing and silently did not get it has been given an answer to
// a question it did not ask.
type DerefAliases uint8

const (
	NeverDerefAliases   DerefAliases = 0
	DerefInSearching    DerefAliases = 1
	DerefFindingBaseObj DerefAliases = 2
	DerefAlways         DerefAliases = 3
)
