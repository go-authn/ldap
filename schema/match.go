// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"bytes"
	"math/big"
	"strings"
)

// A Truth is what a filter item, or a matching rule, evaluates to: RFC 4511
// 4.5.1.7's three values. Undefined is not False: (!(x=1)) of an Undefined
// (x=1) is Undefined too, and an entry is returned only for True.
type Truth int8

const (
	False Truth = iota
	True
	Undefined
)

func (t Truth) String() string {
	switch t {
	case True:
		return "TRUE"
	case Undefined:
		return "Undefined"
	}
	return "FALSE"
}

// truth is a bool as a Truth.
func truth(b bool) Truth {
	if b {
		return True
	}
	return False
}

// and, or and not are X.511's three-valued logic (RFC 4511 4.5.1.7).
func and(a, b Truth) Truth {
	switch {
	case a == False || b == False:
		return False
	case a == Undefined || b == Undefined:
		return Undefined
	}
	return True
}

func or(a, b Truth) Truth {
	switch {
	case a == True || b == True:
		return True
	case a == Undefined || b == Undefined:
		return Undefined
	}
	return False
}

// And, Or and Not combine Truths as RFC 4511 4.5.1.7 says filters do.
func And(a, b Truth) Truth { return and(a, b) }
func Or(a, b Truth) Truth  { return or(a, b) }
func Not(a Truth) Truth {
	switch a {
	case True:
		return False
	case False:
		return True
	}
	return Undefined
}

// A rule is an implementation of a matching rule. A rule implements at most
// one of the three, because RFC 4517 says of each rule which kind it is.
type rule struct {
	// key is a value or an assertion prepared for comparison, or ok=false
	// when it is not a valid value of the rule's syntax (Undefined).
	key func(s *Schema, v []byte, p part) (key string, ok bool)
	// compare orders two keys; nil means keys are compared as strings,
	// which for UTF-8 is code point order (RFC 4517 4.2.5).
	compare func(a, b string) int
	// custom replaces key and compare for the rules that are not "prepare,
	// then compare".
	custom func(s *Schema, v, a []byte) Truth
	kind   ruleKind
}

type ruleKind uint8

const (
	equality ruleKind = iota
	ordering
	substrings
)

// stringKey is the key of the RFC 4518 string rules.
func stringKey(fold bool, mode spaceMode, ia5 bool) func(*Schema, []byte, part) (string, bool) {
	return func(_ *Schema, v []byte, p part) (string, bool) {
		if ia5 {
			for _, c := range v {
				if c >= 0x80 {
					return "", false
				}
			}
		}
		return prepare(string(v), fold, mode, p)
	}
}

var (
	exactKey     = stringKey(false, insignificantSpace, false)
	ignoreKey    = stringKey(true, insignificantSpace, false)
	exactIA5Key  = stringKey(false, insignificantSpace, true)
	ignoreIA5Key = stringKey(true, insignificantSpace, true)
	numericKey   = stringKey(false, numericSpace, false)
	// telephoneNumberMatch folds case (RFC 4517 4.2.29).
	telephoneKey = stringKey(true, telephoneSpace, false)
)

func integerKey(_ *Schema, v []byte, _ part) (string, bool) {
	if _, ok := parseInteger(string(v)); !ok {
		return "", false
	}
	return string(v), true
}

func compareIntegers(a, b string) int {
	x, _ := parseInteger(a)
	y, _ := parseInteger(b)
	return x.Cmp(y)
}

// parseInteger is RFC 4517 3.3.16: Integer = ( HYPHEN LDIGIT *DIGIT ) /
// number. No sign on zero, no leading zero, no space, and no bound.
func parseInteger(s string) (*big.Int, bool) {
	digits := strings.TrimPrefix(s, "-")
	if !isNumber(digits) || (digits == "0" && len(s) != 1) {
		return nil, false
	}
	n, _ := new(big.Int).SetString(s, 10)
	return n, true
}

func octetKey(_ *Schema, v []byte, _ part) (string, bool) { return string(v), true }

func booleanKey(_ *Schema, v []byte, _ part) (string, bool) {
	// Boolean = "TRUE" / "FALSE", and ABNF quoted strings are
	// case-insensitive (RFC 4234 2.3).
	switch u := strings.ToUpper(string(v)); u {
	case "TRUE", "FALSE":
		return u, true
	}
	return "", false
}

func timeKey(_ *Schema, v []byte, _ part) (string, bool) {
	t, ok := parseGeneralizedTime(string(v))
	if !ok {
		return "", false
	}
	// A fixed-width UTC form orders as the instants do.
	return t.UTC().Format("20060102150405.000000000"), true
}

func oidKey(s *Schema, v []byte, _ part) (string, bool) { return s.resolveOID(string(v)) }

// firstComponent is the first component of a value of one of the schema
// description syntaxes: "( 2.5.4.3 NAME ..." is 2.5.4.3.
func firstComponent(v []byte) string {
	t := strings.TrimLeft(strings.TrimPrefix(string(v), "("), " ")
	if i := strings.IndexAny(t, " )"); i >= 0 {
		t = t[:i]
	}
	return t
}

func oidFirstKey(s *Schema, v []byte, p part) (string, bool) {
	if bytes.HasPrefix(v, []byte("(")) {
		v = []byte(firstComponent(v))
	}
	return oidKey(s, v, p)
}

func integerFirstKey(s *Schema, v []byte, p part) (string, bool) {
	if bytes.HasPrefix(v, []byte("(")) {
		v = []byte(firstComponent(v))
	}
	return integerKey(s, v, p)
}

// bitStringKey is RFC 4517 3.3.2: BitString = SQUOTE *binary-digit SQUOTE "B".
func bitStringKey(_ *Schema, v []byte, _ part) (string, bool) {
	s := string(v)
	if len(s) < 3 || s[0] != '\'' || s[len(s)-2] != '\'' || (s[len(s)-1] != 'B' && s[len(s)-1] != 'b') {
		return "", false
	}
	bits := s[1 : len(s)-2]
	if strings.Trim(bits, "01") != "" {
		return "", false
	}
	return bits, true
}

// postalLines is RFC 4517 3.3.28: lines separated by '$', with "\24" for a
// '$' and "\5C" for a '\' inside a line.
func postalLines(v string) ([]string, bool) {
	var lines []string
	var cur []byte
	for i := 0; i < len(v); i++ {
		switch c := v[i]; c {
		case '$':
			if len(cur) == 0 {
				return nil, false // line = 1*line-char
			}
			lines, cur = append(lines, string(cur)), nil
		case '\\':
			b, ok := unescape(v, i, "24", "5C")
			if !ok {
				return nil, false
			}
			cur = append(cur, b)
			i += 2
		default:
			cur = append(cur, c)
		}
	}
	if len(cur) == 0 {
		return nil, false
	}
	return append(lines, string(cur)), true
}

// unescape reads the escape at s[i], a backslash and two hex digits, which
// must be one of those allowed.
func unescape(s string, i int, allowed ...string) (byte, bool) {
	hexes := strings.ToUpper(safeSlice(s, i+1, i+3))
	for _, a := range allowed {
		if hexes == a {
			return map[string]byte{"24": '$', "5C": '\\', "2A": '*'}[a], true
		}
	}
	return 0, false
}

// listKey is caseIgnoreListMatch's: each line prepared as caseIgnoreMatch
// prepares a value, joined by NUL, which preparation removes from every
// string (RFC 4518 2.2), so a substring can never span two lines.
func listKey(s *Schema, v []byte, p part) (string, bool) {
	if p != whole {
		return ignoreKey(s, v, p)
	}
	lines, ok := postalLines(string(v))
	if !ok {
		return "", false
	}
	for i, l := range lines {
		if lines[i], ok = ignoreKey(s, []byte(l), whole); !ok {
			return "", false
		}
	}
	return strings.Join(lines, "\x00"), true
}

// words is wordMatch's and keywordMatch's reading of a value: the prepared
// value split at its spaces. Both rules say the definition of a word is
// "implementation specific", and this is it.
func wordsMatch(s *Schema, v, a []byte) Truth {
	pv, ok1 := ignoreKey(s, v, whole)
	pa, ok2 := ignoreKey(s, a, whole)
	if !ok1 || !ok2 {
		return Undefined
	}
	word := strings.TrimSpace(pa)
	for _, w := range strings.Fields(pv) {
		if w == word {
			return True
		}
	}
	return False
}

// uniqueMember is RFC 4517 4.2.31 on NameAndOptionalUID (3.3.21):
// distinguishedName [ SHARP BitString ].
func uniqueMemberMatch(s *Schema, v, a []byte) Truth {
	split := func(x []byte) (dn, uid []byte) {
		if i := bytes.LastIndex(x, []byte("#'")); i >= 0 {
			if _, ok := bitStringKey(s, x[i+1:], whole); ok {
				return x[:i], x[i+1:]
			}
		}
		return x, nil
	}
	dv, uv := split(v)
	da, ua := split(a)
	m := s.matchDN(dv, da)
	if (uv == nil) != (ua == nil) {
		return and(m, False)
	}
	if uv != nil {
		bv, _ := bitStringKey(s, uv, whole)
		ba, _ := bitStringKey(s, ua, whole)
		m = and(m, truth(bv == ba))
	}
	return m
}

// rules are the matching rules implemented here, by OID. A rule a schema
// defines and this does not implement makes an assertion Undefined.
var rules map[string]rule

// The table is filled in init because distinguishedNameMatch applies the
// rules of the types in a DN, so the table refers to itself.
func init() { rules = ruleTable() }

func ruleTable() map[string]rule {
	return map[string]rule{
		"2.5.13.0":                   {key: oidKey},                                                           // objectIdentifierMatch
		"2.5.13.1":                   {custom: func(s *Schema, v, a []byte) Truth { return s.matchDN(v, a) }}, // distinguishedNameMatch
		"2.5.13.2":                   {key: ignoreKey},                                                        // caseIgnoreMatch
		"2.5.13.3":                   {key: ignoreKey, kind: ordering},                                        // caseIgnoreOrderingMatch
		"2.5.13.4":                   {key: ignoreKey, kind: substrings},                                      // caseIgnoreSubstringsMatch
		"2.5.13.5":                   {key: exactKey},                                                         // caseExactMatch
		"2.5.13.6":                   {key: exactKey, kind: ordering},                                         // caseExactOrderingMatch
		"2.5.13.7":                   {key: exactKey, kind: substrings},                                       // caseExactSubstringsMatch
		"2.5.13.8":                   {key: numericKey},                                                       // numericStringMatch
		"2.5.13.9":                   {key: numericKey, kind: ordering},                                       // numericStringOrderingMatch
		"2.5.13.10":                  {key: numericKey, kind: substrings},                                     // numericStringSubstringsMatch
		"2.5.13.11":                  {key: listKey},                                                          // caseIgnoreListMatch
		"2.5.13.12":                  {key: listKey, kind: substrings},                                        // caseIgnoreListSubstringsMatch
		"2.5.13.13":                  {key: booleanKey},                                                       // booleanMatch
		"2.5.13.14":                  {key: integerKey, compare: compareIntegers},                             // integerMatch
		"2.5.13.15":                  {key: integerKey, compare: compareIntegers, kind: ordering},             // integerOrderingMatch
		"2.5.13.16":                  {key: bitStringKey},                                                     // bitStringMatch
		"2.5.13.17":                  {key: octetKey},                                                         // octetStringMatch
		"2.5.13.18":                  {key: octetKey, kind: ordering},                                         // octetStringOrderingMatch
		"2.5.13.20":                  {key: telephoneKey},                                                     // telephoneNumberMatch
		"2.5.13.21":                  {key: telephoneKey, kind: substrings},                                   // telephoneNumberSubstringsMatch
		"2.5.13.23":                  {custom: uniqueMemberMatch},                                             // uniqueMemberMatch
		"2.5.13.27":                  {key: timeKey},                                                          // generalizedTimeMatch
		"2.5.13.28":                  {key: timeKey, kind: ordering},                                          // generalizedTimeOrderingMatch
		"2.5.13.29":                  {key: integerFirstKey, compare: compareIntegers},                        // integerFirstComponentMatch
		"2.5.13.30":                  {key: oidFirstKey},                                                      // objectIdentifierFirstComponentMatch
		"2.5.13.32":                  {custom: wordsMatch},                                                    // wordMatch
		"2.5.13.33":                  {custom: wordsMatch},                                                    // keywordMatch
		"1.3.6.1.4.1.1466.109.114.1": {key: exactIA5Key},                                                      // caseExactIA5Match
		"1.3.6.1.4.1.1466.109.114.2": {key: ignoreIA5Key},                                                     // caseIgnoreIA5Match
		"1.3.6.1.4.1.1466.109.114.3": {key: ignoreIA5Key, kind: substrings},                                   // caseIgnoreIA5SubstringsMatch
		"1.3.6.1.4.1.4203.1.2.1":     {key: exactIA5Key, kind: substrings},                                    // caseExactIA5SubstringsMatch (OpenLDAP)
	}
}

// Implemented reports whether this package can evaluate a rule. A rule that
// is defined and not implemented -- directoryStringFirstComponentMatch, and
// RFC 4523's certificate rules -- makes every assertion that uses it
// Undefined, which is the answer RFC 4511 4.5.1.7 gives for "the type of
// filtering requested is not implemented".
func Implemented(r *MatchingRule) bool {
	if r == nil {
		return false
	}
	_, ok := rules[r.OID]
	return ok
}

// evaluate applies a rule's equality or ordering to a value and an
// assertion: for an ordering rule, TRUE when the value is "less than" the
// assertion (RFC 4517 4.2.12).
func (s *Schema) evaluate(r *MatchingRule, kind ruleKind, v, a []byte) Truth {
	if r == nil {
		return Undefined
	}
	impl, ok := rules[r.OID]
	if !ok || impl.kind != kind {
		return Undefined
	}
	if impl.custom != nil {
		return impl.custom(s, v, a)
	}
	kv, ok1 := impl.key(s, v, whole)
	ka, ok2 := impl.key(s, a, whole)
	if !ok1 || !ok2 {
		return Undefined
	}
	c := strings.Compare(kv, ka)
	if impl.compare != nil {
		c = impl.compare(kv, ka)
	}
	if kind == ordering {
		return truth(c < 0)
	}
	return truth(c == 0)
}

// Equal applies t's EQUALITY rule: Undefined when t has none (RFC 4512
// 2.5.1: "attribute value assertions ... cannot be performed"), when the
// rule is not implemented here, or when either value is not one of the
// rule's syntax.
func (s *Schema) Equal(t *AttributeType, value, assertion []byte) Truth {
	return s.evaluate(t.equality, equality, value, assertion)
}

// Less applies t's ORDERING rule: TRUE when value sorts before assertion.
func (s *Schema) Less(t *AttributeType, value, assertion []byte) Truth {
	return s.evaluate(t.ordering, ordering, value, assertion)
}

// A SubstringAssertion is the three parts of a substrings filter (RFC 4511
// 4.5.1.7.2) or of a Substring Assertion value (RFC 4517 3.3.30). Initial
// and Final are absent when nil.
type SubstringAssertion struct {
	Initial []byte
	Any     [][]byte
	Final   []byte
}

// Substrings applies t's SUBSTR rule.
func (s *Schema) Substrings(t *AttributeType, value []byte, a SubstringAssertion) Truth {
	return s.substrings(t.sub, value, a)
}

func (s *Schema) substrings(r *MatchingRule, value []byte, a SubstringAssertion) Truth {
	if r == nil {
		return Undefined
	}
	impl, ok := rules[r.OID]
	if !ok || impl.kind != substrings {
		return Undefined
	}
	v, ok := impl.key(s, value, whole)
	if !ok {
		return Undefined
	}
	prep := func(x []byte, p part) (string, bool) { return impl.key(s, x, p) }
	rest := v
	if a.Initial != nil {
		ini, ok := prep(a.Initial, initialPart)
		if !ok {
			return Undefined
		}
		if !strings.HasPrefix(rest, ini) {
			return False
		}
		rest = rest[len(ini):]
	}
	if a.Final != nil {
		fin, ok := prep(a.Final, finalPart)
		if !ok {
			return Undefined
		}
		if !strings.HasSuffix(rest, fin) {
			return False
		}
		rest = rest[:len(rest)-len(fin)]
	}
	// Each any matches after the one before it, in what is left, so that
	// "the prepared substrings ... match disjoint portions ... in the order
	// of the substrings" (RFC 4517 4.2.13).
	for _, x := range a.Any {
		piece, ok := prep(x, anyPart)
		if !ok {
			return Undefined
		}
		i := strings.Index(rest, piece)
		if i < 0 {
			return False
		}
		rest = rest[i+len(piece):]
	}
	return True
}

// parseSubstringAssertion is RFC 4517 3.3.30, the assertion value of a
// substrings rule used in an extensible match: initial*any*final, with "\2A"
// for a '*' and "\5C" for a '\'.
func parseSubstringAssertion(v []byte) (SubstringAssertion, bool) {
	parts := bytes.Split(v, []byte("*"))
	if len(parts) < 2 {
		return SubstringAssertion{}, false
	}
	var a SubstringAssertion
	for i, p := range parts {
		var u []byte
		for j := 0; j < len(p); j++ {
			if p[j] != '\\' {
				u = append(u, p[j])
				continue
			}
			b, ok := unescape(string(p), j, "2A", "5C")
			if !ok {
				return SubstringAssertion{}, false
			}
			u = append(u, b)
			j += 2
		}
		switch {
		case len(p) == 0 && (i == 0 || i == len(parts)-1):
		case len(p) == 0:
			return SubstringAssertion{}, false // "**": a zero-length substring is not permitted
		case i == 0:
			a.Initial = u
		case i == len(parts)-1:
			a.Final = u
		default:
			a.Any = append(a.Any, u)
		}
	}
	return a, true
}

// Rule applies a matching rule as an extensible match does (RFC 4511
// 4.5.1.7.7): an equality rule as equality, an ordering rule as "less
// than", a substrings rule to an assertion in the Substring Assertion
// syntax.
func (s *Schema) Rule(r *MatchingRule, value, assertion []byte) Truth {
	impl, ok := rules[r.OID]
	if !ok {
		return Undefined
	}
	if impl.kind == substrings {
		a, ok := parseSubstringAssertion(assertion)
		if !ok {
			return Undefined
		}
		return s.substrings(r, value, a)
	}
	return s.evaluate(r, impl.kind, value, assertion)
}
