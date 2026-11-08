// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
)

// The string form of a DN (RFC 4514), read far enough to compare two of
// them by distinguishedNameMatch (RFC 4517 4.2.15): RDN by RDN, AVA by AVA,
// each value by its type's EQUALITY rule.
//
// It accepts what RFC 4514 2 produces, and also the spaces around ',' '+'
// and '=' that RFC 2253 allowed, which RFC 4514 3 lets a parser accept
// ("implementations MAY recognize other DN string representations").

type ava struct {
	typ   string
	value []byte
}

var errDN = errors.New("schema: not a DN (RFC 4514)")

// parseDN reads a DN into its RDNs, most specific first. The empty string is
// the DN with no RDNs.
func parseDN(s string) ([][]ava, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	// Every AVA of every RDN lives in one array, and an RDN is a slice of it
	// with its capacity cut, so that appending to one cannot reach the next.
	// A separator that is escaped or inside a hex string only over-counts.
	rdns := strings.Count(s, ",") + strings.Count(s, ";")
	all := make([]ava, 0, rdns+1+strings.Count(s, "+"))
	out := make([][]ava, 0, rdns+1)
	from := 0 // where the RDN being read starts in all
	arena := make([]byte, 0, len(s))
	i := 0
	for {
		// attributeType
		for i < len(s) && s[i] == ' ' {
			i++
		}
		start := i
		for i < len(s) && s[i] != '=' {
			i++
		}
		if i == len(s) {
			return nil, errDN
		}
		typ := strings.TrimRight(s[start:i], " ")
		if !isOID(typ) {
			return nil, errDN
		}
		i++ // '='
		for i < len(s) && s[i] == ' ' {
			i++
		}
		var val []byte
		var err error
		if i < len(s) && s[i] == '#' {
			val, i, err = hexValue(s, i+1)
		} else {
			val, i, err = stringValue(s, i, &arena)
		}
		if err != nil {
			return nil, err
		}
		all = append(all, ava{typ: typ, value: val})
		if i == len(s) {
			out = append(out, all[from:len(all):len(all)])
			return out, nil
		}
		switch s[i] {
		case '+':
		case ',', ';':
			out = append(out, all[from:len(all):len(all)])
			from = len(all)
		default:
			return nil, errDN
		}
		i++
	}
}

// hexValue is hexstring = SHARP 1*hexpair: the BER encoding of the value.
// What is compared is the contents of a primitive element, which is what a
// string value is.
func hexValue(s string, i int) ([]byte, int, error) {
	start := i
	for i < len(s) && strings.IndexByte("0123456789abcdefABCDEF", s[i]) >= 0 {
		i++
	}
	ber, err := hex.DecodeString(s[start:i])
	if err != nil || len(ber) < 2 {
		return nil, i, errDN
	}
	for i < len(s) && s[i] == ' ' {
		i++
	}
	// tag, then length: short form, or long form of up to four octets.
	n, l := int(ber[1]), 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 4 || len(ber) < 2+k {
			return nil, i, errDN
		}
		n = 0
		for _, b := range ber[2 : 2+k] {
			n = n<<8 | int(b)
		}
		l = 2 + k
	}
	if ber[0]&0x20 != 0 || len(ber)-l != n {
		return nil, i, errDN
	}
	return ber[l:], i, nil
}

// stringValue reads a value up to the next unescaped ',', ';' or '+',
// honouring RFC 4514 2.4's escapes, and trims the unescaped spaces at its
// end.
//
// The value is written at the end of *arena, one buffer for every value of a
// DN, and is a slice of it with its capacity cut. A value with nothing in it
// is nil, as it always was.
func stringValue(s string, i int, arena *[]byte) ([]byte, int, error) {
	out := *arena
	from := len(out)
	keep := from // length of out up to the last character that was not a bare space
	// value is what has been read, and leaves the arena after it.
	value := func() []byte {
		*arena = out
		if len(out) == from {
			return nil
		}
		return out[from:keep:keep]
	}
	for i < len(s) {
		c := s[i]
		switch {
		case c == ',' || c == ';' || c == '+':
			return value(), i, nil
		case c == '\\':
			if i+1 >= len(s) {
				return nil, i, errDN
			}
			if b, err := hex.DecodeString(safeSlice(s, i+1, i+3)); err == nil && len(b) == 1 {
				out = append(out, b[0])
				i += 3
			} else if strings.IndexByte(`\ #=+,;<>"`, s[i+1]) >= 0 {
				out = append(out, s[i+1])
				i += 2
			} else {
				return nil, i, errDN
			}
			keep = len(out)
		case c == '"' || c == '<' || c == '>' || c == 0:
			return nil, i, errDN
		default:
			out = append(out, c)
			i++
			if c != ' ' {
				keep = len(out)
			}
		}
	}
	return value(), i, nil
}

func safeSlice(s string, from, to int) string {
	if to > len(s) {
		return ""
	}
	return s[from:to]
}

// matchDN is distinguishedNameMatch (RFC 4517 4.2.15).
func (s *Schema) matchDN(a, b []byte) Truth {
	ra, err1 := parseDN(string(a))
	rb, err2 := parseDN(string(b))
	if err1 != nil || err2 != nil {
		return Undefined
	}
	if len(ra) != len(rb) {
		return False
	}
	result := True
	for i := range ra {
		result = and(result, s.matchRDN(ra[i], rb[i]))
		if result == False {
			return False
		}
	}
	return result
}

// equalityKey is a key such that two values of t are equal by t's EQUALITY
// rule (Equal is True) exactly when their keys are equal, so that a list can
// be checked for duplicates in one pass instead of comparing every pair and
// preparing both values each time. ok=false means no such key exists for this
// value (no rule, a rule that is not "prepare, then compare", an unparsable
// value, an unknown AVA type): the caller falls back to Equal.
func (s *Schema) equalityKey(t *AttributeType, v []byte) (string, bool) {
	if t.equality == nil {
		return "", false
	}
	impl, ok := rules[t.equality.OID]
	if !ok || impl.kind != equality {
		return "", false
	}
	if impl.custom != nil {
		if t.equality.OID == "2.5.13.1" {
			return s.dnKey(v)
		}
		return "", false
	}
	if impl.compare != nil {
		return "", false
	}
	return impl.key(s, v, whole)
}

// dnKey is the key of distinguishedNameMatch: for each RDN its AVAs in the
// order of their types, each as the type and the key of its value under that
// type's rule. It is only given for the DNs matchDN answers True or False for
// by comparing such keys.
func (s *Schema) dnKey(v []byte) (string, bool) {
	if k, ok := s.dnKeyPlain(v); ok {
		return k, true
	}
	return s.dnKeyParsed(v)
}

// plainStringRules are the equality rules of the string kinds whose key is
// prepare(value, fold, insignificantSpace, whole): the OID of the rule and
// whether it folds case (match.go ruleTable). TestPlainRulesAreTheTable keeps
// this in step with that table.
var plainStringRules = map[string]bool{
	"2.5.13.2":                   true,  // caseIgnoreMatch
	"2.5.13.5":                   false, // caseExactMatch
	"1.3.6.1.4.1.1466.109.114.1": false, // caseExactIA5Match
	"1.3.6.1.4.1.1466.109.114.2": true,  // caseIgnoreIA5Match
}

// dnKeyPlain is dnKeyParsed for the DNs that are nearly all of them: each RDN
// one AVA, `type=value` with a keystring type and a value of printable ASCII
// with no escape, no `+ ; # < > " =`, and no space at either end, the type
// naming a string rule of plainStringRules. It writes the same key straight
// from the bytes, with one allocation, instead of parsing. ok=false for
// anything else, and the caller takes the full parse; the key is never
// different from the full parse's (FuzzDNKeyPlain, with dnKeyParsed as the
// oracle).
func (s *Schema) dnKeyPlain(v []byte) (string, bool) {
	var buf [192]byte
	out := buf[:0]
	for i := 0; i < len(v); {
		start := i
		for i < len(v) && (isAlnumASCII(v[i]) || (v[i] == '-' && i > start)) {
			i++
		}
		if i == start || i == len(v) || v[i] != '=' || !isAlphaASCII(v[start]) {
			return "", false
		}
		typ := v[start:i]
		i++
		vstart := i
		for i < len(v) && v[i] != ',' {
			c := v[i]
			if c < 0x20 || c > 0x7e || c == '\\' || c == '"' || c == '+' || c == ';' || c == '#' || c == '<' || c == '>' || c == '=' {
				return "", false
			}
			i++
		}
		val := v[vstart:i]
		if len(val) == 0 || val[0] == ' ' || val[len(val)-1] == ' ' {
			return "", false
		}
		if i < len(v) { // a ',': another RDN must follow
			i++
			if i == len(v) {
				return "", false
			}
		}
		tx := s.AttributeType(string(typ))
		if tx == nil || tx.equality == nil || !isOID(string(typ)) {
			return "", false
		}
		fold, ok := plainStringRules[tx.equality.OID]
		if !ok {
			return "", false
		}
		// the key of the value: " " + the value with each run of spaces as
		// two + " " (prepare, whole, insignificantSpace), length first.
		keyLen := 2
		for j := 0; j < len(val); {
			if val[j] == ' ' {
				for j < len(val) && val[j] == ' ' {
					j++
				}
				keyLen += 2
				continue
			}
			keyLen++
			j++
		}
		out = strconv.AppendInt(out, int64(len(tx.OID)), 10)
		out = append(out, ':')
		out = append(out, tx.OID...)
		out = strconv.AppendInt(out, int64(keyLen), 10)
		out = append(out, ':', ' ')
		for j := 0; j < len(val); {
			if val[j] == ' ' {
				for j < len(val) && val[j] == ' ' {
					j++
				}
				out = append(out, ' ', ' ')
				continue
			}
			c := val[j]
			if fold && c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			out = append(out, c)
			j++
		}
		out = append(out, ' ', ',')
	}
	return string(out), true
}

func isAlphaASCII(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }
func isAlnumASCII(c byte) bool { return isAlphaASCII(c) || '0' <= c && c <= '9' }

func (s *Schema) dnKeyParsed(v []byte) (string, bool) {
	rdns, err := parseDN(string(v))
	if err != nil {
		return "", false
	}
	var b strings.Builder
	type part struct{ oid, key string }
	for _, rdn := range rdns {
		parts := make([]part, 0, len(rdn))
		for _, x := range rdn {
			tx := s.AttributeType(x.typ)
			if tx == nil || tx.equality == nil {
				return "", false
			}
			impl, ok := rules[tx.equality.OID]
			if !ok || impl.kind != equality || impl.custom != nil || impl.compare != nil {
				return "", false
			}
			k, ok := impl.key(s, x.value, whole)
			if !ok {
				return "", false
			}
			parts = append(parts, part{tx.OID, k})
		}
		slices.SortFunc(parts, func(a, b part) int { return strings.Compare(a.oid, b.oid) })
		for i, p := range parts {
			if i > 0 && parts[i-1].oid == p.oid {
				return "", false // matchRDN answers Undefined
			}
			// length-prefixed, so that no two lists of AVAs share a key
			b.WriteString(strconv.Itoa(len(p.oid)))
			b.WriteByte(':')
			b.WriteString(p.oid)
			b.WriteString(strconv.Itoa(len(p.key)))
			b.WriteByte(':')
			b.WriteString(p.key)
		}
		b.WriteByte(',')
	}
	return b.String(), true
}

// matchRDN compares two RDNs: the same number of AVAs, and each AVA of one
// the same as the AVA of the other with the same attribute type. Their order
// does not matter.
func (s *Schema) matchRDN(a, b []ava) Truth {
	if len(a) != len(b) {
		return False
	}
	result := True
	for _, x := range a {
		tx := s.AttributeType(x.typ)
		if tx == nil {
			// An AVA whose type is unknown cannot be compared.
			result = and(result, Undefined)
			continue
		}
		var match *ava
		for j := range b {
			if s.AttributeType(b[j].typ) == tx {
				if match != nil {
					return Undefined // "a particular attribute type may appear in at most one AVA"
				}
				match = &b[j]
			}
		}
		if match == nil {
			return False
		}
		result = and(result, s.Equal(tx, x.value, match.value))
	}
	return result
}

// An AVA is one attribute value assertion of a DN: a type as written and
// the value, unescaped.
type AVA struct {
	Type  string
	Value []byte
}

// DNValues is every AVA of a DN, most specific RDN first, or nil for a DN
// that does not parse. It is what an extensible match with dnAttributes
// compares against (RFC 4511 4.5.1.7.7).
func DNValues(dn string) []AVA {
	rdns, err := parseDN(dn)
	if err != nil {
		return nil
	}
	var out []AVA
	for _, rdn := range rdns {
		for _, a := range rdn {
			out = append(out, AVA{Type: a.typ, Value: a.value})
		}
	}
	return out
}

// MatchDN is distinguishedNameMatch (RFC 4517 4.2.15) on two DNs in their
// string form: each value compared by its type's EQUALITY rule, so
// "CN=Subschema" and "cn=subschema" are the same entry.
func (s *Schema) MatchDN(a, b string) Truth { return s.matchDN([]byte(a), []byte(b)) }
