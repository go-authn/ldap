// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"encoding/hex"
	"errors"
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
