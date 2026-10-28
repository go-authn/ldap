// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// RFC 4518: how a string is prepared before a string matching rule compares
// it. Six steps -- Transcode, Map, Normalize, Prohibit, Check bidi,
// Insignificant Character Handling -- and "failure in any step causes the
// assertion to evaluate to Undefined".
//
// ⛔ Three verified errata are applied, and they change behaviour:
//
//   - 860: the variation selectors mapped to nothing are U+FE00-FE0F, not
//     "FF00-FE0F" as printed (which is an empty range, and would leave them).
//   - 1757 and 1758: in a SUBSTRING assertion, too, an inner run of spaces
//     becomes exactly two spaces. As printed, an "any" substring kept one,
//     and then (cn=*foo bar*) could never match the value "foo bar", which
//     is prepared to " foo  bar ".
//
// Two departures, both said here rather than discovered:
//
//   - The repertoire is the Unicode version Go ships, not Unicode 3.2. So a
//     code point assigned after 3.2 is accepted here where a strict reading
//     of 2.4 would prohibit it as unassigned.
//   - Case folding is full Unicode case folding (golang.org/x/text/cases),
//     applied before and after NFKC, which is what RFC 3454 table B.2 is
//     built to achieve. It is not that table byte for byte.

// spaceMode is the Insignificant Character Handling a rule asks for.
type spaceMode uint8

const (
	insignificantSpace spaceMode = iota // RFC 4518 2.6.1
	numericSpace                        // 2.6.2: every space goes
	telephoneSpace                      // 2.6.3: every space and hyphen goes
)

// part is which piece of an assertion a string is, because 2.6.1 prepares
// a substring differently from a whole value.
type part uint8

const (
	whole part = iota
	initialPart
	anyPart
	finalPart
)

var folder = cases.Fold()

// prepare runs the six steps. ok is false when a step fails.
//
// A string of printable ASCII (0x20-0x7E) takes a path that allocates at most
// once, and gives what the general path gives. Each step on such a string:
//
//   - 2.1 Transcode: ASCII is UTF-8, so the string is valid.
//   - 2.2 Map: the lists name U+0000-0008, 000E-001F and 007F as nothing and
//     U+0009-000D as SPACE, so nothing printable moves; U+0020 maps to itself.
//     Case folding (B.2 of RFC 3454; golang.org/x/text/cases foldFull) takes
//     'A'-'Z' to 'a'-'z' and moves no other ASCII byte.
//   - 2.3 Normalize: NFKC is the identity on ASCII, so the second fold has
//     nothing to do either (NFKC cannot produce a capital from ASCII).
//   - 2.4 Prohibit: every printable ASCII code point is in L, M, N, P, S or Z,
//     and none is private use or a non-character.
//
// TestPrepareMatchesReferenceExhaustive checks all of this against the general
// path, which stays as it was.
func prepare(s string, fold bool, mode spaceMode, p part) (string, bool) {
	if out, ok := printableASCII(s, fold); ok {
		switch mode {
		case numericSpace:
			return removeSpacesASCII(out, false), true
		case telephoneSpace:
			return removeSpacesASCII(out, true), true
		}
		return spacesASCII(out, p), true
	}
	return prepareGeneral(s, fold, mode, p)
}

// printableASCII is steps 1 to 4 for a string of bytes 0x20-0x7E: s itself,
// or a lowered copy when fold is set and s has a capital. ok is false for a
// string with any other byte, which the general path handles.
func printableASCII(s string, fold bool) (out string, ok bool) {
	upper := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7E {
			return "", false
		}
		upper = upper || (c >= 'A' && c <= 'Z')
	}
	if !fold || !upper {
		return s, true
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String(), true
}

// removeSpacesASCII is removeSpaces for a string with no combining mark: every
// SPACE goes, and with hyphen so does U+002D, the one ASCII hyphen isHyphen
// knows.
func removeSpacesASCII(s string, hyphen bool) string {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || (hyphen && s[i] == '-') {
			n++
		}
	}
	if n == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) - n)
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' && !(hyphen && s[i] == '-') {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// spacesASCII is spaces for a string with no combining mark, so that every
// SPACE counts. It is the same walk over the words, with one allocation.
func spacesASCII(s string, p part) string {
	words, wordBytes := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			wordBytes++
			if i == 0 || s[i-1] == ' ' {
				words++
			}
		}
	}
	if words == 0 {
		if p == whole {
			return "  "
		}
		return " "
	}
	leading := s[0] == ' '
	trailing := s[len(s)-1] == ' '
	pre := p == whole || p == initialPart || leading
	post := p == whole || p == finalPart || trailing
	if words == 1 && wordBytes == len(s) && !pre && !post {
		return s
	}
	n := wordBytes + 2*(words-1)
	if pre {
		n++
	}
	if post {
		n++
	}
	var b strings.Builder
	b.Grow(n)
	if pre {
		b.WriteByte(' ')
	}
	first := true
	for i := 0; i < len(s); {
		if s[i] == ' ' {
			i++
			continue
		}
		j := i
		for j < len(s) && s[j] != ' ' {
			j++
		}
		if !first {
			b.WriteString("  ")
		}
		first = false
		b.WriteString(s[i:j])
		i = j
	}
	if post {
		b.WriteByte(' ')
	}
	return b.String()
}

// prepareGeneral is the six steps for any string.
func prepareGeneral(s string, fold bool, mode spaceMode, p part) (string, bool) {
	// 1. Transcode. A value here is UTF-8 already, or it is not a string of
	// characters at all.
	if !utf8.ValidString(s) {
		return "", false
	}
	// 2. Map.
	var b strings.Builder
	for _, r := range s {
		switch {
		case mapsToNothing(r):
		case mapsToSpace(r):
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	// 3. Normalize. Folding is part of Map; it is done again after NFKC
	// because NFKC can produce a capital (U+2160 ROMAN NUMERAL ONE is "I").
	if fold {
		out = folder.String(out)
	}
	out = norm.NFKC.String(out)
	if fold {
		out = norm.NFKC.String(folder.String(out))
	}
	// 4. Prohibit.
	for _, r := range out {
		if prohibited(r) {
			return "", false
		}
	}
	// 5. Check bidi: "Bidirectional characters are ignored."
	// 6. Insignificant Character Handling.
	switch mode {
	case numericSpace:
		return removeSpaces(out, nil), true
	case telephoneSpace:
		return removeSpaces(out, isHyphen), true
	}
	return spaces(out, p), true
}

// mapsToNothing is RFC 4518 2.2's first and third lists, with erratum 860.
func mapsToNothing(r rune) bool {
	switch {
	case r == 0x00AD, r == 0x1806, r == 0x034F, r >= 0x180B && r <= 0x180D,
		r >= 0xFE00 && r <= 0xFE0F, r == 0xFFFC, r == 0x200B:
		return true
	case r <= 0x0008, r >= 0x000E && r <= 0x001F, r >= 0x007F && r <= 0x0084,
		r >= 0x0086 && r <= 0x009F, r == 0x06DD, r == 0x070F, r == 0x180E,
		r >= 0x200C && r <= 0x200F, r >= 0x202A && r <= 0x202E,
		r >= 0x2060 && r <= 0x2063, r >= 0x206A && r <= 0x206F, r == 0xFEFF,
		r >= 0xFFF9 && r <= 0xFFFB, r >= 0x1D173 && r <= 0x1D17A, r == 0xE0001,
		r >= 0xE0020 && r <= 0xE007F:
		return true
	}
	return false
}

// mapsToSpace is RFC 4518 2.2's second and fourth lists.
func mapsToSpace(r rune) bool {
	switch {
	case r >= 0x0009 && r <= 0x000D, r == 0x0085,
		r == 0x0020, r == 0x00A0, r == 0x1680, r >= 0x2000 && r <= 0x200A,
		r == 0x2028, r == 0x2029, r == 0x202F, r == 0x205F, r == 0x3000:
		return true
	}
	return false
}

// prohibited is RFC 4518 2.4.
//
// RFC 3454 table C.8 is not tested here because nothing in it survives the
// steps before: U+200E, 200F, 202A-202E and 206A-206F are mapped to nothing
// (2.2), and NFKC replaces U+0340 and U+0341 with U+0300 and U+0301.
func prohibited(r rune) bool {
	switch {
	case r == 0xFFFD: // REPLACEMENT CHARACTER
		return true
	case unicode.Is(unicode.Co, r): // C.3 private use
		return true
	case r >= 0xFDD0 && r <= 0xFDEF, r&0xFFFE == 0xFFFE: // C.4 non-characters
		return true
	}
	// A.1, unassigned: anything in no general category Go knows.
	return !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z, unicode.Cc, unicode.Cf)
}

func isHyphen(r rune) bool {
	switch r {
	case 0x002D, 0x058A, 0x2010, 0x2011, 0x2212, 0xFE63, 0xFF0D:
		return true
	}
	return false
}

// removeSpaces is 2.6.2 and 2.6.3: a SPACE (or a hyphen, when also is set)
// "followed by no combining marks" goes.
func removeSpaces(s string, also func(rune) bool) string {
	rs := []rune(s)
	var b strings.Builder
	for i, r := range rs {
		combined := i+1 < len(rs) && unicode.Is(unicode.M, rs[i+1])
		if !combined && (r == ' ' || (also != nil && also(r))) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// spaces is 2.6.1, Insignificant Space Handling, with errata 1757 and 1758.
func spaces(s string, p part) string {
	rs := []rune(s)
	isSpace := func(i int) bool {
		return rs[i] == ' ' && !(i+1 < len(rs) && unicode.Is(unicode.M, rs[i+1]))
	}
	var words []string
	var cur []rune
	leading, trailing := false, false
	for i := range rs {
		if isSpace(i) {
			if len(words) == 0 && len(cur) == 0 {
				leading = true
			}
			if len(cur) > 0 {
				words = append(words, string(cur))
				cur = cur[:0]
			}
			trailing = true
			continue
		}
		cur = append(cur, rs[i])
		trailing = false
	}
	if len(cur) > 0 {
		words = append(words, string(cur))
	}
	inner := strings.Join(words, "  ")
	if p == whole {
		if len(words) == 0 {
			return "  "
		}
		return " " + inner + " "
	}
	if len(words) == 0 {
		return " "
	}
	if p == initialPart || leading {
		inner = " " + inner
	}
	if p == finalPart || trailing {
		inner += " "
	}
	return inner
}
