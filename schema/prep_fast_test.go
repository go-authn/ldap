// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// prepareReference is prepare as it was at v0.11.0, byte for byte, before the
// printable-ASCII fast path: the oracle the fast path must equal.
func prepareReference(s string, fold bool, mode spaceMode, p part) (string, bool) {
	if !utf8.ValidString(s) {
		return "", false
	}
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
	if fold {
		out = folder.String(out)
	}
	out = norm.NFKC.String(out)
	if fold {
		out = norm.NFKC.String(folder.String(out))
	}
	for _, r := range out {
		if prohibited(r) {
			return "", false
		}
	}
	switch mode {
	case numericSpace:
		return removeSpaces(out, nil), true
	case telephoneSpace:
		return removeSpaces(out, isHyphen), true
	}
	return spaces(out, p), true
}

// stringValueReference is stringValue as it was at v0.11.0.
func stringValueReference(s string, i int) ([]byte, int, error) {
	var out []byte
	keep := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ',' || c == ';' || c == '+':
			return out[:keep], i, nil
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
	return out[:keep], i, nil
}

// parseDNReference is parseDN as it was at v0.11.0 (with stringValueReference).
func parseDNReference(s string) ([][]ava, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out [][]ava
	var rdn []ava
	i := 0
	for {
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
		i++
		for i < len(s) && s[i] == ' ' {
			i++
		}
		var val []byte
		var err error
		if i < len(s) && s[i] == '#' {
			val, i, err = hexValue(s, i+1)
		} else {
			val, i, err = stringValueReference(s, i)
		}
		if err != nil {
			return nil, err
		}
		rdn = append(rdn, ava{typ: typ, value: val})
		if i == len(s) {
			out = append(out, rdn)
			return out, nil
		}
		switch s[i] {
		case '+':
		case ',', ';':
			out = append(out, rdn)
			rdn = nil
		default:
			return nil, errDN
		}
		i++
	}
}

func checkParseDN(t *testing.T, s string) {
	t.Helper()
	got, gerr := parseDN(s)
	want, werr := parseDNReference(s)
	if !reflect.DeepEqual(got, want) || gerr != werr {
		t.Fatalf("parseDN(%q) = (%#v, %v), reference (%#v, %v)", s, got, gerr, want, werr)
	}
	// An RDN must not reach into the next one through append.
	for _, rdn := range got {
		if cap(rdn) != len(rdn) {
			t.Fatalf("parseDN(%q): an RDN has capacity %d for %d AVAs", s, cap(rdn), len(rdn))
		}
	}
}

func TestParseDNMatchesReference(t *testing.T) {
	for _, s := range []string{
		"", "  ", "cn=a", "cn=a,dc=b", "cn=a+sn=b,dc=c", "cn=a+sn=b+uid=c,dc=d+dc=e,o=f", "CN = a , DC = b",
		`cn=a\,b,dc=c`, `cn=a\+b+sn=c`, "cn=#04024869,dc=a", "cn=#0402", "cn=,dc=a", "cn=a;dc=b",
		"cn", "=a", "cn=a,", ",", "+", "cn=a+", "1.2.3=a", "cn=a\"", "cn=a  ,dc=b", `cn=\ a`, `cn=a\`,
	} {
		checkParseDN(t, s)
	}
}

func FuzzParseDNMatchesReference(f *testing.F) {
	for _, s := range []string{"", "cn=a,dc=b", "cn=a+sn=b,dc=c", `cn=a\,b`, "cn=#04024869", "cn=a;dc=b+uid=c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { checkParseDN(t, s) })
}

type prepCase struct {
	fold bool
	mode spaceMode
	p    part
}

func allPrepCases() []prepCase {
	var cs []prepCase
	for _, fold := range []bool{false, true} {
		for _, mode := range []spaceMode{insignificantSpace, numericSpace, telephoneSpace} {
			for _, p := range []part{whole, initialPart, anyPart, finalPart} {
				cs = append(cs, prepCase{fold, mode, p})
			}
		}
	}
	return cs
}

func checkPrepare(t *testing.T, s string, c prepCase) {
	t.Helper()
	got, gok := prepare(s, c.fold, c.mode, c.p)
	want, wok := prepareReference(s, c.fold, c.mode, c.p)
	if got != want || gok != wok {
		t.Fatalf("prepare(%q, fold=%v, mode=%d, part=%d) = (%q, %v), reference (%q, %v)",
			s, c.fold, c.mode, c.p, got, gok, want, wok)
	}
}

// TestPrepareMatchesReferenceExhaustive: every string of length 0, 1 and 2 over
// bytes 0x00-0x7F, every single byte 0x80-0xFF, and every string of length 3
// over an alphabet that holds each class (the ends of the printable range, the
// controls that map to nothing and to a space, DEL, the hyphen, both cases,
// the byte that begins a combining mark), for every fold, mode and part.
func TestPrepareMatchesReferenceExhaustive(t *testing.T) {
	var inputs []string
	inputs = append(inputs, "")
	for a := 0; a < 0x80; a++ {
		inputs = append(inputs, string([]byte{byte(a)}))
		for b := 0; b < 0x80; b++ {
			inputs = append(inputs, string([]byte{byte(a), byte(b)}))
		}
	}
	for a := 0x80; a < 0x100; a++ {
		inputs = append(inputs, string([]byte{byte(a)}))
	}
	alphabet := []string{"\x00", "\x08", "\t", "\n", "\r", "\x0e", "\x1f", " ", "!", "-", "0", "@", "A", "M", "Z", "[", "`", "a", "z", "~", "\x7f", "́", "é", "K"}
	for _, a := range alphabet {
		for _, b := range alphabet {
			for _, c := range alphabet {
				inputs = append(inputs, a+b+c)
			}
		}
	}
	for _, c := range allPrepCases() {
		for _, s := range inputs {
			checkPrepare(t, s, c)
		}
	}
}

// TestPrepareASCIIFastPathIsTaken pins which strings the fast path handles, so
// that the exhaustive test above is known to exercise both paths.
func TestPrepareASCIIFastPathIsTaken(t *testing.T) {
	for s, want := range map[string]bool{
		"": true, "a b": true, "~": true, " ": true,
		"\x1f": false, "\x7f": false, "\t": false, "\x80": false, "é": false,
	} {
		if _, got := printableASCII(s, true); got != want {
			t.Errorf("printableASCII(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestPrepareASCIIDoesNotAllocateWhenNothingChanges(t *testing.T) {
	for _, c := range []struct {
		s    string
		fold bool
		mode spaceMode
		p    part
	}{
		{"alice", false, numericSpace, whole},
		{"alice", true, telephoneSpace, whole},
		{"alice", true, insignificantSpace, anyPart},
		{"Alice", false, insignificantSpace, anyPart},
	} {
		n := testing.AllocsPerRun(100, func() { prepare(c.s, c.fold, c.mode, c.p) })
		if n != 0 {
			t.Errorf("prepare(%q, fold=%v, mode=%d, part=%d): %v allocations, want 0", c.s, c.fold, c.mode, c.p, n)
		}
	}
	// One allocation for a lowered copy, one for the two spaces round it.
	if n := testing.AllocsPerRun(100, func() { prepare("Alice", true, numericSpace, whole) }); n != 1 {
		t.Errorf("a lowered copy took %v allocations, want 1", n)
	}
	if n := testing.AllocsPerRun(100, func() { prepare("alice", true, insignificantSpace, whole) }); n != 1 {
		t.Errorf("padding took %v allocations, want 1", n)
	}
}

func FuzzPrepareMatchesReference(f *testing.F) {
	for _, s := range []string{"", "Alice", "  a   b  ", "a b c", "-1 2-3", "\t\n", "\x00A\x7f", "É", "Ⅰ", "\xff", "á b", "~ ~", "﷐", "ǅ", "ß"} {
		f.Add(s, true, uint8(0), uint8(0))
		f.Add(s, false, uint8(1), uint8(2))
		f.Add(s, true, uint8(2), uint8(3))
	}
	f.Fuzz(func(t *testing.T, s string, fold bool, mode, p uint8) {
		checkPrepare(t, s, prepCase{fold, spaceMode(mode % 3), part(p % 4)})
	})
}

func TestStringValueMatchesReference(t *testing.T) {
	for _, s := range []string{
		"", ",", "a", "a,b", "a ,b", `a\,b`, `a\2cb`, `a\ `, `a\`, `a\zz`, `\2`, "a  ", "  a", `"`, "a<", "a\x00",
		"alice+cn=b", `x\\y;z`, `\#a`, "é,", " ", "a\\20 ,", "abc",
	} {
		for i := 0; i <= len(s); i++ {
			got, gi, gerr := stringValueBoth(t, s, i)
			want, wi, werr := stringValueReference(s, i)
			if !reflect.DeepEqual(got, want) || gi != wi || gerr != werr {
				t.Errorf("stringValue(%q, %d) = (%#v, %d, %v), reference (%#v, %d, %v)", s, i, got, gi, gerr, want, wi, werr)
			}
		}
	}
}

// stringValueBoth reads a value into an arena with room, and into one with
// none and bytes already in it (so that it grows under the reader), and says
// so if they differ.
func stringValueBoth(t testing.TB, s string, i int) ([]byte, int, error) {
	t.Helper()
	roomy := make([]byte, 0, len(s)+8)
	a, ai, aerr := stringValue(s, i, &roomy)
	full := make([]byte, 2)
	full = full[:2:2]
	b, bi, berr := stringValue(s, i, &full)
	if !reflect.DeepEqual(a, b) || ai != bi || aerr != berr {
		t.Fatalf("stringValue(%q, %d): %#v/%d/%v in a roomy arena, %#v/%d/%v in a full one", s, i, a, ai, aerr, b, bi, berr)
	}
	return a, ai, aerr
}

func FuzzStringValueMatchesReference(f *testing.F) {
	for _, s := range []string{"", "a,b", `a\,b`, `a\2cb`, "a  ", `a\`, "x+y"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, gi, gerr := stringValueBoth(t, s, 0)
		want, wi, werr := stringValueReference(s, 0)
		if !reflect.DeepEqual(got, want) || gi != wi || gerr != werr {
			t.Fatalf("stringValue(%q) = (%#v, %d, %v), reference (%#v, %d, %v)", s, got, gi, gerr, want, wi, werr)
		}
	})
}

var sinkString string

func BenchmarkPrepareASCII(b *testing.B) {
	for _, in := range []string{"alice", "Alice Liddell", "  Mixed   Case  Value  ", "uid=alice,ou=people,dc=example,dc=org"} {
		b.Run(in, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkString, _ = prepare(in, true, insignificantSpace, whole)
			}
		})
	}
}

func BenchmarkPrepareNonASCII(b *testing.B) {
	for _, in := range []string{"Élodie", "Zoë Müller-Ünal", "田中 太郎", "Ⅷ ǅ ß"} {
		b.Run(in, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sinkString, _ = prepare(in, true, insignificantSpace, whole)
			}
		})
	}
}

func BenchmarkParseDN(b *testing.B) {
	const dn = "uid=alice,ou=people,dc=example,dc=org"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		parseDN(dn)
	}
}
