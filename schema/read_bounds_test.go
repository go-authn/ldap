// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"bytes"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// A name longer than a .schema line may be reads from LDIF, which has no
// such bound; Format folds it with backslashes, and it reads back the same
// (FuzzRead found it: testdata/fuzz/FuzzRead/4c7aab3bc2a52768). The DESC is
// placed so that a fold would fall just after the backslash of \5C, which
// a piece may not end with.
func TestFormatFoldsALineLongerThanSlapdAllows(t *testing.T) {
	name := strings.Repeat("v", 3*MaxLineLength)
	// "\tDESC '" then the d's put the backslash at byte 1998 of the line,
	// the last of a 1999-byte piece.
	desc := strings.Repeat("d", MaxLineLength-len("\tDESC '")-2) + `\5Cx`
	ldif := "dn: cn=x\nattributeTypes: ( 1.1 NAME '" + name + "' DESC '" + desc + "' SUP c )\n"
	d, err := Read(File{Name: "long.ldif", Data: []byte(ldif)})
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.Format(false)
	if err != nil {
		t.Fatal(err)
	}
	for i, l := range strings.Split(string(out), "\n") {
		if len(l) > MaxLineLength {
			t.Fatalf("line %d is %d bytes", i+1, len(l))
		}
		if strings.HasSuffix(l, `\\`) {
			t.Fatalf("line %d ends with two backslashes, which do not join: %q", i+1, l[len(l)-8:])
		}
	}
	back, err := Read(File{Name: "formatted", Data: out})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(unplaced(d), unplaced(back)) {
		t.Fatal("read back differently")
	}
	if got := back.AttributeTypes[0].Desc; got != strings.Repeat("d", len(desc)-4)+`\x` {
		t.Fatalf("DESC read back as %q", got[len(got)-8:])
	}
}

// A definition folded on many continuation lines is joined in linear time.
// Joining by repeated string concatenation copied the definition so far at
// every line: a 4 MiB .schema file of 2-byte continuation lines took three
// minutes to read, an LDIF one longer, and FuzzRead's workers stalled at 0
// execs/s on such inputs.
//
// The bound is on bytes allocated, not on time, so that it holds on a
// loaded machine and under emulation: joining 1 MiB of 2-byte lines by
// concatenation allocated 139.6 GB (measured on v0.10.0); in linear time it
// is about 95 MB, mostly the split lines and the line positions kept for
// error messages. The bound, 256 MiB, is 500 times below the former.
func TestManyContinuationLinesJoinInLinearTime(t *testing.T) {
	const size = 1 << 20
	for _, c := range []struct {
		name, head, line string
	}{
		{"schema", "attributetype ( 1.2 NAME 'a' SUP b\n", " \n"},
		{"schema backslash", "attributetype ( 1.2 NAME 'a' SUP b \\\n", " \\\n"},
		{"ldif", "dn: cn=x\nattributeTypes: ( 1.2 NAME 'a' SUP b\n", "  \n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var b bytes.Buffer
			b.WriteString(c.head)
			for b.Len() < size {
				b.WriteString(c.line)
			}
			b.WriteString(" )\n")
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			d, err := Read(File{Name: "folded", Data: b.Bytes()})
			runtime.ReadMemStats(&after)
			if err != nil || len(d.AttributeTypes) != 1 {
				t.Fatalf("not read as one attribute type: %v", err)
			}
			if n := after.TotalAlloc - before.TotalAlloc; n > 256*size {
				t.Errorf("%d bytes read with %d bytes allocated: more than linear", b.Len(), n)
			}
		})
	}
}
