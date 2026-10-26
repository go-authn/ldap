// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"bytes"
	"runtime"
	"testing"
)

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
