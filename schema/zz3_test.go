package schema

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// verbatim: every embedded definition, whitespace-folded, appears in the RFC
// text, whitespace-folded with page breaks removed.
func TestZZVerbatim(t *testing.T) {
	dir := "/private/tmp/claude-501/-Users-david-delavennat-Documents-VCS-GIT-localhost/a2daf7c8-740d-4341-81e2-fd9e403df79f/scratchpad/extract/"
	fold := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	for _, n := range []string{"4512", "4517", "4519", "4524", "2798", "3672", "4523", "3045", "2307"} {
		raw, _ := os.ReadFile(dir + "rfc" + n + ".defs")
		var defsText []string
		for _, block := range strings.Split(string(raw), "@@ ") {
			if i := strings.IndexByte(block, '\n'); i >= 0 {
				defsText = append(defsText, fold(block[i+1:]))
			}
		}
		b, _ := os.ReadFile("defs/rfc" + n + ".schema")
		var d definitions
		lines := strings.Split(string(b), "\n")
		ok, bad := 0, 0
		for i := 0; i < len(lines); i++ {
			l := lines[i]
			if l == "" || l[0] == '#' || l[0] == '\t' {
				continue
			}
			parts := []string{l[strings.IndexByte(l, ' ')+1:]}
			for i+1 < len(lines) && strings.HasPrefix(lines[i+1], "\t") {
				parts = append(parts, lines[i+1])
				i++
			}
			text := fold(strings.Join(parts, " "))
			found := false
			for _, x := range defsText {
				if x == text {
					found = true
				}
			}
			if found {
				ok++
			} else {
				bad++
				fmt.Printf("%s NOT VERBATIM: %s\n", n, text)
			}
		}
		_ = d
		fmt.Printf("%s: %d verbatim, %d not\n", n, ok, bad)
	}
}
