package schema

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestZZOpenLDAP(t *testing.T) {
	s := Standard()
	dir := "/private/tmp/claude-501/-Users-david-delavennat-Documents-VCS-GIT-localhost/a2daf7c8-740d-4341-81e2-fd9e403df79f/scratchpad/ol/"
	for _, f := range []string{"core", "cosine", "inetorgperson", "nis"} {
		b, _ := os.ReadFile(dir + f + ".schema")
		var d definitions
		// read definition by definition, tolerating errors
		lines := strings.Split(string(b), "\n")
		var cur []string
		flush := func() {
			if len(cur) == 0 {
				return
			}
			one := strings.Join(cur, "\n")
			cur = nil
			var dd definitions
			if err := dd.read(File{f, []byte(one)}); err != nil {
				fmt.Printf("%s: PARSE %v\n", f, err)
				return
			}
			d.types = append(d.types, dd.types...)
			d.classes = append(d.classes, dd.classes...)
		}
		for _, l := range lines {
			if l == "" || l[0] == '#' {
				continue
			}
			if l[0] != ' ' && l[0] != '\t' {
				flush()
			}
			cur = append(cur, l)
		}
		flush()
		for _, o := range d.types {
			m := s.AttributeType(o.OID)
			if m == nil {
				fmt.Printf("%s: type %s %v not in ours\n", f, o.OID, o.Names)
				continue
			}
			a, b := *m, *o
			a.Desc, b.Desc = "", ""
			a.sup, a.equality, a.ordering, a.sub, a.syntax, a.linked = nil, nil, nil, nil, "", false
			a.Extensions, b.Extensions = nil, nil
			if !reflect.DeepEqual(a, b) {
				fmt.Printf("%s: type %s differs:\n  ours: %s\n  ol:   %s\n", f, o.Names, m, o)
			}
		}
		for _, o := range d.classes {
			m := s.ObjectClass(o.OID)
			if m == nil {
				fmt.Printf("%s: class %s %v not in ours\n", f, o.OID, o.Names)
				continue
			}
			a, b := *m, *o
			a.Desc, b.Desc = "", ""
			a.sup, a.must, a.may = nil, nil, nil
			a.Extensions, b.Extensions = nil, nil
			norm := func(x []string) []string {
				var out []string
				for _, v := range x {
					out = append(out, strings.ToLower(v))
				}
				return out
			}
			a.Must, a.May, a.Sup, b.Must, b.May, b.Sup = norm(a.Must), norm(a.May), norm(a.Sup), norm(b.Must), norm(b.May), norm(b.Sup)
			if !reflect.DeepEqual(a, b) {
				fmt.Printf("%s: class %s differs:\n  ours: %s\n  ol:   %s\n", f, o.Names, m, o)
			}
		}
	}
}
