// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"strings"
	"testing"
)

// ⛔ A paged search sends what was asked for, as any search does.
//
// Until v0.8.0 the page reader sent each entry as the handler wrote it: a
// paged search for cn alone came back with every attribute, operational ones
// included, and typesOnly was ignored. The plain search applied the selection
// all along, so the same question answered differently depending on whether
// the client paged -- and ldapsearch -E pr=N is what a client pages with.
func TestAPagedSearchKeepsToTheSelection(t *testing.T) {
	bin := judge(t)
	entries := people("alice", "bob", "carol")
	for _, e := range entries {
		e.Attributes = append(e.Attributes, OperationalAttribute("entryUUID", "0f1e2d3c-"+string(e.Attribute("uid").Values[0])))
	}
	r := serve(t, &Server{Bind: reader(), Search: &directory{base: "dc=example,dc=org", entries: entries}})

	for _, c := range []struct {
		name  string
		opts  []string
		attrs []string
		want  []string // attribute names expected on every entry
		never []string // attribute names that must not appear
	}{
		{"cn alone", []string{"-E", "pr=2/noprompt"}, []string{"cn"}, []string{"cn"}, []string{"uid", "objectClass", "entryUUID"}},
		{"user attributes", []string{"-E", "pr=2/noprompt"}, []string{"*"}, []string{"cn", "uid"}, []string{"entryUUID"}},
		{"operational by name", []string{"-E", "pr=2/noprompt"}, []string{"entryUUID"}, []string{"entryUUID"}, []string{"cn", "uid"}},
		{"types only", []string{"-A", "-E", "pr=2/noprompt"}, []string{"cn"}, nil, []string{"cn: "}},
	} {
		_, out := r.ask(t, bin, c.opts, "(objectClass=*)", c.attrs...)
		if n := strings.Count(out, "\ndn: "); n != 3 {
			t.Errorf("%s: %d entries, want 3:\n%s", c.name, n, out)
			continue
		}
		for _, a := range c.want {
			if n := strings.Count(out, "\n"+a+": "); n != 3 {
				t.Errorf("%s: %s on %d entries, want 3:\n%s", c.name, a, n, out)
			}
		}
		for _, a := range c.never {
			needle := "\n" + a
			if !strings.HasSuffix(a, " ") {
				needle += ":"
			}
			if strings.Contains(out, needle) {
				t.Errorf("%s: %q was sent, and was not asked for:\n%s", c.name, a, out)
			}
		}
	}
}
