// SPDX-License-Identifier: BSD-3-Clause

package ldap

import "testing"

// Security audit 2026-11-06 (untracked proof). RFC 4511 4.2.1: "Before
// processing a BindRequest, all uncompleted operations MUST either complete
// or be abandoned." bind() (bind.go:30) makes the connection anonymous but
// leaves c.pages alone, so a paged search the handler authorised as the
// reader keeps delivering pages after a refused bind -- the pooled-connection
// case TestARefusedBindLeavesTheConnectionAnonymous exists for.
func TestSecAuditPagedSearchSurvivesARebind(t *testing.T) {
	var seen []string
	dir := &directory{entries: people("a1", "a2", "a3", "a4", "a5")}
	r := serve(t, &Server{Bind: reader(), Search: &recordingSearcher{inner: dir, seen: &seen}})
	c := dial(t, r)
	defer c.Close()
	if code := c.bind(t, "cn=reader,dc=example,dc=org", "let me read"); code != Success {
		t.Fatalf("control: %s", code)
	}
	if _, res := c.searchWith(t, "(uid=*)", pagedControl(2, "")); res.Code != Success {
		t.Fatalf("first page: %s", res.Code)
	}
	cookie, _ := c.cookieOf(t)
	if cookie == "" {
		t.Fatal("no cookie")
	}
	if code := c.bind(t, "uid=alice,ou=people,dc=example,dc=org", "wrong"); code != InvalidCredentials {
		t.Fatalf("refused bind: %s", code)
	}
	dns, res := c.searchWith(t, "(uid=*)", pagedControl(2, cookie))
	if res.Code == Success && len(dns) > 0 {
		t.Errorf("after the connection became anonymous, the reader's paged search still delivered %v (handler saw binds %q)", dns, seen)
	}
}
