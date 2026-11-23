// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"context"
	"sync/atomic"
	"testing"
)

// yesman is a bind handler with the bug RFC 4513 6.3.1 warns about: it
// answers Success to a name with an empty password, as an LDAP backend that
// treats the empty password as "nothing to check" does.
type yesman struct{ calls atomic.Int32 }

func (y *yesman) Bind(context.Context, Session, *BindRequest) (Result, error) {
	y.calls.Add(1)
	return Result{Code: Success}, nil
}

// Suspicion 10, RFC 4513 5.1.2: a name with a zero-length password is the
// UNAUTHENTICATED mechanism. The name is "not to be used (directly or
// indirectly) for authorization purposes" and "Servers SHOULD by default fail"
// it with unwillingToPerform. The library answers that itself: one handler
// that forgets the case must not turn a name into an identity.
func TestAnUnauthenticatedBindNeverReachesTheHandler(t *testing.T) {
	y := &yesman{}
	seen := make(chan Session, 1)
	r := serve(t, &Server{Bind: y, Search: sessionSearcher{seen}})
	c := dial(t, r)
	defer c.Close()

	if code := c.bind(t, "cn=admin,dc=example,dc=org", ""); code != UnwillingToPerform {
		t.Errorf("a name with an empty password answered %s", code)
	}
	if n := y.calls.Load(); n != 0 {
		t.Errorf("the handler was asked %d times about an unauthenticated bind", n)
	}
	c.search(t, "(uid=*)")
	if got := (<-seen).BoundDN(); got != "" {
		t.Errorf("the connection is bound as %q after a refused bind", got)
	}

	// The anonymous bind of 5.1.1 (no name, no password) still goes through,
	// and so does a name with a password.
	if code := c.bind(t, "", ""); code != Success {
		t.Errorf("an anonymous bind answered %s", code)
	}
	if code := c.bind(t, "cn=admin,dc=example,dc=org", "pw"); code != Success {
		t.Errorf("a name with a password answered %s", code)
	}
	if n := y.calls.Load(); n != 2 {
		t.Errorf("the handler saw %d binds, want the 2 that carry a password or no name", n)
	}
}
