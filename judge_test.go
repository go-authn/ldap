// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"
)

// ⛔ OpenLDAP's own client is the judge.
//
// A server tested only by a client written in the same module can agree with
// it about a MISREADING of the protocol and both be wrong -- which is
// exactly how the library this replaces evaluated `(uid=svc-*-prod)` as
// `(uid=svc-*)`: its own client encoded the filter with the same defect, so
// the round trip looked clean. The first time I measured that bug with that
// client it reported zero matches. Judge and subject were one thing.
//
// LDAP_REQUIRE_JUDGE=1 turns a missing ldapsearch into a FAILURE rather than
// a skip, which is what CI sets. A judge that is merely usually present
// measures nothing on the day it is absent, and says so in the same words as
// a pass.
func judge(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("ldapsearch")
	if err != nil {
		if os.Getenv("LDAP_REQUIRE_JUDGE") != "" {
			t.Fatal("LDAP_REQUIRE_JUDGE is set and ldapsearch is not installed")
		}
		t.Skip("ldapsearch is not installed; set LDAP_REQUIRE_JUDGE=1 to make this a failure")
	}
	return bin
}

// directory is a tiny read-only Searcher over a fixed set of entries, so that
// what a test asserts is the SERVER's behaviour and not a data source's.
type directory struct {
	base    string
	entries []*Entry
	// refuse, when set, is what Search answers instead.
	refuse *Result
	// onSearch observes the request the server decoded, so a test can assert
	// what arrived rather than only what came back.
	onSearch func(*SearchRequest)
}

func (d *directory) Search(ctx context.Context, s Session, req *SearchRequest, w EntryWriter) (Result, error) {
	if d.onSearch != nil {
		d.onSearch(req)
	}
	if d.refuse != nil {
		return *d.refuse, nil
	}
	for _, e := range d.entries {
		if !inScope(e.DN, req.BaseObject, req.Scope) {
			continue
		}
		if !req.Filter.Matches(e) {
			continue
		}
		if err := w.Entry(e); err != nil {
			return Result{}, err
		}
	}
	return Result{Code: Success}, nil
}

// inScope is the scope rule (RFC 4511 4.5.1.2), which a directory owns
// rather than the server: only the data knows what is under what.
func inScope(dn, base string, scope Scope) bool {
	dn, base = strings.ToLower(dn), strings.ToLower(base)
	switch scope {
	case ScopeBaseObject:
		return dn == base
	case ScopeSingleLevel:
		rest, ok := strings.CutSuffix(dn, ","+base)
		return ok && !strings.Contains(rest, ",")
	}
	return dn == base || strings.HasSuffix(dn, ","+base)
}

// password is a Binder that knows one person.
type password struct {
	dn, pw string
	seen   func(*BindRequest)
}

func (p *password) Bind(ctx context.Context, s Session, req *BindRequest) (Result, error) {
	if p.seen != nil {
		p.seen(req)
	}
	// RFC 4513 5.1.2: a name with an EMPTY password is an UNAUTHENTICATED
	// bind and means "I am anonymous" -- not "I proved this name". A server
	// that answers it success lets anybody in as anybody.
	if len(req.Simple) == 0 {
		return Refuse(InvalidCredentials, "an unauthenticated bind is not a proof"), nil
	}
	if strings.EqualFold(req.Name, p.dn) && string(req.Simple) == p.pw {
		return Result{Code: Success}, nil
	}
	return Result{Code: InvalidCredentials}, nil
}

// running is a server on a port the kernel picked.
type running struct {
	*Server
	addr string
}

func serve(t *testing.T, s *Server) *running {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	t.Cleanup(func() {
		s.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the server did not stop")
		}
	})
	return &running{Server: s, addr: ln.Addr().String()}
}

func (r *running) url() string { return "ldap://" + r.addr }

// ask runs ldapsearch and returns the uids it came back with.
//
// ⛔ opts go BEFORE the filter. ldapsearch takes everything after the filter
// as an attribute SELECTOR, so `-z 2` placed at the end is not a size limit
// -- it asks for two attributes called "-z" and "2", which no entry has, and
// the search runs unlimited. Two tests here passed nothing and reported
// failures about the server; the harness was the thing that was wrong.
func (r *running) ask(t *testing.T, bin string, opts []string, filter string, attrs ...string) ([]string, string) {
	t.Helper()
	full := []string{"-x", "-H", r.url(),
		"-D", "cn=reader,dc=example,dc=org", "-w", "let me read",
		"-b", "dc=example,dc=org"}
	full = append(full, opts...)
	full = append(full, filter)
	if len(attrs) == 0 {
		attrs = []string{"uid"}
	}
	full = append(full, attrs...)
	out, _ := exec.Command(bin, full...).CombinedOutput()
	var got []string
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(line, "uid: "); ok {
			got = append(got, v)
		}
	}
	sort.Strings(got)
	return got, string(out)
}

func people(names ...string) []*Entry {
	var out []*Entry
	for _, n := range names {
		out = append(out, &Entry{
			DN: fmt.Sprintf("uid=%s,ou=people,dc=example,dc=org", n),
			Attributes: []*Attribute{
				StringAttribute("objectClass", "top", "person", "posixAccount"),
				StringAttribute("uid", n),
				StringAttribute("cn", n),
			},
		})
	}
	return out
}

func reader() *password {
	return &password{dn: "cn=reader,dc=example,dc=org", pw: "let me read"}
}

func run(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	return string(out), err
}

// recordingSearcher reports which DN the server believed it was talking to.
type recordingSearcher struct {
	inner Searcher
	seen  *[]string
}

func (r *recordingSearcher) Search(ctx context.Context, s Session, req *SearchRequest, w EntryWriter) (Result, error) {
	*r.seen = append(*r.seen, s.BoundDN())
	return r.inner.Search(ctx, s, req, w)
}

// twoStep is a SASL mechanism that needs a round trip, which is the case a
// simple bind's shape cannot express -- and which binds the connection as a
// DN the client never sent (RFC 4513 5.2.1).
type twoStep struct{}

func (twoStep) Mechanisms() []string { return []string{"TWOSTEP"} }

func (twoStep) BindSASL(ctx context.Context, s Session, req *BindRequest) (SASLResult, error) {
	if req.SASL.Mechanism != "TWOSTEP" {
		return SASLResult{Result: Result{Code: AuthMethodNotSupported}}, nil
	}
	switch {
	case req.SASL.Credentials == nil:
		return SASLResult{
			Result:      Result{Code: SaslBindInProgress},
			ServerCreds: []byte("who are you"),
		}, nil
	case string(req.SASL.Credentials) == "i am gwen":
		return SASLResult{
			Result:      Result{Code: Success},
			BoundDN:     "uid=gwen,dc=example,dc=org",
			ServerCreds: []byte{},
		}, nil
	}
	return SASLResult{Result: Result{Code: InvalidCredentials}}, nil
}
