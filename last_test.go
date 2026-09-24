// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// ⛔ A search filter carries what somebody TYPED -- a name, an address,
// sometimes a token pasted into the wrong box. A directory that writes them
// to its log has made a permanent record of every question anybody asked
// about anybody, usually without meaning to. The shape is logged; the values
// are not.
func TestTheLogRecordsTheShapeOfAFilterAndNotItsValues(t *testing.T) {
	// ⛔ A locked buffer, not a bytes.Buffer. The server logs from its own
	// goroutines -- including a deferred line when the connection ends --
	// and reading one while it writes is a data race whatever the buffer
	// holds. It passed locally and CI's race detector caught it, which is
	// what a race is: a thing that is fine until the timing changes.
	buf := &lockedBuffer{}
	log := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r := serve(t, &Server{Bind: reader(), Search: &directory{}, Log: log})
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")

	secret := "hunter2-pasted-into-the-wrong-box"
	c.search(t, "(&(uid="+secret+")(mail=*)(cn>=a)(sn<=z)(givenName~=x)(o=a*b))")

	out := buf.String()
	if strings.Contains(out, secret) {
		t.Errorf("the log recorded what somebody typed:\n%s", out)
	}
	// The SHAPE is there, which is what is worth recording.
	for _, want := range []string{"uid=·", "mail=*", "cn>=·", "sn<=·", "givenName~=·", "o=·*·"} {
		if !strings.Contains(out, want) {
			t.Errorf("the log does not carry %q:\n%s", want, out)
		}
	}

	// Every filter shape renders, including the ones with no values at all.
	for _, tc := range []struct {
		f    Filter
		want string
	}{
		{&Or{Filters: []Filter{&Present{Attribute: "cn"}}}, "(|(cn=*))"},
		{&Not{Filter: &Present{Attribute: "cn"}}, "(!(cn=*))"},
		{&ExtensibleMatch{Attribute: "cn", MatchingRule: "2.5.13.2", Value: "x"}, "(cn:2.5.13.2:=·)"},
		{nil, "(?)"},
	} {
		if got := shapeOf(tc.f); got != tc.want {
			t.Errorf("shapeOf rendered %q, want %q", got, tc.want)
		}
	}
}

// ⛔ The smaller of the client's limit and the server's applies. A client
// asking for more than the server allows does not RAISE the server's, which
// is what taking the client's value whenever it is non-zero would do.
func TestTheSmallerLimitWins(t *testing.T) {
	for _, tc := range []struct{ client, server, want int }{
		{0, 0, 0},  // neither limits
		{5, 0, 5},  // only the client
		{0, 5, 5},  // only the server
		{2, 5, 2},  // the client is stricter
		{5, 2, 2},  // the server is stricter
		{5, 5, 5},  // equal
		{-1, 3, 3}, // a negative client limit is "none"
	} {
		if got := effectiveLimit(tc.client, tc.server); got != tc.want {
			t.Errorf("client %d, server %d gave %d, want %d", tc.client, tc.server, got, tc.want)
		}
	}
}

// A server with no logger and no limits still works: the zero Server is
// usable, because a caller that has to remember to set three fields before
// anything answers will forget one.
func TestTheZeroServerWorks(t *testing.T) {
	s := &Server{Bind: reader(), Search: &directory{entries: people("alice")}}
	if s.logger() == nil {
		t.Error("the default logger is nil")
	}
	if s.maxMessageSize() != DefaultMaxMessageSize {
		t.Errorf("the default message size is %d", s.maxMessageSize())
	}
	r := serve(t, s)
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")
	if dns, res := c.search(t, "(uid=*)"); res.Code != Success || len(dns) != 1 {
		t.Errorf("the zero server answered %s with %d entries", res.Code, len(dns))
	}
}

// Writing to a client that has gone away closes the connection rather than
// filling a socket nobody reads.
func TestWritingToAClientThatLeftClosesTheConnection(t *testing.T) {
	gone := make(chan struct{})
	s := &Server{Bind: reader(), Search: leaverSearcher{gone}}
	r := serve(t, s)
	c := dial(t, r)
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")

	// Send a search, then hang up before reading any of it.
	c.write(t, 99, searchOp(t, "(uid=*)"))
	c.Close()
	close(gone)
	// The handler keeps sending into a closed socket; the server must stop
	// rather than loop. Nothing to assert but that the test ends.
}

type leaverSearcher struct{ gone chan struct{} }

func (l leaverSearcher) Search(ctx context.Context, _ Session, _ *SearchRequest, w EntryWriter) (Result, error) {
	<-l.gone
	for i := 0; i < 200; i++ {
		if err := w.Entry(&Entry{DN: "uid=a", Attributes: []*Attribute{StringAttribute("uid", "a")}}); err != nil {
			return Result{}, err
		}
	}
	return Result{Code: Success}, nil
}

// An entry written after the context ended is refused, which is what stops a
// handler walking a directory nobody is reading.
func TestAWriterRefusesAfterTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := &entryWriter{ctx: ctx}
	if err := w.Entry(&Entry{DN: "x"}); err == nil {
		t.Error("an entry was accepted after the context ended")
	}
	if err := w.Reference("ldap://x/"); err == nil {
		t.Error("a reference was accepted after the context ended")
	}
}

// decodeAttributes refuses a partial attribute with no type.
func TestAnAttributeWithNoTypeIsRefused(t *testing.T) {
	if _, err := decodeAttributes(seq(seq())); err == nil {
		t.Error("an attribute with no type was accepted")
	}
	if _, err := child(seq(), 0, "a thing"); err == nil {
		t.Error("child returned a field that is not there")
	}
}

// responseFor covers every request tag the protocol has, so that a refusal
// reaches the client as the right KIND of message.
func TestEveryRequestHasAResponseType(t *testing.T) {
	for _, tc := range []struct {
		req, resp int
	}{
		{appBindRequest, appBindResponse},
		{appSearchRequest, appSearchResDone},
		{appModifyRequest, appModifyResponse},
		{appAddRequest, appAddResponse},
		{appDelRequest, appDelResponse},
		{appModDNRequest, appModDNResponse},
		{appCompareRequest, appCompareResponse},
		{appExtendedRequest, appExtendedResponse},
	} {
		if got := responseFor(ber.Tag(tc.req)); int(got) != tc.resp {
			t.Errorf("request %d answers with %d, want %d", tc.req, got, tc.resp)
		}
	}
}

// lockedBuffer is a buffer a test can read while a server writes it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
