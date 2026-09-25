// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"context"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// pagedControl builds the RFC 2696 request control.
func pagedControl(size int, cookie string) *Control {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "realSearchControlValue")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(size), "size"))
	seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, cookie, "cookie"))
	return &Control{Type: OIDPaging, Value: seq.Bytes()}
}

// cookieOf reads the cookie a searchResDone carried, and whether the control
// was there at all.
func (c *client) cookieOf(t *testing.T) (string, bool) {
	t.Helper()
	for _, ctl := range c.lastControls {
		if ctl.Type != OIDPaging {
			continue
		}
		p, err := ber.DecodePacketErr(ctl.Value)
		if err != nil || len(p.Children) != 2 {
			t.Fatalf("the paged control does not parse: %v", err)
		}
		return string(p.Children[1].Data.Bytes()), true
	}
	return "", false
}

// ⛔ The whole point: a directory read a page at a time, arriving COMPLETE
// and with no entry seen twice. A size limit is not an answer to "give me
// everybody" -- a client that truncates cannot tell that from a directory
// with fewer people in it.
func TestAPagedSearchReturnsEveryEntryExactlyOnce(t *testing.T) {
	var names []string
	for i := 0; i < 23; i++ {
		names = append(names, string(rune('a'+i/5))+string(rune('0'+i%5)))
	}
	r := serve(t, &Server{Bind: reader(), Search: &directory{entries: people(names...)}})
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")

	seen := map[string]int{}
	cookie := ""
	pages := 0
	for {
		pages++
		if pages > 20 {
			t.Fatal("the sequence never ended")
		}
		dns, res := c.searchWith(t, "(uid=*)", pagedControl(5, cookie))
		if res.Code != Success {
			t.Fatalf("page %d answered %s", pages, res.Code)
		}
		for _, dn := range dns {
			seen[dn]++
		}
		next, ok := c.cookieOf(t)
		if !ok {
			t.Fatalf("page %d carried no paged control", pages)
		}
		if next == "" {
			break
		}
		if next == cookie {
			t.Fatal("the cookie did not change, so the sequence cannot move forwards")
		}
		if len(dns) != 5 {
			t.Errorf("page %d has %d entries and is not the last", pages, len(dns))
		}
		cookie = next
	}

	if len(seen) != len(names) {
		t.Errorf("saw %d distinct entries, want %d", len(seen), len(names))
	}
	for dn, n := range seen {
		if n != 1 {
			t.Errorf("%s arrived %d times", dn, n)
		}
	}
	// 23 entries at 5 a page: five of five, then one of three.
	if pages != 5 {
		t.Errorf("it took %d pages, want 5", pages)
	}
}

// A page larger than the directory ends in one round trip, with an empty
// cookie -- not with a second page that happens to be empty.
func TestAPageLargerThanTheDirectoryEndsAtOnce(t *testing.T) {
	r := serve(t, &Server{Bind: reader(), Search: &directory{entries: people("a", "b")}})
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")

	dns, res := c.searchWith(t, "(uid=*)", pagedControl(100, ""))
	if res.Code != Success || len(dns) != 2 {
		t.Fatalf("answered %s with %d entries", res.Code, len(dns))
	}
	cookie, ok := c.cookieOf(t)
	if !ok {
		t.Fatal("no paged control came back")
	}
	if cookie != "" {
		t.Errorf("a finished sequence carried a cookie %q, so a client would ask again", cookie)
	}
}

// ⛔ A cookie from nowhere. RFC 2696 says the server SHOULD return an error
// rather than start a new search: a client that believes it is resuming and
// is actually restarting reads the first page twice and never notices.
func TestACookieThisConnectionNeverIssuedIsRefused(t *testing.T) {
	r := serve(t, &Server{Bind: reader(), Search: &directory{entries: people("a", "b", "c")}})
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")

	dns, res := c.searchWith(t, "(uid=*)", pagedControl(2, "deadbeefdeadbeefdeadbeefdeadbeef"))
	if res.Code == Success {
		t.Fatalf("an invented cookie was accepted, returning %d entries", len(dns))
	}
	if !strings.Contains(res.Diagnostic, "cookie") {
		t.Errorf("the refusal does not say why: %q", res.Diagnostic)
	}
}

// ⛔ And a cookie is valid ONLY on the connection that issued it. Honouring
// one from another connection would let anybody resume somebody else's
// search -- reading, at THEIR access level, entries they were never shown.
func TestACookieDoesNotCrossConnections(t *testing.T) {
	r := serve(t, &Server{Bind: reader(), Search: &directory{entries: people("a", "b", "c", "d")}})

	first := dial(t, r)
	defer first.Close()
	first.bind(t, "cn=reader,dc=example,dc=org", "let me read")
	if _, res := first.searchWith(t, "(uid=*)", pagedControl(2, "")); res.Code != Success {
		t.Fatalf("the first page answered %s", res.Code)
	}
	cookie, ok := first.cookieOf(t)
	if !ok || cookie == "" {
		t.Fatal("the control failed: no cookie to carry across")
	}

	second := dial(t, r)
	defer second.Close()
	second.bind(t, "cn=reader,dc=example,dc=org", "let me read")
	if _, res := second.searchWith(t, "(uid=*)", pagedControl(2, cookie)); res.Code == Success {
		t.Error("a cookie from another connection was honoured")
	}
}

// RFC 2696 3: size zero WITH a cookie abandons the sequence. The server must
// answer, and must not leave the search running.
func TestASequenceCanBeAbandoned(t *testing.T) {
	s := &Server{Bind: reader(), Search: &directory{entries: people("a", "b", "c", "d", "e", "f")}}
	r := serve(t, s)
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")

	if _, res := c.searchWith(t, "(uid=*)", pagedControl(2, "")); res.Code != Success {
		t.Fatal("the first page failed")
	}
	cookie, _ := c.cookieOf(t)
	if cookie == "" {
		t.Fatal("the control failed: the sequence was already over")
	}

	if _, res := c.searchWith(t, "(uid=*)", pagedControl(0, cookie)); res.Code != Success {
		t.Errorf("abandoning answered %s", res.Code)
	}
	// The cookie is spent: using it again is refused.
	if _, res := c.searchWith(t, "(uid=*)", pagedControl(2, cookie)); res.Code == Success {
		t.Error("an abandoned sequence was resumed")
	}
}

// ⛔ Each unfinished paged search is a goroutine parked on its next entry,
// holding whatever the handler holds. A client that starts them and never
// finishes them is a resource exhaustion that needs NO credentials, because
// the first page is served before anything is known about it.
func TestAConnectionMayNotHoldUnboundedPagedSearches(t *testing.T) {
	r := serve(t, &Server{
		Bind: reader(), MaxPagedSearches: 2,
		Search: &directory{entries: people("a", "b", "c", "d", "e", "f")},
	})
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")

	// Two started and left unfinished.
	for i := 0; i < 2; i++ {
		if _, res := c.searchWith(t, "(uid=*)", pagedControl(1, "")); res.Code != Success {
			t.Fatalf("search %d answered %s", i, res.Code)
		}
	}
	// The third is refused, in words.
	_, res := c.searchWith(t, "(uid=*)", pagedControl(1, ""))
	if res.Code != AdminLimitExceeded {
		t.Errorf("the third answered %s, want adminLimitExceeded", res.Code)
	}
	if !strings.Contains(res.Diagnostic, "unfinished") {
		t.Errorf("the refusal does not say why: %q", res.Diagnostic)
	}
}

// ⛔ A paged search left unfinished must not outlive its connection. The
// handler is parked on a channel send; without the connection waking it, the
// goroutine and whatever it holds live as long as the process.
func TestAnUnfinishedPagedSearchDiesWithItsConnection(t *testing.T) {
	released := make(chan struct{})
	s := &Server{Bind: reader(), Search: &blocker{released: released}}
	r := serve(t, s)

	c := dial(t, r)
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")
	if _, res := c.searchWith(t, "(uid=*)", pagedControl(1, "")); res.Code != Success {
		t.Fatalf("the first page answered %s", res.Code)
	}
	// The handler is now parked on its SECOND entry.
	c.Close()

	select {
	case <-released:
	case <-time.After(10 * time.Second):
		t.Fatal("the handler was never released; it would outlive the connection")
	}
}

// blocker sends entries for ever, so that a paged search is always parked on
// the next one. It closes `released` when its context ends, which is how the
// test sees that the connection woke it.
type blocker struct{ released chan struct{} }

func (b *blocker) Search(ctx context.Context, _ Session, _ *SearchRequest, w EntryWriter) (Result, error) {
	defer close(b.released)
	for i := 0; ; i++ {
		e := &Entry{DN: "uid=x", Attributes: []*Attribute{StringAttribute("uid", "x")}}
		if err := w.Entry(e); err != nil {
			return Result{}, err
		}
	}
}

// The control's own refusals. Every one is a byte string a client can send,
// and a paged search that mis-reads its control answers a different question
// from the one asked.
func TestThePagedControlsThatAreNotControls(t *testing.T) {
	junk := func(b []byte) *Control { return &Control{Type: OIDPaging, Value: b} }
	seq := func(children ...*ber.Packet) []byte {
		p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "v")
		for _, c := range children {
			p.AppendChild(c)
		}
		return p.Bytes()
	}
	num := func(v int64) *ber.Packet {
		return ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, v, "n")
	}
	str := func(v string) *ber.Packet {
		return ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "s")
	}

	r := serve(t, &Server{Bind: reader(), Search: &directory{entries: people("a", "b")}})
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")

	for _, tc := range []struct {
		what string
		ctl  *Control
	}{
		{"no value at all", &Control{Type: OIDPaging}},
		{"a value that is not BER", junk([]byte("not a control"))},
		{"one field", junk(seq(num(2)))},
		{"three fields", junk(seq(num(2), str(""), str("?")))},
		{"a size that is not an integer", junk(seq(str("two"), str("")))},
		{"a negative size", junk(seq(num(-1), str("")))},
	} {
		dns, res := c.searchWith(t, "(uid=*)", tc.ctl)
		if res.Code != ProtocolError {
			t.Errorf("%s answered %s", tc.what, res.Code)
		}
		if len(dns) != 0 {
			t.Errorf("%s returned %d entries anyway", tc.what, len(dns))
		}
	}
}

// A continuation reference inside a paged search reaches the client, rather
// than being swallowed by the page reader.
func TestAPagedSearchCarriesReferences(t *testing.T) {
	r := serve(t, &Server{Bind: reader(), Search: pagedReferrer{}})
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")

	dns, res := c.searchWith(t, "(uid=*)", pagedControl(5, ""))
	if res.Code != Success {
		t.Fatalf("answered %s", res.Code)
	}
	if len(dns) != 1 {
		t.Errorf("returned %d entries, want 1", len(dns))
	}
}

type pagedReferrer struct{}

func (pagedReferrer) Search(_ context.Context, _ Session, _ *SearchRequest, w EntryWriter) (Result, error) {
	// A reference with no URIs is refused here as it is anywhere: it tells a
	// client to ask somewhere and names nowhere.
	if err := w.Reference(); err == nil {
		return Result{}, nil
	}
	if err := w.Reference("ldap://other.example.org/dc=example,dc=org"); err != nil {
		return Result{}, err
	}
	if err := w.Entry(&Entry{DN: "uid=a", Attributes: []*Attribute{StringAttribute("uid", "a")}}); err != nil {
		return Result{}, err
	}
	return Result{Code: Success}, nil
}

// A handler that fails mid-sequence is `other` and nothing else, and the
// sequence ENDS -- an empty cookie, so the client stops asking rather than
// retrying into the same failure.
func TestAPagedSearchWhoseHandlerFailsEndsTheSequence(t *testing.T) {
	r := serve(t, &Server{Bind: reader(), Search: failAfterOne{}})
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")

	_, res := c.searchWith(t, "(uid=*)", pagedControl(5, ""))
	if res.Code != Other {
		t.Errorf("a failing handler answered %s", res.Code)
	}
	if cookie, ok := c.cookieOf(t); !ok || cookie != "" {
		t.Errorf("it carried cookie %q (present=%v); the client would ask again", cookie, ok)
	}
}

type failAfterOne struct{}

func (failAfterOne) Search(_ context.Context, _ Session, _ *SearchRequest, w EntryWriter) (Result, error) {
	if err := w.Entry(&Entry{DN: "uid=a", Attributes: []*Attribute{StringAttribute("uid", "a")}}); err != nil {
		return Result{}, err
	}
	return Result{}, context.DeadlineExceeded
}

// The paged pieces that a network test cannot reach on demand.
func TestThePagedWriterStopsWhenItsSearchIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := &pagedWriter{ctx: ctx, page: &page{entries: make(chan *Entry), refs: make(chan []string)}}
	if err := w.Entry(&Entry{DN: "x"}); err == nil {
		t.Error("an entry was accepted after the search was cancelled")
	}
	if err := w.Reference("ldap://x/"); err == nil {
		t.Error("a reference was accepted after the search was cancelled")
	}
	// A reference naming nowhere is refused whether or not it is cancelled.
	live := &pagedWriter{ctx: context.Background(), page: &page{refs: make(chan []string)}}
	if err := live.Reference(); err == nil {
		t.Error("a reference with no URIs was accepted")
	}
}

// ⛔ A client that goes away mid-page must not leave the page reader waiting
// on a handler that is itself waiting for the reader. The connection's own
// close is what breaks that.
func TestAPageReaderStopsWhenTheConnectionCloses(t *testing.T) {
	released := make(chan struct{})
	r := serve(t, &Server{Bind: reader(), Search: &slowBlocker{released: released}})
	c := dial(t, r)
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")

	// Ask for more entries than the handler will ever produce, then leave.
	go func() {
		time.Sleep(100 * time.Millisecond)
		c.Close()
	}()
	c.sendSearch(t, "(uid=*)", pagedControl(50, ""))

	select {
	case <-released:
	case <-time.After(10 * time.Second):
		t.Fatal("the handler was never released")
	}
}

// slowBlocker sends one entry and then never another, so the page reader is
// still waiting when the connection goes.
type slowBlocker struct{ released chan struct{} }

func (b *slowBlocker) Search(ctx context.Context, _ Session, _ *SearchRequest, w EntryWriter) (Result, error) {
	defer close(b.released)
	if err := w.Entry(&Entry{DN: "uid=a", Attributes: []*Attribute{StringAttribute("uid", "a")}}); err != nil {
		return Result{}, err
	}
	<-ctx.Done()
	return Result{}, ctx.Err()
}

// appendControls: nothing to append, and a critical one.
func TestAppendControls(t *testing.T) {
	bare := resultMessage(1, appSearchResDone, Result{Code: Success})
	if n := len(appendControls(bare).Children); n != 2 {
		t.Errorf("appending nothing gave %d fields, want 2", n)
	}
	withOne := appendControls(resultMessage(1, appSearchResDone, Result{Code: Success}),
		Control{Type: OIDPaging, Criticality: true, Value: []byte("v")})
	p, err := ber.DecodePacketErr(withOne.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeControls(p.Children[2])
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].Criticality || string(got[0].Value) != "v" {
		t.Errorf("the control came back as %+v", got)
	}
}

// ⛔ A paged search asking for something this server cannot match is refused
// with inappropriateMatching, BEFORE any page is started. Answering the
// narrower question quietly would be indistinguishable from the answer being
// right -- and paging makes it worse, because the client would page happily
// through a result that silently excludes everything the rule was about.
func TestAPagedSearchWithAnUnimplementedRuleIsRefusedBeforeItStarts(t *testing.T) {
	s := &Server{Bind: reader(), Search: &directory{entries: people("a", "b")}}
	r := serve(t, s)
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")

	dns, res := c.searchWith(t, "(memberOf:1.2.840.113556.1.4.1941:=cn=admins)", pagedControl(1, ""))
	if res.Code != InappropriateMatching {
		t.Errorf("answered %s, want inappropriateMatching", res.Code)
	}
	if len(dns) != 0 {
		t.Errorf("it returned %d entries", len(dns))
	}
	// And no search was left running behind it.
	if n := c.pagesOpen(t, s); n != 0 {
		t.Errorf("%d paged searches were left open", n)
	}
}
