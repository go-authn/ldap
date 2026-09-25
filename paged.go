// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Simple paged results (RFC 2696): a search answered a page at a time.
//
// ⛔ It exists because the alternative is a size limit, and a size limit is
// not an answer to "give me everybody". A directory of ten thousand people
// either sends ten thousand entries in one breath or truncates, and a client
// that truncates cannot tell that from a directory with fewer people in it.
//
// The shape here is a HANDLER LEFT RUNNING between pages, blocked on sending
// its next entry. The alternatives are worse in ways that are not obvious:
//
//   - Re-running the search per page and skipping the first N is O(n²) and,
//     worse, INCONSISTENT: a person added between two pages shifts everything
//     after them, so an entry can be sent twice or never.
//   - Buffering the whole result on the first page throws away the streaming
//     the EntryWriter exists for, and does it precisely when the result is
//     too large to want in memory.
//
// The cost is a goroutine and a cursor per outstanding paged search, which
// is why there is a limit on how many a connection may hold and why
// everything is cancelled when the connection ends.

// pagedRequest is what a client sent in the control.
type pagedRequest struct {
	size   int
	cookie string
}

// decodePaged reads the control value (RFC 2696 2).
func decodePaged(c *Control) (*pagedRequest, error) {
	if len(c.Value) == 0 {
		return nil, errors.New("ldap: a paged results control with no value")
	}
	p, err := ber.DecodePacketErr(c.Value)
	if err != nil {
		return nil, fmt.Errorf("ldap: the paged results control does not parse: %w", err)
	}
	if len(p.Children) != 2 {
		return nil, fmt.Errorf("ldap: a paged results control with %d fields, want 2", len(p.Children))
	}
	size, ok := p.Children[0].Value.(int64)
	if !ok || size < 0 {
		return nil, fmt.Errorf("ldap: a page size of %v", p.Children[0].Value)
	}
	return &pagedRequest{size: int(size), cookie: string(p.Children[1].Data.Bytes())}, nil
}

// encodePaged builds the control for a response.
//
// size is the server's ESTIMATE of the whole result set, or zero when it has
// none -- RFC 2696 2 allows either, and this server sends zero rather than a
// number it would have to count the directory to know. A client that treats
// the estimate as the truth would be wrong about a directory that changed.
func encodePaged(size int, cookie string) Control {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "realSearchControlValue")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(size), "size"))
	seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, cookie, "cookie"))
	return Control{Type: OIDPaging, Value: seq.Bytes()}
}

// A page is one search left running between requests.
type page struct {
	entries chan *Entry
	refs    chan []string
	done    chan Result
	cancel  context.CancelFunc
	// err is what the handler returned, read only after done is closed.
	err error
}

// pages is a connection's outstanding paged searches.
//
// ⛔ Per CONNECTION, which is not a detail. RFC 2696 makes the cookie valid
// only for the sequence it came from, and a cookie that worked on another
// connection would let anybody resume somebody else's search -- reading, at
// their access level, entries they were never shown.
type pages struct {
	mu   sync.Mutex
	open map[string]*page
}

func (p *pages) get(cookie string) (*page, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pg, ok := p.open[cookie]
	return pg, ok
}

func (p *pages) put(cookie string, pg *page) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.open == nil {
		p.open = map[string]*page{}
	}
	p.open[cookie] = pg
}

func (p *pages) drop(cookie string) {
	p.mu.Lock()
	pg := p.open[cookie]
	delete(p.open, cookie)
	p.mu.Unlock()
	if pg != nil {
		pg.cancel()
	}
}

// drop2 forgets a cookie WITHOUT cancelling the search behind it, which is
// what happens when a page is answered and the same search continues under a
// new cookie.
func (p *pages) drop2(cookie string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.open, cookie)
}

func (p *pages) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.open)
}

// closeAll cancels every outstanding search, which is what stops a handler
// blocked on its next entry from living as long as the process does.
func (p *pages) closeAll() {
	p.mu.Lock()
	all := make([]*page, 0, len(p.open))
	for _, pg := range p.open {
		all = append(all, pg)
	}
	p.open = nil
	p.mu.Unlock()
	for _, pg := range all {
		pg.cancel()
	}
}

// newCookie is an opaque, unguessable resume token.
//
// ⛔ Not a counter and not the offset. RFC 2696 calls it opaque, and a client
// that can GUESS one can resume a search it never started -- on this
// connection, which is the one place a cookie is honoured. Sixteen random
// bytes cost nothing and remove the question.
func newCookie() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
