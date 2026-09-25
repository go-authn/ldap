// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"context"
	"fmt"
	"log/slog"
)

// DefaultMaxPagedSearches is how many paged searches one connection may hold
// open at once.
//
// ⛔ Each one is a goroutine parked on its next entry, holding whatever the
// handler holds -- a database cursor, a row set. A client that starts a
// paged search and never finishes it has left that behind, and a client that
// does so in a loop is a resource exhaustion that needs no credentials,
// because the FIRST page is served before anything is known about it.
const DefaultMaxPagedSearches = 4

func (s *Server) maxPagedSearches() int {
	if s.MaxPagedSearches > 0 {
		return s.MaxPagedSearches
	}
	return DefaultMaxPagedSearches
}

// searchPaged answers a search carrying the paged results control.
func (c *conn) searchPaged(ctx context.Context, m *message, req *SearchRequest, ctl *Control, log *slog.Logger) {
	want, err := decodePaged(ctl)
	if err != nil {
		c.send(resultMessage(m.id, appSearchResDone, Refuse(ProtocolError, "%v", err)))
		return
	}

	// ⛔ A cookie the client did not get from this connection. RFC 2696 says
	// the server SHOULD return an error rather than start a new search: a
	// client that believes it is resuming and is actually restarting reads
	// the first page twice and never notices.
	var pg *page
	if want.cookie != "" {
		var ok bool
		if pg, ok = c.pages.get(want.cookie); !ok {
			c.send(resultMessage(m.id, appSearchResDone, Refuse(UnwillingToPerform,
				"this connection has no paged search with that cookie")))
			return
		}
	}

	// RFC 2696 3: size zero WITH a cookie abandons the sequence. There are
	// no more entries to send and the client is not waiting for any.
	if want.size == 0 && want.cookie != "" {
		c.pages.drop(want.cookie)
		c.sendWithControls(resultMessage(m.id, appSearchResDone, Result{Code: Success}),
			encodePaged(0, ""))
		return
	}

	if pg == nil {
		if n := c.pages.count(); n >= c.srv.maxPagedSearches() {
			// Said plainly rather than by hanging: a client that has left
			// searches open needs to know that is why this one is refused.
			c.send(resultMessage(m.id, appSearchResDone, Refuse(AdminLimitExceeded,
				"this connection already holds %d unfinished paged searches", n)))
			return
		}
		pg = c.startPaged(req, log)
	}

	c.sendPage(m, pg, want, log)
}

// startPaged runs the handler in its own goroutine, sending entries down a
// channel that the page reader drains a page at a time.
//
// ⛔ The context is the CONNECTION's, not the request's. A paged search
// outlives the request that began it -- that is what paging IS -- so tying it
// to the request would cancel the handler the moment the first page was
// answered, and the second page would resume a search that had already been
// told to stop.
func (c *conn) startPaged(req *SearchRequest, log *slog.Logger) *page {
	ctx, cancel := context.WithCancel(context.Background())
	pg := &page{
		entries: make(chan *Entry),
		refs:    make(chan []string),
		done:    make(chan Result, 1),
		cancel:  cancel,
	}
	w := &pagedWriter{ctx: ctx, page: pg}
	go func() {
		defer close(pg.done)
		r, err := c.srv.Search.Search(ctx, c, req, w)
		if err != nil {
			pg.err = err
			log.Error("a paged search failed", "err", err)
			return
		}
		pg.done <- r
	}()
	return pg
}

// sendPage drains up to want.size entries and answers.
//
// ⛔ The page is cancelled on EVERY path out of here except the one that
// hands it to c.pages under a new cookie. A page that is neither handed over
// nor cancelled is a goroutine parked on its next entry for the life of the
// process -- and the path that produced it is the likeliest one there is:
// the client disappearing during its FIRST page, before any cookie exists
// for the connection's map to hold.
func (c *conn) sendPage(m *message, pg *page, want *pagedRequest, log *slog.Logger) {
	handed := false
	defer func() {
		if !handed {
			pg.cancel()
		}
	}()
	sent := 0
	for sent < want.size {
		select {
		case e := <-pg.entries:
			// ⛔ No "the channel closed" case, and there must not be one.
			// The handler signals completion on `done`, and the send here
			// is UNBUFFERED -- so by the time the handler can return, this
			// side has already taken its last entry. A second completion
			// signal would be a second thing to keep in step with the
			// first.
			c.send(entryMessage(m.id, e, false))
			sent++
		case uris := <-pg.refs:
			c.send(referenceMessage(m.id, uris))
		case r, ok := <-pg.done:
			// The handler finished without filling the page.
			c.endPage(m, pg, want.cookie, r, ok)
			return
		case <-c.closedCh():
			return
		}
	}

	// A full page, and more to come. A NEW cookie each time: reusing one
	// would let a client replay the previous page by sending it again, and
	// the sequence is supposed to move forwards only.
	cookie, err := newCookie()
	if err != nil {
		c.send(resultMessage(m.id, appSearchResDone, Refuse(Other, "no cookie could be made")))
		return
	}
	if want.cookie != "" {
		c.pages.drop2(want.cookie) // forget the old handle, keep the search
	}
	c.pages.put(cookie, pg)
	handed = true
	c.sendWithControls(resultMessage(m.id, appSearchResDone, Result{Code: Success}),
		encodePaged(0, cookie))
}

// endPage answers the last page of a sequence, with an EMPTY cookie -- which
// is how RFC 2696 says "there is no more", and the only thing that tells a
// client to stop asking.
func (c *conn) endPage(m *message, pg *page, cookie string, r Result, ok bool) {
	// Cancelling twice is harmless -- context.CancelFunc is idempotent -- and
	// sendPage's defer will do it again on the way out. Doing it here too
	// means the search stops the moment the sequence ends rather than when
	// the answer has been written.
	if cookie != "" {
		c.pages.drop(cookie)
	} else {
		pg.cancel()
	}
	if !ok {
		// The handler returned an error, which the client is told nothing
		// about beyond `other` -- see answer().
		c.sendWithControls(resultMessage(m.id, appSearchResDone, Result{Code: Other}),
			encodePaged(0, ""))
		return
	}
	c.sendWithControls(resultMessage(m.id, appSearchResDone, r), encodePaged(0, ""))
}

// pagedWriter hands entries to the page reader, one at a time, and blocks
// until it is ready -- which is the backpressure that makes paging work
// without buffering the result.
type pagedWriter struct {
	ctx  context.Context
	page *page
}

func (w *pagedWriter) Entry(e *Entry) error {
	select {
	case w.page.entries <- e:
		return nil
	case <-w.ctx.Done():
		return w.ctx.Err()
	}
}

func (w *pagedWriter) Reference(uris ...string) error {
	if len(uris) == 0 {
		return fmt.Errorf("ldap: a continuation reference with no URIs")
	}
	select {
	case w.page.refs <- uris:
		return nil
	case <-w.ctx.Done():
		return w.ctx.Err()
	}
}
