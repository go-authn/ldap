// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
)

// errSizeLimit ends a search that has sent everything it was allowed to.
var errSizeLimit = errors.New("ldap: the size limit was reached")

// entryWriter sends entries as the handler finds them, and stops it at the
// limit.
type entryWriter struct {
	c         *conn
	id        int
	typesOnly bool
	limit     int // 0 means no limit
	sent      atomic.Int64
	// attributes is the selection, already resolved. Nil means "everything
	// the handler gave us".
	attributes []string
	ctx        context.Context
}

func (w *entryWriter) Entry(e *Entry) error {
	if err := w.ctx.Err(); err != nil {
		// Abandoned, or out of time. Saying so stops a handler walking a
		// directory nobody is reading any more.
		return err
	}
	if w.limit > 0 && int(w.sent.Load()) >= w.limit {
		return errSizeLimit
	}
	w.c.send(entryMessage(w.id, w.project(e), w.typesOnly))
	w.sent.Add(1)
	return nil
}

func (w *entryWriter) Reference(uris ...string) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if len(uris) == 0 {
		// RFC 4511 4.5.3: SIZE (1..MAX). An empty reference tells a client
		// to ask somewhere and names nowhere.
		return errors.New("ldap: a continuation reference with no URIs")
	}
	w.c.send(referenceMessage(w.id, uris))
	return nil
}

// project keeps only the attributes the client selected.
//
// ⛔ It is done HERE rather than left to each handler, because a handler that
// forgets returns MORE than the client asked for -- and "more" out of a
// directory is the attribute somebody deliberately did not request. The
// selection rules are RFC 4511 4.5.1.8: an empty list means all USER
// attributes, "*" means the same, "1.1" means none at all.
func (w *entryWriter) project(e *Entry) *Entry {
	if w.attributes == nil {
		return e
	}
	out := &Entry{DN: e.DN}
	for _, a := range e.Attributes {
		for _, want := range w.attributes {
			if strings.EqualFold(a.Name, want) || strings.EqualFold(baseName(a.Name), want) {
				out.Attributes = append(out.Attributes, a)
				break
			}
		}
	}
	return out
}

// selection resolves the attribute list into either nil (send everything) or
// the names to keep.
func selection(req *SearchRequest) []string {
	if len(req.Attributes) == 0 {
		return nil // all user attributes
	}
	for _, a := range req.Attributes {
		switch a {
		case "*":
			return nil
		case "1.1":
			// RFC 4511 4.5.1.8: "1.1" means no attributes at all, and it is
			// an OID that cannot name one. An empty non-nil slice says
			// "keep nothing", which nil would not.
			return []string{}
		}
	}
	return req.Attributes
}

func (c *conn) search(ctx context.Context, m *message, log *slog.Logger) {
	req, err := decodeSearchRequest(m.op)
	if err != nil {
		c.send(resultMessage(m.id, appSearchResDone, Refuse(ProtocolError, "%v", err)))
		return
	}

	// ⛔ A filter asking for something this server cannot do is refused with
	// inappropriateMatching, NOT answered with the entries that happen to
	// match the rest. RFC 4511 4.5.1.7.7 says so, and the reason is that
	// answering a narrower question quietly is indistinguishable from the
	// answer being right.
	if err := Unsupported(req.Filter); err != nil {
		c.send(resultMessage(m.id, appSearchResDone, Refuse(InappropriateMatching, "%v", err)))
		return
	}

	// ⛔ The filter's SHAPE is logged, never its values. A filter carries
	// what somebody typed -- a name, an address, sometimes a token pasted
	// into the wrong box -- and a directory that writes them down has made a
	// record of every question anybody asked about anybody.
	log.Debug("search",
		"base", req.BaseObject, "scope", req.Scope.String(),
		"filter", shapeOf(req.Filter), "dn", c.BoundDN())

	if c.srv.Search == nil {
		c.send(resultMessage(m.id, appSearchResDone, Refuse(UnwillingToPerform,
			"this server answers no searches")))
		return
	}

	w := &entryWriter{
		c: c, id: m.id, ctx: ctx,
		typesOnly:  req.TypesOnly,
		limit:      effectiveLimit(req.SizeLimit, c.srv.MaxEntries),
		attributes: selection(req),
	}
	r, err := c.srv.Search.Search(ctx, c, req, w)
	switch {
	case errors.Is(err, errSizeLimit):
		// RFC 4511 4.5.2: the entries already sent STAND, and the result
		// says the limit was reached. It is not an error and not an empty
		// answer -- a client that asked for 10 and got 10 has what it asked
		// for.
		c.send(resultMessage(m.id, appSearchResDone, Result{Code: SizeLimitExceeded}))
	case errors.Is(err, context.DeadlineExceeded):
		c.send(resultMessage(m.id, appSearchResDone, Result{Code: TimeLimitExceeded}))
	case errors.Is(err, context.Canceled):
		// Abandoned. RFC 4511 4.11: there is no response to an abandoned
		// operation, so nothing is sent -- a searchResDone here would arrive
		// for an operation the client has already forgotten.
	default:
		c.answer(m.id, appSearchResDone, r, err, log, "search")
	}
}

// effectiveLimit is the smaller of what the client asked for and what the
// server allows. Zero on either side means "no limit from that side".
//
// ⛔ A client asking for more than the server allows does not RAISE the
// server's -- which is what taking the client's value whenever it is
// non-zero would do.
func effectiveLimit(client, server int) int {
	switch {
	case client <= 0:
		return server
	case server <= 0:
		return client
	case client < server:
		return client
	}
	return server
}

// shapeOf renders a filter with its values replaced, for a log line.
//
// The shape is what is worth recording -- which attributes were asked about,
// and how -- and the values are what must not be.
func shapeOf(f Filter) string {
	switch t := f.(type) {
	case *And:
		return "(&" + shapeAll(t.Filters) + ")"
	case *Or:
		return "(|" + shapeAll(t.Filters) + ")"
	case *Not:
		return "(!" + shapeOf(t.Filter) + ")"
	case *Equality:
		return "(" + t.Attribute + "=·)"
	case *GreaterOrEqual:
		return "(" + t.Attribute + ">=·)"
	case *LessOrEqual:
		return "(" + t.Attribute + "<=·)"
	case *Approx:
		return "(" + t.Attribute + "~=·)"
	case *Present:
		return "(" + t.Attribute + "=*)"
	case *Substrings:
		return "(" + t.Attribute + "=·*·)"
	case *ExtensibleMatch:
		return "(" + t.Attribute + ":" + t.MatchingRule + ":=·)"
	}
	return "(?)"
}

func shapeAll(fs []Filter) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(shapeOf(f))
	}
	return b.String()
}
