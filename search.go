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
	// selection is what the client asked to be sent back, already resolved.
	selection selector
	ctx       context.Context
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

// A selector is what a client asked to be sent back.
//
// ⛔ It is resolved HERE and applied HERE rather than left to each handler,
// because a handler that forgets returns MORE than the client asked for --
// and "more" out of a directory is the attribute somebody deliberately did
// not request.
type selector struct {
	// user is true when "*" or an empty list asked for the user attributes.
	user bool
	// operational is true when "+" asked for the ones the directory keeps
	// (RFC 3673).
	operational bool
	// named is the attributes asked for by name, which are sent whether they
	// are operational or not -- that is what "unless requested by name"
	// means.
	named []string
}

// selection resolves the attribute list (RFC 4511 4.5.1.8, RFC 3673).
//
//   - an empty list, or "*", is all USER attributes
//   - "+" is all OPERATIONAL attributes
//   - "1.1" is none at all, and is an OID that cannot name one
//   - anything else is a name, and a named attribute is sent even when it is
//     operational
func selection(req *SearchRequest) selector {
	if len(req.Attributes) == 0 {
		return selector{user: true}
	}
	var s selector
	for _, a := range req.Attributes {
		switch a {
		case "*":
			s.user = true
		case "+":
			s.operational = true
		case "1.1":
			// Nothing at all. It is listed alone by every client that means
			// it, and a client that sends it alongside a name has asked two
			// contradictory things -- the name wins, because it is the
			// specific one.
		default:
			s.named = append(s.named, a)
		}
	}
	return s
}

// wants reports whether an attribute was selected.
func (s selector) wants(a *Attribute) bool {
	for _, want := range s.named {
		if strings.EqualFold(a.Name, want) || strings.EqualFold(baseName(a.Name), want) {
			return true
		}
	}
	if a.Operational {
		return s.operational
	}
	return s.user
}

// project keeps only the attributes the client selected.
func (w *entryWriter) project(e *Entry) *Entry {
	out := &Entry{DN: e.DN}
	for _, a := range e.Attributes {
		if w.selection.wants(a) {
			out.Attributes = append(out.Attributes, a)
		}
	}
	return out
}

// searchRootDSE answers this server's own entry (RFC 4512 5.1).
func (c *conn) searchRootDSE(ctx context.Context, m *message, req *SearchRequest) {
	w := &entryWriter{c: c, id: m.id, ctx: ctx, typesOnly: req.TypesOnly, selection: selection(req)}
	// The filter still applies: a client asking for (objectClass=nothing)
	// against the root DSE has asked a question with no answer, and giving
	// it one anyway would make the filter decorative.
	if req.Filter.Matches(c.rootDSE()) {
		if err := w.Entry(c.rootDSE()); err != nil {
			return
		}
	}
	c.send(resultMessage(m.id, appSearchResDone, Result{Code: Success}))
}

func (c *conn) search(ctx context.Context, m *message, req *SearchRequest, log *slog.Logger) {
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
		typesOnly: req.TypesOnly,
		limit:     effectiveLimit(req.SizeLimit, c.srv.MaxEntries),
		selection: selection(req),
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
