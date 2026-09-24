// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"context"
	"crypto/tls"
	"net"
)

// A Session is what a handler knows about the client it is answering.
//
// ⛔ BoundDN is here rather than passed as a string, and TLS is here at all,
// because the two questions a write has to ask are "who is this" and "over
// what". A handler given only a DN cannot refuse a password change sent in
// the clear, and every server that wants to must reach for the raw net.Conn
// and type-assert it -- which is a thing each of them then gets slightly
// differently.
type Session interface {
	// BoundDN is who this connection proved itself to be, and is empty for
	// anonymous. RFC 4511 4.2.1: a failed bind leaves it empty, and so does
	// a bind still in progress.
	BoundDN() string
	// TLS is the connection's TLS state, and ok is false on a connection that
	// was never protected -- including one where StartTLS was offered and
	// never asked for.
	TLS() (tls.ConnectionState, bool)
	// RemoteAddr is where the client is.
	RemoteAddr() net.Addr
	// Conn is the underlying connection, for the handler that genuinely needs
	// it. Reading or writing it corrupts the LDAP stream; it is here for
	// peer certificates and addresses.
	Conn() net.Conn
	// Controls are the request's controls (RFC 4511 4.1.11).
	Controls() []Control
}

// A Binder answers a simple bind.
//
// ⛔ The password is []byte, not string. It goes to a constant-time
// comparison or to a KDF, both of which take bytes, and a string cannot be
// wiped -- Go strings are immutable, so a password that arrives as one stays
// in memory until the collector happens to reach it. It is also not
// necessarily UTF-8.
type Binder interface {
	Bind(ctx context.Context, s Session, req *BindRequest) (Result, error)
}

// A SASLBinder answers a SASL bind, which may take several round trips.
//
// It is separate from Binder because a server may implement one and not the
// other, and because the two carry different things: a SASL exchange has a
// challenge to send back and an identity of its own, and a simple bind has
// neither.
type SASLBinder interface {
	// Mechanisms is what this server offers, for the root DSE to advertise.
	// A client discovers what it may use by reading
	// supportedSASLMechanisms, so a mechanism missing here is one nothing
	// will ever try.
	Mechanisms() []string
	// BindSASL answers one step. A Result with code SaslBindInProgress and a
	// non-nil ServerCreds is a challenge; one with Success must set BoundDN,
	// because the name field of a SASL bind is ignored (RFC 4513 5.2.1) and
	// the mechanism is the only thing that knows who this is.
	BindSASL(ctx context.Context, s Session, req *BindRequest) (SASLResult, error)
}

// A SASLResult is what one step of a SASL bind decided.
type SASLResult struct {
	Result
	// ServerCreds is serverSaslCreds, sent whenever it is non-nil INCLUDING
	// empty: RFC 4511 4.2.2 gives absent and zero-length different meanings.
	ServerCreds []byte
	// BoundDN is who the exchange proved, read only when the code is
	// Success. Empty binds the connection as anonymous, which is a
	// legitimate thing for a mechanism to decide and never an accident the
	// server can spot.
	BoundDN string
}

// A Searcher answers a search.
//
// ⛔ Entries are written to w as they are found, not returned as a slice.
// A directory that materialises every match before sending any has decided
// that its largest answer fits in memory, and the search that finds out it
// does not is the one a client ran by accident. Writing as it goes also lets
// the server stop at the size limit without the handler having to know what
// the limit is.
type Searcher interface {
	Search(ctx context.Context, s Session, req *SearchRequest, w EntryWriter) (Result, error)
}

// An EntryWriter takes the entries a search found.
type EntryWriter interface {
	// Entry sends one. The error is the client going away or a limit being
	// reached, and a handler that ignores it keeps walking a directory
	// nobody is reading any more.
	Entry(*Entry) error
	// Reference sends a continuation reference (RFC 4511 4.5.3): other
	// servers to ask for the part of the tree this one does not hold.
	Reference(uris ...string) error
}

// A Comparer answers a compare (RFC 4511 4.10).
//
// ⛔ It answers CompareTrue or CompareFalse, and neither is an error.
// A handler returning Success is saying something the protocol has no word
// for, and a client reading `code == 0` as "they matched" would be wrong
// about every entry.
type Comparer interface {
	Compare(ctx context.Context, s Session, req *CompareRequest) (Result, error)
}

// An Extender answers an extended operation (RFC 4511 4.12).
//
// StartTLS is NOT routed here: it changes the connection under the protocol
// and the server does it itself. A handler that received it could not
// perform the handshake without racing the server's own reader.
type Extender interface {
	// ExtendedNames is the OIDs this handler answers, for the root DSE to
	// advertise as supportedExtension.
	ExtendedNames() []string
	Extended(ctx context.Context, s Session, req *ExtendedRequest) (ExtendedResult, error)
}

// An ExtendedResult is an extended response (RFC 4511 4.12).
type ExtendedResult struct {
	Result
	Name  string // responseName, usually the request's OID or empty
	Value []byte // responseValue, absent as nil
}

// --- Writes ---------------------------------------------------------------
//
// ⛔ Each of these is its own interface, and a server implements the ones it
// means. An operation with no handler is answered unwillingToPerform, which
// is what RFC 4511 4.1.9 means by it, and NOT insufficientAccessRights: "I
// do not do that" and "you may not do that" send an administrator looking in
// two different places, and telling a client the second when the first is
// true sends them to argue about permissions that do not exist.

// An Adder adds an entry (RFC 4511 4.7).
type Adder interface {
	Add(ctx context.Context, s Session, req *AddRequest) (Result, error)
}

// A Modifier modifies one (RFC 4511 4.6).
//
// ⛔ The changes are applied IN ORDER and ATOMICALLY -- see ModifyRequest.
// A handler that applies half of them and fails has left the directory in a
// state the client never asked for, and must answer as though it applied
// none.
type Modifier interface {
	Modify(ctx context.Context, s Session, req *ModifyRequest) (Result, error)
}

// A Deleter deletes one (RFC 4511 4.8).
type Deleter interface {
	Delete(ctx context.Context, s Session, req *DeleteRequest) (Result, error)
}

// A DNModifier renames or moves one (RFC 4511 4.9).
type DNModifier interface {
	ModifyDN(ctx context.Context, s Session, req *ModifyDNRequest) (Result, error)
}

// An Abandoner is told a client gave up on an operation (RFC 4511 4.11).
//
// There is no response to an abandon, ever -- which is why this returns
// nothing. A server that answered one would be sending a message the client
// has no way to interpret.
type Abandoner interface {
	Abandon(ctx context.Context, s Session, messageID int)
}

// A Disconnecter is told a connection ended, however it ended.
type Disconnecter interface {
	Disconnect(s Session)
}
