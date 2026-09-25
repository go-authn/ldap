// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"
)

// A Server answers LDAP on a listener.
//
// ⛔ The handlers are fields rather than one big interface, and a nil one
// means "this server does not do that". An operation with no handler is
// answered unwillingToPerform, NOT insufficientAccessRights: "I do not do
// that" and "you may not do that" send an administrator to two different
// places, and saying the second when the first is true starts an argument
// about permissions that do not exist.
type Server struct {
	// Bind answers a simple bind. With none, every simple bind is refused --
	// a server with no way to prove anybody should not let anybody in.
	Bind Binder
	// SASL answers a SASL bind, and names the mechanisms the root DSE
	// advertises.
	SASL SASLBinder
	// Search answers a search. With none, only the root DSE is answerable.
	Search Searcher

	Compare  Comparer
	Extended Extender

	// The writes. Each is independently optional.
	Add      Adder
	Modify   Modifier
	Delete   Deleter
	ModifyDN DNModifier

	Abandon      Abandoner
	Disconnected Disconnecter

	// TLSConfig, when set, makes StartTLS available (RFC 4511 4.14). It is
	// also what an ldaps:// listener is wrapped with, but that is the
	// caller's to do -- a tls.Listener is a listener like any other.
	TLSConfig *tls.Config

	// RequireTLS refuses every operation on a connection that is not
	// protected, with confidentialityRequired.
	//
	// ⛔ It exists because StartTLS is asked for by the CLIENT: a server that
	// merely OFFERS it has promised nothing, and a client that does not ask
	// sends its bind password in the clear while everything looks normal at
	// both ends. This is what turns "we have a certificate" from an offer
	// into a guarantee.
	RequireTLS bool

	// MaxMessageSize bounds one message. Zero means DefaultMaxMessageSize.
	MaxMessageSize int
	// MaxPagedSearches is how many paged searches (RFC 2696) one connection
	// may hold open at once. Zero means DefaultMaxPagedSearches.
	//
	// ⛔ Each one is a goroutine parked on its next entry, holding whatever
	// the handler holds. A client that starts them and never finishes them
	// is a resource exhaustion that needs no credentials, because the first
	// page is served before anything is known about it.
	MaxPagedSearches int
	// MaxEntries bounds what one search may return, whatever the client
	// asked for. Zero means no server-side limit.
	//
	// The SMALLER of this and the client's sizeLimit applies: a client
	// asking for more than the server allows does not raise the server's.
	MaxEntries int
	// Timeout is how long one operation may take. Zero means no limit.
	Timeout time.Duration
	// IdleTimeout closes a connection nothing has been sent on. Zero means
	// never.
	IdleTimeout time.Duration

	// NamingContexts is what this server holds, published on the root DSE so
	// that a client can find out where to search (RFC 4512 5.1.2).
	NamingContexts []string
	// AltServers are other servers to try when this one is unavailable.
	AltServers []string
	// Vendor and VendorVersion identify the implementation (RFC 3045).
	Vendor        string
	VendorVersion string

	// Log receives what happened. Nil discards it.
	//
	// ⛔ Nothing here logs an assertion VALUE. A search filter carries what
	// somebody typed -- a name, an email address, sometimes a token pasted
	// into the wrong box -- and a directory that writes them to disk has
	// made a record of every question anybody asked about anybody. The
	// filter's SHAPE is logged instead.
	Log *slog.Logger

	mu        sync.Mutex
	listeners map[net.Listener]struct{}
	conns     map[*conn]struct{}
	closing   bool
}

func (s *Server) logger() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (s *Server) maxMessageSize() int {
	if s.MaxMessageSize > 0 {
		return s.MaxMessageSize
	}
	return DefaultMaxMessageSize
}

// Serve answers connections until the listener is closed.
func (s *Server) Serve(ln net.Listener) error {
	if !s.track(ln) {
		return net.ErrClosed
	}
	defer s.untrack(ln)

	for {
		c, err := ln.Accept()
		if err != nil {
			if s.isClosing() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.serve(c)
	}
}

// ListenAndServe listens on addr and serves it.
func (s *Server) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Close stops the listeners and closes every connection.
//
// ⛔ It closes the CONNECTIONS too, not only the listeners. A server that
// stopped accepting and left the established ones running looks stopped and
// is still answering, which is the shape of a restart that does not take.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closing = true
	lns := make([]net.Listener, 0, len(s.listeners))
	for ln := range s.listeners {
		lns = append(lns, ln)
	}
	cs := make([]*conn, 0, len(s.conns))
	for c := range s.conns {
		cs = append(cs, c)
	}
	s.mu.Unlock()

	var err error
	for _, ln := range lns {
		if e := ln.Close(); e != nil && err == nil {
			err = e
		}
	}
	for _, c := range cs {
		c.close()
	}
	return err
}

func (s *Server) isClosing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing
}

func (s *Server) track(ln net.Listener) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	if s.listeners == nil {
		s.listeners = map[net.Listener]struct{}{}
	}
	s.listeners[ln] = struct{}{}
	return true
}

func (s *Server) untrack(ln net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.listeners, ln)
}

func (s *Server) add(c *conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	if s.conns == nil {
		s.conns = map[*conn]struct{}{}
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) remove(c *conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, c)
}
