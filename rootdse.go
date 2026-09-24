// SPDX-License-Identifier: BSD-3-Clause

package ldap

import "strings"

// The root DSE (RFC 4512 5.1): what a client reads BEFORE it binds, to find
// out what this server can do.
//
// ⛔ Every attribute on it is OPERATIONAL, so a bare search returns almost
// nothing and `+` returns the lot. RFC 4512 5.1 is explicit: root DSE
// attributes "are not returned in search requests unless requested by name".
// A server that sends them all for a bare query is handing a client the
// answer to a question it did not ask -- which for supportedSASLMechanisms
// and namingContexts is a list of ways in and a map of the tree.

// rootDSE builds this server's own entry.
//
// It is built per CONNECTION rather than once, because RFC 4512 5.1 says the
// values "may depend on session-specific factors": StartTLS is not offered
// on a connection that is already protected, and a mechanism that rests on
// the transport should not be advertised where there is no transport to rest
// on.
func (c *conn) rootDSE() *Entry {
	e := &Entry{DN: ""}
	// objectClass is the one USER attribute here, which is why a bare query
	// against the root DSE comes back with it and nothing else.
	e.Attributes = append(e.Attributes, StringAttribute("objectClass", "top", "OpenLDAProotDSE"))
	e.Attributes = append(e.Attributes, OperationalAttribute("supportedLDAPVersion", "3"))

	if len(c.srv.NamingContexts) > 0 {
		e.Attributes = append(e.Attributes, OperationalAttribute("namingContexts", c.srv.NamingContexts...))
	}
	if len(c.srv.AltServers) > 0 {
		e.Attributes = append(e.Attributes, OperationalAttribute("altServer", c.srv.AltServers...))
	}

	// ⛔ A mechanism missing here is one nothing will ever try: a client
	// discovers what it may use by reading this attribute. Advertising one
	// the server cannot answer is the opposite mistake and sends a client
	// down a path that ends in authMethodNotSupported.
	if c.srv.SASL != nil {
		if ms := c.srv.SASL.Mechanisms(); len(ms) > 0 {
			e.Attributes = append(e.Attributes, OperationalAttribute("supportedSASLMechanisms", ms...))
		}
	}

	var extensions []string
	// StartTLS is offered only where it can still be used. On a connection
	// that is already protected a second one is an operationsError, and
	// advertising it there invites exactly that.
	if c.srv.TLSConfig != nil && !c.encrypted() {
		extensions = append(extensions, OIDStartTLS)
	}
	extensions = append(extensions, OIDWhoAmI)
	if c.srv.Extended != nil {
		extensions = append(extensions, c.srv.Extended.ExtendedNames()...)
	}
	e.Attributes = append(e.Attributes, OperationalAttribute("supportedExtension", extensions...))

	if v := c.srv.Vendor; v != "" {
		e.Attributes = append(e.Attributes, OperationalAttribute("vendorName", v))
	}
	if v := c.srv.VendorVersion; v != "" {
		e.Attributes = append(e.Attributes, OperationalAttribute("vendorVersion", v))
	}
	return e
}

// isRootDSERead reports whether this search is the one RFC 4512 5.1
// describes: an empty base, at base scope.
//
// ⛔ The scope matters. "The root DSE SHALL NOT be included if the client
// performs a subtree search starting from the root" -- so a search with an
// empty base and a subtree scope must reach the handler like any other, and
// must not have this entry mixed into its answer.
func isRootDSERead(req *SearchRequest) bool {
	return strings.TrimSpace(req.BaseObject) == "" && req.Scope == ScopeBaseObject
}
