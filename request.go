// SPDX-License-Identifier: BSD-3-Clause

package ldap

import "fmt"

// The requests, as RFC 4511 defines them. Every one of them is a type that
// carries the protocol's own fields, because a field a type cannot hold is a
// question a server cannot answer.

// A SearchRequest is RFC 4511 4.5.1.
type SearchRequest struct {
	BaseObject   string
	Scope        Scope
	DerefAliases DerefAliases
	// SizeLimit and TimeLimit are 0 for "no limit from the client". The
	// server may have its own, and the SMALLER of the two applies -- a client
	// asking for more than the server allows does not raise the server's.
	SizeLimit int
	TimeLimit int
	// TypesOnly asks for attribute descriptions WITHOUT their values.
	TypesOnly bool
	Filter    Filter
	// Attributes is the selection (RFC 4511 4.5.1.8). Empty means "all user
	// attributes", which is NOT the same as "everything": operational
	// attributes are returned only when named, or by "+".
	Attributes []string
}

// A BindRequest is RFC 4511 4.2. Exactly one of Simple and SASL is set.
type BindRequest struct {
	Version int
	Name    string
	Simple  []byte
	SASL    *SASLCredentials
}

// SASLCredentials is RFC 4511 4.2's SaslCredentials.
type SASLCredentials struct {
	Mechanism string
	// Credentials is absent as nil and present-and-empty as an empty non-nil
	// slice. RFC 4511 gives the two different meanings and several mechanisms
	// use a zero-length response as a message in its own right.
	Credentials []byte
}

// A CompareRequest is RFC 4511 4.10.
type CompareRequest struct {
	DN        string
	Attribute string
	Value     []byte
}

// An ExtendedRequest is RFC 4511 4.12.
type ExtendedRequest struct {
	Name  string // the OID
	Value []byte // absent as nil
}

// --- Writes ---------------------------------------------------------------

// An AddRequest is RFC 4511 4.7.
type AddRequest struct {
	DN         string
	Attributes []*Attribute

	// PreRead and PostRead are the attribute selections a client asked for
	// with RFC 4527's read entry controls, or nil when it asked for neither.
	// A handler that can honour them fills WriteResult; one that cannot
	// leaves them, and no response control is sent.
	PreRead  *ReadSelection
	PostRead *ReadSelection
}

// A DeleteRequest is RFC 4511 4.8: a DN, and what the client asked to see of
// the entry before it goes.
type DeleteRequest struct {
	DN string

	// PreRead and PostRead are the attribute selections a client asked for
	// with RFC 4527's read entry controls, or nil when it asked for neither.
	// A handler that can honour them fills WriteResult; one that cannot
	// leaves them, and no response control is sent.
	PreRead  *ReadSelection
	PostRead *ReadSelection
}

// A ModifyDNRequest is RFC 4511 4.9.
type ModifyDNRequest struct {
	DN           string
	NewRDN       string
	DeleteOldRDN bool
	// NewSuperior moves the entry to another parent. Empty means "leave it
	// where it is", which is a rename rather than a move.
	NewSuperior string

	// PreRead and PostRead are the attribute selections a client asked for
	// with RFC 4527's read entry controls, or nil when it asked for neither.
	// A handler that can honour them fills WriteResult; one that cannot
	// leaves them, and no response control is sent.
	PreRead  *ReadSelection
	PostRead *ReadSelection
}

// A ModifyOperation is one of RFC 4511 4.6's three.
type ModifyOperation uint8

const (
	// AddValues adds values, leaving any already there.
	AddValues ModifyOperation = 0
	// DeleteValues removes the listed values, or the whole attribute when
	// none are listed.
	DeleteValues ModifyOperation = 1
	// ReplaceValues replaces every value, and with none listed removes the
	// attribute -- which is how a client clears one.
	ReplaceValues ModifyOperation = 2
)

func (o ModifyOperation) String() string {
	switch o {
	case AddValues:
		return "add"
	case DeleteValues:
		return "delete"
	case ReplaceValues:
		return "replace"
	}
	return fmt.Sprintf("modifyOperation(%d)", uint8(o))
}

// A Change is one modification: an operation and what it applies to.
type Change struct {
	Operation ModifyOperation
	Attribute *Attribute
}

// A ModifyRequest is RFC 4511 4.6.
//
// ⛔ Changes is an ORDERED LIST, and that is the whole point of this type.
// RFC 4511 4.6: "the modification operations are performed in the order
// listed", and the whole list is "performed as an atomic operation".
//
// The library this replaces held three buckets -- AddAttributes,
// DeleteAttributes, ReplaceAttributes -- which throws the order away. Then
//
//	delete member=alice; add member=alice     (alice stays)
//	add member=alice; delete member=alice     (alice goes)
//
// arrive as the same request, and a server cannot tell which was asked. That
// is not an edge case: it is how a client that reconciles a group membership
// writes one, and getting it backwards removes somebody's access or grants
// it. A shape that cannot express the difference produces a write that is
// wrong INVISIBLY, which is why writes could not simply be bolted onto that
// library.
//
// Atomicity is the implementation's to provide: a handler that applies half
// this list and then fails has left the directory in a state the client
// never asked for, and must answer as though it had applied none.
type ModifyRequest struct {
	DN      string
	Changes []Change

	// PreRead and PostRead are the attribute selections a client asked for
	// with RFC 4527's read entry controls, or nil when it asked for neither.
	// A handler that can honour them fills WriteResult; one that cannot
	// leaves them, and no response control is sent.
	PreRead  *ReadSelection
	PostRead *ReadSelection
}

// The read-control accessors, so that one function can answer any write.
func (r *AddRequest) preRead() *ReadSelection       { return r.PreRead }
func (r *AddRequest) postRead() *ReadSelection      { return r.PostRead }
func (r *ModifyRequest) preRead() *ReadSelection    { return r.PreRead }
func (r *ModifyRequest) postRead() *ReadSelection   { return r.PostRead }
func (r *DeleteRequest) preRead() *ReadSelection    { return r.PreRead }
func (r *DeleteRequest) postRead() *ReadSelection   { return r.PostRead }
func (r *ModifyDNRequest) preRead() *ReadSelection  { return r.PreRead }
func (r *ModifyDNRequest) postRead() *ReadSelection { return r.PostRead }
