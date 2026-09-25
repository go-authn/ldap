// SPDX-License-Identifier: BSD-3-Clause

package ldap

import "slices"

// A Control is RFC 4511 4.1.11.
//
// ⛔ Criticality is not decoration. A control marked critical that the server
// does not recognise means the operation MUST be refused with
// unavailableCriticalExtension -- because the client has said the operation
// is not the one it wants unless the control is honoured. Ignoring it
// performs a DIFFERENT operation and reports success: a client that sent
// the ManageDsaIT control critically and had it dropped is editing the alias
// rather than what it points at.
type Control struct {
	Type        string
	Criticality bool
	// Value is absent as nil, which is different from present and empty.
	Value []byte
}

// The controls this server knows by name.
const (
	// OIDPaging is the simple paged results control (RFC 2696).
	OIDPaging = "1.2.840.113556.1.4.319"
	// OIDManageDsaIT says to act on an alias or referral entry itself rather
	// than following it (RFC 3296).
	OIDManageDsaIT = "2.16.840.1.113730.3.4.2"
	// OIDPreRead and OIDPostRead return the entry as it was before, or as it
	// became after, a write (RFC 4527). They are how a client learns what it
	// actually wrote.
	OIDPreRead  = "1.3.6.1.1.13.1"
	OIDPostRead = "1.3.6.1.1.13.2"
)

// The extended operations named in this package.
const (
	// OIDStartTLS is RFC 4511 4.14.
	OIDStartTLS = "1.3.6.1.4.1.1466.20037"
	// OIDWhoAmI is RFC 4532: "who does this connection say I am".
	OIDWhoAmI = "1.3.6.1.4.1.4203.1.11.3"
	// OIDPasswordModify is RFC 3062, the one write every directory is
	// expected to offer even when it offers no other.
	OIDPasswordModify = "1.3.6.1.4.1.4203.1.11.1"
	// OIDCancel is RFC 3909, an abandon that gets an answer.
	OIDCancel = "1.3.6.1.1.8"
)

// supportedControls is the list the server both HONOURS and advertises.
//
// ⛔ ONE list, read in two places: the criticality check in operation.go and
// the root DSE. Written twice they drift, and the two directions of drift are
// both bad -- advertising a control nothing honours sends a client down a path
// that silently does the wrong thing, and honouring one never advertised means
// a client that discovers capabilities properly will never ask for it.
//
// ManageDsaIT is deliberately ABSENT: it is named as a constant because a
// client may send it, but nothing here follows aliases or referrals, so it is
// neither honoured nor advertised. A critical one is therefore refused, which
// is correct.
var supportedControls = []string{OIDPaging, OIDPreRead, OIDPostRead}

// SupportedControls is the request controls this server honours, in the order
// the root DSE reports them.
func SupportedControls() []string { return slices.Clone(supportedControls) }

// The features this package implements, for supportedFeatures (RFC 3674).
//
// Unlike controls these are not optional behaviour a client switches on: they
// are how the filter and the attribute list are READ, always. A client cannot
// discover them any other way -- "(&)" and "+" either mean what the
// specification says or they silently mean something else.
const (
	// FeatureAllOperationalAttributes is RFC 3673: "+" in an attribute list
	// asks for all operational attributes. "Servers supporting this feature
	// SHOULD publish the Object Identifier 1.3.6.1.4.1.4203.1.5.1".
	FeatureAllOperationalAttributes = "1.3.6.1.4.1.4203.1.5.1"
	// FeatureAbsoluteFilters is RFC 4526: "(&)" matches every entry and "(|)"
	// matches none. "Servers supporting this feature SHOULD publish the
	// Object Identifier 1.3.6.1.4.1.4203.1.5.3".
	FeatureAbsoluteFilters = "1.3.6.1.4.1.4203.1.5.3"
)

// supportedFeatures is what the root DSE reports for the above.
var supportedFeatures = []string{FeatureAllOperationalAttributes, FeatureAbsoluteFilters}

// Find returns the named control, or nil.
func Find(controls []Control, oid string) *Control {
	for i := range controls {
		if controls[i].Type == oid {
			return &controls[i]
		}
	}
	return nil
}

// UnhandledCritical returns the first control that is marked critical and is
// not in known, or nil.
//
// A server calls it for every operation and refuses when it returns
// something. Getting this wrong is silent in exactly the direction that
// matters: the operation succeeds, and it is not the operation that was
// asked for.
func UnhandledCritical(controls []Control, known ...string) *Control {
	for i := range controls {
		if !controls[i].Criticality {
			continue
		}
		found := false
		for _, k := range known {
			if controls[i].Type == k {
				found = true
				break
			}
		}
		if !found {
			return &controls[i]
		}
	}
	return nil
}
