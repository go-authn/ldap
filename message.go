// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"bufio"
	"errors"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// The protocolOp tags (RFC 4511 Appendix B, the APPLICATION tags).
const (
	appBindRequest      = 0
	appBindResponse     = 1
	appUnbindRequest    = 2
	appSearchRequest    = 3
	appSearchResEntry   = 4
	appSearchResDone    = 5
	appModifyRequest    = 6
	appModifyResponse   = 7
	appAddRequest       = 8
	appAddResponse      = 9
	appDelRequest       = 10
	appDelResponse      = 11
	appModDNRequest     = 12
	appModDNResponse    = 13
	appCompareRequest   = 14
	appCompareResponse  = 15
	appAbandonRequest   = 16
	appSearchResRef     = 19
	appExtendedRequest  = 23
	appExtendedResponse = 24
)

// The context tags inside a BindRequest and its response.
const (
	tagAuthSimple      = 0
	tagAuthSASL        = 3
	tagServerSASLCreds = 7
)

// tagReferral is [3] on an LDAPResult, and tagControls is [0] on the message.
const (
	tagReferral = 3
	tagControls = 0
)

// The context tags of an ExtendedRequest and ExtendedResponse.
const (
	tagExtRequestName   = 0
	tagExtRequestValue  = 1
	tagExtResponseName  = 10
	tagExtResponseValue = 11
)

// A message is one LDAPMessage: an id, an operation, and its controls.
type message struct {
	id       int
	op       *ber.Packet
	controls []Control
}

// errClosed is the client having gone away, which is not a fault.
var errClosed = errors.New("ldap: the connection closed")

// readMessage reads one LDAPMessage. The frame is bounded before it is
// decoded -- see readFrame.
func readMessage(r *bufio.Reader, maxSize int) (*message, error) {
	raw, err := readFrame(r, maxSize)
	if err != nil {
		return nil, err
	}
	p, err := decodeFrame(raw)
	if err != nil {
		return nil, err
	}
	// Every access below is length-checked. A malformed packet is a REFUSAL,
	// and the shape of one is decided by whoever is on the other end.
	if len(p.Children) < 2 {
		return nil, fmt.Errorf("ldap: a message with %d fields, want at least 2", len(p.Children))
	}
	id, ok := p.Children[0].Value.(int64)
	if !ok {
		return nil, fmt.Errorf("ldap: the message id is not an integer")
	}
	// RFC 4511 4.1.1: MessageID is INTEGER (0 .. maxInt), and 0 is reserved
	// for the unsolicited notification a SERVER sends. A request carrying it
	// cannot be answered without the answer looking like a notification.
	if id <= 0 || id > 2147483647 {
		return nil, fmt.Errorf("ldap: message id %d is outside (0 .. maxInt)", id)
	}
	m := &message{id: int(id), op: p.Children[1]}
	if len(p.Children) > 2 {
		m.controls, err = decodeControls(p.Children[2])
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}

func decodeControls(p *ber.Packet) ([]Control, error) {
	if p.ClassType != ber.ClassContext || p.Tag != tagControls {
		// Not the controls field. Something else in the third position is a
		// message this package does not understand, and guessing is how a
		// critical control gets dropped.
		return nil, fmt.Errorf("ldap: a third message field that is not controls")
	}
	out := make([]Control, 0, len(p.Children))
	for _, c := range p.Children {
		if len(c.Children) == 0 {
			return nil, fmt.Errorf("ldap: a control with no type")
		}
		ctl := Control{Type: string(c.Children[0].Data.Bytes())}
		// criticality BOOLEAN DEFAULT FALSE, controlValue OCTET STRING
		// OPTIONAL -- so the second field is either, and is told apart by its
		// universal tag rather than by position.
		for _, f := range c.Children[1:] {
			switch f.Tag {
			case ber.TagBoolean:
				b := f.Data.Bytes()
				ctl.Criticality = len(b) > 0 && b[0] != 0
			case ber.TagOctetString:
				ctl.Value = append([]byte{}, f.Data.Bytes()...)
			}
		}
		out = append(out, ctl)
	}
	return out, nil
}

// newMessage starts a response envelope.
func newMessage(id int) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(id), "messageID"))
	return p
}

// appendResult writes the COMPONENTS OF LDAPResult into an operation packet.
func appendResult(op *ber.Packet, r Result) {
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(r.Code), "resultCode"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, r.MatchedDN, "matchedDN"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, r.Diagnostic, "diagnosticMessage"))
	if len(r.Referral) > 0 {
		ref := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagReferral, nil, "referral")
		for _, u := range r.Referral {
			ref.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, u, "uri"))
		}
		op.AppendChild(ref)
	}
}

// resultMessage is the whole response for an operation that answers with
// nothing but an LDAPResult.
func resultMessage(id int, app ber.Tag, r Result) *ber.Packet {
	m := newMessage(id)
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, app, nil, "response")
	appendResult(op, r)
	m.AppendChild(op)
	return m
}

// bindResponse is a BindResponse, with serverSaslCreds when there is one.
func bindResponse(id int, r SASLResult) *ber.Packet {
	m := newMessage(id)
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appBindResponse, nil, "bindResponse")
	appendResult(op, r.Result)
	// ⛔ Sent whenever non-nil, INCLUDING empty: RFC 4511 4.2.2 gives a
	// zero-length OCTET STRING and an absent field different meanings, and
	// mechanisms rely on the distinction.
	if r.ServerCreds != nil {
		op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagServerSASLCreds,
			string(r.ServerCreds), "serverSaslCreds"))
	}
	m.AppendChild(op)
	return m
}

// entryMessage is a SearchResultEntry.
func entryMessage(id int, e *Entry, typesOnly bool) *ber.Packet {
	m := newMessage(id)
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchResEntry, nil, "searchResEntry")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.DN, "objectName"))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, a := range e.Attributes {
		pa := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "partialAttribute")
		pa.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a.Name, "type"))
		vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		// ⛔ typesOnly sends the descriptions with an EMPTY value set, which
		// is what RFC 4511 4.5.1.6 asks for -- not the attribute omitted.
		// A client that asked which attributes exist and got none back reads
		// it as "this entry has none".
		if !typesOnly {
			for _, v := range a.Values {
				vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(v), "value"))
			}
		}
		pa.AppendChild(vals)
		attrs.AppendChild(pa)
	}
	op.AppendChild(attrs)
	m.AppendChild(op)
	return m
}

// referenceMessage is a SearchResultReference (RFC 4511 4.5.3).
func referenceMessage(id int, uris []string) *ber.Packet {
	m := newMessage(id)
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchResRef, nil, "searchResRef")
	for _, u := range uris {
		op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, u, "uri"))
	}
	m.AppendChild(op)
	return m
}

// extendedResponse is an ExtendedResponse (RFC 4511 4.12).
func extendedResponse(id int, r ExtendedResult) *ber.Packet {
	m := newMessage(id)
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appExtendedResponse, nil, "extendedResp")
	appendResult(op, r.Result)
	if r.Name != "" {
		op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagExtResponseName, r.Name, "responseName"))
	}
	if r.Value != nil {
		op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagExtResponseValue, string(r.Value), "responseValue"))
	}
	m.AppendChild(op)
	return m
}

// appendControls attaches response controls to a message (RFC 4511 4.1.11).
//
// They go on the LDAPMessage, not on the operation: a control is about the
// message, and a client looking for the paged-results cookie reads it there.
func appendControls(m *ber.Packet, controls ...Control) *ber.Packet {
	if len(controls) == 0 {
		return m
	}
	list := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagControls, nil, "controls")
	for _, c := range controls {
		one := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "control")
		one.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.Type, "controlType"))
		if c.Criticality {
			one.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "criticality"))
		}
		if c.Value != nil {
			one.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(c.Value), "controlValue"))
		}
		list.AppendChild(one)
	}
	m.AppendChild(list)
	return m
}
