// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// The read entry controls (RFC 4527): "show me the entry as it was before
// this write", and "as it became".
//
// ⛔ They are answered by the HANDLER, not by this package, and that is not a
// convenience. RFC 4527 requires the read and the update to be "one atomic
// action isolated from other update operations". A server that read the
// entry, performed the write, and read it again would be doing three things
// with gaps between them -- and the copy it returned could be one somebody
// else's write made, which is a lie in the shape of a confirmation.
//
// So the request carries the SELECTION and the handler returns the entries.
// What this package does is parse the control, apply the attribute selection
// so that every handler does not re-implement it, and refuse the pairings
// that cannot mean anything.

// A ReadSelection is the attributes a read entry control asked for.
//
// It is a type rather than a []string so that "did not ask" and "asked for
// everything" are different things: a nil *ReadSelection means no control
// arrived, and one with no attributes means the empty selection, which RFC
// 4511 4.5.1.8 makes "all user attributes".
type ReadSelection struct{ Attributes []string }

// Keep returns a copy of e carrying only the attributes this selection asked
// for, by the same rules a search uses.
func (s *ReadSelection) Keep(e *Entry) *Entry {
	if e == nil {
		return nil
	}
	sel := selection(&SearchRequest{Attributes: s.Attributes})
	out := &Entry{DN: e.DN}
	for _, a := range e.Attributes {
		if sel.wants(a) {
			out.Attributes = append(out.Attributes, a)
		}
	}
	return out
}

// decodeReadSelection reads the request control's value: a BER-encoded
// AttributeSelection (RFC 4527 3.1), which is a SEQUENCE OF LDAPString.
func decodeReadSelection(c *Control) (*ReadSelection, error) {
	s := &ReadSelection{}
	if len(c.Value) == 0 {
		// An absent value is an empty selection, which means all user
		// attributes. Refusing it would refuse the commonest form.
		return s, nil
	}
	p, err := ber.DecodePacketErr(c.Value)
	if err != nil {
		return nil, fmt.Errorf("ldap: the %s control does not parse: %w", c.Type, err)
	}
	for _, child := range p.Children {
		s.Attributes = append(s.Attributes, string(child.Data.Bytes()))
	}
	return s, nil
}

// encodeReadEntry builds the response control: a BER-encoded
// SearchResultEntry carrying the copy the client asked for.
func encodeReadEntry(oid string, e *Entry) Control {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchResEntry, nil, "SearchResultEntry")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.DN, "objectName"))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, a := range e.Attributes {
		pa := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "partialAttribute")
		pa.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a.Name, "type"))
		vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		for _, v := range a.Values {
			vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(v), "value"))
		}
		pa.AppendChild(vals)
		attrs.AppendChild(pa)
	}
	op.AppendChild(attrs)
	return Control{Type: oid, Value: op.Bytes()}
}

// readControls pulls the pre-read and post-read selections off a request,
// refusing the pairings RFC 4527 3 does not define.
//
// ⛔ A pre-read on an ADD asks to see an entry that did not exist, and a
// post-read on a DELETE asks to see one that no longer does. Neither can be
// answered, so a CRITICAL one refuses the operation -- the client said the
// operation is not the one it wants without it -- and a non-critical one is
// dropped, which is what non-critical means.
func readControls(controls []Control, op ber.Tag) (pre, post *ReadSelection, refuse *Control, err error) {
	for i := range controls {
		c := &controls[i]
		var allowed bool
		switch c.Type {
		case OIDPreRead:
			allowed = op == appModifyRequest || op == appDelRequest || op == appModDNRequest
		case OIDPostRead:
			allowed = op == appAddRequest || op == appModifyRequest || op == appModDNRequest
		default:
			continue
		}
		if !allowed {
			if c.Criticality {
				return nil, nil, c, nil
			}
			continue
		}
		sel, decErr := decodeReadSelection(c)
		if decErr != nil {
			return nil, nil, nil, decErr
		}
		if c.Type == OIDPreRead {
			pre = sel
		} else {
			post = sel
		}
	}
	return pre, post, nil, nil
}
