// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Reading the requests off the wire.
//
// ⛔ Every access is length-checked, because the shape of what arrives is
// decided by whoever connected. The library this replaces indexed
// Children[0] unguarded in several of these positions, and a malformed
// packet took the whole process down rather than being refused.

func child(p *ber.Packet, i int, what string) (*ber.Packet, error) {
	if len(p.Children) <= i {
		return nil, fmt.Errorf("ldap: %s is missing (%d fields)", what, len(p.Children))
	}
	return p.Children[i], nil
}

func decodeBindRequest(p *ber.Packet) (*BindRequest, error) {
	if len(p.Children) != 3 {
		return nil, fmt.Errorf("ldap: a bind request with %d fields, want 3", len(p.Children))
	}
	version, ok := p.Children[0].Value.(int64)
	if !ok {
		return nil, fmt.Errorf("ldap: the bind version is not an integer")
	}
	// RFC 4511 4.2: version is INTEGER (1 .. 127), and this server speaks 3.
	// A version outside the range is a protocol error; version 2 is a
	// DIFFERENT protocol and is refused as such rather than answered as
	// though it were 3.
	if version < 1 || version > 127 {
		return nil, fmt.Errorf("ldap: bind version %d is outside (1 .. 127)", version)
	}
	req := &BindRequest{Version: int(version), Name: string(p.Children[1].Data.Bytes())}
	auth := p.Children[2]
	switch auth.Tag {
	case tagAuthSimple:
		// Copied, because the packet's buffer is reused and a password kept
		// by reference would change under whoever held it.
		req.Simple = append([]byte{}, auth.Data.Bytes()...)
	case tagAuthSASL:
		creds, err := decodeSASLCredentials(auth)
		if err != nil {
			return nil, err
		}
		req.SASL = creds
	default:
		return nil, fmt.Errorf("ldap: authentication choice %d is neither simple nor SASL", auth.Tag)
	}
	return req, nil
}

func decodeSASLCredentials(p *ber.Packet) (*SASLCredentials, error) {
	if len(p.Children) < 1 {
		return nil, fmt.Errorf("ldap: SASL credentials with no mechanism")
	}
	creds := &SASLCredentials{Mechanism: string(p.Children[0].Data.Bytes())}
	// credentials is OPTIONAL: absent is nil, present-and-empty is an empty
	// non-nil slice, and the two are not the same answer.
	if len(p.Children) > 1 {
		creds.Credentials = append([]byte{}, p.Children[1].Data.Bytes()...)
	}
	return creds, nil
}

func decodeSearchRequest(p *ber.Packet) (*SearchRequest, error) {
	if len(p.Children) != 8 {
		return nil, fmt.Errorf("ldap: a search request with %d fields, want 8", len(p.Children))
	}
	scope, ok := p.Children[1].Value.(int64)
	if !ok || scope < 0 || scope > 2 {
		return nil, fmt.Errorf("ldap: scope %v is not one of base, one or sub", p.Children[1].Value)
	}
	deref, ok := p.Children[2].Value.(int64)
	if !ok || deref < 0 || deref > 3 {
		return nil, fmt.Errorf("ldap: derefAliases %v is not one of the four", p.Children[2].Value)
	}
	sizeLimit, ok := p.Children[3].Value.(int64)
	if !ok || sizeLimit < 0 {
		return nil, fmt.Errorf("ldap: sizeLimit %v is not a non-negative integer", p.Children[3].Value)
	}
	timeLimit, ok := p.Children[4].Value.(int64)
	if !ok || timeLimit < 0 {
		return nil, fmt.Errorf("ldap: timeLimit %v is not a non-negative integer", p.Children[4].Value)
	}
	typesOnly, ok := p.Children[5].Value.(bool)
	if !ok {
		return nil, fmt.Errorf("ldap: typesOnly is not a boolean")
	}
	filter, err := DecodeFilter(p.Children[6])
	if err != nil {
		return nil, err
	}
	req := &SearchRequest{
		BaseObject:   string(p.Children[0].Data.Bytes()),
		Scope:        Scope(scope),
		DerefAliases: DerefAliases(deref),
		SizeLimit:    int(sizeLimit),
		TimeLimit:    int(timeLimit),
		TypesOnly:    typesOnly,
		Filter:       filter,
	}
	for _, a := range p.Children[7].Children {
		req.Attributes = append(req.Attributes, string(a.Data.Bytes()))
	}
	return req, nil
}

func decodeCompareRequest(p *ber.Packet) (*CompareRequest, error) {
	if len(p.Children) != 2 {
		return nil, fmt.Errorf("ldap: a compare request with %d fields, want 2", len(p.Children))
	}
	ava := p.Children[1]
	if len(ava.Children) != 2 {
		return nil, fmt.Errorf("ldap: a compare assertion with %d fields, want 2", len(ava.Children))
	}
	return &CompareRequest{
		DN:        string(p.Children[0].Data.Bytes()),
		Attribute: string(ava.Children[0].Data.Bytes()),
		Value:     append([]byte{}, ava.Children[1].Data.Bytes()...),
	}, nil
}

func decodeExtendedRequest(p *ber.Packet) (*ExtendedRequest, error) {
	if len(p.Children) < 1 || len(p.Children) > 2 {
		return nil, fmt.Errorf("ldap: an extended request with %d fields, want 1 or 2", len(p.Children))
	}
	if p.Children[0].Tag != tagExtRequestName {
		return nil, fmt.Errorf("ldap: an extended request whose first field is not its name")
	}
	req := &ExtendedRequest{Name: string(p.Children[0].Data.Bytes())}
	if len(p.Children) == 2 {
		req.Value = append([]byte{}, p.Children[1].Data.Bytes()...)
	}
	return req, nil
}

func decodeAttributes(p *ber.Packet) ([]*Attribute, error) {
	out := make([]*Attribute, 0, len(p.Children))
	for _, a := range p.Children {
		name, err := child(a, 0, "an attribute type")
		if err != nil {
			return nil, err
		}
		vals, err := child(a, 1, "an attribute value set")
		if err != nil {
			return nil, err
		}
		attr := &Attribute{Name: string(name.Data.Bytes())}
		for _, v := range vals.Children {
			attr.Values = append(attr.Values, append([]byte{}, v.Data.Bytes()...))
		}
		out = append(out, attr)
	}
	return out, nil
}

func decodeAddRequest(p *ber.Packet) (*AddRequest, error) {
	if len(p.Children) != 2 {
		return nil, fmt.Errorf("ldap: an add request with %d fields, want 2", len(p.Children))
	}
	attrs, err := decodeAttributes(p.Children[1])
	if err != nil {
		return nil, err
	}
	// RFC 4511 4.7: an Attribute is a PartialAttribute with SIZE(1..MAX)
	// values. An add carrying an attribute with NO values is asking for an
	// entry that cannot exist, and accepting it would create one whose
	// attribute list disagrees with what it holds.
	for _, a := range attrs {
		if len(a.Values) == 0 {
			return nil, fmt.Errorf("ldap: the add names %q with no values", a.Name)
		}
	}
	return &AddRequest{DN: string(p.Children[0].Data.Bytes()), Attributes: attrs}, nil
}

func decodeModifyRequest(p *ber.Packet) (*ModifyRequest, error) {
	if len(p.Children) != 2 {
		return nil, fmt.Errorf("ldap: a modify request with %d fields, want 2", len(p.Children))
	}
	req := &ModifyRequest{DN: string(p.Children[0].Data.Bytes())}
	// ⛔ IN ORDER. RFC 4511 4.6: "the modification operations are performed
	// in the order listed". The order IS the request -- see ModifyRequest.
	for _, ch := range p.Children[1].Children {
		op, err := child(ch, 0, "a modify operation")
		if err != nil {
			return nil, err
		}
		n, ok := op.Value.(int64)
		if !ok || n < 0 || n > 2 {
			return nil, fmt.Errorf("ldap: modify operation %v is not add, delete or replace", op.Value)
		}
		pa, err := child(ch, 1, "the attribute a modify operates on")
		if err != nil {
			return nil, err
		}
		attrs, err := decodeAttributes(wrap(pa))
		if err != nil {
			return nil, err
		}
		req.Changes = append(req.Changes, Change{
			Operation: ModifyOperation(n),
			Attribute: attrs[0],
		})
	}
	return req, nil
}

// wrap puts one packet where decodeAttributes expects a list of them.
func wrap(p *ber.Packet) *ber.Packet {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "wrapper")
	seq.AppendChild(p)
	return seq
}

func decodeModifyDNRequest(p *ber.Packet) (*ModifyDNRequest, error) {
	if len(p.Children) < 3 || len(p.Children) > 4 {
		return nil, fmt.Errorf("ldap: a modifyDN request with %d fields, want 3 or 4", len(p.Children))
	}
	deleteOld, ok := p.Children[2].Value.(bool)
	if !ok {
		return nil, fmt.Errorf("ldap: deleteoldrdn is not a boolean")
	}
	req := &ModifyDNRequest{
		DN:           string(p.Children[0].Data.Bytes()),
		NewRDN:       string(p.Children[1].Data.Bytes()),
		DeleteOldRDN: deleteOld,
	}
	if len(p.Children) == 4 {
		req.NewSuperior = string(p.Children[3].Data.Bytes())
	}
	return req, nil
}
