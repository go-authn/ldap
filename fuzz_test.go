// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"bufio"
	"bytes"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// FuzzMessage feeds whatever a client may send, before any bind, through
// everything that reads it: the frame, the element count, the message, the
// decoder for its operation, and its controls. Nothing may panic -- a panic
// in a connection's goroutine is the process -- and a filter that decodes
// must survive a trip through the wire form unchanged.
//
// The seeds run with every `go test`; `go test -fuzz FuzzMessage` explores.
func FuzzMessage(f *testing.F) {
	t := &testing.T{}
	f.Add(bindRequest(t, "cn=reader,dc=example,dc=org", "let me read"))
	f.Add(searchRequest(t, "dc=example,dc=org", "(&(objectClass=person)(|(uid=a*b*c)(!(cn~=x)))(mail:caseExactMatch:=y))", "cn", "+"))
	f.Add(searchRequest(t, "", "(objectClass=*)"))
	f.Add(flatMessage(64))
	for _, op := range []int{appModifyRequest, appAddRequest, appDelRequest, appModDNRequest, appCompareRequest, appExtendedRequest, appAbandonRequest} {
		m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
		m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "id"))
		p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(op), nil, "op")
		p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid=a,dc=example,dc=org", "dn"))
		m.AppendChild(p)
		f.Add(m.Bytes())
	}

	entry := &Entry{DN: "uid=a,dc=example,dc=org", Attributes: []*Attribute{
		{Name: "objectClass", Values: [][]byte{[]byte("person")}},
		{Name: "uid", Values: [][]byte{[]byte("abc")}},
		{Name: "cn", Values: [][]byte{[]byte("x"), []byte("")}},
	}}

	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := readMessage(bufio.NewReader(bytes.NewReader(b)), DefaultMaxMessageSize, DefaultMaxMessageElements)
		if err != nil {
			return
		}
		for i := range m.controls {
			_, _ = decodePaged(&m.controls[i])
			_, _ = decodeReadSelection(&m.controls[i])
		}
		switch m.op.Tag {
		case appBindRequest:
			_, _ = decodeBindRequest(m.op)
		case appSearchRequest:
			req, err := decodeSearchRequest(m.op)
			if err != nil {
				return
			}
			roundTrip(t, req.Filter, entry)
		case appModifyRequest:
			_, _ = decodeModifyRequest(m.op)
		case appAddRequest:
			_, _ = decodeAddRequest(m.op)
		case appModDNRequest:
			_, _ = decodeModifyDNRequest(m.op)
		case appCompareRequest:
			_, _ = decodeCompareRequest(m.op)
		case appExtendedRequest:
			_, _ = decodeExtendedRequest(m.op)
		}
	})
}

// roundTrip holds a decoded filter to what this package promises of one:
// the string form, the wire form and the matcher read the same tree.
func roundTrip(t *testing.T, f Filter, e *Entry) {
	t.Helper()
	s := f.String()
	got := f.Matches(e)
	p, err := EncodeFilter(f)
	if err != nil {
		t.Fatalf("a decoded filter %s will not encode: %v", s, err)
	}
	again, err := DecodeFilter(ber.DecodePacket(p.Bytes()))
	if err != nil {
		t.Fatalf("%s, encoded, will not decode: %v", s, err)
	}
	if again.String() != s {
		t.Fatalf("through the wire %s became %s", s, again.String())
	}
	if again.Matches(e) != got {
		t.Fatalf("%s matches the entry %v before the wire and %v after", s, got, !got)
	}
	parsed, err := ParseFilter(s)
	if err != nil {
		t.Fatalf("the string form %q of a decoded filter will not parse: %v", s, err)
	}
	if parsed.String() != s || parsed.Matches(e) != got {
		t.Fatalf("through the string form %s became %s", s, parsed.String())
	}
}
