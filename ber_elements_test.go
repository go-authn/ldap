// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"bufio"
	"bytes"
	"errors"
	"runtime"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func berLen4(n int) []byte {
	return []byte{0x84, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// flatMessage is an LDAPMessage of n empty OCTET STRINGs inside a search
// request: two bytes on the wire for each element the decoder builds.
func flatMessage(n int) []byte {
	var inner bytes.Buffer
	inner.Write([]byte{0x02, 0x01, 0x01}) // message id 1
	ops := bytes.Repeat([]byte{0x04, 0x00}, n)
	inner.WriteByte(0x63) // [APPLICATION 3] search request, constructed
	inner.Write(berLen4(len(ops)))
	inner.Write(ops)
	frame := append([]byte{0x30}, berLen4(inner.Len())...)
	return append(frame, inner.Bytes()...)
}

// A message within the size cap whose decoding cost a hundred times its
// bytes: 4 MiB of empty OCTET STRINGs, sent before any bind, held 373 MiB live
// (measured, per connection). It is now refused before the decoder runs.
func TestAMessageOfTooManyElementsIsRefusedBeforeDecoding(t *testing.T) {
	raw := flatMessage((DefaultMaxMessageSize - 64) / 2)
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	_, err := readMessage(bufio.NewReader(bytes.NewReader(raw)), DefaultMaxMessageSize, DefaultMaxMessageElements)
	runtime.ReadMemStats(&m1)
	if !errors.Is(err, errTooManyElements) {
		t.Fatalf("2M elements: %v", err)
	}
	// What was asked for: the frame itself (about 4 MiB, read as it
	// arrives), not a packet per element.
	if got := m1.TotalAlloc - m0.TotalAlloc; got > 16<<20 {
		t.Errorf("refusing it allocated %d MiB", got>>20)
	}
	// Under the cap, the same shape is decoded as before.
	if _, err := readMessage(bufio.NewReader(bytes.NewReader(flatMessage(100))), DefaultMaxMessageSize, DefaultMaxMessageElements); errors.Is(err, errTooManyElements) {
		t.Errorf("100 elements refused: %v", err)
	}
	// And the cap is the server's to set.
	if _, err := readMessage(bufio.NewReader(bytes.NewReader(flatMessage(100))), DefaultMaxMessageSize, 50); !errors.Is(err, errTooManyElements) {
		t.Errorf("100 elements under a cap of 50: %v", err)
	}
}

// countElements counts what the decoder builds: on real messages, every
// packet of the tree, no more and no fewer.
func TestCountElementsAgreesWithTheDecoder(t *testing.T) {
	var all func(p *ber.Packet) int
	all = func(p *ber.Packet) int {
		n := 1
		for _, c := range p.Children {
			n += all(c)
		}
		return n
	}
	for _, raw := range [][]byte{
		flatMessage(7),
		bindRequest(t, "cn=reader,dc=example,dc=org", "secret"),
		searchRequest(t, "dc=example,dc=org", "(&(objectClass=person)(|(uid=a*)(mail=*@example.org)))", "cn", "mail"),
	} {
		p, err := ber.DecodePacketErr(raw)
		if err != nil {
			t.Fatal(err)
		}
		want := all(p)
		if err := countElements(raw, want); err != nil {
			t.Errorf("%d elements refused under a cap of %d", want, want)
		}
		if err := countElements(raw, want-1); !errors.Is(err, errTooManyElements) {
			t.Errorf("%d elements passed a cap of %d", want, want-1)
		}
	}
}

// bindRequest and searchRequest are real LDAPMessages, built with the BER
// library the decoder belongs to.
func bindRequest(t *testing.T, dn, password string) []byte {
	t.Helper()
	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "id"))
	bind := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "bind")
	bind.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "version"))
	bind.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "dn"))
	bind.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, password, "simple"))
	msg.AppendChild(bind)
	return msg.Bytes()
}

func searchRequest(t *testing.T, base, filter string, attrs ...string) []byte {
	t.Helper()
	parsed, err := ParseFilter(filter)
	if err != nil {
		t.Fatal(err)
	}
	f, err := EncodeFilter(parsed)
	if err != nil {
		t.Fatal(err)
	}
	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 2, "id"))
	s := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "search")
	s.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, base, "base"))
	s.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 2, "scope"))
	s.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "deref"))
	s.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "size"))
	s.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "time"))
	s.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))
	s.AppendChild(f)
	as := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attrs")
	for _, a := range attrs {
		as.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a, "attr"))
	}
	s.AppendChild(as)
	msg.AppendChild(s)
	return msg.Bytes()
}

// The walk's own edges: what it counts, and what it leaves to the decoder.
// None of these may be refused as "too many" -- a frame the walk cannot
// follow is not evidence of amplification, and the decoder has the better
// error for it.
func TestCountElementsAtItsEdges(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    []byte
		max  int
		want error
	}{
		{"empty", nil, 1, nil},
		{"high tag number, two primitives", []byte{0x5f, 0x81, 0x01, 0x00, 0x04, 0x00}, 2, nil},
		{"high tag number, three needed", []byte{0x5f, 0x81, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}, 2, errTooManyElements},
		{"tag with no length", []byte{0x04}, 1, nil},
		{"high tag cut short", []byte{0x5f, 0x81}, 1, nil},
		{"long form length", []byte{0x04, 0x81, 0x02, 'h', 'i', 0x04, 0x00}, 2, nil},
		{"long form, one too many", []byte{0x04, 0x81, 0x02, 'h', 'i', 0x04, 0x00, 0x04, 0x00}, 2, errTooManyElements},
		{"indefinite length", []byte{0x30, 0x80, 0x04, 0x00}, 1, nil},
		{"length of five octets", []byte{0x04, 0x85, 1, 1, 1, 1, 1}, 1, nil},
		{"length octets cut short", []byte{0x04, 0x82, 0x01}, 1, nil},
		{"constructed contents counted", []byte{0x30, 0x04, 0x04, 0x00, 0x04, 0x00}, 2, errTooManyElements},
	} {
		if got := countElements(tc.b, tc.max); !errors.Is(got, tc.want) || (got == nil) != (tc.want == nil) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := (&Server{}).maxMessageElements(); got != DefaultMaxMessageElements {
		t.Errorf("a Server with no cap set allows %d elements, not the default %d", got, DefaultMaxMessageElements)
	}
	if got := (&Server{MaxMessageElements: 7}).maxMessageElements(); got != 7 {
		t.Errorf("a Server capped at 7 elements allows %d", got)
	}
}
