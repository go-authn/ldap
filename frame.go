// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"slices"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// DefaultMaxMessageSize is how large one LDAPMessage may be.
//
// It is generous enough for a search result carrying a certificate and small
// enough that a client cannot ask this process to allocate its way out of
// memory. A deployment that publishes something larger raises it on the
// Server.
const DefaultMaxMessageSize = 4 << 20 // 4 MiB

// readFrame reads exactly one BER element and returns its bytes.
//
// ⛔ The length is read HERE rather than left to the BER library, for two
// reasons that are both about an unauthenticated client.
//
// The library's limit is a package-level global (ber.MaxPacketLengthBytes),
// so a server setting it would change it for every other user of that
// library in the same process, and two servers in one process could not have
// different limits. A limit that cannot be per-listener is not a limit a
// deployment controls.
//
// And the length prefix decides an allocation. A five-byte header claiming
// four gigabytes is a memory exhaustion anybody can perform, so the claim is
// checked BEFORE anything is reserved for it.
//
// RFC 4511 5.1 also restricts LDAP to "the definite form of length
// encoding", so the indefinite form is a protocol error here rather than
// something to support -- a parser that accepts it accepts messages the
// protocol does not have.
func readFrame(r *bufio.Reader, limit int) ([]byte, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return nil, eofAsClosed(err)
	}
	// A high-tag-number form (the low five bits all set) continues over more
	// bytes. No LDAPMessage uses one -- it is a SEQUENCE, tag 0x30 -- so it
	// is refused rather than parsed.
	if tag&0x1f == 0x1f {
		return nil, fmt.Errorf("ldap: a multi-byte tag at the start of a message")
	}
	header := []byte{tag}

	first, err := r.ReadByte()
	if err != nil {
		return nil, eofAsClosed(err)
	}
	header = append(header, first)

	var length int
	switch {
	case first == 0x80:
		return nil, fmt.Errorf("ldap: indefinite length, which RFC 4511 5.1 does not permit")
	case first&0x80 == 0:
		length = int(first)
	default:
		n := int(first & 0x7f)
		// 0xff is reserved, and more than eight bytes cannot fit an int64
		// anyway. Both are refused before any arithmetic on them.
		if n > 4 {
			return nil, fmt.Errorf("ldap: a %d-byte length, which is larger than any message this server accepts", n)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, eofAsClosed(err)
		}
		header = append(header, buf...)
		for _, b := range buf {
			length = length<<8 | int(b)
		}
	}
	if length < 0 || length > limit {
		return nil, fmt.Errorf("ldap: a message claiming %d bytes, and the limit is %d", length, limit)
	}

	// ⛔ The claim is checked, and then NOT reserved. Passing the limit says
	// only that the claim is allowed; it says nothing about whether the bytes
	// will ever come. Reserving all of it here turned six bytes from an
	// unauthenticated client into four mebibytes held for as long as that
	// client stayed silent -- fifty connections, 300 bytes, 200 MiB.
	//
	// So the buffer starts small and grows only once what it holds has
	// ARRIVED, at most doubling each time: what is held is never more than
	// twice what was received (or frameChunk, whichever is larger). A client
	// that wants this process to hold four mebibytes has to send them.
	out := make([]byte, len(header), len(header)+min(length, frameChunk))
	copy(out, header)
	for remaining := length; remaining > 0; {
		if len(out) == cap(out) {
			out = slices.Grow(out, min(remaining, max(len(out), frameChunk)))
		}
		n := min(remaining, cap(out)-len(out))
		got, err := io.ReadFull(r, out[len(out):len(out)+n])
		out = out[:len(out)+got]
		if err != nil {
			return nil, eofAsClosed(err)
		}
		remaining -= got
	}
	return out, nil
}

// frameChunk is the most readFrame reserves ahead of bytes it has not yet
// received. It is the size of one ordinary request with room to spare, so
// the messages a directory mostly sees -- binds, searches, their controls --
// are read in one step and never regrown.
const frameChunk = 4 << 10

func eofAsClosed(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errClosed
	}
	return err
}

// decodeFrame turns the bytes of one element into a packet.
func decodeFrame(b []byte) (*ber.Packet, error) {
	p, err := ber.DecodePacketErr(b)
	if err != nil {
		return nil, fmt.Errorf("ldap: %w", err)
	}
	return p, nil
}

// DefaultMaxMessageElements is how many BER elements one message may hold.
//
// ⛔ The size cap alone bounds bytes, not memory: decoding builds a packet
// of some 190 bytes for every element, and an empty OCTET STRING is two
// bytes on the wire. 4 MiB of them, sent before any bind, held 373 MiB live
// while decoding (measured), per connection. 16384 elements is a search
// with thousands of filter terms, or a modify with thousands of values --
// about 3 MiB of packets at most.
const DefaultMaxMessageElements = 16384

// errTooManyElements is a message holding more elements than allowed.
var errTooManyElements = errors.New("ldap: the message holds more elements than this server decodes")

// countElements walks the frame's tags and lengths, without building
// anything, and refuses one holding more than max elements: linear in the
// bytes, constant in memory, run before the decoder that is neither. A
// frame it cannot walk is left to the decoder to refuse.
func countElements(b []byte, max int) error {
	n := 0
	for i := 0; i < len(b); {
		n++
		if n > max {
			return errTooManyElements
		}
		tag := b[i]
		i++
		if tag&0x1f == 0x1f { // high tag number: continuation octets
			for i < len(b) && b[i]&0x80 != 0 {
				i++
			}
			i++
		}
		if i >= len(b) {
			return nil
		}
		l := int(b[i])
		i++
		if l&0x80 != 0 {
			k := l & 0x7f
			if k == 0 || k > 4 || i+k > len(b) {
				return nil // indefinite or absurd: readFrame and the decoder refuse it
			}
			l = 0
			for _, c := range b[i : i+k] {
				l = l<<8 | int(c)
			}
			i += k
		}
		if tag&0x20 == 0 { // primitive: its contents are not elements
			i += l
		}
		// constructed: its contents are the next elements, walked in turn
	}
	return nil
}
