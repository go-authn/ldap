// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"bufio"
	"errors"
	"fmt"
	"io"

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
func readFrame(r *bufio.Reader, max int) ([]byte, error) {
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
	if length < 0 || length > max {
		return nil, fmt.Errorf("ldap: a message claiming %d bytes, and the limit is %d", length, max)
	}

	// Only now is anything reserved, and it is exactly what was claimed.
	out := make([]byte, len(header)+length)
	copy(out, header)
	if _, err := io.ReadFull(r, out[len(header):]); err != nil {
		return nil, eofAsClosed(err)
	}
	return out, nil
}

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
