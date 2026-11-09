// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// The client reads an LDAPMessage (RFC 4511 4.1.1) straight out of the bytes
// of its frame, with no intermediate tree of packets: a cursor over the
// slice, which allocates nothing. What LDAP uses of BER (ITU-T X.690) is small
// and fixed -- single-octet tags, definite lengths -- and everything outside
// it is refused rather than interpreted, which is also what bounds a hostile
// server: no tag, length or count in a frame can ask for more than the frame
// itself holds.

// BER identifier octets this client reads (RFC 4511 4.1.1 and 5.1).
const (
	berInteger     = 0x02
	berOctetString = 0x04
	berEnumerated  = 0x0A
	berSequence    = 0x30
	berSet         = 0x31

	opBindResponse   = 0x61 // [APPLICATION 1]
	opSearchEntry    = 0x64 // [APPLICATION 4]
	opSearchDone     = 0x65 // [APPLICATION 5]
	opSearchRef      = 0x73 // [APPLICATION 19]
	opExtendedResp   = 0x78 // [APPLICATION 24]
	opIntermediate   = 0x79 // [APPLICATION 25]
	berControls      = 0xA0 // [0] Controls
	berReferral      = 0xA3 // [3] Referral
	berSASLCreds     = 0x87 // [7] serverSaslCreds
	extResponseName  = 0x8A // [10] responseName
	extResponseValue = 0x8B // [11] responseValue
)

var errBER = errors.New("ldap: malformed BER")

// next reads one element at the start of b: its identifier octet, its
// contents, and what follows. Refused: a high-tag-number identifier (LDAP has
// none), an indefinite length (RFC 4511 5.1 requires the definite form), a
// length of more than four octets, and a length that runs past b.
func next(b []byte) (tag byte, val, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errBER
	}
	tag = b[0]
	if tag&0x1F == 0x1F {
		return 0, nil, nil, fmt.Errorf("%w: a high tag number", errBER)
	}
	n, hdr := int(b[1]), 2
	if n >= 0x80 {
		k := n & 0x7F
		if k == 0 || k > 4 || len(b) < 2+k {
			return 0, nil, nil, fmt.Errorf("%w: a length of %d octets", errBER, k)
		}
		n = 0
		for _, c := range b[2 : 2+k] {
			n = n<<8 | int(c)
		}
		hdr = 2 + k
	}
	if n < 0 || n > len(b)-hdr {
		return 0, nil, nil, fmt.Errorf("%w: a length past the end", errBER)
	}
	return tag, b[hdr : hdr+n], b[hdr+n:], nil
}

// expect reads one element and requires its tag.
func expect(b []byte, want byte, what string) (val, rest []byte, err error) {
	tag, val, rest, err := next(b)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap: %s: %w", what, err)
	}
	if tag != want {
		return nil, nil, fmt.Errorf("ldap: %s: tag %#x, want %#x", what, tag, want)
	}
	return val, rest, nil
}

// integer reads the contents of an INTEGER or ENUMERATED as a non-negative
// number below 2^31, which is all LDAP carries in either.
func integer(v []byte, what string) (int, error) {
	if len(v) == 0 || len(v) > 4 || v[0]&0x80 != 0 {
		return 0, fmt.Errorf("ldap: %s is not a non-negative integer of up to 4 octets", what)
	}
	n := 0
	for _, c := range v {
		n = n<<8 | int(c)
	}
	return n, nil
}

// readClientFrame reads one LDAPMessage into buf (grown as needed, and reused
// by the caller) and returns it. A message larger than limit is refused before
// a byte of it is read.
func readClientFrame(r *bufio.Reader, buf []byte, limit int) ([]byte, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return buf, err
	}
	if tag != berSequence {
		return buf, fmt.Errorf("ldap: a message starts with %#x, want a SEQUENCE", tag)
	}
	l, err := r.ReadByte()
	if err != nil {
		return buf, unexpected(err)
	}
	hdr := []byte{tag, l}
	n := int(l)
	if l >= 0x80 {
		k := int(l & 0x7F)
		if k == 0 || k > 4 {
			return buf, fmt.Errorf("ldap: a message length of %d octets", k)
		}
		var lb [4]byte
		if _, err := io.ReadFull(r, lb[:k]); err != nil {
			return buf, unexpected(err)
		}
		hdr = append(hdr, lb[:k]...)
		n = 0
		for _, c := range lb[:k] {
			n = n<<8 | int(c)
		}
	}
	if n < 0 || n > limit {
		return buf, fmt.Errorf("ldap: a message of %d bytes, the limit is %d", n, limit)
	}
	total := len(hdr) + n
	if cap(buf) < total {
		buf = make([]byte, total, max(total, min(2*cap(buf), limit)))
	}
	buf = buf[:total]
	copy(buf, hdr)
	if _, err := io.ReadFull(r, buf[len(hdr):]); err != nil {
		return buf, unexpected(err)
	}
	return buf, nil
}

// unexpected turns an EOF inside a message into the error it is.
func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
