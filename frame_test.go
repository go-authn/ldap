// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
)

func frameOf(t *testing.T, b []byte, max int) ([]byte, error) {
	t.Helper()
	return readFrame(bufio.NewReader(bytes.NewReader(b)), max)
}

// ⛔ The length prefix decides an allocation, and it arrives from whoever
// connected. A five-byte header claiming four gigabytes must be refused
// BEFORE anything is reserved for it -- otherwise one packet from anybody is
// a memory exhaustion.
//
// The test asserts the refusal rather than the allocation, because a test
// that tried to observe the allocation would have to perform it.
func TestAFrameLargerThanTheLimitIsRefusedBeforeItIsRead(t *testing.T) {
	// SEQUENCE, long-form length of 4 bytes, claiming 0x7fffffff.
	header := []byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}
	_, err := frameOf(t, header, DefaultMaxMessageSize)
	if err == nil {
		t.Fatal("a frame claiming 2 GiB was accepted")
	}
	if !strings.Contains(err.Error(), "the limit is") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
	// The control: a frame at exactly the limit is fine, so the check is a
	// limit and not a blanket refusal of long-form lengths.
	body := make([]byte, 300)
	ok := append([]byte{0x30, 0x82, 0x01, 0x2c}, body...)
	if _, err := frameOf(t, ok, DefaultMaxMessageSize); err != nil {
		t.Errorf("a 300-byte frame was refused: %v", err)
	}
}

// RFC 4511 5.1: "Only the definite form of length encoding is used." A parser
// that accepts the indefinite form accepts messages the protocol does not
// have, and cannot bound them.
func TestTheIndefiniteLengthFormIsRefused(t *testing.T) {
	_, err := frameOf(t, []byte{0x30, 0x80, 0x00, 0x00}, DefaultMaxMessageSize)
	if err == nil {
		t.Fatal("an indefinite length was accepted")
	}
	if !strings.Contains(err.Error(), "indefinite") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

func TestFramesThatAreNotFrames(t *testing.T) {
	for _, tc := range []struct {
		what string
		in   []byte
	}{
		{"nothing at all", nil},
		{"a tag and no length", []byte{0x30}},
		{"a multi-byte tag", []byte{0x3f, 0x81, 0x01, 0x00}},
		{"a length longer than 4 bytes", []byte{0x30, 0x88, 1, 2, 3, 4, 5, 6, 7, 8}},
		{"a truncated long-form length", []byte{0x30, 0x83, 0x00}},
		{"a body shorter than its length", []byte{0x30, 0x05, 0x01}},
	} {
		if _, err := frameOf(t, tc.in, DefaultMaxMessageSize); err == nil {
			t.Errorf("%s was accepted", tc.what)
		}
	}
}

// A client that hangs up is not a fault, and must be told apart from one that
// sent something wrong -- a server that logged every disconnection as a
// protocol error would bury the real ones.
func TestAClosedConnectionIsNotAProtocolError(t *testing.T) {
	for _, in := range [][]byte{nil, {0x30}, {0x30, 0x05, 0x01}} {
		_, err := frameOf(t, in, DefaultMaxMessageSize)
		if !errors.Is(err, errClosed) {
			t.Errorf("reading %v gave %v, want errClosed", in, err)
		}
	}
}

// The short form, the long form, and the boundary between them.
func TestBothLengthFormsAreRead(t *testing.T) {
	for _, n := range []int{0, 1, 127, 128, 255, 256, 65535, 65536} {
		body := make([]byte, n)
		for i := range body {
			body[i] = byte(i)
		}
		var buf bytes.Buffer
		buf.WriteByte(0x30)
		switch {
		case n < 128:
			buf.WriteByte(byte(n))
		case n < 256:
			buf.Write([]byte{0x81, byte(n)})
		case n < 65536:
			buf.Write([]byte{0x82, byte(n >> 8), byte(n)})
		default:
			buf.Write([]byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)})
		}
		head := buf.Len()
		buf.Write(body)

		got, err := frameOf(t, buf.Bytes(), DefaultMaxMessageSize)
		if err != nil {
			t.Errorf("a %d-byte body: %v", n, err)
			continue
		}
		if len(got) != head+n {
			t.Errorf("a %d-byte body came back as %d bytes, want %d", n, len(got), head+n)
		}
		if !bytes.Equal(got[head:], body) {
			t.Errorf("a %d-byte body came back changed", n)
		}
	}
}

func TestDecodeFrameRefusesRubbish(t *testing.T) {
	if _, err := decodeFrame([]byte{0x30, 0x7f, 0x01}); err == nil {
		t.Error("a truncated packet decoded")
	}
}
