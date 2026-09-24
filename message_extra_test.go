// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// failingReader fails with something that is NOT the end of the stream, so
// that a real read error is told apart from a client hanging up. A server
// that reported every read failure as a disconnection would never log a
// broken pipe or a TLS fault.
type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }

func TestARealReadErrorIsNotReportedAsADisconnection(t *testing.T) {
	boom := errors.New("the network went away in an interesting way")
	_, err := readFrame(bufio.NewReader(failingReader{err: boom}), DefaultMaxMessageSize)
	if errors.Is(err, errClosed) {
		t.Error("a read error was reported as a clean disconnection")
	}
	if !errors.Is(err, boom) {
		t.Errorf("the reason was lost: %v", err)
	}
	// And the same inside the long-form length, which reads again.
	r := bufio.NewReader(io.MultiReader(bytes.NewReader([]byte{0x30, 0x83}), failingReader{err: boom}))
	if _, err := readFrame(r, DefaultMaxMessageSize); !errors.Is(err, boom) {
		t.Errorf("a read error inside the length was reported as %v", err)
	}
}

// A message whose controls cannot be decoded is refused, and the reason
// reaches the caller rather than the controls being silently dropped -- a
// dropped control may have been critical.
func TestAMessageWithBrokenControlsIsRefused(t *testing.T) {
	ctls := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagControls, nil, "controls")
	ctls.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "control"))
	m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "messageID"))
	m.AppendChild(ber.Encode(ber.ClassApplication, ber.TypePrimitive, appUnbindRequest, nil, "unbindRequest"))
	m.AppendChild(ctls)
	if _, err := readMessage(bufio.NewReader(bytes.NewReader(m.Bytes())), DefaultMaxMessageSize); err == nil {
		t.Error("a message with an unreadable control was accepted")
	}
}

// A message larger than the limit is refused by readMessage too, not only by
// readFrame -- the limit has to be on the path a server actually calls.
func TestReadMessageAppliesTheLimit(t *testing.T) {
	m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "messageID"))
	m.AppendChild(ber.NewString(ber.ClassApplication, ber.TypePrimitive, appExtendedRequest,
		string(make([]byte, 4096)), "big"))
	if _, err := readMessage(bufio.NewReader(bytes.NewReader(m.Bytes())), 64); err == nil {
		t.Error("a message over the limit was read")
	}
}

// A frame whose LENGTH is fine but whose contents are not BER. Framing and
// decoding are separate steps and each has to refuse on its own: a frame
// that reads cleanly and then fails to decode must reach the caller as a
// refusal, not as a message with no fields.
func TestAWellFramedPacketThatIsNotBER(t *testing.T) {
	// SEQUENCE of 2 bytes, holding an INTEGER claiming 0x7f bytes of value.
	junk := []byte{0x30, 0x02, 0x02, 0x7f}
	if _, err := readFrame(bufio.NewReader(bytes.NewReader(junk)), DefaultMaxMessageSize); err != nil {
		t.Fatalf("the frame itself should read: %v", err)
	}
	if _, err := readMessage(bufio.NewReader(bytes.NewReader(junk)), DefaultMaxMessageSize); err == nil {
		t.Error("a well-framed packet that is not BER was accepted")
	}
}
