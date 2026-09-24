// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// envelope builds an LDAPMessage around an operation, for the decoder to read.
func envelope(t *testing.T, id int64, op *ber.Packet, controls *ber.Packet) []byte {
	t.Helper()
	m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "messageID"))
	m.AppendChild(op)
	if controls != nil {
		m.AppendChild(controls)
	}
	return m.Bytes()
}

func unbindOp() *ber.Packet {
	return ber.Encode(ber.ClassApplication, ber.TypePrimitive, appUnbindRequest, nil, "unbindRequest")
}

func read(t *testing.T, b []byte) (*message, error) {
	t.Helper()
	return readMessage(bufio.NewReader(bytes.NewReader(b)), DefaultMaxMessageSize)
}

// ⛔ RFC 4511 4.1.1: MessageID is INTEGER (0 .. maxInt), and ZERO is reserved
// for the unsolicited notification a SERVER sends. A request carrying it
// cannot be answered without the answer looking like a notification to the
// client -- so it is refused rather than answered.
func TestAMessageIdOutsideItsRangeIsRefused(t *testing.T) {
	for _, tc := range []struct {
		what string
		id   int64
		ok   bool
	}{
		{"zero, which is the notification id", 0, false},
		{"negative", -1, false},
		{"one past maxInt", 2147483648, false},
		{"one", 1, true},
		{"maxInt", 2147483647, true},
	} {
		_, err := read(t, envelope(t, tc.id, unbindOp(), nil))
		if tc.ok && err != nil {
			t.Errorf("%s was refused: %v", tc.what, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s was accepted", tc.what)
		}
	}
}

// ⛔ criticality is BOOLEAN DEFAULT FALSE and controlValue is OCTET STRING
// OPTIONAL, so the field after the type is EITHER. Reading it by position
// turns a control's value into its criticality flag, or the reverse -- and a
// critical control read as non-critical is silently dropped, which makes the
// server perform a different operation and report success.
func TestAControlIsReadByTagNotByPosition(t *testing.T) {
	build := func(fields ...*ber.Packet) []byte {
		ctls := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagControls, nil, "controls")
		c := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "control")
		c.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, OIDPaging, "controlType"))
		for _, f := range fields {
			c.AppendChild(f)
		}
		ctls.AppendChild(c)
		return envelope(t, 1, unbindOp(), ctls)
	}
	boolean := func(v bool) *ber.Packet {
		return ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, v, "criticality")
	}
	value := func(s string) *ber.Packet {
		return ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, s, "controlValue")
	}

	// A value in the SECOND position, with no criticality: read positionally
	// this would be a criticality of whatever the first byte is.
	m, err := read(t, build(value("page")))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.controls) != 1 || m.controls[0].Criticality || string(m.controls[0].Value) != "page" {
		t.Errorf("value-only control read as %+v", m.controls)
	}

	// Criticality alone, and criticality followed by a value.
	m, err = read(t, build(boolean(true)))
	if err != nil {
		t.Fatal(err)
	}
	if !m.controls[0].Criticality || m.controls[0].Value != nil {
		t.Errorf("criticality-only control read as %+v", m.controls[0])
	}
	m, err = read(t, build(boolean(true), value("page")))
	if err != nil {
		t.Fatal(err)
	}
	if !m.controls[0].Criticality || string(m.controls[0].Value) != "page" {
		t.Errorf("both-fields control read as %+v", m.controls[0])
	}

	// A control with NO type at all is refused rather than left with an
	// empty OID, which would compare equal to nothing and be dropped.
	ctls := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagControls, nil, "controls")
	ctls.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "control"))
	if _, err := read(t, envelope(t, 1, unbindOp(), ctls)); err == nil {
		t.Error("a control with no type was accepted")
	}
}

// A third field that is not the controls field is a message this package does
// not understand. Guessing is how a critical control gets dropped.
func TestAThirdFieldThatIsNotControlsIsRefused(t *testing.T) {
	junk := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "?", "junk")
	if _, err := read(t, envelope(t, 1, unbindOp(), junk)); err == nil {
		t.Error("a third field that is not controls was accepted")
	}
}

func TestMessagesThatAreNotMessages(t *testing.T) {
	// A SEQUENCE with one child: an id and no operation.
	lone := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	lone.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "messageID"))
	if _, err := read(t, lone.Bytes()); err == nil {
		t.Error("a message with no operation was accepted")
	}

	// An id that is not an integer.
	bad := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	bad.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "one", "messageID"))
	bad.AppendChild(unbindOp())
	if _, err := read(t, bad.Bytes()); err == nil {
		t.Error("a non-integer message id was accepted")
	}
}

// ⛔ RFC 4511 4.1.9 makes matchedDN and diagnosticMessage fields of EVERY
// result, and 4.1.10 adds the referral. A server that cannot set them cannot
// tell a client how far along a DN its search base stopped existing.
func TestAResultCarriesItsMatchedDNAndReferral(t *testing.T) {
	m := resultMessage(7, appSearchResDone, Result{
		Code:       NoSuchObject,
		MatchedDN:  "dc=example,dc=org",
		Diagnostic: "no ou=sales under it",
		Referral:   []string{"ldap://other.example.org/dc=example,dc=org"},
	})
	back, err := ber.DecodePacketErr(m.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	op := back.Children[1]
	if got := op.Children[0].Value.(int64); ResultCode(got) != NoSuchObject {
		t.Errorf("resultCode came back as %d", got)
	}
	if got := string(op.Children[1].Data.Bytes()); got != "dc=example,dc=org" {
		t.Errorf("matchedDN came back as %q", got)
	}
	if got := string(op.Children[2].Data.Bytes()); !strings.Contains(got, "ou=sales") {
		t.Errorf("diagnosticMessage came back as %q", got)
	}
	if len(op.Children) != 4 || op.Children[3].Tag != tagReferral {
		t.Fatalf("the referral is missing: %d fields", len(op.Children))
	}
	if got := string(op.Children[3].Children[0].Data.Bytes()); !strings.HasPrefix(got, "ldap://") {
		t.Errorf("the referral URI came back as %q", got)
	}

	// And a plain success carries no referral field at all -- an empty one is
	// not the same as none, and RFC 4511 4.1.10 only allows it with the
	// referral result code.
	plain, err := ber.DecodePacketErr(resultMessage(7, appSearchResDone, Result{Code: Success}).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if n := len(plain.Children[1].Children); n != 3 {
		t.Errorf("a plain success carries %d fields, want 3", n)
	}
}

// ⛔ serverSaslCreds is sent whenever it is non-nil INCLUDING empty: RFC 4511
// 4.2.2 gives a zero-length OCTET STRING and an absent field different
// meanings, and mechanisms rely on the distinction.
func TestAnEmptyServerSASLCredsIsSentAndNilIsNot(t *testing.T) {
	fields := func(r SASLResult) int {
		p, err := ber.DecodePacketErr(bindResponse(3, r).Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return len(p.Children[1].Children)
	}
	if n := fields(SASLResult{Result: Result{Code: Success}}); n != 3 {
		t.Errorf("a bind response with no creds carries %d fields, want 3", n)
	}
	if n := fields(SASLResult{Result: Result{Code: Success}, ServerCreds: []byte{}}); n != 4 {
		t.Errorf("a bind response with EMPTY creds carries %d fields, want 4", n)
	}
	if n := fields(SASLResult{Result: Result{Code: SaslBindInProgress}, ServerCreds: []byte("challenge")}); n != 4 {
		t.Errorf("a challenge carries %d fields, want 4", n)
	}
}

// ⛔ typesOnly sends the attribute descriptions with an EMPTY value set,
// which is what RFC 4511 4.5.1.6 asks for -- not the attribute omitted. A
// client that asked which attributes exist and got none back reads it as
// "this entry has none".
func TestTypesOnlySendsTheNamesWithNoValues(t *testing.T) {
	e := &Entry{DN: "uid=a", Attributes: []*Attribute{
		StringAttribute("uid", "a"),
		StringAttribute("mail", "a@example.org", "a2@example.org"),
	}}
	for _, typesOnly := range []bool{false, true} {
		p, err := ber.DecodePacketErr(entryMessage(1, e, typesOnly).Bytes())
		if err != nil {
			t.Fatal(err)
		}
		attrs := p.Children[1].Children[1]
		if len(attrs.Children) != 2 {
			t.Fatalf("typesOnly=%v: %d attributes, want 2", typesOnly, len(attrs.Children))
		}
		for _, a := range attrs.Children {
			name := string(a.Children[0].Data.Bytes())
			vals := len(a.Children[1].Children)
			switch {
			case typesOnly && vals != 0:
				t.Errorf("typesOnly: %s came back with %d values", name, vals)
			case !typesOnly && name == "mail" && vals != 2:
				t.Errorf("mail came back with %d values, want 2", vals)
			}
		}
	}
}

func TestAReferenceAndAnExtendedResponseEncode(t *testing.T) {
	p, err := ber.DecodePacketErr(referenceMessage(2, []string{"ldap://a/", "ldap://b/"}).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if n := len(p.Children[1].Children); n != 2 {
		t.Errorf("the reference carries %d URIs, want 2", n)
	}

	// An extended response with a name and a value, and one with neither.
	full, err := ber.DecodePacketErr(extendedResponse(2, ExtendedResult{
		Result: Result{Code: Success}, Name: OIDWhoAmI, Value: []byte("dn:uid=a"),
	}).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if n := len(full.Children[1].Children); n != 5 {
		t.Errorf("a full extended response carries %d fields, want 5", n)
	}
	bare, err := ber.DecodePacketErr(extendedResponse(2, ExtendedResult{Result: Result{Code: ProtocolError}}).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if n := len(bare.Children[1].Children); n != 3 {
		t.Errorf("a bare extended response carries %d fields, want 3", n)
	}
}
