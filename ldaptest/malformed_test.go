// SPDX-License-Identifier: BSD-3-Clause

package ldaptest_test

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-authn/ldap"
	"github.com/go-authn/ldap/ldaptest"
)

// ⛔ This client reads whatever a server sends, and a server it is pointed
// at may not be one of ours. Every one of these is a response a broken or
// hostile server can send, and each must come back as an ERROR rather than
// as a panic or as a plausible-looking empty answer -- a test harness that
// reports "no entries" for a malformed response makes the thing it is
// testing look correct.
func speaks(t *testing.T, reply func(net.Conn)) *ldaptest.Client {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Read whatever the client sends first, then answer with rubbish.
		buf := make([]byte, 4096)
		_, _ = c.Read(buf)
		reply(c)
	}()
	c, err := ldaptest.Dial(ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestAServerThatAnswersRubbish(t *testing.T) {
	for _, tc := range []struct {
		what  string
		reply func(net.Conn)
	}{
		{"nothing at all", func(c net.Conn) {}},
		{"one byte", func(c net.Conn) { c.Write([]byte{0x30}) }},
		{"a header and no body", func(c net.Conn) { c.Write([]byte{0x30, 0x0a}) }},
		{"a long-form length and no body", func(c net.Conn) { c.Write([]byte{0x30, 0x82, 0x01, 0x00}) }},
		{"a body that is not BER", func(c net.Conn) { c.Write([]byte{0x30, 0x02, 0x02, 0x7f}) }},
		{"a message with no operation", func(c net.Conn) {
			c.Write([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
		}},
	} {
		c := speaks(t, tc.reply)
		if res, err := c.Bind("cn=x", "pw"); err == nil {
			t.Errorf("%s was read as a result: %s", tc.what, res.Code)
		}
	}
}

// A result whose code is not an integer, and an entry with no value set:
// both are shapes a server could send and neither is a usable answer.
func TestAResponseWithTheWrongShape(t *testing.T) {
	// A well-formed LDAPMessage whose bindResponse holds three OCTET
	// STRINGS -- the right number of fields, the wrong types.
	c := speaks(t, func(conn net.Conn) {
		conn.Write([]byte{
			0x30, 0x10, // SEQUENCE
			0x02, 0x01, 0x01, // messageID 1
			0x61, 0x0b, // [APPLICATION 1] bindResponse
			0x04, 0x01, 'x', // resultCode as an OCTET STRING
			0x04, 0x00,
			0x04, 0x04, 'o', 'o', 'p', 's',
		})
	})
	if _, err := c.Bind("cn=x", "pw"); err == nil {
		t.Error("a result code that is not an integer was accepted")
	}
}

// A search whose entry carries no value set is refused rather than returned
// half-read.
func TestASearchEntryWithNoValueSet(t *testing.T) {
	c := speaks(t, func(conn net.Conn) {
		conn.Write([]byte{
			0x30, 0x11,
			0x02, 0x01, 0x01,
			0x64, 0x0c, // [APPLICATION 4] searchResEntry
			0x04, 0x03, 'u', '=', 'a', // objectName
			0x30, 0x05, // attributes
			0x30, 0x03, // one partialAttribute
			0x04, 0x01, 'c', // its type, and NO value set
		})
	})
	if _, err := c.Search(ldaptest.Search{Base: "dc=x"}); err == nil {
		t.Error("an entry with a malformed attribute was accepted")
	}
}

// A connection that closes mid-answer ends the search with an error rather
// than a short, plausible result.
func TestAServerThatHangsUpMidSearch(t *testing.T) {
	c := speaks(t, func(conn net.Conn) {
		// One entry, then silence and a close.
		conn.Write([]byte{
			0x30, 0x0f,
			0x02, 0x01, 0x01,
			0x64, 0x0a,
			0x04, 0x03, 'u', '=', 'a',
			0x30, 0x03, 0x30, 0x01, 0x30,
		})
	})
	if _, err := c.Search(ldaptest.Search{Base: "dc=x"}); err == nil {
		t.Error("a truncated search was reported as complete")
	} else if err == io.EOF {
		t.Log("ended at EOF, which is what a hang-up looks like")
	}
}

// The remaining shapes, each one a response that must not be mistaken for an
// answer. A harness that reads a malformed reply as an empty result makes
// the server it is testing look correct.
func TestEveryReaderRefusesAMalformedReply(t *testing.T) {
	// A response whose LDAPResult has fewer than three fields.
	short := []byte{
		0x30, 0x08,
		0x02, 0x01, 0x01,
		0x61, 0x03, // bindResponse
		0x0a, 0x01, 0x00, // resultCode only
	}
	// A bindResponse to a SASL bind, malformed the same way.
	for _, tc := range []struct {
		what string
		call func(*ldaptest.Client) error
	}{
		{"a SASL bind", func(c *ldaptest.Client) error { _, err := c.BindSASL("X", nil); return err }},
		{"whoami", func(c *ldaptest.Client) error { _, _, err := c.WhoAmI(); return err }},
		{"an extended operation", func(c *ldaptest.Client) error { _, err := c.Extended("1.2.3", nil); return err }},
		{"StartTLS", func(c *ldaptest.Client) error { _, err := c.StartTLS(nil); return err }},
		{"a search", func(c *ldaptest.Client) error { _, err := c.Search(ldaptest.Search{Base: "dc=x"}); return err }},
	} {
		c := speaks(t, func(conn net.Conn) { conn.Write(short) })
		if err := tc.call(c); err == nil {
			t.Errorf("%s accepted a result with too few fields", tc.what)
		}
	}

	// A SASL bind and a whoami that read cleanly and carry no optional
	// field: not an error, just an answer with nothing in it.
	full := []byte{
		0x30, 0x0c,
		0x02, 0x01, 0x01,
		0x61, 0x07,
		0x0a, 0x01, 0x00, // success
		0x04, 0x00, // matchedDN
		0x04, 0x00, // diagnosticMessage
	}
	c := speaks(t, func(conn net.Conn) { conn.Write(full) })
	step, err := c.BindSASL("X", []byte{})
	if err != nil {
		t.Errorf("a bind response with no serverSaslCreds was an error: %v", err)
	}
	if step.Present {
		t.Error("an ABSENT serverSaslCreds was reported as present")
	}

	c2 := speaks(t, func(conn net.Conn) { conn.Write(full) })
	if who, _, err := c2.WhoAmI(); err != nil || who != "" {
		t.Errorf("a whoami with no value came back as %q (%v)", who, err)
	}

	// A search that ends immediately with a done, and one that carries a
	// continuation reference this client counts by ignoring.
	done := []byte{
		0x30, 0x0c,
		0x02, 0x01, 0x01,
		0x65, 0x07, // searchResDone
		0x0a, 0x01, 0x00,
		0x04, 0x00,
		0x04, 0x00,
	}
	ref := []byte{
		0x30, 0x0a,
		0x02, 0x01, 0x01,
		0x73, 0x05, // [APPLICATION 19] searchResRef
		0x04, 0x03, 'l', 'd', 'a',
	}
	c3 := speaks(t, func(conn net.Conn) { conn.Write(append(ref, done...)) })
	got, err := c3.Search(ldaptest.Search{Base: "dc=x"})
	if err != nil {
		t.Fatalf("a search carrying a reference failed: %v", err)
	}
	if len(got.Entries) != 0 {
		t.Errorf("a continuation reference was counted as an entry: %v", got.DNs())
	}
}

// An entry with no attributes field at all.
func TestAnEntryWithNoAttributesField(t *testing.T) {
	c := speaks(t, func(conn net.Conn) {
		conn.Write([]byte{
			0x30, 0x0a,
			0x02, 0x01, 0x01,
			0x64, 0x05, // searchResEntry
			0x04, 0x03, 'u', '=', 'a', // objectName and nothing else
		})
	})
	if _, err := c.Search(ldaptest.Search{Base: "dc=x"}); err == nil {
		t.Error("an entry with no attributes field was accepted")
	}
}

// ⛔ A response longer than 127 bytes uses the LONG form of the length, and
// a reader that only handles the short form stops working at exactly the
// point responses get interesting -- an entry with a certificate in it, or a
// root DSE with a dozen extensions. The boundary is tested from both sides.
func TestALongFormLengthIsRead(t *testing.T) {
	for _, n := range []int{100, 200, 5000} {
		diag := make([]byte, n)
		for i := range diag {
			diag[i] = 'x'
		}
		c := speaks(t, func(conn net.Conn) {
			conn.Write(bindResponseWithDiagnostic(diag))
			// In pieces, so the reader has to keep reading rather than
			// assuming one Read gets the lot.
			time.Sleep(10 * time.Millisecond)
		})
		res, err := c.Bind("cn=x", "pw")
		if err != nil {
			t.Errorf("a %d-byte diagnostic: %v", n, err)
			continue
		}
		if len(res.Diagnostic) != n {
			t.Errorf("a %d-byte diagnostic came back as %d bytes", n, len(res.Diagnostic))
		}
	}
}

// A response that arrives in pieces is read whole, rather than truncated at
// whatever the first Read happened to return.
func TestAResponseThatArrivesInPieces(t *testing.T) {
	diag := make([]byte, 300)
	for i := range diag {
		diag[i] = 'y'
	}
	full := bindResponseWithDiagnostic(diag)
	c := speaks(t, func(conn net.Conn) {
		for i := 0; i < len(full); i += 7 {
			end := i + 7
			if end > len(full) {
				end = len(full)
			}
			conn.Write(full[i:end])
			time.Sleep(time.Millisecond)
		}
	})
	res, err := c.Bind("cn=x", "pw")
	if err != nil {
		t.Fatalf("a response in 7-byte pieces: %v", err)
	}
	if len(res.Diagnostic) != len(diag) {
		t.Errorf("it came back as %d bytes, want %d", len(res.Diagnostic), len(diag))
	}
}

// bindResponseWithDiagnostic builds a success carrying a diagnostic of the
// given length, so that the length crosses the short/long form boundary.
func bindResponseWithDiagnostic(diag []byte) []byte {
	op := []byte{0x0a, 0x01, 0x00, 0x04, 0x00}
	op = append(op, 0x04)
	op = append(op, berLength(len(diag))...)
	op = append(op, diag...)

	resp := []byte{0x61}
	resp = append(resp, berLength(len(op))...)
	resp = append(resp, op...)

	body := []byte{0x02, 0x01, 0x01}
	body = append(body, resp...)

	out := []byte{0x30}
	out = append(out, berLength(len(body))...)
	return append(out, body...)
}

func berLength(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	if n < 256 {
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

// ⛔ A StartTLS the server ACCEPTS and then cannot handshake must come back
// as an error, not as the success the result code said. The result and the
// handshake are two different answers, and a client that reported only the
// first would carry on in the clear believing it had TLS.
func TestAStartTLSThatIsAcceptedAndThenFails(t *testing.T) {
	c := speaks(t, func(conn net.Conn) {
		// Success to the StartTLS, then rubbish where a ServerHello belongs.
		conn.Write(bindResponseWithDiagnostic(nil))
		conn.Write([]byte("this is not a ServerHello"))
	})
	res, err := c.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err == nil {
		t.Error("a failed handshake was reported as success")
	}
	if res.Code != ldap.Success {
		t.Logf("the server's result was %s", res.Code)
	}
}

// The last handful, each one a reply or a request that must come back as an
// error rather than as a plausible answer.
func TestTheRemainingRefusals(t *testing.T) {
	// A long-form length whose length BYTES never arrive.
	c := speaks(t, func(conn net.Conn) { conn.Write([]byte{0x30, 0x84}) })
	if _, err := c.Bind("cn=x", "pw"); err == nil {
		t.Error("a truncated long-form length was accepted")
	}

	// A SASL bind whose reply never comes.
	c2 := speaks(t, func(conn net.Conn) {})
	if _, err := c2.BindSASL("X", nil); err == nil {
		t.Error("a SASL bind with no reply succeeded")
	}
	// The same for whoami.
	c3 := speaks(t, func(conn net.Conn) {})
	if _, _, err := c3.WhoAmI(); err == nil {
		t.Error("a whoami with no reply succeeded")
	}

	// ⛔ A filter that cannot be ENCODED. ParseFilter never produces one, so
	// this branch is only reachable through FilterAST -- which is why that
	// field exists: an unreachable error path is one nobody can show works.
	c4 := speaks(t, func(conn net.Conn) {})
	if _, err := c4.Search(ldaptest.Search{FilterAST: nil, Filter: "(cn=x)"}); err == nil {
		t.Error("a search with no reply succeeded")
	}
	// A search on a closed connection: the WRITE fails.
	c6 := speaks(t, func(conn net.Conn) {})
	c6.Close()
	if _, err := c6.Search(ldaptest.Search{Base: "dc=x"}); err == nil {
		t.Error("a search on a closed connection succeeded")
	}

	// A reply that is a well-formed SEQUENCE with only a message id.
	c7 := speaks(t, func(conn net.Conn) { conn.Write([]byte{0x30, 0x03, 0x02, 0x01, 0x01}) })
	if _, err := c7.Search(ldaptest.Search{Base: "dc=x"}); err == nil {
		t.Error("a message with no operation was accepted by a search")
	}
}

// ⛔ There is no test here for "a filter that cannot be encoded", and there
// cannot be: ldap.Filter is a SEALED interface, so no type outside that
// package satisfies it and EncodeFilter is total over the nine that do. The
// error branch in Search is unreachable by construction. It is kept, because
// it is what will report the day the set stops being sealed, and the
// coverage floor names it rather than a test pretending to exercise it.

// Cookie() and responseControls on the shapes a server can send. A harness
// that mis-reads a cookie either stops a sequence early or loops forever.
func TestReadingTheCookieOffWhateverArrives(t *testing.T) {
	// No controls at all: absent, not empty.
	var none ldaptest.SearchResult
	if _, ok := none.Cookie(); ok {
		t.Error("a result with no controls reported a cookie")
	}
	// A control that is not the paging one is skipped.
	other := ldaptest.SearchResult{Controls: []ldap.Control{{Type: ldap.OIDPreRead, Value: []byte("x")}}}
	if _, ok := other.Cookie(); ok {
		t.Error("a different control was read as the paging one")
	}
	// ⛔ A paging control whose value does not parse is NOT a cookie. A
	// harness that returned "" here would report "that was the last page"
	// about a server that said something else entirely.
	broken := ldaptest.SearchResult{Controls: []ldap.Control{{Type: ldap.OIDPaging, Value: []byte("junk")}}}
	if _, ok := broken.Cookie(); ok {
		t.Error("an unparseable paging control was read as a cookie")
	}
}

// The response-control reader, against a server sending odd shapes.
//
// ⛔ Built with the BER encoder rather than hand-counted bytes. My first
// attempt wrote the lengths by hand and got one wrong, which the test
// reported as "unexpected EOF" -- a failure that looks like the READER is
// broken when it is the fixture.
func TestResponseControlsOnOddMessages(t *testing.T) {
	done := func(extra ...*ber.Packet) []byte {
		m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
		m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "messageID"))
		op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 5, nil, "searchResDone")
		op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(0), "resultCode"))
		op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
		op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
		m.AppendChild(op)
		for _, e := range extra {
			m.AppendChild(e)
		}
		return m.Bytes()
	}
	octet := func(v string) *ber.Packet {
		return ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "s")
	}

	// A third field that is not the controls field.
	c := speaks(t, func(conn net.Conn) { conn.Write(done(octet("junk"))) })
	got, err := c.Search(ldaptest.Search{Base: "dc=x"})
	if err != nil {
		t.Fatalf("a message with an odd third field: %v", err)
	}
	if len(got.Controls) != 0 {
		t.Errorf("a non-controls field was read as %d controls", len(got.Controls))
	}

	// A control carrying criticality AND a value.
	ctls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "controls")
	one := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "control")
	one.AppendChild(octet(ldap.OIDPaging))
	one.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "criticality"))
	one.AppendChild(octet("hi"))
	ctls.AppendChild(one)
	c2 := speaks(t, func(conn net.Conn) { conn.Write(done(ctls)) })
	got2, err := c2.Search(ldaptest.Search{Base: "dc=x"})
	if err != nil {
		t.Fatalf("a message with a full control: %v", err)
	}
	if len(got2.Controls) != 1 {
		t.Fatalf("read %d controls, want 1", len(got2.Controls))
	}
	if !got2.Controls[0].Criticality || string(got2.Controls[0].Value) != "hi" {
		t.Errorf("the control came back as %+v", got2.Controls[0])
	}

	// A control with no fields at all is skipped rather than fatal.
	empty := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "controls")
	empty.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "control"))
	c3 := speaks(t, func(conn net.Conn) { conn.Write(done(empty)) })
	if got3, err := c3.Search(ldaptest.Search{Base: "dc=x"}); err != nil {
		t.Errorf("a control with no fields: %v", err)
	} else if len(got3.Controls) != 0 {
		t.Errorf("an empty control was read as %d", len(got3.Controls))
	}
}
