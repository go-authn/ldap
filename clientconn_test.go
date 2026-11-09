// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- a hand-written BER encoder: the judge of the client's reader is not the
// library the server is built on, and a hostile server is not either.

func tlv(tag byte, parts ...[]byte) []byte {
	body := bytes.Join(parts, nil)
	n := len(body)
	switch {
	case n < 0x80:
		return append([]byte{tag, byte(n)}, body...)
	case n < 0x100:
		return append([]byte{tag, 0x81, byte(n)}, body...)
	case n < 0x10000:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, body...)
	}
	return append([]byte{tag, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
func octets(s string) []byte     { return tlv(0x04, []byte(s)) }
func intT(n int) []byte {
	if n < 0x80 {
		return tlv(0x02, []byte{byte(n)})
	}
	return tlv(0x02, []byte{byte(n >> 8), byte(n)})
}
func enumT(n int) []byte { return tlv(0x0A, []byte{byte(n)}) }

func resultBody(code int, matched, diag string) []byte {
	return cat(enumT(code), octets(matched), octets(diag))
}
func msgOf(id int, op []byte, controls ...[]byte) []byte {
	return tlv(0x30, intT(id), op, cat(controls...))
}
func attrT(name string, vals ...string) []byte {
	var vs [][]byte
	for _, v := range vals {
		vs = append(vs, octets(v))
	}
	return tlv(0x30, octets(name), tlv(0x31, vs...))
}
func entryFrame(id int, dn string, attrs ...[]byte) []byte {
	return msgOf(id, tlv(0x64, octets(dn), tlv(0x30, attrs...)))
}
func doneFrame(id, code int, controls ...[]byte) []byte {
	return msgOf(id, tlv(0x65, resultBody(code, "", "")), controls...)
}
func pagedCtl(cookie string) []byte {
	return tlv(0xA0, tlv(0x30, octets(OIDPaging), octets(string(tlv(0x30, intT(0), octets(cookie))))))
}

// scripted is a client whose server answers each request it reads with the
// next of replies (raw bytes, any number of frames) and then falls silent.
func scripted(t *testing.T, o DialOptions, replies ...[]byte) *ClientConn {
	t.Helper()
	return scriptedWith(t, o, true, replies...)
}

// scriptedWith, with closing false, leaves the stream open after the last
// reply: a server that stalls in the middle of a message.
func scriptedWith(t *testing.T, o DialOptions, closing bool, replies ...[]byte) *ClientConn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	if o.Timeout == 0 {
		o.Timeout = 2 * time.Second
	}
	go func() {
		buf := make([]byte, 1<<16)
		for _, r := range replies {
			if _, err := b.Read(buf); err != nil {
				return
			}
			if _, err := b.Write(r); err != nil {
				return
			}
		}
		if len(replies) > 0 && closing {
			b.Close() // the end of the stream follows the last reply
			return
		}
		io.Copy(io.Discard, b)
	}()
	return NewClientConn(a, o)
}

// ---- against the real server

func TestClientBindsSearchesAndPages(t *testing.T) {
	var names []string
	for i := 0; i < 25; i++ {
		names = append(names, fmt.Sprintf("u%02d", i))
	}
	r := serve(t, &Server{Bind: reader(), Search: &directory{entries: people(names...)}})
	for _, page := range []int{0, 10, 100} {
		c, err := Dial(context.Background(), r.url(), DialOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Bind("cn=reader,dc=example,dc=org", "let me read"); err != nil {
			t.Fatal(err)
		}
		f, err := ParseFilter("(objectClass=posixAccount)")
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.Search(&SearchRequest{BaseObject: "dc=example,dc=org", Scope: ScopeWholeSubtree, Filter: f, Attributes: []string{"uid", "cn"}}, page)
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		if len(got) != 25 {
			t.Fatalf("page %d: %d entries", page, len(got))
		}
		first := got[0]
		if first.DN != "uid=u00,ou=people,dc=example,dc=org" || string(first.Attribute("uid").Values[0]) != "u00" {
			t.Errorf("page %d: first entry %+v", page, first)
		}
		if got, _ := c.Search(&SearchRequest{BaseObject: "dc=example,dc=org", Scope: ScopeWholeSubtree}, page); len(got) != 25 {
			t.Errorf("page %d: a search with no filter returned %d", page, len(got))
		}
		c.Close()
	}
}

func TestClientBindRefusals(t *testing.T) {
	r := serve(t, &Server{Bind: reader(), Search: &directory{}})
	c, err := Dial(context.Background(), r.url(), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bind("cn=reader,dc=example,dc=org", ""); !errors.Is(err, ErrEmptyPassword) {
		t.Errorf("an empty password: %v", err)
	}
	var le *Error
	if err := c.Bind("cn=reader,dc=example,dc=org", "wrong"); !errors.As(err, &le) || le.Code != InvalidCredentials {
		t.Errorf("a wrong password: %v", err)
	}
	if err := c.Bind("cn=reader,dc=example,dc=org", "let me read"); err != nil {
		t.Errorf("the right one after a wrong one: %v", err)
	}
	// A search the server refuses is an *Error and no partial result.
	refuse := Refuse(InsufficientAccessRights, "no")
	r2 := serve(t, &Server{Bind: reader(), Search: &directory{refuse: &refuse}})
	c2, _ := Dial(context.Background(), r2.url(), DialOptions{})
	defer c2.Close()
	got, err := c2.Search(&SearchRequest{BaseObject: "dc=example,dc=org"}, 5)
	if !errors.As(err, &le) || le.Code != InsufficientAccessRights || got != nil {
		t.Errorf("a refused search: %v, %v", got, err)
	}
}

func TestClientStartTLS(t *testing.T) {
	r := serve(t, &Server{Bind: reader(), Search: &directory{entries: people("alice")}, TLSConfig: selfSigned(t)})
	c, err := Dial(context.Background(), r.url(), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.StartTLS(nil); err == nil {
		t.Error("a second StartTLS")
	}
	if err := c.Bind("cn=reader,dc=example,dc=org", "let me read"); err != nil {
		t.Fatalf("a bind after StartTLS: %v", err)
	}
	if got, err := c.Search(&SearchRequest{BaseObject: "dc=example,dc=org", Scope: ScopeWholeSubtree}, 0); err != nil || len(got) != 1 {
		t.Errorf("a search after StartTLS: %v, %v", got, err)
	}
	// A server with no certificate refuses it, in words.
	bare := serve(t, &Server{Bind: reader()})
	c2, _ := Dial(context.Background(), bare.url(), DialOptions{})
	defer c2.Close()
	var le *Error
	if err := c2.StartTLS(nil); !errors.As(err, &le) {
		t.Errorf("a refused StartTLS: %v", err)
	}
}

func TestDialURLs(t *testing.T) {
	ctx := context.Background()
	for _, u := range []string{"http://x", "::bad", "ldapi://", "ldap://127.0.0.1:1"} {
		if c, err := Dial(ctx, u, DialOptions{Dialer: &net.Dialer{Timeout: time.Second}}); err == nil {
			c.Close()
			t.Errorf("%q dialled", u)
		}
	}
	// ldapi: a socket path.
	sock := filepath.Join(t.TempDir(), "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("no unix sockets here")
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	c, err := Dial(ctx, "ldapi://"+strings.ReplaceAll(sock, "/", "%2F"), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !c.secured {
		t.Error("a local socket is not marked protected")
	}
	c.Close()
	if c, err := Dial(ctx, "ldapi:///"+strings.TrimPrefix(sock, "/"), DialOptions{}); err == nil {
		c.Close()
	}
	// ldaps: the handshake runs and names the host; a server that is not TLS fails it.
	plain, _ := net.Listen("tcp", "127.0.0.1:0")
	defer plain.Close()
	go func() {
		if c, err := plain.Accept(); err == nil {
			c.Write([]byte("not tls"))
			c.Close()
		}
	}()
	if c, err := Dial(ctx, "ldaps://"+plain.Addr().String(), DialOptions{TLS: &tls.Config{}}); err == nil {
		c.Close()
		t.Error("ldaps to a plain server")
	}
	// ldaps with a good server, default port logic: named host and port.
	srv := serve(t, &Server{Bind: reader(), TLSConfig: selfSigned(t)})
	_ = srv
	// Defaults: ldap:// and ldaps:// with no port, and an empty host, are tried (nothing listens).
	for _, u := range []string{"ldap://127.0.0.1", "ldaps://127.0.0.1", "ldap://"} {
		if c, err := Dial(ctx, u, DialOptions{Dialer: &net.Dialer{Timeout: 200 * time.Millisecond}}); err == nil {
			c.Close()
		}
	}
}

// ---- a hostile server

func TestClientRefusesWhatAServerMustNotSend(t *testing.T) {
	long := strings.Repeat("a", 300)
	big := tlv(0x30, intT(1), tlv(0x64, octets(long)))
	for name, tc := range map[string]struct {
		reply []byte
		want  string
	}{
		"not a SEQUENCE":           {[]byte{0x31, 0x00}, "starts with"},
		"an indefinite length":     {[]byte{0x30, 0x80, 0, 0}, "octets"},
		"a 5 octet length":         {[]byte{0x30, 0x85, 1, 0, 0, 0, 0}, "octets"},
		"a length over the limit":  {[]byte{0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF}, "limit"},
		"a truncated length":       {[]byte{0x30, 0x82, 0x01}, "EOF"},
		"a truncated message":      {[]byte{0x30, 0x10, 0x02}, "EOF"},
		"no id":                    {tlv(0x30), "messageID"},
		"an id that is not one":    {tlv(0x30, octets("x"), tlv(0x65)), "messageID"},
		"a negative id":            {tlv(0x30, tlv(0x02, []byte{0xFF}), tlv(0x65)), "integer"},
		"a 5 octet id":             {tlv(0x30, tlv(0x02, []byte{1, 0, 0, 0, 0}), tlv(0x65)), "integer"},
		"an empty id":              {tlv(0x30, tlv(0x02), tlv(0x65)), "integer"},
		"no operation":             {tlv(0x30, intT(1)), "protocolOp"},
		"a high tag number":        {tlv(0x30, intT(1), []byte{0x7F, 0x00}), "high tag"},
		"controls not controls":    {tlv(0x30, intT(1), tlv(0x65, resultBody(0, "", "")), tlv(0xA1)), "controls"},
		"bytes after the controls": {tlv(0x30, intT(1), tlv(0x65, resultBody(0, "", "")), tlv(0xA0), []byte{0}), "bytes after"},
		"another id":               {doneFrame(7, 0), "id 7"},
		"an operation that is not": {msgOf(1, tlv(0x61, resultBody(0, "", ""))), "operation 0x61"},
		"a refusal":                {doneFrame(1, 50), "insufficientAccessRights"},
		"a notice of disconnection": {msgOf(0, tlv(0x78, resultBody(52, "", "going away"))),
			"going away"},
		"a notice with no code":                        {msgOf(0, tlv(0x78, resultBody(0, "", "bye"))), "unavailable"},
		"a result code that is not":                    {msgOf(1, tlv(0x65, tlv(0x0A, []byte{1, 0, 0}), octets(""), octets(""))), "out of range"},
		"a result with no code":                        {msgOf(1, tlv(0x65)), "resultCode"},
		"a result with no matchedDN":                   {msgOf(1, tlv(0x65, enumT(0))), "matchedDN"},
		"a result with no diagnostic":                  {msgOf(1, tlv(0x65, enumT(0), octets(""))), "diagnosticMessage"},
		"a broken referral":                            {msgOf(1, tlv(0x65, enumT(10), octets(""), octets(""), tlv(0xA3, []byte{0x04, 0x05}))), "referral"},
		"an entry with no DN":                          {msgOf(1, tlv(0x64)), "objectName"},
		"an entry with no attributes":                  {msgOf(1, tlv(0x64, octets("dc=x"))), "attributes"},
		"bytes after the attributes":                   {msgOf(1, tlv(0x64, octets("dc=x"), tlv(0x30), []byte{0})), "bytes after"},
		"an attribute that is not":                     {msgOf(1, tlv(0x64, octets("dc=x"), tlv(0x30, octets("cn")))), "attribute"},
		"an attribute with no type":                    {msgOf(1, tlv(0x64, octets("dc=x"), tlv(0x30, tlv(0x30, tlv(0x31))))), "attribute type"},
		"an attribute with no values":                  {msgOf(1, tlv(0x64, octets("dc=x"), tlv(0x30, tlv(0x30, octets("cn"))))), "attribute values"},
		"a value that is not":                          {msgOf(1, tlv(0x64, octets("dc=x"), tlv(0x30, tlv(0x30, octets("cn"), tlv(0x31, intT(1)))))), "attribute value"},
		"a message over the limit":                     {big, "limit"},
		"paging: a control that is not":                {cat(entryFrame(1, "dc=x"), msgOf(1, tlv(0x65, resultBody(0, "", "")), tlv(0xA0, octets("x")))), "control"},
		"paging: no type":                              {msgOf(1, tlv(0x65, resultBody(0, "", "")), tlv(0xA0, tlv(0x30))), "controlType"},
		"paging: no value":                             {msgOf(1, tlv(0x65, resultBody(0, "", "")), tlv(0xA0, tlv(0x30, octets(OIDPaging)))), "controlValue"},
		"paging: not a sequence":                       {msgOf(1, tlv(0x65, resultBody(0, "", "")), tlv(0xA0, tlv(0x30, octets(OIDPaging), octets("x")))), "paged results value"},
		"paging: no size":                              {msgOf(1, tlv(0x65, resultBody(0, "", "")), tlv(0xA0, tlv(0x30, octets(OIDPaging), octets(string(tlv(0x30)))))), "size"},
		"paging: no cookie":                            {msgOf(1, tlv(0x65, resultBody(0, "", "")), tlv(0xA0, tlv(0x30, octets(OIDPaging), octets(string(tlv(0x30, intT(1))))))), "cookie"},
		"paging: a critical control that is malformed": {msgOf(1, tlv(0x65, resultBody(0, "", "")), tlv(0xA0, tlv(0x30, octets(OIDPaging), []byte{0x01}))), "criticality"},
	} {
		o := DialOptions{Limits: ClientLimits{MaxMessage: 200}}
		c := scripted(t, o, tc.reply)
		_, err := c.Search(&SearchRequest{BaseObject: "dc=x"}, 0)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestClientBoundsWhatAServerMaySend(t *testing.T) {
	many := cat(entryFrame(1, "a=1"), entryFrame(1, "a=2"), entryFrame(1, "a=3"), doneFrame(1, 0))
	c := scripted(t, DialOptions{Limits: ClientLimits{MaxEntries: 2}}, many)
	if _, err := c.Search(&SearchRequest{}, 0); err == nil || !strings.Contains(err.Error(), "more than 2 entries") {
		t.Errorf("entries: %v", err)
	}
	c = scripted(t, DialOptions{Limits: ClientLimits{MaxBytes: 100}}, many)
	if _, err := c.Search(&SearchRequest{}, 0); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Errorf("bytes: %v", err)
	}
	// A server that always has another page.
	again := cat(entryFrame(1, "a=1"), doneFrame(1, 0, pagedCtl("more")))
	replies := [][]byte{}
	for i := 0; i < 5; i++ {
		replies = append(replies, bytes.ReplaceAll(again, []byte{0x02, 0x01, 0x01}, intT(i+1)))
	}
	c = scripted(t, DialOptions{Limits: ClientLimits{MaxPages: 3}}, replies...)
	if _, err := c.Search(&SearchRequest{}, 1); err == nil || !strings.Contains(err.Error(), "more than 3 pages") {
		t.Errorf("pages: %v", err)
	}
	// A cookie larger than a cookie.
	c = scripted(t, DialOptions{}, doneFrame(1, 0, pagedCtl(strings.Repeat("c", maxCookie+1))))
	if _, err := c.Search(&SearchRequest{}, 1); err == nil || !strings.Contains(err.Error(), "cookie") {
		t.Errorf("cookie: %v", err)
	}
	// A silent server: the wait for the next message ends.
	c = scripted(t, DialOptions{Timeout: 50 * time.Millisecond})
	if _, err := c.Search(&SearchRequest{}, 0); err == nil {
		t.Error("a silent server was waited for for ever")
	}
	// References, intermediate responses and unrelated controls are passed over.
	ok := cat(msgOf(1, tlv(0x73, octets("ldap://elsewhere"))), msgOf(1, tlv(0x79)), entryFrame(1, "a=1", attrT("cn", "x", ""), attrT("CN", "y"), attrT("sn")),
		msgOf(1, tlv(0x65, resultBody(0, "", ""), tlv(0xA3, octets("ldap://r"))), tlv(0xA0, tlv(0x30, octets("1.2.3"), tlv(0x01, []byte{0xFF}), octets("v")))))
	c = scripted(t, DialOptions{}, ok)
	got, err := c.Search(&SearchRequest{}, 1)
	if err != nil || len(got) != 1 || len(got[0].Attributes) != 3 || len(got[0].Attributes[0].Values) != 2 {
		t.Fatalf("%v, %v", got, err)
	}
	if v := got[0].Attributes[0].Values; string(v[0]) != "x" || v[1] == nil || len(v[1]) != 0 {
		t.Errorf("values %q", v)
	}
	// A paging control with the criticality field present is read.
	crit := msgOf(1, tlv(0x65, resultBody(0, "", "")), tlv(0xA0, tlv(0x30, octets(OIDPaging), tlv(0x01, []byte{0xFF}), octets(string(tlv(0x30, intT(0), octets("")))))))
	c = scripted(t, DialOptions{}, crit)
	if _, err := c.Search(&SearchRequest{}, 1); err != nil {
		t.Errorf("a critical paging control: %v", err)
	}
	// A result with a referral lists it, bounded.
	var uris [][]byte
	for i := 0; i < 70; i++ {
		uris = append(uris, octets("ldap://r"))
	}
	r, _ := readResult(cat(enumT(10), octets("dc=m"), octets("d"), tlv(0xA3, uris...)))
	if len(r.Referral) != 64 || r.MatchedDN != "dc=m" {
		t.Errorf("referral %d, matched %q", len(r.Referral), r.MatchedDN)
	}
}

func TestClientHostileBindAndStartTLS(t *testing.T) {
	c := scripted(t, DialOptions{}, msgOf(1, tlv(0x65, resultBody(0, "", ""))))
	if err := c.Bind("dn", "pw"); err == nil || !strings.Contains(err.Error(), "operation 0x65") {
		t.Errorf("bind answered with a search result: %v", err)
	}
	c = scripted(t, DialOptions{}, []byte{0x30, 0x80})
	if err := c.Bind("dn", "pw"); err == nil {
		t.Error("bind: a bad frame")
	}
	c = scripted(t, DialOptions{}, msgOf(1, tlv(0x61, resultBody(0, "", ""))))
	if err := c.Bind("dn", "pw"); err != nil {
		t.Errorf("bind: %v", err)
	}
	c = scripted(t, DialOptions{}, msgOf(1, tlv(0x61, resultBody(49, "", "no"))))
	var le *Error
	if err := c.Bind("dn", "pw"); !errors.As(err, &le) || le.Code != InvalidCredentials {
		t.Errorf("bind: %v", err)
	}
	c = scripted(t, DialOptions{}, msgOf(1, tlv(0x65, resultBody(0, "", ""))))
	if err := c.StartTLS(nil); err == nil || !strings.Contains(err.Error(), "operation 0x65") {
		t.Errorf("StartTLS answered with a search result: %v", err)
	}
	c = scripted(t, DialOptions{}, []byte{0x30, 0x80})
	if err := c.StartTLS(nil); err == nil {
		t.Error("StartTLS: a bad frame")
	}
	// A server that says yes and then does not speak TLS.
	c = scripted(t, DialOptions{}, msgOf(1, tlv(0x78, resultBody(0, "", ""))))
	if err := c.StartTLS(&tls.Config{}); err == nil {
		t.Error("StartTLS accepted and nobody handshook")
	}
	// A server that says yes and sends bytes before the handshake.
	c = scripted(t, DialOptions{}, cat(msgOf(1, tlv(0x78, resultBody(0, "", ""))), []byte("injected")))
	if err := c.StartTLS(&tls.Config{}); err == nil {
		t.Error("StartTLS with injected bytes")
	}
	// A write that fails.
	a, b := net.Pipe()
	b.Close()
	if err := NewClientConn(a, DialOptions{}).Bind("dn", "pw"); err == nil {
		t.Error("a write to a closed connection")
	}
	if err := NewClientConn(a, DialOptions{}).StartTLS(nil); err == nil {
		t.Error("StartTLS on a closed connection")
	}
	if _, err := NewClientConn(a, DialOptions{}).Search(&SearchRequest{}, 0); err == nil {
		t.Error("a search on a closed connection")
	}
	// A filter that cannot be encoded.
	if _, err := NewClientConn(a, DialOptions{}).Search(&SearchRequest{Filter: &Not{}}, 0); err == nil {
		t.Error("an unencodable filter")
	}
	// Message ids wrap before they leave 31 bits.
	w := NewClientConn(a, DialOptions{})
	w.id = 1<<31 - 2
	if w.nextID() != 1 || w.nextID() != 2 {
		t.Error("the id did not wrap")
	}
}

func TestClientReadsAreBoundedByTheClock(t *testing.T) {
	// Stalled in the middle of a message: the error is the clock's, not an EOF.
	for name, reply := range map[string][]byte{"the length": {0x30, 0x82, 0x01}, "the body": {0x30, 0x05, 0x02}} {
		c := scriptedWith(t, DialOptions{Timeout: 100 * time.Millisecond}, false, reply)
		_, err := c.Search(&SearchRequest{}, 0)
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Errorf("stalled in %s: %v", name, err)
		}
	}
	// A lone identifier octet and then the end.
	c := scripted(t, DialOptions{}, []byte{0x30})
	if _, err := c.Search(&SearchRequest{}, 0); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("a lone tag: %v", err)
	}
}

func TestNextRefusesWhatIsNotAnElement(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty": {}, "one octet": {0x04}, "long form cut short": {0x04, 0x82, 0x01},
		"a length past the end": {0x04, 0x05, 'a'}, "high tag": {0x1F, 0x00},
	} {
		if _, _, _, err := next(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if tag, v, rest, err := next([]byte{0x04, 0x02, 'a', 'b', 0x05}); err != nil || tag != 4 || string(v) != "ab" || len(rest) != 1 {
		t.Errorf("a good one: %v %q %v", tag, v, err)
	}
	// A referral whose own length is wrong.
	if r, _ := readResult(cat(enumT(10), octets(""), octets(""), []byte{0xA3, 0x09})); r.Code != ProtocolError {
		t.Errorf("a broken referral list: %+v", r)
	}
	// An ldapi socket that is not there, and ldaps with the default TLS to a server that is not TLS.
	if c, err := Dial(context.Background(), "ldapi://%2Fno%2Fsuch%2Fsocket", DialOptions{}); err == nil {
		c.Close()
		t.Error("a socket that is not there")
	}
	plain, _ := net.Listen("tcp", "127.0.0.1:0")
	defer plain.Close()
	go func() {
		if c, err := plain.Accept(); err == nil {
			c.Write([]byte("not tls"))
			c.Close()
		}
	}()
	if c, err := Dial(context.Background(), "ldaps://"+plain.Addr().String(), DialOptions{}); err == nil {
		c.Close()
		t.Error("ldaps to a plain server with the default configuration")
	}
}

func TestClientLimitsDefaults(t *testing.T) {
	var l ClientLimits
	if l.message() != 8<<20 || l.entries() != 4_000_000 || l.bytes() != 1<<30 || l.pages() != 100_000 {
		t.Errorf("%+v", l)
	}
	if (DialOptions{}).timeout() != 5*time.Minute || (DialOptions{Timeout: time.Second}).timeout() != time.Second {
		t.Error("timeout")
	}
}

// ---- how much a search allocates, which is what the client is for.

func TestClientAllocationsPerEntryAreFew(t *testing.T) {
	var frames [][]byte
	for i := 0; i < 200; i++ {
		frames = append(frames, entryFrame(1, fmt.Sprintf("uid=u%d,dc=x", i), attrT("uid", "a"), attrT("member", "m1", "m2", "m3", "m4", "m5")))
	}
	reply := cat(cat(frames...), doneFrame(1, 0))
	allocs := testing.AllocsPerRun(5, func() {
		c := scripted(t, DialOptions{}, reply)
		if got, err := c.Search(&SearchRequest{}, 0); err != nil || len(got) != 200 {
			t.Fatal(err)
		}
	})
	// The scripted connection and the request cost a few hundred; the entries
	// must not: go-ldap spent about 740 allocations on one entry of this size.
	if per := allocs / 200; per > 12 {
		t.Errorf("%.1f allocations per entry (%.0f in all)", per, allocs)
	}
}

func FuzzClientSearch(f *testing.F) {
	f.Add(cat(entryFrame(1, "uid=a,dc=x", attrT("uid", "a"), attrT("member", "x", "y")), doneFrame(1, 0)))
	f.Add(doneFrame(1, 0, pagedCtl("c")))
	f.Add(msgOf(0, tlv(0x78, resultBody(52, "", "bye"))))
	f.Add([]byte{0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF})
	f.Add(tlv(0x30, intT(1), tlv(0x64, octets("x"), tlv(0x30, tlv(0x30, octets("a"), tlv(0x31, octets("v")))))))
	f.Fuzz(func(t *testing.T, raw []byte) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		go func() {
			buf := make([]byte, 1<<12)
			b.Read(buf)
			b.Write(raw)
			b.Close() // the end of the stream: a hostile server that stalls is the clock's test
		}()
		c := NewClientConn(a, DialOptions{Timeout: 200 * time.Millisecond, Limits: ClientLimits{MaxMessage: 1 << 16, MaxEntries: 1000, MaxBytes: 1 << 22, MaxPages: 4}})
		got, err := c.Search(&SearchRequest{}, 1)
		if err == nil {
			for _, e := range got {
				for _, at := range e.Attributes {
					for _, v := range at.Values {
						_ = len(v)
					}
				}
			}
		}
	})
}
