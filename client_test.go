// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"bufio"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// A minimal wire client, for the tests OpenLDAP's cannot express.
//
// ⛔ It is NOT the judge, and nothing about the protocol is asserted through
// it alone: a client from this same module can agree with this server about
// a misreading and both be wrong, which is how the substring defect went
// unnoticed in the library this replaces. Conformance is judged by
// ldapsearch (see judge_test.go).
//
// What it is for is the questions about ONE CONNECTION'S STATE: two binds
// and a search on a single socket. Two ldapsearch runs are two connections,
// and "a refused bind keeps the previous bind's rights" only exists on one.
type client struct {
	c  net.Conn
	r  *bufio.Reader
	id int
	// values is every attribute value the last search returned, as
	// "name: value", for asserting what an entry published.
	values []string
	// lastControls is what the last searchResDone carried, which is where
	// the paged-results cookie arrives.
	lastControls []Control
}

func dial(t *testing.T, r *running) *client {
	t.Helper()
	c, err := net.DialTimeout("tcp", r.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return &client{c: c, r: bufio.NewReader(c)}
}

func (c *client) Close() { c.c.Close() }

func (c *client) next() int { c.id++; return c.id }

func (c *client) write(t *testing.T, id int, op *ber.Packet) {
	t.Helper()
	m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(id), "messageID"))
	m.AppendChild(op)
	if _, err := c.c.Write(m.Bytes()); err != nil {
		t.Fatal(err)
	}
}

func (c *client) read(t *testing.T) *ber.Packet {
	t.Helper()
	raw, err := readFrame(c.r, DefaultMaxMessageSize)
	if err != nil {
		t.Fatalf("reading a response: %v", err)
	}
	p, err := decodeFrame(raw)
	if err != nil {
		t.Fatalf("decoding a response: %v", err)
	}
	return p
}

// resultOf reads the LDAPResult out of a response.
func resultOf(t *testing.T, p *ber.Packet) Result {
	t.Helper()
	op := p.Children[1]
	code, ok := op.Children[0].Value.(int64)
	if !ok {
		t.Fatalf("the result code is %v", op.Children[0].Value)
	}
	return Result{
		Code:       ResultCode(code),
		MatchedDN:  string(op.Children[1].Data.Bytes()),
		Diagnostic: string(op.Children[2].Data.Bytes()),
	}
}

func (c *client) bind(t *testing.T, dn, pw string) ResultCode {
	t.Helper()
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appBindRequest, nil, "bindRequest")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(3), "version"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "name"))
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagAuthSimple, pw, "simple"))
	id := c.next()
	c.write(t, id, op)
	return resultOf(t, c.read(t)).Code
}

// bindSASL sends one step and returns the code, the serverSaslCreds, and
// whether the field was present at all.
func (c *client) bindSASL(t *testing.T, mechanism string, creds []byte) (ResultCode, []byte, bool) {
	t.Helper()
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appBindRequest, nil, "bindRequest")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(3), "version"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "name"))
	sasl := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagAuthSASL, nil, "sasl")
	sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, mechanism, "mechanism"))
	if creds != nil {
		sasl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(creds), "credentials"))
	}
	op.AppendChild(sasl)
	id := c.next()
	c.write(t, id, op)

	p := c.read(t)
	res := resultOf(t, p)
	for _, f := range p.Children[1].Children {
		if f.ClassType == ber.ClassContext && f.Tag == tagServerSASLCreds {
			return res.Code, append([]byte{}, f.Data.Bytes()...), true
		}
	}
	return res.Code, nil, false
}

// search sends one and reads to the searchResDone, returning the DNs.
func (c *client) search(t *testing.T, filter string, attrs ...string) ([]string, Result) {
	t.Helper()
	f, err := ParseFilter(filter)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := EncodeFilter(f)
	if err != nil {
		t.Fatal(err)
	}
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchRequest, nil, "searchRequest")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dc=example,dc=org", "baseObject"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(ScopeWholeSubtree), "scope"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(0), "derefAliases"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "sizeLimit"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "timeLimit"))
	op.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))
	op.AppendChild(fp)
	sel := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, a := range attrs {
		sel.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a, "selector"))
	}
	op.AppendChild(sel)

	id := c.next()
	c.write(t, id, op)

	var dns []string
	for {
		p := c.read(t)
		switch p.Children[1].Tag {
		case appSearchResEntry:
			dns = append(dns, string(p.Children[1].Children[0].Data.Bytes()))
		case appSearchResDone:
			return dns, resultOf(t, p)
		case appSearchResRef:
			// counted, not collected
		default:
			t.Fatalf("a search got a %d back", p.Children[1].Tag)
		}
	}
}

// whoami is the RFC 4532 extended operation.
func (c *client) whoami(t *testing.T) (string, ResultCode) {
	t.Helper()
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appExtendedRequest, nil, "extendedReq")
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagExtRequestName, OIDWhoAmI, "requestName"))
	id := c.next()
	c.write(t, id, op)
	p := c.read(t)
	res := resultOf(t, p)
	for _, f := range p.Children[1].Children {
		if f.ClassType == ber.ClassContext && f.Tag == tagExtResponseValue {
			return string(f.Data.Bytes()), res.Code
		}
	}
	return "", res.Code
}

// --- writes, for the tests that assert what the server decoded ------------

func (c *client) add(t *testing.T, dn string, attrs []*Attribute) ResultCode {
	t.Helper()
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appAddRequest, nil, "addRequest")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "entry"))
	list := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, a := range attrs {
		list.AppendChild(encodeAttribute(a))
	}
	op.AppendChild(list)
	id := c.next()
	c.write(t, id, op)
	return resultOf(t, c.read(t)).Code
}

func (c *client) modify(t *testing.T, dn string, changes []Change) ResultCode {
	t.Helper()
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appModifyRequest, nil, "modifyRequest")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "object"))
	list := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "changes")
	for _, ch := range changes {
		one := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "change")
		one.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(ch.Operation), "operation"))
		one.AppendChild(encodeAttribute(ch.Attribute))
		list.AppendChild(one)
	}
	op.AppendChild(list)
	id := c.next()
	c.write(t, id, op)
	return resultOf(t, c.read(t)).Code
}

func (c *client) delete(t *testing.T, dn string) ResultCode {
	t.Helper()
	op := ber.NewString(ber.ClassApplication, ber.TypePrimitive, appDelRequest, dn, "delRequest")
	id := c.next()
	c.write(t, id, op)
	return resultOf(t, c.read(t)).Code
}

func (c *client) modifyDN(t *testing.T, dn, newRDN string, deleteOld bool, newSuperior string) ResultCode {
	t.Helper()
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appModDNRequest, nil, "modDNRequest")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "entry"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, newRDN, "newrdn"))
	op.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, deleteOld, "deleteoldrdn"))
	if newSuperior != "" {
		op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, newSuperior, "newSuperior"))
	}
	id := c.next()
	c.write(t, id, op)
	return resultOf(t, c.read(t)).Code
}

func (c *client) compare(t *testing.T, dn, attr, value string) ResultCode {
	t.Helper()
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appCompareRequest, nil, "compareRequest")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "entry"))
	ava := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "ava")
	ava.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr, "attributeDesc"))
	ava.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "assertionValue"))
	op.AppendChild(ava)
	id := c.next()
	c.write(t, id, op)
	return resultOf(t, c.read(t)).Code
}

func encodeAttribute(a *Attribute) *ber.Packet {
	pa := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
	pa.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a.Name, "type"))
	vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
	for _, v := range a.Values {
		vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(v), "value"))
	}
	pa.AppendChild(vals)
	return pa
}

// startTLS asks for the upgrade and returns the result. The handshake is the
// caller's, because a test that wants to assert a REFUSAL must not perform
// one.
func (c *client) startTLS(t *testing.T) ResultCode {
	t.Helper()
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appExtendedRequest, nil, "extendedReq")
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagExtRequestName, OIDStartTLS, "requestName"))
	id := c.next()
	c.write(t, id, op)
	return resultOf(t, c.read(t)).Code
}

// upgrade replaces this client's socket after its own handshake.
func (c *client) upgrade(tc *tls.Conn) {
	c.c = tc
	c.r = bufio.NewReader(tc)
}

// searchWith sends a search carrying controls.
func (c *client) searchWith(t *testing.T, filter string, controls ...*Control) ([]string, Result) {
	t.Helper()
	m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	id := c.next()
	m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(id), "messageID"))
	m.AppendChild(searchOp(t, filter))
	ctls := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagControls, nil, "controls")
	for _, ctl := range controls {
		one := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "control")
		one.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ctl.Type, "controlType"))
		if ctl.Criticality {
			one.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "criticality"))
		}
		if ctl.Value != nil {
			one.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(ctl.Value), "controlValue"))
		}
		ctls.AppendChild(one)
	}
	m.AppendChild(ctls)
	if _, err := c.c.Write(m.Bytes()); err != nil {
		t.Fatal(err)
	}
	return c.collect(t)
}

// collect reads entries to the searchResDone.
func (c *client) collect(t *testing.T) ([]string, Result) {
	t.Helper()
	var dns []string
	for {
		p := c.read(t)
		switch p.Children[1].Tag {
		case appSearchResEntry:
			dns = append(dns, string(p.Children[1].Children[0].Data.Bytes()))
		case appSearchResDone:
			c.lastControls = controlsOf(p)
			return dns, resultOf(t, p)
		}
	}
}

// controlsOf reads the response controls off an LDAPMessage.
func controlsOf(p *ber.Packet) []Control {
	if len(p.Children) < 3 {
		return nil
	}
	got, err := decodeControls(p.Children[2])
	if err != nil {
		return nil
	}
	return got
}

// sendSearch writes a search carrying controls and does NOT wait for the
// answer, for a test about what happens while one is in flight.
func (c *client) sendSearch(t *testing.T, filter string, controls ...*Control) {
	t.Helper()
	m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(c.next()), "messageID"))
	m.AppendChild(searchOp(t, filter))
	list := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagControls, nil, "controls")
	for _, ctl := range controls {
		one := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "control")
		one.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ctl.Type, "controlType"))
		if ctl.Value != nil {
			one.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(ctl.Value), "controlValue"))
		}
		list.AppendChild(one)
	}
	m.AppendChild(list)
	if _, err := c.c.Write(m.Bytes()); err != nil {
		t.Fatal(err)
	}
}

// searchOp builds a whole-subtree search over the test base.
func searchOp(t *testing.T, filter string) *ber.Packet {
	t.Helper()
	f, err := ParseFilter(filter)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := EncodeFilter(f)
	if err != nil {
		t.Fatal(err)
	}
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchRequest, nil, "searchRequest")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dc=example,dc=org", "baseObject"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(ScopeWholeSubtree), "scope"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(0), "derefAliases"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "sizeLimit"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "timeLimit"))
	op.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))
	op.AppendChild(fp)
	op.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes"))
	return op
}

// searchBase sends a base-scope search against any base.
func (c *client) searchBase(t *testing.T, base, filter string, attrs ...string) ([]string, Result) {
	t.Helper()
	f, err := ParseFilter(filter)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := EncodeFilter(f)
	if err != nil {
		t.Fatal(err)
	}
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchRequest, nil, "searchRequest")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, base, "baseObject"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(ScopeBaseObject), "scope"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(0), "derefAliases"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "sizeLimit"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "timeLimit"))
	op.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))
	op.AppendChild(fp)
	sel := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, a := range attrs {
		sel.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a, "selector"))
	}
	op.AppendChild(sel)
	id := c.next()
	c.write(t, id, op)
	return c.collectValues(t)
}

// collectValues reads to the searchResDone, keeping every attribute value it
// saw so that a test can assert what the root DSE published.
func (c *client) collectValues(t *testing.T) ([]string, Result) {
	t.Helper()
	c.values = nil
	var dns []string
	for {
		p := c.read(t)
		switch p.Children[1].Tag {
		case appSearchResEntry:
			e := p.Children[1]
			dns = append(dns, string(e.Children[0].Data.Bytes()))
			for _, a := range e.Children[1].Children {
				name := string(a.Children[0].Data.Bytes())
				for _, v := range a.Children[1].Children {
					c.values = append(c.values, name+": "+string(v.Data.Bytes()))
				}
			}
		case appSearchResDone:
			return dns, resultOf(t, p)
		}
	}
}

// rootValues reads the whole root DSE and returns it as text.
func (c *client) rootValues(t *testing.T) string {
	t.Helper()
	c.searchBase(t, "", "(objectClass=*)", "+", "*")
	return strings.Join(c.values, "\n")
}

// handshake completes the TLS upgrade this client just asked for.
func (c *client) handshake(t *testing.T) {
	t.Helper()
	tc := tls.Client(c.c, &tls.Config{InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("the handshake failed: %v", err)
	}
	c.upgrade(tc)
}

// pagesOpen reports how many paged searches this client's connection holds.
// It reaches into the server because the number is not observable from the
// wire -- and "nothing was left running" is exactly the thing a leak test
// has to assert.
func (c *client) pagesOpen(t *testing.T, s *Server) int {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn := range s.conns {
		return conn.pages.count()
	}
	return 0
}
