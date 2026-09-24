// SPDX-License-Identifier: BSD-3-Clause

// Package ldaptest drives an LDAP server over the wire, for the questions a
// real client cannot express.
//
// ⛔ It is NOT a judge, and it is not a client library. A client from the
// same module as the server can agree with it about a misreading of the
// protocol and both be wrong -- which is exactly how a substring filter
// defect went unnoticed for years in the library go-authn/ldap replaces: its
// own client encoded the filter with the same mistake, so the round trip
// looked clean. Conformance belongs to OpenLDAP's `ldapsearch`.
//
// What this is for is the questions ldapsearch cannot ask, all of which are
// about ONE CONNECTION'S STATE:
//
//   - two binds and a search on a single socket, because "a refused bind
//     keeps the previous bind's rights" does not exist across two;
//   - a SASL bind with an arbitrary mechanism, which go-ldap/ldap/v3 offers
//     no way to send;
//   - a StartTLS upgrade followed by more LDAP on the same connection.
//
// It returns errors rather than taking a *testing.T, so that importing it
// pulls no test flags into anything, and so it can be used from a fixture
// that is not a test.
package ldaptest

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-authn/ldap"
)

// The protocol tags this package needs. They are repeated rather than
// exported from the server package, because exporting them would put wire
// details in the API a real consumer reads.
const (
	appBindRequest      = 0
	appBindResponse     = 1
	appSearchRequest    = 3
	appSearchResEntry   = 4
	appSearchResDone    = 5
	appExtendedRequest  = 23
	appExtendedResponse = 24

	tagAuthSimple       = 0
	tagAuthSASL         = 3
	tagServerSASLCreds  = 7
	tagControls         = 0
	tagExtRequestName   = 0
	tagExtRequestValue  = 1
	tagExtResponseValue = 11
)

// A Client is one connection to a server.
type Client struct {
	conn net.Conn
	r    *bufio.Reader
	id   int
}

// Dial opens a connection.
func Dial(addr string, timeout time.Duration) (*Client, error) {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	return &Client{conn: c, r: bufio.NewReader(c)}, nil
}

// Close hangs up.
func (c *Client) Close() error { return c.conn.Close() }

// Conn is the underlying socket, for a caller that wants a deadline on it.
func (c *Client) Conn() net.Conn { return c.conn }

// SetDeadline bounds every exchange, so that a test against a server that
// stops answering fails rather than hangs.
func (c *Client) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

func (c *Client) next() int { c.id++; return c.id }

func (c *Client) write(id int, op *ber.Packet, controls []ldap.Control) error {
	m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(id), "messageID"))
	m.AppendChild(op)
	if len(controls) > 0 {
		list := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagControls, nil, "controls")
		for _, ctl := range controls {
			one := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "control")
			one.AppendChild(str(ctl.Type))
			if ctl.Criticality {
				one.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "criticality"))
			}
			if ctl.Value != nil {
				one.AppendChild(str(string(ctl.Value)))
			}
			list.AppendChild(one)
		}
		m.AppendChild(list)
	}
	_, err := c.conn.Write(m.Bytes())
	return err
}

// Read reads one message, for a caller asserting that something arrived --
// or, with a deadline, that nothing did.
func (c *Client) Read() (*ber.Packet, error) {
	// A definite-length frame, read the way RFC 4511 5.1 constrains it.
	head, err := c.r.Peek(2)
	if err != nil {
		return nil, err
	}
	n := 2
	if head[1]&0x80 != 0 {
		n += int(head[1] & 0x7f)
	}
	hdr, err := c.r.Peek(n)
	if err != nil {
		return nil, err
	}
	length := 0
	if hdr[1]&0x80 == 0 {
		length = int(hdr[1])
	} else {
		for _, b := range hdr[2:] {
			length = length<<8 | int(b)
		}
	}
	buf := make([]byte, n+length)
	if _, err := ioReadFull(c.r, buf); err != nil {
		return nil, err
	}
	return ber.DecodePacketErr(buf)
}

func ioReadFull(r *bufio.Reader, buf []byte) (int, error) {
	read := 0
	for read < len(buf) {
		n, err := r.Read(buf[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

// result reads an LDAPResult out of a response.
func result(p *ber.Packet) (ldap.Result, error) {
	if len(p.Children) < 2 || len(p.Children[1].Children) < 3 {
		return ldap.Result{}, errors.New("ldaptest: a response with too few fields")
	}
	op := p.Children[1]
	code, ok := op.Children[0].Value.(int64)
	if !ok {
		return ldap.Result{}, fmt.Errorf("ldaptest: the result code is %v", op.Children[0].Value)
	}
	return ldap.Result{
		Code:       ldap.ResultCode(code),
		MatchedDN:  string(op.Children[1].Data.Bytes()),
		Diagnostic: string(op.Children[2].Data.Bytes()),
	}, nil
}

// Bind sends a simple bind.
//
// The password is a string here and not []byte, because a test writes a
// literal. A SERVER must take it as bytes -- see ldap.BindRequest.
func (c *Client) Bind(dn, password string) (ldap.Result, error) {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appBindRequest, nil, "bindRequest")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(3), "version"))
	op.AppendChild(str(dn))
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagAuthSimple, password, "simple"))
	return c.exchange(op)
}

// A SASLStep is what one step of a SASL bind answered.
type SASLStep struct {
	ldap.Result
	// ServerCreds is serverSaslCreds, and Present says whether the field was
	// there at all -- RFC 4511 4.2.2 gives an absent field and a zero-length
	// one different meanings, and a test that cannot tell them apart cannot
	// check either.
	ServerCreds []byte
	Present     bool
}

// BindSASL sends one step of a SASL bind. Passing nil credentials sends the
// field ABSENT, which several mechanisms use as their first message.
func (c *Client) BindSASL(mechanism string, credentials []byte) (SASLStep, error) {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appBindRequest, nil, "bindRequest")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(3), "version"))
	// RFC 4513 5.2.1: the name field of a SASL bind is ignored, so it is
	// sent empty -- a client that put something here would be saying
	// something the server must not read.
	op.AppendChild(str(""))
	sasl := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagAuthSASL, nil, "sasl")
	sasl.AppendChild(str(mechanism))
	if credentials != nil {
		sasl.AppendChild(str(string(credentials)))
	}
	op.AppendChild(sasl)

	id := c.next()
	if err := c.write(id, op, nil); err != nil {
		return SASLStep{}, err
	}
	p, err := c.Read()
	if err != nil {
		return SASLStep{}, err
	}
	res, err := result(p)
	if err != nil {
		return SASLStep{}, err
	}
	step := SASLStep{Result: res}
	for _, f := range p.Children[1].Children {
		if f.ClassType == ber.ClassContext && f.Tag == tagServerSASLCreds {
			step.ServerCreds = append([]byte{}, f.Data.Bytes()...)
			step.Present = true
		}
	}
	return step, nil
}

// A SearchResult is what a search came back with.
type SearchResult struct {
	ldap.Result
	Entries []*ldap.Entry
}

// DNs is every entry's DN, for a test that only cares which entries came.
func (r SearchResult) DNs() []string {
	out := make([]string, 0, len(r.Entries))
	for _, e := range r.Entries {
		out = append(out, e.DN)
	}
	return out
}

// Values is every attribute value, as "name: value", for a test asserting
// what an entry published.
func (r SearchResult) Values() []string {
	var out []string
	for _, e := range r.Entries {
		for _, a := range e.Attributes {
			for _, v := range a.Values {
				out = append(out, a.Name+": "+string(v))
			}
		}
	}
	return out
}

// A Search is what to ask for. The zero value is a base-scope search of the
// root DSE with a present filter, which is what discovery looks like.
type Search struct {
	Base   string
	Scope  ldap.Scope
	Filter string // RFC 4515; empty means "(objectClass=*)"
	// FilterAST is sent instead of Filter when it is set, so that a test can
	// send a filter the RFC 4515 parser would never produce -- which is what
	// this package is for. A nil one is an error rather than a filter that
	// matches everything.
	FilterAST ldap.Filter
	Attrs     []string
	SizeLimit int
	TypesOnly bool
	Controls  []ldap.Control
}

// Search sends one and reads to the searchResDone.
func (c *Client) Search(s Search) (SearchResult, error) {
	f := s.FilterAST
	if f == nil {
		if s.Filter == "" {
			s.Filter = "(objectClass=*)"
		}
		var err error
		if f, err = ldap.ParseFilter(s.Filter); err != nil {
			return SearchResult{}, err
		}
	}
	fp, err := ldap.EncodeFilter(f)
	if err != nil {
		// ⛔ Unreachable, and kept anyway. ldap.Filter is a SEALED
		// interface: no type outside that package satisfies it, EncodeFilter
		// is total over the nine that do, and ParseFilter never returns
		// anything else. So this line cannot run today -- and it is the line
		// that will say so on the day the set stops being sealed. It is the
		// one statement in this package no test covers, and the coverage
		// floor names it rather than pretending otherwise.
		return SearchResult{}, err
	}
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchRequest, nil, "searchRequest")
	op.AppendChild(str(s.Base))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(s.Scope), "scope"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(0), "derefAliases"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(s.SizeLimit), "sizeLimit"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "timeLimit"))
	op.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, s.TypesOnly, "typesOnly"))
	op.AppendChild(fp)
	sel := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, a := range s.Attrs {
		sel.AppendChild(str(a))
	}
	op.AppendChild(sel)

	id := c.next()
	if err := c.write(id, op, s.Controls); err != nil {
		return SearchResult{}, err
	}
	var out SearchResult
	for {
		p, err := c.Read()
		if err != nil {
			return out, err
		}
		if len(p.Children) < 2 {
			return out, errors.New("ldaptest: a message with no operation")
		}
		switch p.Children[1].Tag {
		case appSearchResEntry:
			e, err := entryOf(p.Children[1])
			if err != nil {
				return out, err
			}
			out.Entries = append(out.Entries, e)
		case appSearchResDone:
			out.Result, err = result(p)
			return out, err
		default:
			// A continuation reference, or something else. Counted by being
			// ignored rather than treated as an entry.
		}
	}
}

func entryOf(op *ber.Packet) (*ldap.Entry, error) {
	if len(op.Children) < 2 {
		return nil, errors.New("ldaptest: an entry with no attributes field")
	}
	e := &ldap.Entry{DN: string(op.Children[0].Data.Bytes())}
	for _, a := range op.Children[1].Children {
		if len(a.Children) < 2 {
			return nil, errors.New("ldaptest: an attribute with no value set")
		}
		attr := &ldap.Attribute{Name: string(a.Children[0].Data.Bytes())}
		for _, v := range a.Children[1].Children {
			attr.Values = append(attr.Values, append([]byte{}, v.Data.Bytes()...))
		}
		e.Attributes = append(e.Attributes, attr)
	}
	return e, nil
}

// StartTLS upgrades the connection (RFC 4511 4.14).
//
// The handshake is done here, which means a caller that wants to assert a
// REFUSAL gets it from the result rather than from a handshake that never
// happens: the result is returned before the handshake is attempted, and the
// handshake only runs on success.
func (c *Client) StartTLS(cfg *tls.Config) (ldap.Result, error) {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appExtendedRequest, nil, "extendedReq")
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagExtRequestName, ldap.OIDStartTLS, "requestName"))
	res, err := c.exchange(op)
	if err != nil || res.Code != ldap.Success {
		return res, err
	}
	tc := tls.Client(c.conn, cfg)
	if err := tc.Handshake(); err != nil {
		return res, err
	}
	c.conn = tc
	c.r = bufio.NewReader(tc)
	return res, nil
}

// WhoAmI is RFC 4532: what this connection says the client is.
func (c *Client) WhoAmI() (string, ldap.Result, error) {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appExtendedRequest, nil, "extendedReq")
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagExtRequestName, ldap.OIDWhoAmI, "requestName"))
	id := c.next()
	if err := c.write(id, op, nil); err != nil {
		return "", ldap.Result{}, err
	}
	p, err := c.Read()
	if err != nil {
		return "", ldap.Result{}, err
	}
	res, err := result(p)
	if err != nil {
		return "", res, err
	}
	for _, f := range p.Children[1].Children {
		if f.ClassType == ber.ClassContext && f.Tag == tagExtResponseValue {
			return string(f.Data.Bytes()), res, nil
		}
	}
	return "", res, nil
}

// Extended sends any extended operation.
func (c *Client) Extended(oid string, value []byte) (ldap.Result, error) {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appExtendedRequest, nil, "extendedReq")
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagExtRequestName, oid, "requestName"))
	if value != nil {
		op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagExtRequestValue, string(value), "requestValue"))
	}
	return c.exchange(op)
}

// exchange sends one request and reads one result.
func (c *Client) exchange(op *ber.Packet) (ldap.Result, error) {
	id := c.next()
	if err := c.write(id, op, nil); err != nil {
		return ldap.Result{}, err
	}
	p, err := c.Read()
	if err != nil {
		return ldap.Result{}, err
	}
	return result(p)
}

func str(v string) *ber.Packet {
	return ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "s")
}
