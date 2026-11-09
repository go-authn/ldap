// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// A ClientConn is the client half of RFC 4511: bind, StartTLS and search, with
// the paged results control (RFC 2696). It is for a program that READS a
// directory -- go-authn/directory's ldapdir is the first -- and it exists
// because the general client libraries build a tree of packets for every
// message, which for a directory of ten thousand people and two thousand
// groups was 7 million allocations and 480 MB per refresh, three quarters of
// them in the BER reader.
//
// Here a message is read into one reusable buffer and decoded in two passes
// straight into the [Entry] the caller gets: a handful of allocations per
// entry, whatever its size.
//
// A ClientConn does one operation at a time and is not safe for concurrent
// use, except Close, which may be called from any goroutine and is how an
// operation is cancelled: the read in progress then fails.
type ClientConn struct {
	mu      sync.Mutex // guards nc against Close from another goroutine
	nc      net.Conn
	br      *bufio.Reader
	buf     []byte
	id      int
	names   map[string]string // attribute descriptions seen, so each is one string
	o       DialOptions
	secured bool
}

// ClientLimits bound what a server can make a client hold. A zero field is its
// default. Everything a hostile server controls -- a message, the entries of a
// search, the pages of one, the memory the result takes -- has a limit.
type ClientLimits struct {
	MaxMessage int // bytes of one LDAPMessage; default 8 MiB
	MaxEntries int // entries of one search; default 4,000,000
	MaxBytes   int // bytes kept for the entries of one search; default 1 GiB
	MaxPages   int // pages of one paged search; default 100,000
}

func (l ClientLimits) message() int { return orDefault(l.MaxMessage, 8<<20) }
func (l ClientLimits) entries() int { return orDefault(l.MaxEntries, 4_000_000) }
func (l ClientLimits) bytes() int   { return orDefault(l.MaxBytes, 1<<30) }
func (l ClientLimits) pages() int   { return orDefault(l.MaxPages, 100_000) }

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// DialOptions configure [Dial] and [NewClientConn].
type DialOptions struct {
	// TLS is for ldaps:// and for StartTLS. Nil means TLS 1.2 and the system
	// roots. Its ServerName, when empty, is the host of the URL.
	TLS *tls.Config
	// Dialer makes the connection; nil means a net.Dialer with a 30 second
	// timeout.
	Dialer *net.Dialer
	// Timeout is how long the client waits for the NEXT message of the server
	// (and for each write). Zero means 5 minutes: a server that accepts and
	// never answers is an outage, not a wait.
	Timeout time.Duration
	Limits  ClientLimits
}

func (o DialOptions) timeout() time.Duration {
	if o.Timeout <= 0 {
		return 5 * time.Minute
	}
	return o.Timeout
}

// ErrEmptyPassword is what [ClientConn.Bind] answers to a bind with a DN and no
// password: on the wire that is an unauthenticated bind (RFC 4513 5.1.2),
// which most servers answer with success and which proves nothing.
var ErrEmptyPassword = errors.New("ldap: an empty password is an unauthenticated bind, refused by the client")

// Dial connects to an ldap://, ldaps:// or ldapi:// URL. ldapi has the socket
// path, percent-escaped, as its host (ldapi://%2Fvar%2Frun%2Fldapi).
func Dial(ctx context.Context, rawurl string, o DialOptions) (*ClientConn, error) {
	if rest, ok := strings.CutPrefix(rawurl, "ldapi://"); ok {
		// Go's URL parser refuses the percent-escapes of a socket path in the
		// host, which is where ldapi puts it: the path is unescaped here.
		path, _, _ := strings.Cut(rest, "?")
		path, err := url.PathUnescape(path)
		if err != nil || path == "" {
			return nil, fmt.Errorf("ldap: %q names no socket", rawurl)
		}
		d := o.Dialer
		if d == nil {
			d = &net.Dialer{Timeout: 30 * time.Second}
		}
		nc, err := d.DialContext(ctx, "unix", path)
		if err != nil {
			return nil, err
		}
		c := NewClientConn(nc, o)
		c.secured = true // nobody is on the way
		return c, nil
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, fmt.Errorf("ldap: %w", err)
	}
	d := o.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: 30 * time.Second}
	}
	var nc net.Conn
	secured := false
	switch u.Scheme {
	case "ldap", "ldaps":
		host, port := u.Hostname(), u.Port()
		if port == "" {
			port = "389"
			if u.Scheme == "ldaps" {
				port = "636"
			}
		}
		if host == "" {
			host = "localhost"
		}
		nc, err = d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err == nil && u.Scheme == "ldaps" {
			nc, err = handshake(ctx, nc, o.TLS, host)
			secured = err == nil
		}
	default:
		return nil, fmt.Errorf("ldap: %q is not an ldap, ldaps or ldapi URL", rawurl)
	}
	if err != nil {
		return nil, err
	}
	c := NewClientConn(nc, o)
	c.secured = secured
	return c, nil
}

// handshake runs TLS on nc, naming host when the configuration names none.
func handshake(ctx context.Context, nc net.Conn, cfg *tls.Config, host string) (net.Conn, error) {
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		cfg = cfg.Clone()
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	tc := tls.Client(nc, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		nc.Close()
		return nil, err
	}
	return tc, nil
}

// NewClientConn speaks LDAP on nc.
func NewClientConn(nc net.Conn, o DialOptions) *ClientConn {
	return &ClientConn{nc: nc, br: bufio.NewReaderSize(nc, 32<<10), names: map[string]string{}, o: o}
}

// Close sends an unbind (RFC 4511 4.3), best effort, and closes the
// connection.
func (c *ClientConn) Close() error {
	c.mu.Lock()
	nc := c.nc
	c.mu.Unlock()
	unbind := ber.Encode(ber.ClassApplication, ber.TypePrimitive, 2, nil, "UnbindRequest") // [APPLICATION 2] NULL
	m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1<<30, "messageID")) // never an id of an operation
	m.AppendChild(unbind)
	nc.SetWriteDeadline(time.Now().Add(time.Second))
	nc.Write(m.Bytes())
	return nc.Close()
}

func (c *ClientConn) nextID() int {
	c.id++
	if c.id >= 1<<31-1 {
		c.id = 1
	}
	return c.id
}

// send writes one request: the message id, the operation and the controls.
func (c *ClientConn) send(id int, op *ber.Packet, controls *ber.Packet) error {
	m := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(id), "messageID"))
	m.AppendChild(op)
	if controls != nil {
		m.AppendChild(controls)
	}
	c.nc.SetWriteDeadline(time.Now().Add(c.o.timeout()))
	_, err := c.nc.Write(m.Bytes())
	return err
}

// clientMsg is one LDAPMessage of the server, cut into its parts.
type clientMsg struct {
	id       int
	op       byte
	body     []byte // contents of the protocolOp
	controls []byte // contents of [0] Controls, or nil
}

// receive reads the next message. The slices of the result point into the
// connection's buffer: they are good until the next receive.
func (c *ClientConn) receive() (clientMsg, error) {
	c.nc.SetReadDeadline(time.Now().Add(c.o.timeout()))
	var err error
	if c.buf, err = readClientFrame(c.br, c.buf, c.o.Limits.message()); err != nil {
		return clientMsg{}, err
	}
	body, _, _ := expect(c.buf, berSequence, "message") // readClientFrame checked its tag and length
	idv, body, err := expect(body, berInteger, "messageID")
	if err != nil {
		return clientMsg{}, err
	}
	id, err := integer(idv, "messageID")
	if err != nil {
		return clientMsg{}, err
	}
	op, val, rest, err := next(body)
	if err != nil {
		return clientMsg{}, fmt.Errorf("ldap: protocolOp: %w", err)
	}
	m := clientMsg{id: id, op: op, body: val}
	if len(rest) > 0 {
		var ctl []byte
		if ctl, rest, err = expect(rest, berControls, "controls"); err != nil {
			return clientMsg{}, err
		}
		m.controls = ctl
		if len(rest) > 0 {
			return clientMsg{}, errors.New("ldap: bytes after the controls of a message")
		}
	}
	return m, nil
}

// await reads until the message answering id, refusing an unsolicited one: a
// notice of disconnection (RFC 4511 4.4.1, message id 0) is the server saying
// it is going, and is returned as the error it is.
func (c *ClientConn) await(id int) (clientMsg, error) {
	m, err := c.receive()
	if err != nil {
		return m, err
	}
	if m.id == 0 && m.op == opExtendedResp {
		r, _ := readResult(m.body)
		return m, &Error{Result: Result{Code: ResultCode(orCode(r.Code, Unavailable)), Diagnostic: "the server is disconnecting: " + r.Diagnostic}}
	}
	if m.id != id {
		return m, fmt.Errorf("ldap: a message for id %d while waiting for %d", m.id, id)
	}
	return m, nil
}

func orCode(c, def ResultCode) ResultCode {
	if c == Success {
		return def
	}
	return c
}

// readResult reads an LDAPResult (RFC 4511 4.1.9) at the start of b.
func readResult(b []byte) (Result, []byte) {
	var r Result
	code, rest, err := expect(b, berEnumerated, "resultCode")
	if err != nil {
		return Result{Code: ProtocolError, Diagnostic: err.Error()}, nil
	}
	n, err := integer(code, "resultCode")
	if err != nil || n > 0xFFFF {
		return Result{Code: ProtocolError, Diagnostic: "a result code out of range"}, nil
	}
	r.Code = ResultCode(n)
	var v []byte
	if v, rest, err = expect(rest, berOctetString, "matchedDN"); err != nil {
		return Result{Code: ProtocolError, Diagnostic: err.Error()}, nil
	}
	r.MatchedDN = string(v)
	if v, rest, err = expect(rest, berOctetString, "diagnosticMessage"); err != nil {
		return Result{Code: ProtocolError, Diagnostic: err.Error()}, nil
	}
	r.Diagnostic = string(v)
	if len(rest) > 0 && rest[0] == berReferral {
		uris, after, err := expect(rest, berReferral, "referral")
		if err != nil {
			return Result{Code: ProtocolError, Diagnostic: err.Error()}, nil
		}
		for len(uris) > 0 && len(r.Referral) < 64 {
			u, more, err := expect(uris, berOctetString, "referral URI")
			if err != nil {
				break
			}
			r.Referral = append(r.Referral, string(u))
			uris = more
		}
		rest = after
	}
	return r, rest
}

// StartTLS upgrades the connection (RFC 4511 4.14). Call it before any other
// operation. The server's refusal is an *Error; a handshake that fails leaves
// the connection unusable and closed.
func (c *ClientConn) StartTLS(cfg *tls.Config) error {
	if c.secured {
		return errors.New("ldap: the connection is already protected")
	}
	id := c.nextID()
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 23, nil, "ExtendedRequest")
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, OIDStartTLS, "requestName"))
	if err := c.send(id, op, nil); err != nil {
		return err
	}
	m, err := c.await(id)
	if err != nil {
		return err
	}
	if m.op != opExtendedResp {
		return fmt.Errorf("ldap: the answer to StartTLS is operation %#x", m.op)
	}
	if r, _ := readResult(m.body); r.Code != Success {
		return &Error{Result: r}
	}
	host, _, err := net.SplitHostPort(c.nc.RemoteAddr().String())
	if err != nil {
		host = ""
	}
	if c.br.Buffered() != 0 {
		return errors.New("ldap: the server sent data before the TLS handshake")
	}
	tc, err := handshake(context.Background(), c.nc, cfg, host)
	if err != nil {
		return fmt.Errorf("ldap: StartTLS: %w", err)
	}
	c.mu.Lock()
	c.nc = tc
	c.mu.Unlock()
	c.br, c.secured = bufio.NewReaderSize(tc, 32<<10), true
	return nil
}

// Bind does a simple bind (RFC 4511 4.2, RFC 4513 5.1.3). An empty password
// is [ErrEmptyPassword]; a server's refusal, invalidCredentials among them, is
// an *Error with its result code.
func (c *ClientConn) Bind(dn, password string) error {
	if password == "" {
		return ErrEmptyPassword
	}
	id := c.nextID()
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 0, nil, "BindRequest")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "version"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "name"))
	op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, password, "simple"))
	if err := c.send(id, op, nil); err != nil {
		return err
	}
	m, err := c.await(id)
	if err != nil {
		return err
	}
	if m.op != opBindResponse {
		return fmt.Errorf("ldap: the answer to a bind is operation %#x", m.op)
	}
	r, _ := readResult(m.body)
	if r.Code != Success {
		return &Error{Result: r}
	}
	return nil
}

// Search runs a search and returns every entry (RFC 4511 4.5). With pageSize
// above zero it asks for the result in pages of that many entries (RFC 2696) and
// follows the cookie until the server says it is done; a server that ignores
// the control answers in one piece, which is fine. References are skipped. A
// result code that is not success is an *Error and the entries read so far are
// discarded: an incomplete directory read is not a smaller directory.
func (c *ClientConn) Search(req *SearchRequest, pageSize int) ([]*Entry, error) {
	var filter Filter = &Present{Attribute: "objectClass"}
	if req.Filter != nil {
		filter = req.Filter
	}
	fp, err := EncodeFilter(filter)
	if err != nil {
		return nil, err
	}
	lim := c.o.Limits
	var (
		out   []*Entry
		cost  int
		saved []byte
	)
	for page := 0; ; page++ {
		if page >= lim.pages() {
			return nil, fmt.Errorf("ldap: more than %d pages", lim.pages())
		}
		id := c.nextID()
		var controls *ber.Packet
		if pageSize > 0 {
			controls = clientPagedControl(pageSize, saved)
		}
		if err := c.send(id, clientSearchOp(req, fp), controls); err != nil {
			return nil, err
		}
		cookie, done, err := c.collect(id, &out, &cost)
		if err != nil {
			return nil, err
		}
		if !done || len(cookie) == 0 || pageSize <= 0 {
			return out, nil
		}
		saved = cookie
	}
}

// collect reads the answer to one search request: its entries into out and
// the paging cookie of its result.
func (c *ClientConn) collect(id int, out *[]*Entry, cost *int) (cookie []byte, done bool, err error) {
	lim := c.o.Limits
	for {
		m, err := c.await(id)
		if err != nil {
			return nil, false, err
		}
		switch m.op {
		case opSearchEntry:
			if len(*out) >= lim.entries() {
				return nil, false, fmt.Errorf("ldap: more than %d entries", lim.entries())
			}
			e, size, err := c.decodeEntry(m.body)
			if err != nil {
				return nil, false, err
			}
			if *cost += size; *cost > lim.bytes() {
				return nil, false, fmt.Errorf("ldap: the entries of one search are more than %d bytes", lim.bytes())
			}
			*out = append(*out, e)
		case opSearchRef, opIntermediate:
			// A continuation reference names another server; a directory read
			// does not follow it. An intermediate response is not asked for.
		case opSearchDone:
			r, _ := readResult(m.body)
			if r.Code != Success {
				return nil, false, &Error{Result: r}
			}
			ck, err := pagedCookie(m.controls)
			return ck, true, err
		default:
			return nil, false, fmt.Errorf("ldap: operation %#x in the answer to a search", m.op)
		}
	}
}

// searchOp builds the SearchRequest (RFC 4511 4.5.1).
func clientSearchOp(req *SearchRequest, filter *ber.Packet) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "SearchRequest")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, req.BaseObject, "baseObject"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(req.Scope), "scope"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(req.DerefAliases), "derefAliases"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(req.SizeLimit), "sizeLimit"))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(req.TimeLimit), "timeLimit"))
	op.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, req.TypesOnly, "typesOnly"))
	op.AppendChild(filter)
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, a := range req.Attributes {
		attrs.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a, "attribute"))
	}
	op.AppendChild(attrs)
	return op
}

// pagedControl is the Simple Paged Results control (RFC 2696 2): the page size
// and the cookie of the page before, empty for the first.
func clientPagedControl(size int, cookie []byte) *ber.Packet {
	val := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "realSearchControlValue")
	val.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(size), "size"))
	val.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(cookie), "cookie"))
	ctl := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "control")
	ctl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, OIDPaging, "controlType"))
	ctl.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(val.Bytes()), "controlValue"))
	list := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "controls")
	list.AppendChild(ctl)
	return list
}

// maxCookie bounds the cookie a server may hand back: they are kilobytes.
const maxCookie = 1 << 20

// pagedCookie finds the paging control in the controls of a SearchResultDone
// and returns its cookie, nil when there is none or it is empty.
func pagedCookie(controls []byte) ([]byte, error) {
	for len(controls) > 0 {
		ctl, rest, err := expect(controls, berSequence, "control")
		if err != nil {
			return nil, err
		}
		controls = rest
		typ, ctl, err := expect(ctl, berOctetString, "controlType")
		if err != nil {
			return nil, err
		}
		if string(typ) != OIDPaging {
			continue
		}
		if len(ctl) > 0 && ctl[0] == 0x01 { // criticality BOOLEAN
			if _, ctl, err = expect(ctl, 0x01, "criticality"); err != nil {
				return nil, err
			}
		}
		val, _, err := expect(ctl, berOctetString, "controlValue")
		if err != nil {
			return nil, err
		}
		seq, _, err := expect(val, berSequence, "paged results value")
		if err != nil {
			return nil, err
		}
		if _, seq, err = expect(seq, berInteger, "paged results size"); err != nil {
			return nil, err
		}
		ck, _, err := expect(seq, berOctetString, "paged results cookie")
		if err != nil {
			return nil, err
		}
		if len(ck) > maxCookie {
			return nil, fmt.Errorf("ldap: a paging cookie of %d bytes", len(ck))
		}
		return append([]byte(nil), ck...), nil
	}
	return nil, nil
}

// decodeEntry reads a SearchResultEntry (RFC 4511 4.5.2) into an Entry, and
// returns the bytes it keeps. Two passes over the message: the first counts
// attributes, values and the bytes of the values, the second fills five
// allocations sized by the first -- one array of attributes, one of their
// pointers, one of the value slices, one block holding every value -- plus
// the DN. An attribute description seen before is not allocated again.
func (c *ClientConn) decodeEntry(body []byte) (*Entry, int, error) {
	dn, rest, err := expect(body, berOctetString, "objectName")
	if err != nil {
		return nil, 0, err
	}
	list, rest, err := expect(rest, berSequence, "attributes")
	if err != nil {
		return nil, 0, err
	}
	if len(rest) > 0 {
		return nil, 0, errors.New("ldap: bytes after the attributes of an entry")
	}

	var natts, nvals, nbytes int
	for l := list; len(l) > 0; {
		var attr []byte
		if attr, l, err = expect(l, berSequence, "attribute"); err != nil {
			return nil, 0, err
		}
		var set []byte
		if _, attr, err = expect(attr, berOctetString, "attribute type"); err != nil {
			return nil, 0, err
		}
		if set, _, err = expect(attr, berSet, "attribute values"); err != nil {
			return nil, 0, err
		}
		natts++
		for ; len(set) > 0; nvals++ {
			var v []byte
			if v, set, err = expect(set, berOctetString, "attribute value"); err != nil {
				return nil, 0, err
			}
			nbytes += len(v)
		}
	}

	e := &Entry{DN: string(dn), Attributes: make([]*Attribute, natts)}
	atts := make([]Attribute, natts)
	vals := make([][]byte, nvals)
	block := make([]byte, nbytes)
	for i, l := 0, list; i < natts; i++ {
		attr, more, _ := expect(l, berSequence, "attribute")
		l = more
		typ, attr, _ := expect(attr, berOctetString, "attribute type")
		set, _, _ := expect(attr, berSet, "attribute values")
		name, ok := c.names[string(typ)]
		if !ok {
			name = string(typ)
			if len(c.names) < 4096 { // a hostile server cannot grow the table without end
				c.names[name] = name
			}
		}
		a := &atts[i]
		a.Name = name
		n := 0
		for s := set; len(s) > 0; n++ {
			_, s, _ = expect(s, berOctetString, "attribute value")
		}
		a.Values, vals = vals[:n:n], vals[n:]
		for j := range a.Values {
			v, more, _ := expect(set, berOctetString, "attribute value")
			set = more
			k := copy(block, v)
			a.Values[j], block = block[:k:k], block[k:]
		}
		e.Attributes[i] = a
	}
	return e, len(dn) + nbytes + 24*nvals + 64*natts + 64, nil
}
