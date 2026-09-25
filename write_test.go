// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"context"
	"fmt"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// A recorder that accepts every write and remembers what arrived, so that a
// test can assert what the SERVER decoded rather than what a store did with
// it.
type writes struct {
	add      *AddRequest
	modify   *ModifyRequest
	del      *DeleteRequest
	modifyDN *ModifyDNRequest
	compare  *CompareRequest
	result   Result
	err      error
	// pre and post are what this handler reports for the read entry
	// controls, when a test sets them.
	pre, post *Entry
}

func (w *writes) Add(_ context.Context, _ Session, r *AddRequest) (WriteResult, error) {
	w.add = r
	return w.wrote()
}
func (w *writes) Modify(_ context.Context, _ Session, r *ModifyRequest) (WriteResult, error) {
	w.modify = r
	return w.wrote()
}
func (w *writes) Delete(_ context.Context, _ Session, r *DeleteRequest) (WriteResult, error) {
	w.del = r
	return w.wrote()
}
func (w *writes) ModifyDN(_ context.Context, _ Session, r *ModifyDNRequest) (WriteResult, error) {
	w.modifyDN = r
	return w.wrote()
}
func (w *writes) Compare(_ context.Context, _ Session, r *CompareRequest) (Result, error) {
	w.compare = r
	return w.answer()
}

// wrote is answer(), plus whatever entries the test asked it to report for
// the read entry controls.
func (w *writes) wrote() (WriteResult, error) {
	r, err := w.answer()
	return WriteResult{Result: r, PreRead: w.pre, PostRead: w.post}, err
}

func (w *writes) answer() (Result, error) {
	if w.err != nil {
		return Result{}, w.err
	}
	if w.result.Code == 0 && w.result.Diagnostic == "" {
		return Result{Code: Success}, nil
	}
	return w.result, nil
}

func withWrites(t *testing.T, w *writes) (*running, *client) {
	t.Helper()
	s := &Server{Bind: reader(), Search: &directory{}, Add: w, Modify: w, Delete: w, ModifyDN: w, Compare: w}
	r := serve(t, s)
	c := dial(t, r)
	t.Cleanup(c.Close)
	if code := c.bind(t, "cn=reader,dc=example,dc=org", "let me read"); code != Success {
		t.Fatalf("the bind answered %s", code)
	}
	return r, c
}

// ⛔ THE reason this server exists for writes: RFC 4511 4.6 says the
// modifications are "performed in the order listed". The library this
// replaces held three buckets -- add, delete, replace -- so
//
//	delete member=alice; add member=alice     (alice stays)
//	add member=alice; delete member=alice     (alice goes)
//
// arrived as the same request and a server could not tell which was asked.
// This asserts the two arrive DIFFERENT, which is the whole claim.
func TestTwoOppositeModificationsDoNotArriveTheSame(t *testing.T) {
	first := &writes{}
	_, c1 := withWrites(t, first)
	c1.modify(t, "cn=admins,dc=example,dc=org", []Change{
		{Operation: DeleteValues, Attribute: StringAttribute("member", "alice")},
		{Operation: AddValues, Attribute: StringAttribute("member", "alice")},
	})

	second := &writes{}
	_, c2 := withWrites(t, second)
	c2.modify(t, "cn=admins,dc=example,dc=org", []Change{
		{Operation: AddValues, Attribute: StringAttribute("member", "alice")},
		{Operation: DeleteValues, Attribute: StringAttribute("member", "alice")},
	})

	shape := func(r *ModifyRequest) string {
		var b strings.Builder
		for _, ch := range r.Changes {
			fmt.Fprintf(&b, "%s:%s=%s;", ch.Operation, ch.Attribute.Name, ch.Attribute.Values[0])
		}
		return b.String()
	}
	a, b := shape(first.modify), shape(second.modify)
	if a == b {
		t.Fatalf("two opposite modifications arrived identically: %s", a)
	}
	if a != "delete:member=alice;add:member=alice;" {
		t.Errorf("the first arrived as %s", a)
	}
	if b != "add:member=alice;delete:member=alice;" {
		t.Errorf("the second arrived as %s", b)
	}
}

func TestTheWritesArriveAsTheyWereSent(t *testing.T) {
	w := &writes{}
	_, c := withWrites(t, w)

	// Add, with a value that is not text -- an NT hash, a certificate. A
	// []string would have replaced every invalid byte with U+FFFD and stored
	// something else.
	binary := []byte{0x00, 0xff, 0xfe, 0x80}
	c.add(t, "uid=alice,dc=example,dc=org", []*Attribute{
		StringAttribute("objectClass", "person"),
		{Name: "sambaNTPassword", Values: [][]byte{binary}},
	})
	if w.add == nil || w.add.DN != "uid=alice,dc=example,dc=org" {
		t.Fatalf("the add arrived as %+v", w.add)
	}
	if got := w.add.Attributes[1].Values[0]; string(got) != string(binary) {
		t.Errorf("a binary value arrived as % x, want % x", got, binary)
	}

	// Delete: a DN and nothing else.
	c.delete(t, "uid=alice,dc=example,dc=org")
	if w.del == nil || w.del.DN != "uid=alice,dc=example,dc=org" {
		t.Errorf("the delete arrived as %+v", w.del)
	}

	// ModifyDN, with and without a new superior -- a rename and a move are
	// different operations and the field is what tells them apart.
	c.modifyDN(t, "uid=alice,dc=example,dc=org", "uid=alice2", true, "")
	if w.modifyDN.NewSuperior != "" || !w.modifyDN.DeleteOldRDN || w.modifyDN.NewRDN != "uid=alice2" {
		t.Errorf("the rename arrived as %+v", w.modifyDN)
	}
	c.modifyDN(t, "uid=alice,dc=example,dc=org", "uid=alice", false, "ou=former,dc=example,dc=org")
	if w.modifyDN.NewSuperior != "ou=former,dc=example,dc=org" || w.modifyDN.DeleteOldRDN {
		t.Errorf("the move arrived as %+v", w.modifyDN)
	}

	// Compare, whose answer is compareTrue or compareFalse and neither is an
	// error.
	w.result = Result{Code: CompareTrue}
	if code := c.compare(t, "uid=alice,dc=example,dc=org", "uid", "alice"); code != CompareTrue {
		t.Errorf("compare answered %s", code)
	}
	if w.compare.Attribute != "uid" || string(w.compare.Value) != "alice" {
		t.Errorf("the compare arrived as %+v", w.compare)
	}
}

// An operation with no handler is unwillingToPerform, not
// insufficientAccessRights -- "I do not do that" and "you may not do that"
// send an administrator to two different places.
func TestWritesWithNoHandlerSayTheyAreNotDone(t *testing.T) {
	r := serve(t, &Server{Bind: reader()})
	c := dial(t, r)
	defer c.Close()
	c.bind(t, "cn=reader,dc=example,dc=org", "let me read")

	for _, tc := range []struct {
		what string
		send func() ResultCode
	}{
		{"add", func() ResultCode { return c.add(t, "uid=a,dc=example,dc=org", nil) }},
		{"modify", func() ResultCode {
			return c.modify(t, "uid=a,dc=example,dc=org",
				[]Change{{Operation: AddValues, Attribute: StringAttribute("cn", "a")}})
		}},
		{"delete", func() ResultCode { return c.delete(t, "uid=a,dc=example,dc=org") }},
		{"modifyDN", func() ResultCode { return c.modifyDN(t, "uid=a,dc=example,dc=org", "uid=b", true, "") }},
		{"compare", func() ResultCode { return c.compare(t, "uid=a,dc=example,dc=org", "cn", "a") }},
	} {
		if code := tc.send(); code != UnwillingToPerform {
			t.Errorf("%s with no handler answered %s, want unwillingToPerform", tc.what, code)
		}
	}
}

// ⛔ A handler that returns an error has failed in a way it had no result
// code for. The client is told `other` and NOTHING else: whatever went wrong
// inside a directory is for the directory's own log, and a diagnostic built
// from an internal error hands a client the shape of the code behind it.
func TestAHandlerErrorTellsTheClientNothing(t *testing.T) {
	w := &writes{err: fmt.Errorf("the database is on fire at /srv/db/shard7.sqlite")}
	_, c := withWrites(t, w)

	id := c.next()
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appAddRequest, nil, "addRequest")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid=a,dc=example,dc=org", "entry"))
	op.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes"))
	c.write(t, id, op)
	res := resultOf(t, c.read(t))

	if res.Code != Other {
		t.Errorf("a handler error answered %s, want other", res.Code)
	}
	if strings.Contains(res.Diagnostic, "shard7") || strings.Contains(res.Diagnostic, "fire") {
		t.Errorf("the diagnostic leaked the internal error: %q", res.Diagnostic)
	}
}

// ⛔ RFC 4511 4.7: an Attribute has SIZE(1..MAX) values. An add naming an
// attribute with NO values asks for an entry that cannot exist, and
// accepting it would create one whose attribute list disagrees with what it
// holds.
func TestAnAddWithAValuelessAttributeIsRefused(t *testing.T) {
	w := &writes{}
	_, c := withWrites(t, w)

	id := c.next()
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appAddRequest, nil, "addRequest")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid=a,dc=example,dc=org", "entry"))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	pa := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
	pa.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "type"))
	pa.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals"))
	attrs.AppendChild(pa)
	op.AppendChild(attrs)
	c.write(t, id, op)

	if res := resultOf(t, c.read(t)); res.Code != ProtocolError {
		t.Errorf("an add with a valueless attribute answered %s", res.Code)
	}
	if w.add != nil {
		t.Error("it reached the handler")
	}
}
