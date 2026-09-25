// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// readControl builds an RFC 4527 request control: an AttributeSelection.
func readControl(oid string, critical bool, attrs ...string) *Control {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "AttributeSelection")
	for _, a := range attrs {
		seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a, "selector"))
	}
	return &Control{Type: oid, Criticality: critical, Value: seq.Bytes()}
}

// entryIn reads the SearchResultEntry out of a response control.
func entryIn(t *testing.T, controls []Control, oid string) (*Entry, bool) {
	t.Helper()
	for _, c := range controls {
		if c.Type != oid {
			continue
		}
		p, err := ber.DecodePacketErr(c.Value)
		if err != nil {
			t.Fatalf("the %s response control does not parse: %v", oid, err)
		}
		e := &Entry{DN: string(p.Children[0].Data.Bytes())}
		for _, a := range p.Children[1].Children {
			attr := &Attribute{Name: string(a.Children[0].Data.Bytes())}
			for _, v := range a.Children[1].Children {
				attr.Values = append(attr.Values, append([]byte{}, v.Data.Bytes()...))
			}
			e.Attributes = append(e.Attributes, attr)
		}
		return e, true
	}
	return nil, false
}

func before() *Entry {
	return &Entry{DN: "cn=admins,dc=example,dc=org", Attributes: []*Attribute{
		StringAttribute("objectClass", "groupOfNames"),
		StringAttribute("member", "alice", "bob"),
		StringAttribute("description", "the people who can"),
	}}
}

func after() *Entry {
	return &Entry{DN: "cn=admins,dc=example,dc=org", Attributes: []*Attribute{
		StringAttribute("objectClass", "groupOfNames"),
		StringAttribute("member", "bob"),
		StringAttribute("description", "the people who can"),
	}}
}

// ⛔ The reason these controls exist: a client that writes a group membership
// needs to know what it actually wrote. Without them it has to read the entry
// afterwards -- a second operation, with a gap, in which somebody else's
// write can land, so the copy it reads may not be the one its own write made.
func TestAModifyCanReportTheEntryBeforeAndAfter(t *testing.T) {
	w := &writes{pre: before(), post: after()}
	_, c := withWrites(t, w)

	code := c.modifyWith(t, "cn=admins,dc=example,dc=org",
		[]Change{{Operation: DeleteValues, Attribute: StringAttribute("member", "alice")}},
		readControl(OIDPreRead, false, "member"),
		readControl(OIDPostRead, false, "member"))
	if code != Success {
		t.Fatalf("the modify answered %s", code)
	}

	pre, ok := entryIn(t, c.lastControls, OIDPreRead)
	if !ok {
		t.Fatal("no pre-read control came back")
	}
	if got := pre.Values("member"); strings.Join(got, ",") != "alice,bob" {
		t.Errorf("the entry BEFORE had members %v", got)
	}
	post, ok := entryIn(t, c.lastControls, OIDPostRead)
	if !ok {
		t.Fatal("no post-read control came back")
	}
	if got := post.Values("member"); strings.Join(got, ",") != "bob" {
		t.Errorf("the entry AFTER had members %v", got)
	}

	// ⛔ And ONLY the attributes asked for. A control that returned the whole
	// entry would hand the client attributes it did not request -- which out
	// of a directory is the one somebody deliberately left out.
	if pre.Attribute("description") != nil {
		t.Errorf("the pre-read returned an attribute nobody asked for: %v", pre.Attributes)
	}
}

// ⛔ RFC 4527 3.1: "If the update operation fails ... no Pre-Read response
// control is provided." A control attached to a failure would describe an
// entry the operation did not produce -- and a client reading it would
// believe a write happened that did not.
func TestAFailedWriteCarriesNoReadControl(t *testing.T) {
	w := &writes{pre: before(), post: after(), result: Refuse(InsufficientAccessRights, "no")}
	_, c := withWrites(t, w)

	code := c.modifyWith(t, "cn=admins,dc=example,dc=org",
		[]Change{{Operation: DeleteValues, Attribute: StringAttribute("member", "alice")}},
		readControl(OIDPreRead, false), readControl(OIDPostRead, false))
	if code != InsufficientAccessRights {
		t.Fatalf("answered %s", code)
	}
	if _, ok := entryIn(t, c.lastControls, OIDPreRead); ok {
		t.Error("a failed write returned a pre-read control")
	}
	if _, ok := entryIn(t, c.lastControls, OIDPostRead); ok {
		t.Error("a failed write returned a post-read control")
	}
}

// ⛔ A handler that leaves the entry nil sends NO control, even on success.
// RFC 4527 4 requires the server to ensure the client may read what the
// control carries -- so "I performed the write but you may not see the
// entry" has to be expressible, and it is: an absent control.
func TestAHandlerMayPerformTheWriteAndWithholdTheEntry(t *testing.T) {
	w := &writes{} // no pre, no post
	_, c := withWrites(t, w)

	code := c.modifyWith(t, "cn=admins,dc=example,dc=org",
		[]Change{{Operation: AddValues, Attribute: StringAttribute("member", "carol")}},
		readControl(OIDPreRead, false))
	if code != Success {
		t.Fatalf("the modify answered %s", code)
	}
	if _, ok := entryIn(t, c.lastControls, OIDPreRead); ok {
		t.Error("a control came back for an entry the handler did not provide")
	}
	// The selection still reached the handler, so it could have answered.
	if w.modify == nil || w.modify.PreRead == nil {
		t.Error("the handler was not told the client had asked")
	}
}

// ⛔ RFC 4527 3 says which operation each control is FOR. A pre-read on an
// ADD asks to see an entry that did not exist; a post-read on a DELETE asks
// to see one that no longer does. Critical, the operation is refused -- the
// client said it is not the operation it wants without the control. Not
// critical, the control is dropped, which is what non-critical means.
func TestTheControlsThatCannotMeanAnything(t *testing.T) {
	w := &writes{pre: before(), post: after()}
	_, c := withWrites(t, w)

	// A CRITICAL pre-read on an add.
	code := c.addWith(t, "uid=new,dc=example,dc=org", nil, readControl(OIDPreRead, true))
	if code != UnavailableCriticalExtension {
		t.Errorf("a critical pre-read on an add answered %s", code)
	}
	if w.add != nil {
		t.Error("it reached the handler")
	}

	// The same, NOT critical: performed, and no control comes back.
	code = c.addWith(t, "uid=new,dc=example,dc=org",
		[]*Attribute{StringAttribute("objectClass", "person")}, readControl(OIDPreRead, false))
	if code != Success {
		t.Errorf("a non-critical pre-read on an add answered %s", code)
	}
	if _, ok := entryIn(t, c.lastControls, OIDPreRead); ok {
		t.Error("a pre-read control came back from an add")
	}

	// A critical POST-read on a delete.
	if code := c.deleteWith(t, "uid=x,dc=example,dc=org", readControl(OIDPostRead, true)); code != UnavailableCriticalExtension {
		t.Errorf("a critical post-read on a delete answered %s", code)
	}
	// And a pre-read on a delete IS allowed -- it is the one that shows what
	// was removed.
	if code := c.deleteWith(t, "uid=x,dc=example,dc=org", readControl(OIDPreRead, false)); code != Success {
		t.Errorf("a pre-read on a delete answered %s", code)
	}
	if _, ok := entryIn(t, c.lastControls, OIDPreRead); !ok {
		t.Error("a delete did not return the entry it removed")
	}
}

// A control value that is not an AttributeSelection is a protocol error, and
// the write does not happen.
func TestAMalformedReadControlIsRefused(t *testing.T) {
	w := &writes{pre: before()}
	_, c := withWrites(t, w)

	code := c.modifyWith(t, "cn=admins,dc=example,dc=org",
		[]Change{{Operation: AddValues, Attribute: StringAttribute("member", "carol")}},
		&Control{Type: OIDPreRead, Value: []byte("not a selection")})
	if code != ProtocolError {
		t.Errorf("answered %s", code)
	}
	if w.modify != nil {
		t.Error("the write happened anyway")
	}
}

// An empty selection is "all user attributes", which is the commonest form
// and must not be refused.
func TestAnEmptySelectionMeansEverything(t *testing.T) {
	w := &writes{post: after()}
	_, c := withWrites(t, w)

	code := c.modifyWith(t, "cn=admins,dc=example,dc=org",
		[]Change{{Operation: AddValues, Attribute: StringAttribute("member", "carol")}},
		&Control{Type: OIDPostRead}) // no value at all
	if code != Success {
		t.Fatalf("answered %s", code)
	}
	e, ok := entryIn(t, c.lastControls, OIDPostRead)
	if !ok {
		t.Fatal("no post-read control came back")
	}
	if len(e.Attributes) != 3 {
		t.Errorf("an empty selection returned %d attributes, want all 3", len(e.Attributes))
	}
}

// ⛔ The handler-error path for the operations that do NOT go through
// answerWrite. It used to be covered by a failing add; writes moved to their
// own answer function and took the test's reach with them, leaving the
// branch that hides an internal error from the client untested.
func TestAFailingCompareTellsTheClientNothing(t *testing.T) {
	w := &writes{err: errBoom}
	_, c := withWrites(t, w)

	id := c.next()
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appCompareRequest, nil, "compareRequest")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid=a,dc=example,dc=org", "entry"))
	ava := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "ava")
	ava.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid", "d"))
	ava.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "a", "v"))
	op.AppendChild(ava)
	c.write(t, id, op)

	res := resultOf(t, c.read(t))
	if res.Code != Other {
		t.Errorf("a failing compare answered %s, want other", res.Code)
	}
	if strings.Contains(res.Diagnostic, "shard7") {
		t.Errorf("the diagnostic leaked the internal error: %q", res.Diagnostic)
	}
}

// A modifyDN carrying a control that means nothing on it, and one carrying a
// malformed post-read. modifyDN takes BOTH controls, so it is the operation
// where a mistake in the plumbing shows up in only one of them.
func TestAModifyDNTakesBothControls(t *testing.T) {
	w := &writes{pre: before(), post: after()}
	_, c := withWrites(t, w)

	code := c.modifyDNWith(t, "cn=admins,dc=example,dc=org", "cn=owners", true, "",
		readControl(OIDPreRead, false, "member"), readControl(OIDPostRead, false, "member"))
	if code != Success {
		t.Fatalf("answered %s", code)
	}
	if _, ok := entryIn(t, c.lastControls, OIDPreRead); !ok {
		t.Error("no pre-read came back from a modifyDN")
	}
	if _, ok := entryIn(t, c.lastControls, OIDPostRead); !ok {
		t.Error("no post-read came back from a modifyDN")
	}

	// A malformed POST-read, which is the other decode path.
	if code := c.modifyDNWith(t, "cn=admins,dc=example,dc=org", "cn=owners", true, "",
		&Control{Type: OIDPostRead, Value: []byte("not a selection")}); code != ProtocolError {
		t.Errorf("a malformed post-read answered %s", code)
	}
}

// Keep on nothing is nothing: a handler that reports no entry must not make
// the server render one.
func TestKeepOnNoEntry(t *testing.T) {
	if got := (&ReadSelection{}).Keep(nil); got != nil {
		t.Errorf("Keep(nil) returned %+v", got)
	}
	// And "1.1" keeps the DN and no attributes, as it does in a search.
	e := (&ReadSelection{Attributes: []string{"1.1"}}).Keep(before())
	if e == nil || e.DN == "" {
		t.Fatal("1.1 dropped the DN")
	}
	if len(e.Attributes) != 0 {
		t.Errorf("1.1 kept %d attributes", len(e.Attributes))
	}
}

var errBoom = errBoomType{}

type errBoomType struct{}

func (errBoomType) Error() string { return "the database is on fire at /srv/db/shard7.sqlite" }

// A write carrying a control that is neither read control is left alone by
// the read-control plumbing -- it is not its business, and a non-critical
// one nobody handles is ignored as it is anywhere else.
func TestAWriteMayCarryAnUnrelatedControl(t *testing.T) {
	w := &writes{post: after()}
	_, c := withWrites(t, w)

	code := c.modifyWith(t, "cn=admins,dc=example,dc=org",
		[]Change{{Operation: AddValues, Attribute: StringAttribute("member", "carol")}},
		&Control{Type: OIDManageDsaIT},
		readControl(OIDPostRead, false, "member"))
	if code != Success {
		t.Fatalf("answered %s", code)
	}
	if _, ok := entryIn(t, c.lastControls, OIDPostRead); !ok {
		t.Error("the post-read was lost because another control was present")
	}
}
