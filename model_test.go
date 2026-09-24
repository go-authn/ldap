// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"strings"
	"testing"
)

// The Filter set is CLOSED: `filter()` is unexported, so a type outside this
// package cannot satisfy the interface. That matters because a Filter this
// package cannot encode is a search it cannot answer -- the closure is what
// makes EncodeFilter total over the interface rather than over a list
// somebody has to remember to extend.
//
// Every implementation is listed here, so adding one without teaching the
// rest of the package about it fails: EncodeFilter refuses an unknown type.
func TestTheFilterSetIsClosedAndEveryMemberRoundTrips(t *testing.T) {
	all := []Filter{
		&And{Filters: []Filter{&Present{Attribute: "cn"}}},
		&Or{Filters: []Filter{&Present{Attribute: "cn"}}},
		&Not{Filter: &Present{Attribute: "cn"}},
		&Equality{Attribute: "cn", Value: "a"},
		&GreaterOrEqual{Attribute: "cn", Value: "a"},
		&LessOrEqual{Attribute: "cn", Value: "a"},
		&Approx{Attribute: "cn", Value: "a"},
		&Present{Attribute: "cn"},
		&Substrings{Attribute: "cn", Initial: "a", Any: []string{"b"}, Final: "c"},
		&ExtensibleMatch{Attribute: "cn", Value: "a"},
	}
	for _, f := range all {
		f.filter() // the marker that keeps the set closed
		p, err := EncodeFilter(f)
		if err != nil {
			t.Errorf("%T cannot be encoded: %v", f, err)
			continue
		}
		if p == nil {
			t.Errorf("%T encoded to nothing", f)
		}
		if f.String() == "" {
			t.Errorf("%T rendered to nothing", f)
		}
	}
	// A Filter from outside cannot exist, but a nil one can be passed, and
	// EncodeFilter must refuse rather than panic.
	if _, err := EncodeFilter(nil); err == nil {
		t.Error("a nil filter was encoded")
	}
}

// An extensible match with no matching rule and no dnAttributes is an
// equality on the named attribute, which RFC 4511 4.5.1.7.7 permits. With
// either of those, it matches NOTHING -- see the comment on the method.
func TestAnExtensibleMatchIsAnEqualityOnlyWhenItAsksForNothingElse(t *testing.T) {
	e := entry("x", "cn", "alice")
	for _, tc := range []struct {
		what  string
		f     *ExtensibleMatch
		match bool
	}{
		{"plain", &ExtensibleMatch{Attribute: "cn", Value: "alice"}, true},
		{"plain, wrong value", &ExtensibleMatch{Attribute: "cn", Value: "bob"}, false},
		{"with a matching rule", &ExtensibleMatch{Attribute: "cn", Value: "alice", MatchingRule: "2.5.13.2"}, false},
		{"with dnAttributes", &ExtensibleMatch{Attribute: "cn", Value: "alice", DNAttributes: true}, false},
		{"with no attribute", &ExtensibleMatch{Value: "alice"}, false},
	} {
		if got := tc.f.Matches(e); got != tc.match {
			t.Errorf("%s: matched=%v, want %v", tc.what, got, tc.match)
		}
	}
}

// Unsupported must find the offending filter wherever it is, including under
// a NOT and inside an OR -- a server that only checked the top level would
// answer a narrower question than it was asked and call it success.
func TestUnsupportedLooksEverywhere(t *testing.T) {
	rule := &ExtensibleMatch{Attribute: "cn", Value: "a", MatchingRule: "2.5.13.2"}
	for _, tc := range []struct {
		what string
		f    Filter
		bad  bool
	}{
		{"at the top", rule, true},
		{"inside an AND", &And{Filters: []Filter{&Present{Attribute: "cn"}, rule}}, true},
		{"inside an OR", &Or{Filters: []Filter{rule}}, true},
		{"under a NOT", &Not{Filter: rule}, true},
		{"nested twice", &And{Filters: []Filter{&Or{Filters: []Filter{&Not{Filter: rule}}}}}, true},
		{"dnAttributes", &ExtensibleMatch{Attribute: "cn", Value: "a", DNAttributes: true}, true},
		{"no attribute", &ExtensibleMatch{Value: "a"}, true},
		{"a plain extensible match", &ExtensibleMatch{Attribute: "cn", Value: "a"}, false},
		{"an ordinary filter", &And{Filters: []Filter{&Present{Attribute: "cn"}}}, false},
	} {
		err := Unsupported(tc.f)
		if tc.bad && err == nil {
			t.Errorf("%s: not noticed", tc.what)
		}
		if !tc.bad && err != nil {
			t.Errorf("%s: refused: %v", tc.what, err)
		}
	}
}

// ⛔ An attribute description carries OPTIONS: `mail;lang-fr` is a different
// description from `mail`, and both answer to `mail` in a filter (RFC 4512
// 2.5). An entry that carries the same base name twice must have BOTH walked
// -- stopping at the first is how a value that matches is missed.
func TestAnAttributeWithOptionsStillAnswersToItsBaseName(t *testing.T) {
	e := &Entry{DN: "x", Attributes: []*Attribute{
		StringAttribute("mail;lang-en", "a@example.org"),
		StringAttribute("mail;lang-fr", "b@example.org"),
	}}
	f, err := ParseFilter("(mail=b@example.org)")
	if err != nil {
		t.Fatal(err)
	}
	if !f.Matches(e) {
		t.Error("the SECOND mail attribute was not reached")
	}
	if e.Attribute("mail") != nil {
		t.Error("Attribute(\"mail\") found an attribute that is not there: options are part of the description")
	}
	if got := e.Values("mail;lang-fr"); len(got) != 1 || got[0] != "b@example.org" {
		t.Errorf("Values came back as %v", got)
	}
	if got := e.Values("nothing"); got != nil {
		t.Errorf("Values of a missing attribute is %v, want nil", got)
	}
	// A present filter is about the attribute, and an attribute with no
	// values at all is not present.
	empty := &Entry{DN: "x", Attributes: []*Attribute{{Name: "mail"}}}
	if (&Present{Attribute: "mail"}).Matches(empty) {
		t.Error("an attribute with no values counted as present")
	}
}

func TestScopeAndModifyOperationName(t *testing.T) {
	for _, tc := range []struct {
		s    Scope
		want string
	}{{ScopeBaseObject, "base"}, {ScopeSingleLevel, "one"}, {ScopeWholeSubtree, "sub"}, {Scope(9), "scope(?)"}} {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("Scope(%d) is %q, want %q", tc.s, got, tc.want)
		}
	}
	for _, tc := range []struct {
		o    ModifyOperation
		want string
	}{{AddValues, "add"}, {DeleteValues, "delete"}, {ReplaceValues, "replace"}, {ModifyOperation(9), "modifyOperation(9)"}} {
		if got := tc.o.String(); got != tc.want {
			t.Errorf("ModifyOperation(%d) is %q, want %q", tc.o, got, tc.want)
		}
	}
}

// ⛔ OK() is not `code == Success`. compareTrue and compareFalse are both
// answers to a Compare and neither is a failure; saslBindInProgress is a
// bind that has not finished; referral is an answer that says where to ask.
// A caller comparing against Success treats all four as errors.
func TestWhichResultCodesAreNotFailures(t *testing.T) {
	for _, c := range []ResultCode{Success, CompareTrue, CompareFalse, SaslBindInProgress, Referral} {
		if !c.OK() {
			t.Errorf("%s is reported as a failure", c)
		}
		if err := (Result{Code: c}).Err(); err != nil {
			t.Errorf("%s produced an error: %v", c, err)
		}
	}
	for _, c := range []ResultCode{InvalidCredentials, NoSuchObject, Other, ResultCode(999)} {
		if c.OK() {
			t.Errorf("%s is reported as a success", c)
		}
	}
	if got := ResultCode(999).String(); got != "resultCode(999)" {
		t.Errorf("an unknown code renders as %q", got)
	}
	if got := InvalidCredentials.String(); got != "invalidCredentials" {
		t.Errorf("code 49 renders as %q, want the specification's own name", got)
	}

	// An error says the code, and the diagnostic when there is one.
	bare := (Result{Code: NoSuchObject}).Err()
	if bare == nil || bare.Error() != "ldap: noSuchObject" {
		t.Errorf("a bare error reads %v", bare)
	}
	full := Refuse(NoSuchObject, "no ou=%s under it", "sales")
	if err := full.Err(); err == nil || !strings.Contains(err.Error(), "no ou=sales under it") {
		t.Errorf("an error with a diagnostic reads %v", err)
	}
}

// ⛔ A critical control the server does not handle means the operation MUST
// be refused: the client has said the operation is not the one it wants
// unless the control is honoured. Ignoring it performs a DIFFERENT operation
// and reports success.
func TestACriticalControlNobodyHandlesIsFound(t *testing.T) {
	controls := []Control{
		{Type: OIDPaging, Criticality: false},
		{Type: OIDManageDsaIT, Criticality: true},
	}
	if c := UnhandledCritical(controls, OIDManageDsaIT); c != nil {
		t.Errorf("a control that IS handled was reported: %s", c.Type)
	}
	if c := UnhandledCritical(controls, OIDPaging); c == nil {
		t.Error("a critical control nobody handles was not reported")
	} else if c.Type != OIDManageDsaIT {
		t.Errorf("reported %s", c.Type)
	}
	// A non-critical one nobody handles is fine to ignore: that is what
	// non-critical MEANS.
	if c := UnhandledCritical([]Control{{Type: OIDPostRead}}); c != nil {
		t.Errorf("a NON-critical unknown control was reported: %s", c.Type)
	}

	if Find(controls, OIDPaging) == nil {
		t.Error("Find did not find a control that is there")
	}
	if Find(controls, OIDPreRead) != nil {
		t.Error("Find found one that is not")
	}
}
