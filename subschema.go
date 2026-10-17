// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"context"

	"github.com/go-authn/ldap/schema"
)

// SubschemaDN is where a server with a Schema publishes it: the subschema
// subentry of RFC 4512 4.2, named as OpenLDAP names its own.
//
// RFC 4512 3.2 names a subentry with 'cn', and so does this.
const SubschemaDN = "cn=Subschema"

// subschemaEntry is the subschema subentry (RFC 4512 4.2).
//
// ⛔ Its classes are top, subentry and subschema. 'subschema' is AUXILIARY
// (RFC 4512 4.2) and an entry needs exactly one structural chain (2.4.2);
// RFC 4512 3.2 says a server following X.500 uses a subentry, whose class
// is RFC 3672's STRUCTURAL 'subentry' -- and 'subentry' MUST have cn and a
// subtreeSpecification. OpenLDAP's cn=Subschema claims 'subentry' and has
// no subtreeSpecification, so it breaks its own schema; this one carries
// "{}", which RFC 3672 2.1 says is the whole subtree, and the test checks
// that this entry passes schema.Validate.
//
// Everything but objectClass and cn is operational, so a bare search gets
// those two and "+" (RFC 3673), or the names, get the definitions -- the
// rule the root DSE follows, and RFC 4512 4.4: clients list "the names of
// the desired schema attributes (as they are operational)".
//
// There are no dITStructureRules, nameForms or dITContentRules: none is
// implemented, and publishing one would promise a rule nothing enforces.
func subschemaEntry(s *schema.Schema) *Entry {
	e := &Entry{DN: SubschemaDN}
	e.Attributes = append(e.Attributes,
		StringAttribute("objectClass", "top", "subentry", "subschema"),
		StringAttribute("cn", "Subschema"),
		OperationalAttribute("subtreeSpecification", "{}"),
	)
	add := func(name string, values []string) {
		if len(values) > 0 {
			e.Attributes = append(e.Attributes, OperationalAttribute(name, values...))
		}
	}
	add("ldapSyntaxes", strs(s.Syntaxes()))
	add("matchingRules", strs(s.MatchingRules()))
	add("matchingRuleUse", strs(s.MatchingRuleUses()))
	add("attributeTypes", strs(s.AttributeTypes()))
	add("objectClasses", strs(s.ObjectClasses()))
	return e
}

func strs[T interface{ String() string }](xs []T) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = x.String()
	}
	return out
}

// isSubschemaRead reports whether this search is the one RFC 4512 4.4
// describes: the subschema subentry, at base scope.
//
// Only base scope: RFC 3672 3 says subentries "are not visible to
// singleLevel and wholeSubtree scope Search requests". A one-level or
// subtree search based at cn=Subschema reaches the handler, which holds no
// such entry.
func isSubschemaRead(s *schema.Schema, req *SearchRequest) bool {
	return s != nil && req.Scope == ScopeBaseObject && s.MatchDN(req.BaseObject, SubschemaDN) == schema.True
}

// searchSubschema answers the subschema subentry. The filter applies, as it
// does to the root DSE: a client asking (objectClass=subschema) gets it, and
// one asking (objectClass=person) does not.
func (c *conn) searchSubschema(ctx context.Context, m *message, req *SearchRequest) {
	w := &entryWriter{c: c, id: m.id, ctx: ctx, typesOnly: req.TypesOnly, selection: selection(req)}
	e := subschemaEntry(c.srv.Schema)
	if Evaluate(req.Filter, e, c.srv.Schema) == schema.True {
		if err := w.Entry(e); err != nil {
			return
		}
	}
	c.send(resultMessage(m.id, appSearchResDone, Result{Code: Success}))
}
