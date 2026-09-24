// SPDX-License-Identifier: BSD-3-Clause

package ldap

import "strings"

// Scope and DN comparison, which belong to the PROTOCOL and not to whatever
// holds the data.
//
// ⛔ They are here because every consumer otherwise writes them again. RFC
// 4511 4.5.1.2 defines scope purely in terms of DNs -- nothing about it needs
// to know what an entry contains -- so a directory that implements it is
// implementing the protocol, badly, in a place nobody reviews it as
// protocol. The test fixture in this very package got it wrong: written as a
// suffix test, an empty base becomes HasSuffix(dn, ",") and matches NOTHING,
// so a search of the whole tree came back empty while looking like a correct
// answer. That is the argument, and it is not hypothetical.

// InScope reports whether an entry's DN is within a search's scope
// (RFC 4511 4.5.1.2).
//
//   - ScopeBaseObject is the base entry itself.
//   - ScopeSingleLevel is its IMMEDIATE subordinates: the base is not in it,
//     and neither is anything two levels down.
//   - ScopeWholeSubtree is the base and everything beneath it.
//
// An EMPTY base is the root of the DIT: everything is beneath it, its single
// level is the entries with exactly one RDN, and at base scope it is the
// root DSE -- which a server answers itself and never asks a handler about.
func InScope(dn, base string, scope Scope) bool {
	dn, base = strings.TrimSpace(dn), strings.TrimSpace(base)
	if base == "" {
		switch scope {
		case ScopeBaseObject:
			return dn == ""
		case ScopeSingleLevel:
			return dn != "" && len(splitDN(dn)) == 1
		}
		return true
	}
	if EqualDN(dn, base) {
		return scope != ScopeSingleLevel
	}
	rest, under := underDN(dn, base)
	if !under {
		return false
	}
	if scope == ScopeSingleLevel {
		return len(splitDN(rest)) == 1
	}
	return scope == ScopeWholeSubtree
}

// EqualDN reports whether two DNs name the same entry.
//
// ⛔ It compares RDN by RDN with case folded, and trims the space either side
// of each separator, because `uid=a, ou=people` and `uid=a,ou=people` are the
// same DN (RFC 4514 2). Comparing the whole strings makes them different, and
// then an entry is in scope or not depending on how the client happened to
// type its base.
//
// It does NOT normalise attribute values by their matching rules, which
// needs a schema this package does not have: `cn=Bob` and `cn=bob ` are
// treated as equal (case, and trailing space) but `cn=B\6fb` is not unescaped
// to `cn=Bob`. A deployment whose DNs differ only by escaping needs a schema-
// aware comparison, and should say so rather than discover it.
func EqualDN(a, b string) bool {
	ra, rb := splitDN(a), splitDN(b)
	if len(ra) != len(rb) {
		return false
	}
	for i := range ra {
		if !strings.EqualFold(ra[i], rb[i]) {
			return false
		}
	}
	return true
}

// underDN reports whether dn is beneath base, and returns the part above it.
func underDN(dn, base string) (rest string, ok bool) {
	rdns, brdns := splitDN(dn), splitDN(base)
	if len(rdns) <= len(brdns) {
		return "", false
	}
	tail := rdns[len(rdns)-len(brdns):]
	for i := range brdns {
		if !strings.EqualFold(tail[i], brdns[i]) {
			return "", false
		}
	}
	return strings.Join(rdns[:len(rdns)-len(brdns)], ","), true
}

// splitDN splits a DN into its RDNs, trimming the space around each and
// honouring the backslash escape so that a comma INSIDE a value does not
// split it (RFC 4514 2.4): `cn=Smith\, John,ou=people` is two RDNs, not
// three, and splitting it into three puts an entry in the wrong place in the
// tree.
func splitDN(dn string) []string {
	var out []string
	var cur strings.Builder
	escaped := false
	for i := 0; i < len(dn); i++ {
		c := dn[i]
		switch {
		case escaped:
			cur.WriteByte(c)
			escaped = false
		case c == '\\':
			cur.WriteByte(c)
			escaped = true
		case c == ',':
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if s := strings.TrimSpace(cur.String()); s != "" || cur.Len() > 0 {
		out = append(out, s)
	}
	if len(out) == 1 && out[0] == "" {
		return nil
	}
	return out
}
