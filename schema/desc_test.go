// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// descs lists every DESC of d as "kind OID: text".
func descs(d *Definitions) map[string]string {
	out := map[string]string{}
	for _, x := range d.Syntaxes {
		out["syntax "+x.OID] = x.Desc
	}
	for _, x := range d.MatchingRules {
		out["matching rule "+x.OID] = x.Desc
	}
	for _, x := range d.AttributeTypes {
		out["attribute type "+x.OID] = x.Desc
	}
	for _, x := range d.ObjectClasses {
		out["object class "+x.OID] = x.Desc
	}
	return out
}

// wrapped says whether a DESC still carries the line layout of the text it
// was copied from: a newline, a tab, or two spaces in a row.
func wrapped(s string) bool {
	return strings.ContainsAny(s, "\n\t\r") || strings.Contains(s, "  ")
}

// ⛔ The RFCs show a definition across several lines for the reader (RFC 4512
// 4.1: white space may separate any two terms); the line break inside a
// quoted DESC is not part of the value. slapd (fp_getline, config.c) keeps
// the indentation of a continuation line after its first character, so a
// DESC wrapped in a file is published with the run of spaces in it: v0.10.1
// published 'An integer uniquely identifying a user in an         administrative
// domain' for uidNumber, where OpenLDAP's nis.schema has one line.
func TestEmbeddedDESCsCarryNoLineLayout(t *testing.T) {
	var named int
	for _, f := range StandardFiles() {
		d, err := Read(f)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range descs(d) {
			if wrapped(v) {
				named++
				t.Errorf("%s: %s: DESC %q has line layout in it", f.Name, k, v)
			}
		}
	}
	if named > 0 {
		t.Logf("%d DESCs", named)
	}
}

// The control: the check above must see a wrapped DESC, in each of the four
// kinds, whatever the indentation, or a pass means nothing.
func TestTheDESCCheckSeesAWrappedDESC(t *testing.T) {
	src := "ldapsyntax ( 1.1.1 DESC 'a\n\t        b' )\n" +
		"matchingrule ( 1.1.2 NAME 'eq' DESC 'a\n   b' SYNTAX 1.1.1 )\n" +
		"attributetype ( 1.1.3 NAME 'a' DESC 'a\n\t\tb' SYNTAX 1.1.1 )\n" +
		"objectclass ( 1.1.4 NAME 'c' DESC 'a\n b  c' )\n"
	d, err := Read(File{"planted", []byte(src)})
	if err != nil {
		t.Fatal(err)
	}
	m := descs(d)
	if len(m) != 4 {
		t.Fatalf("%d definitions read", len(m))
	}
	for k, v := range m {
		if !wrapped(v) {
			t.Errorf("%s: %q is wrapped and the check does not see it", k, v)
		}
	}
	if wrapped("one line, single spaces") || wrapped("") {
		t.Error("a clean DESC is reported as wrapped")
	}
}

// Where OpenLDAP ships the same definition, it may write a DESC of its own.
// Three kinds of difference are OpenLDAP's, not ours, and are not "fixed"
// toward it: one side has no DESC (RFC 4519 and 4524 define none; the two
// X.509 classes of RFC 4523 have one that core.schema leaves out),
// OpenLDAP's starts with the RFC it came from ("RFC2256: ...", its
// own gloss), and nis.schema shortens RFC 2307's DESC to its first words,
// listed here with what the RFC says (opened at rfc-editor.org/rfc/rfc2307).
var openldapDiverges = map[string]bool{
	"attribute type 1.3.6.1.1.1.1.19": true, // RFC 2307 5: "IP address as a dotted decimal, eg. 192.168.1.1, omitting leading zeros"
	"attribute type 1.3.6.1.1.1.1.20": true, // "IP network as a dotted decimal, eg. 192.168, omitting leading zeros"
	"attribute type 1.3.6.1.1.1.1.21": true, // "IP netmask as a dotted decimal, eg. 255.255.255.0, omitting leading zeros"
	"attribute type 1.3.6.1.1.1.1.22": true, // "MAC address in maximal, colon separated hex notation, eg. 00:00:92:90:ee:e2"
	"object class 1.3.6.1.1.1.2.3":    true, // ipService
	"object class 1.3.6.1.1.1.2.4":    true, // ipProtocol
	"object class 1.3.6.1.1.1.2.5":    true, // oncRpc
	"object class 1.3.6.1.1.1.2.6":    true, // ipHost
	"object class 1.3.6.1.1.1.2.7":    true, // ipNetwork
	"object class 1.3.6.1.1.1.2.8":    true, // nisNetgroup
	"object class 1.3.6.1.1.1.2.11":   true, // ieee802Device
	"object class 1.3.6.1.1.1.2.12":   true, // bootableDevice
}

func TestEmbeddedDESCsAgreeWithOpenLDAPWhereItShipsTheSame(t *testing.T) {
	ours := map[string]string{}
	for _, f := range StandardFiles() {
		d, err := Read(f)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range descs(d) {
			ours[k] = v
		}
	}
	var compared int
	seen := map[string]bool{}
	for _, name := range []string{"core.schema", "cosine.schema", "inetorgperson.schema", "nis.schema"} {
		b, err := os.ReadFile(filepath.Join("..", "cmd", "ldapschema", "testdata", "openldap", name))
		if err != nil {
			t.Fatal(err)
		}
		d, err := Read(File{name, b})
		if err != nil {
			t.Fatal(err)
		}
		for k, theirs := range descs(d) {
			mine, ok := ours[k]
			if !ok {
				continue
			}
			compared++
			if mine == "" || theirs == "" || strings.HasPrefix(theirs, "RFC") {
				continue
			}
			if mine == theirs {
				continue
			}
			if !openldapDiverges[k] {
				t.Errorf("%s: %s:\n  ours     %q\n  openldap %q", name, k, mine, theirs)
			}
			seen[k] = true
		}
	}
	for k := range openldapDiverges {
		if !seen[k] {
			t.Errorf("%s is listed as diverging and does not: remove it", k)
		}
	}
	if compared < 30 {
		t.Errorf("only %d definitions are in both: the comparison is blind", compared)
	}
	t.Logf("%d definitions compared", compared)
}
