// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-authn/ldap/schema"
)

func write(t *testing.T, name, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func ldapschema(args ...string) (status int, stdout, stderr string) {
	var out, errw bytes.Buffer
	status = run(args, &out, &errw)
	return status, out.String(), errw.String()
}

const mine = `objectidentifier site 1.3.6.1.4.1.99999
objectidentifier siteAttr site:1
attributetype ( siteAttr:1 NAME 'siteBadge'
	DESC 'the badge number'
	EQUALITY caseIgnoreMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32} SINGLE-VALUE )
objectclass ( site:2.1 NAME 'sitePerson' SUP top AUXILIARY MAY siteBadge )
`

func TestConvertBothWays(t *testing.T) {
	src := write(t, "site.schema", mine)
	status, h, stderr := ldapschema("to-hcl", src)
	if status != 0 {
		t.Fatalf("to-hcl: %d %s", status, stderr)
	}
	if !strings.Contains(h, "attribute_type \"siteBadge\" {\n  oid          = \"1.3.6.1.4.1.99999.1.1\"") || !strings.Contains(h, "syntax_len   = 32") {
		t.Errorf("to-hcl:\n%s", h)
	}
	_, hm, _ := ldapschema("to-hcl", "--macros", src)
	if !strings.Contains(hm, `"siteAttr:1"`) {
		t.Errorf("to-hcl --macros:\n%s", hm)
	}
	hcl := write(t, "site.hcl", hm)
	status, text, stderr := ldapschema("to-schema", "-m", hcl)
	if status != 0 {
		t.Fatalf("to-schema: %d %s", status, stderr)
	}
	want := "objectidentifier site 1.3.6.1.4.1.99999\nobjectidentifier siteAttr site:1\n\n" +
		"attributetype ( siteAttr:1\n\tNAME 'siteBadge'\n\tDESC 'the badge number'\n\tEQUALITY caseIgnoreMatch\n" +
		"\tSYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32}\n\tSINGLE-VALUE )\n\n" +
		"objectclass ( site:2.1\n\tNAME 'sitePerson'\n\tSUP top\n\tAUXILIARY\n\tMAY siteBadge )\n"
	if text != want {
		t.Errorf("to-schema --macros:\n%s\nwant\n%s", text, want)
	}
	status, out, _ := ldapschema("check", src, hcl+".nothing-here")
	if status != 1 {
		t.Errorf("check of a missing file: %d %s", status, out)
	}
	other := write(t, "other.hcl", "attribute_type \"siteRoom\" {\n  oid = \"1.3.6.1.4.1.99999.1.2\"\n  sup = \"siteBadge\"\n}\n")
	status, out, _ = ldapschema("check", src, other)
	if status != 0 || !strings.Contains(out, "read: 2 object identifiers, 0 syntaxes, 0 matching rules, 2 attribute types, 1 object classes\n") ||
		!strings.Contains(out, "build: ok, 3 definitions added to schema.Standard()\n") {
		t.Errorf("check: %d\n%s", status, out)
	}
}

// differing is three of the standard definitions: title as it is, cn with
// another DESC, sn with another SUP.
func differing(t *testing.T) string {
	std, err := schema.Read(schema.StandardFiles()...)
	if err != nil {
		t.Fatal(err)
	}
	// One syntax and one rule as they are, too.
	d := &schema.Definitions{Syntaxes: std.Syntaxes[:1], MatchingRules: std.MatchingRules[:1]}
	for _, x := range std.AttributeTypes {
		c := *x
		switch c.Name() {
		case "title":
		case "cn":
			c.Desc = "another"
		case "sn":
			c.Sup = "title"
		default:
			continue
		}
		d.AttributeTypes = append(d.AttributeTypes, &c)
	}
	out, err := d.Format(false)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestCheckReports(t *testing.T) {
	for _, c := range []struct {
		text   string
		status int
		want   string
	}{
		{"matchingrule ( 1.9 NAME 'mm' SYNTAX 1.9.9 )\nobjectclass ( 1.9.1 NAME 'oc' SUP nope MUST ( cn $ gone ) MAY gone )\n", 1,
			"missing: syntax 1.9.9, used by mm\nmissing: object class nope, used by oc\nmissing: attribute type gone, used by oc\n"},
		{"attributetype ( 1.9 NAME 'z' SUP cn USAGE dSAOperation )\n", 1, "x.schema:1:1: schema: the attribute type z is dSAOperation and its supertype cn is userApplications"},
		{differing(t), 0,
			"already in schema.Standard(), which is kept: 3 identical, 2 different (1 in DESC only)\n  differs: sn (Sup)\nbuild: ok, 0 definitions"},
		// The rules: every reference they make that nothing defines.
		{"ditcontentrule ( 1.9.9 NAME 'r' AUX nope MUST gone )\nnameform ( 1.9.8 NAME 'f' OC nada MUST cn MAY gone )\nditstructurerule ( 1 NAME 's' FORM g SUP 2 )\n", 1,
			"read: 1 DIT content rules, 1 name forms, 1 DIT structure rules\n" +
				"missing: object class 1.9.9, used by r\nmissing: object class nope, used by r\nmissing: attribute type gone, used by r, f\n" +
				"missing: object class nada, used by f\nmissing: name form g, used by s\nmissing: DIT structure rule 2, used by s\n"},
		{"nameform ( 1.9.8 NAME 'f' OC organizationalUnit MUST ou )\nditstructurerule ( 1 NAME 's' FORM f SUP 1 )\nditcontentrule ( 2.5.6.5 NOT seeAlso )\n", 0,
			"build: ok, 3 definitions added to schema.Standard()\n"},
		{"nameform ( 1.9.8 NAME 'f' OC top MUST ou )\n", 1, "x.schema:1:1: schema: the name form f names the abstract class top"},
	} {
		status, out, _ := ldapschema("check", write(t, "x.schema", c.text))
		if status != c.status || !strings.Contains(out, c.want) {
			t.Errorf("%s: %d\n%s\nwant %d %q", c.text, status, out, c.status, c.want)
		}
	}
}

// The rules go to HCL and back to the .schema form Format writes, and check
// builds them.
func TestTheRulesRoundTrip(t *testing.T) {
	text := "ditcontentrule ( 2.5.6.5 NAME 'r' AUX extensibleObject NOT seeAlso )\n" +
		"nameform ( 1.9.8 NAME 'f' OC organizationalUnit MUST ou )\n" +
		"ditstructurerule ( 1 NAME 's' FORM f SUP ( 1 2 ) )\nditstructurerule ( 2 FORM f )\n"
	src := write(t, "rules.schema", text)
	status, h, stderr := ldapschema("to-hcl", src)
	if status != 0 || !strings.Contains(h, "dit_structure_rule \"s\" {\n  id   = 1\n  form = \"f\"\n  sup  = [1, 2]\n}") {
		t.Fatalf("to-hcl: %d %s\n%s", status, stderr, h)
	}
	status, back, stderr := ldapschema("to-schema", write(t, "rules.hcl", h))
	d, err := schema.Read(schema.File{Name: "x", Data: []byte(text)})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := d.Format(false)
	if status != 0 || back != string(want) {
		t.Errorf("to-schema: %d %s\n%s\nwant\n%s", status, stderr, back, want)
	}
	if status, out, _ := ldapschema("check", src); status != 0 || !strings.Contains(out, "build: ok, 4 definitions added") {
		t.Errorf("check: %d\n%s", status, out)
	}
}

func TestUsageAndFailures(t *testing.T) {
	dir := t.TempDir()
	big := write(t, "big.schema", "")
	if err := os.Truncate(big, schema.MaxFileSize+1); err != nil {
		t.Fatal(err)
	}
	bad := write(t, "bad.schema", "bogus ( 1.1 )\n")
	twice := write(t, "twice.schema", "attributetype ( 1.1 NAME 'a' SYNTAX 1.1 X-A 'x' X-A 'y' )\n")
	badHCL := write(t, "bad.hcl", "nonsense\n")
	newline := write(t, "nl.hcl", "attribute_type \"a\" {\n  oid = \"1.1\"\n  syntax = \"1.1\"\n  desc = \"two\\nlines\"\n}\n")
	for _, c := range []struct {
		args   []string
		status int
		out    string
		err    string
	}{
		{[]string{"-h"}, 0, "Usage:\n  ldapschema [flags]\n  ldapschema [command]", ""},
		{[]string{"to-hcl", "--help"}, 0, "to-hcl reads the files in order", ""},
		{nil, 2, "", "ldapschema: a command is needed"},
		{[]string{"convert"}, 2, "", `ldapschema: unknown command "convert"`},
		{[]string{"to-hcl"}, 2, "", "ldapschema: no FILE given"},
		{[]string{"to-hcl", "--nope", bad}, 2, "", "ldapschema: unknown flag: --nope"},
		{[]string{"to-hcl", bad}, 1, "", `bad.schema:1: "bogus" is not a kind of definition`},
		{[]string{"to-hcl", big}, 1, "", "more than the 4194304 a schema file may have"},
		{[]string{"to-hcl", dir}, 1, "", "ldapschema: read " + dir}, // the wording is the OS's
		{[]string{"to-hcl", twice}, 1, "", "the attribute type a has the extension X-A twice"},
		{[]string{"to-schema", bad}, 1, "", "Argument or block definition required"},
		{[]string{"to-schema", badHCL}, 1, "", "bad.hcl:1:1: Argument or block definition required"},
		{[]string{"to-schema", newline}, 1, "", "has a line break in a value"},
		{[]string{"to-schema", big}, 1, "", "more than the 4194304"},
		{[]string{"check", bad}, 1, "", `"bogus" is not a kind`},
		{[]string{"check", badHCL}, 1, "", "bad.hcl"},
	} {
		status, out, errw := ldapschema(c.args...)
		if status != c.status || !strings.Contains(out, c.out) || !strings.Contains(errw, c.err) {
			t.Errorf("%v: %d\nstdout %s\nstderr %s\nwant %d %q %q", c.args, status, out, errw, c.status, c.out, c.err)
		}
	}
}

func TestMain_(t *testing.T) {
	var got int
	osExit = func(code int) { got = code }
	defer func() { osExit = os.Exit }()
	args := os.Args
	defer func() { os.Args = args }()
	os.Args = []string{"ldapschema", "to-hcl"}
	stderr := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)
	defer func() { os.Stderr = stderr }()
	main()
	if got != 2 {
		t.Errorf("main: exit %d, want 2", got)
	}
}
