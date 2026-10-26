// SPDX-License-Identifier: BSD-3-Clause

package libldap

import (
	"os"
	"testing"

	"github.com/go-authn/ldap/schema"
)

// cosine is OpenLDAP's cosine.schema, committed in the parent module; COSINE
// names another file to compare on.
func cosine() string {
	if p := os.Getenv("COSINE"); p != "" {
		return p
	}
	return "../../cmd/ldapschema/testdata/openldap/cosine.schema"
}

// defs are the attribute types and object classes of the file, each printed
// in RFC 4512 form by String(): the same strings for both parsers.
func defs(tb testing.TB) (ats, ocs []string) {
	tb.Helper()
	data, err := os.ReadFile(cosine())
	if err != nil {
		tb.Fatal(err)
	}
	d, err := schema.Read(schema.File{Name: "cosine.schema", Data: data})
	if err != nil {
		tb.Fatal(err)
	}
	for _, a := range d.AttributeTypes {
		ats = append(ats, a.String())
	}
	for _, o := range d.ObjectClasses {
		ocs = append(ocs, o.String())
	}
	return ats, ocs
}

func goParseAll(ats, ocs []string) error {
	for _, s := range ats {
		if _, err := schema.ParseAttributeType(s); err != nil {
			return err
		}
	}
	for _, s := range ocs {
		if _, err := schema.ParseObjectClass(s); err != nil {
			return err
		}
	}
	return nil
}

// Both parsers must accept every definition, or the timing compares nothing.
func TestBothAccept(t *testing.T) {
	ats, ocs := defs(t)
	s := NewSet(ats, ocs)
	defer s.Free()
	if err := s.ParseAll(); err != nil {
		t.Fatalf("libldap: %v", err)
	}
	if err := goParseAll(ats, ocs); err != nil {
		t.Fatalf("go: %v", err)
	}
	t.Logf("%d attribute types, %d object classes", len(ats), len(ocs))
}

// rules are DIT content rules, name forms and DIT structure rules made from
// cosine.schema's classes, since no published file holds such rules (slapd
// has no directive for the last two): for each class, a content rule with
// its superclasses as AUX, its MUST, its MAY and its first MAY as NOT; a
// name form for it; a structure rule with that form. Printed in RFC 4512
// form by String().
//
// ⛔ The structure rules have no SUP: ldap_str2structurerule has no branch
// for it (libraries/libldap/schema.c), and refuses a rule that has one --
// TestLibldapRefusesSUP.
func rules(tb testing.TB) (crs, nfs, srs []string) {
	tb.Helper()
	data, err := os.ReadFile(cosine())
	if err != nil {
		tb.Fatal(err)
	}
	d, err := schema.Read(schema.File{Name: "cosine.schema", Data: data})
	if err != nil {
		tb.Fatal(err)
	}
	for i, c := range d.ObjectClasses {
		cr := &schema.DITContentRule{OID: c.OID, Names: []string{c.Name() + "Rule"}, Desc: "for " + c.Name(), Aux: c.Sup, Must: c.Must, May: c.May}
		if len(c.May) > 1 {
			cr.May, cr.Not = c.May[1:], c.May[:1]
		}
		must := c.Must
		if len(must) == 0 {
			must = []string{"cn"}
		}
		nf := &schema.NameForm{OID: c.OID + ".1", Names: []string{c.Name() + "Form"}, OC: c.Name(), Must: must[:1], May: c.May}
		sr := &schema.DITStructureRule{ID: i + 1, Names: []string{c.Name() + "Structure"}, Form: nf.Names[0]}
		crs, nfs, srs = append(crs, cr.String()), append(nfs, nf.String()), append(srs, sr.String())
	}
	return crs, nfs, srs
}

func goParseRules(crs, nfs, srs []string) error {
	for _, s := range crs {
		if _, err := schema.ParseDITContentRule(s); err != nil {
			return err
		}
	}
	for _, s := range nfs {
		if _, err := schema.ParseNameForm(s); err != nil {
			return err
		}
	}
	for _, s := range srs {
		if _, err := schema.ParseDITStructureRule(s); err != nil {
			return err
		}
	}
	return nil
}

func TestBothAcceptRules(t *testing.T) {
	crs, nfs, srs := rules(t)
	r := NewRules(crs, nfs, srs)
	defer r.Free()
	if err := r.ParseAll(); err != nil {
		t.Fatalf("libldap: %v", err)
	}
	if err := goParseRules(crs, nfs, srs); err != nil {
		t.Fatalf("go: %v", err)
	}
	t.Logf("%d content rules, %d name forms, %d structure rules", len(crs), len(nfs), len(srs))
}

// libldap cannot read the SUP of a DIT structure rule, which RFC 4512
// 4.1.7.1 defines and its own ldap_structurerule2bv writes; this package
// can. A planted positive: the same rule without SUP reads in both.
func TestLibldapRefusesSUP(t *testing.T) {
	if rc := ParseStructureRule("( 2 FORM f )"); rc != 0 {
		t.Fatalf("libldap refuses a rule without SUP: %d", rc)
	}
	if rc := ParseStructureRule("( 2 FORM f SUP 1 )"); rc == 0 {
		t.Error("libldap now reads SUP: the comparison may include it")
	}
	if _, err := schema.ParseDITStructureRule("( 2 FORM f SUP 1 )"); err != nil {
		t.Error(err)
	}
}

// BenchmarkParseRules is BenchmarkParse for the three rule parsers.
func BenchmarkParseRules(b *testing.B) {
	crs, nfs, srs := rules(b)
	r := NewRules(crs, nfs, srs)
	defer r.Free()
	b.Run("go", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := goParseRules(crs, nfs, srs); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("libldap", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := r.ParseAll(); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkParse/go and BenchmarkParse/libldap are one pass over every
// definition each. ⚠ -count repeats each sub-benchmark back to back, so a
// change in the machine's load can reach one and not the other: to
// interleave them, build the test binary once (go test -c) and run it
// several times with -test.count 1 (the repository's README.md,
// "Performance").
func BenchmarkParse(b *testing.B) {
	ats, ocs := defs(b)
	s := NewSet(ats, ocs)
	defer s.Free()
	b.Run("go", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := goParseAll(ats, ocs); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("libldap", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := s.ParseAll(); err != nil {
				b.Fatal(err)
			}
		}
	})
}
