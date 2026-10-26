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
