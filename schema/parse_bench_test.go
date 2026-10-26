// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"os"
	"testing"
)

// cosineDefs are the 41 attribute types and 13 object classes of OpenLDAP's
// cosine.schema, each printed in RFC 4512 form by String(): the input the
// libldap comparison in bench/libldap parses too, so that the two numbers
// are about the same strings.
func cosineDefs(tb testing.TB) (ats, ocs []string) {
	tb.Helper()
	data, err := os.ReadFile("../cmd/ldapschema/testdata/openldap/cosine.schema")
	if err != nil {
		tb.Fatal(err)
	}
	d, err := Read(File{Name: "cosine.schema", Data: data})
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

// BenchmarkParseCosine is the parser alone: one iteration parses all 54
// definitions with ParseAttributeType and ParseObjectClass.
func BenchmarkParseCosine(b *testing.B) {
	ats, ocs := cosineDefs(b)
	b.ReportAllocs()
	for b.Loop() {
		for _, s := range ats {
			if _, err := ParseAttributeType(s); err != nil {
				b.Fatal(err)
			}
		}
		for _, s := range ocs {
			if _, err := ParseObjectClass(s); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkReadCosine is the whole of Read on cosine.schema: the file
// unwrapped into definitions, each one parsed in the OpenLDAP dialect.
func BenchmarkReadCosine(b *testing.B) {
	data, err := os.ReadFile("../cmd/ldapschema/testdata/openldap/cosine.schema")
	if err != nil {
		b.Fatal(err)
	}
	f := File{Name: "cosine.schema", Data: data}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Read(f); err != nil {
			b.Fatal(err)
		}
	}
}
