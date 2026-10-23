// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"os"
	"testing"

	"github.com/go-authn/ldap/schema"
	"github.com/go-authn/ldap/schema/hclschema"
)

// The largest schema file OpenLDAP publishes is cosine.schema (74,626
// bytes, 41 attribute types, 13 object classes): each benchmark reads or
// writes it once per iteration.
func cosine(b *testing.B) (schema.File, *schema.Definitions, []byte) {
	data, err := os.ReadFile("testdata/openldap/cosine.schema")
	if err != nil {
		b.Fatal(err)
	}
	f := schema.File{Name: "cosine.schema", Data: data}
	d, err := schema.Read(f)
	if err != nil {
		b.Fatal(err)
	}
	h, err := hclschema.Encode(d, hclschema.EncodeOptions{})
	if err != nil {
		b.Fatal(err)
	}
	return f, d, h
}

func BenchmarkReadSchema(b *testing.B) {
	f, _, _ := cosine(b)
	b.SetBytes(int64(len(f.Data)))
	for b.Loop() {
		if _, err := schema.Read(f); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeHCL(b *testing.B) {
	_, _, h := cosine(b)
	f := schema.File{Name: "cosine.hcl", Data: h}
	b.SetBytes(int64(len(h)))
	for b.Loop() {
		if _, err := hclschema.Decode(f); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeHCL(b *testing.B) {
	_, d, _ := cosine(b)
	for b.Loop() {
		if _, err := hclschema.Encode(d, hclschema.EncodeOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}
