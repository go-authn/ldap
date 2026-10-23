// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/ldap/schema"
	"github.com/go-authn/ldap/schema/hclschema"
)

// The schemas a directory actually loads, as their authors publish them.
//
// ⛔ Only OpenLDAP's are committed (testdata/openldap, with the OpenLDAP
// Public License 2.8 they are under, which allows it). The others are
// DOWNLOADED, when LDAP_SCHEMA_NETWORK=1, and checked against the SHA-256
// recorded here, so that a change upstream is reported rather than
// silently tested:
//
//   - SUPANN 2021 (RENATER): no licence or copyright statement in either
//     file, so no permission to redistribute them.
//   - eduPerson (REFEDS): CC BY-NC-SA 4.0 (the repository's LICENSE), whose
//     NonCommercial and ShareAlike terms this BSD-3-Clause module cannot
//     carry.
//   - samba.schema (Samba): GPL-3.0, the licence of the Samba tree; no
//     excerpt is kept either.
type source struct {
	url     string
	sha256  string
	fetched string // the date the checksum was taken
	file    string // committed copy under testdata, if any
}

type publication struct {
	name         string
	schema, ldif source
	// types, classes and macros are the counts the .schema file must give:
	// the positive control that the reader saw every definition.
	types, classes, macros int
	// ldifDiffers is what the LDIF form says differently from the .schema
	// form; nil when they agree.
	ldifDiffers []string
	// check is what `ldapschema check` must report on the .schema alone.
	checkStatus int
	checkLines  []string
}

const openldapCommit = "0160e81d9e55f44ee865152f60698a53bc902ba2" // 2026-04-30

func openldap(file, sum string) source {
	return source{
		url:     "https://git.openldap.org/openldap/openldap/-/raw/" + openldapCommit + "/servers/slapd/schema/" + file,
		sha256:  sum,
		fetched: "2026-10-22",
		file:    "testdata/openldap/" + file,
	}
}

var publications = []publication{
	{
		name:   "OpenLDAP core",
		schema: openldap("core.schema", "299ccc269e7e07f1ed85989a5a5befd96c57202aeb93414d605e8ff94f0354fe"),
		ldif:   openldap("core.ldif", "0c42eba81d52942e33686724a9d615375fe1e74c918e9254e27c745efa3d8d7c"),
		types:  52, classes: 27, macros: 47,
		checkStatus: 1,
		checkLines: []string{
			"missing: matching rule presentationAddressMatch, used by presentationAddress",
			"missing: syntax 1.3.6.1.4.1.1466.115.121.1.43, used by presentationAddress",
		},
	},
	{
		name:   "OpenLDAP cosine",
		schema: openldap("cosine.schema", "9405cf28b1b6bdb8c185436a5cb7f44d678ef657ff095772f78bb87e5f6d3397"),
		ldif:   openldap("cosine.ldif", "763ea5eea2c745e2676f659324201a86c3600d74339e5914cff51bad4f06243b"),
		types:  41, classes: 13,
		checkStatus: 1,
		checkLines: []string{
			"missing: syntax 1.3.6.1.4.1.1466.115.121.1.19, used by dSAQuality",
			"missing: object class dsa, used by pilotDSA",
		},
	},
	{
		name:   "OpenLDAP inetorgperson",
		schema: openldap("inetorgperson.schema", "b793e020a7681fbfc4fa19a555f17e11978fac583e0afe554f19b042f2d881ac"),
		ldif:   openldap("inetorgperson.ldif", "794f3e6713ca180ae08090023777f1ffb1adf42dcea6471552325756de8c4c69"),
		types:  9, classes: 1,
		checkLines: []string{"build: ok, 0 definitions added to schema.Standard()"},
	},
	{
		name:   "OpenLDAP nis",
		schema: openldap("nis.schema", "61b8ec970f779f116bbef8dc80c07c76efca8584aa6b473af85abea4a50484a6"),
		ldif:   openldap("nis.ldif", "716567f121dd904f50836e51a3d946f7336ba6c69548df75f13a84b4855058da"),
		types:  25, classes: 13,
		checkLines: []string{"already in schema.Standard(), which is kept: 26 identical, 12 different (12 in DESC only)"},
	},
	{
		name: "SUPANN 2021",
		// RENATER's DokuWiki serves each file as the page's code block.
		schema: source{
			url:     "https://services.renater.fr/_export/code/documentation/supann/supann2021/recommandations/tables_references/schematechnique_openldap?codeblock=0",
			sha256:  "961ba0e6bc38951332abb7335633b5a94ea3ba5f6bccd8516d32182e75f42ea3",
			fetched: "2026-10-22",
		},
		ldif: source{
			url:     "https://services.renater.fr/_export/code/documentation/supann/supann2021/recommandations/tables_references/schematechnique_openldap_ldif?codeblock=0",
			sha256:  "35fb191bb32045c5b57329cdca6249a50ad3e1278e1b408dda3c994fac40eeb3",
			fetched: "2026-10-22",
		},
		types: 67, classes: 8,
		checkLines: []string{"build: ok, 75 definitions added to schema.Standard()"},
	},
	{
		name: "eduPerson",
		schema: source{
			url:     "https://raw.githubusercontent.com/REFEDS/eduperson/c672bc4be5e081cba95013b1ac1f7e18fd247ca1/schema/openldap/eduperson.schema",
			sha256:  "c6247977be7f1ac89fcac18cb640be87dfdb149cdad6eb94cd10bbfa7614e891",
			fetched: "2026-10-22",
		},
		ldif: source{
			url:     "https://raw.githubusercontent.com/REFEDS/eduperson/c672bc4be5e081cba95013b1ac1f7e18fd247ca1/schema/openldap/eduperson.ldif",
			sha256:  "b97043552f911b918330d4060d68724edac851301e37f315e69876d583aca63c",
			fetched: "2026-10-22",
		},
		types: 16, classes: 1,
		// The .schema says "eduPerson (202111)", the .ldif "eduPerson
		// (202208) - v4.4.0": REFEDS publishes two versions side by side.
		ldifDiffers: []string{"object class 1.3.6.1.4.1.5923.1.1.2: Desc, May"},
		checkLines:  []string{"build: ok, 17 definitions added to schema.Standard()"},
	},
	{
		name: "Samba",
		schema: source{
			url:     "https://raw.githubusercontent.com/samba-team/samba/bb912a482796f496aaca597c04f864f45ca2e41c/examples/LDAP/samba.schema",
			sha256:  "b9081b7234762c3fc02861fbb88ed8b52a523dced38e15051dc980f0b34b23dd",
			fetched: "2026-10-22",
		},
		ldif: source{
			url:     "https://raw.githubusercontent.com/samba-team/samba/bb912a482796f496aaca597c04f864f45ca2e41c/examples/LDAP/samba.ldif",
			sha256:  "cb10bfbd6e204dbc56bf3dc698b344ff45dce187347ee5ff0e939c8ae8d2f40f",
			fetched: "2026-10-22",
		},
		types: 58, classes: 12,
		checkLines: []string{"build: ok, 70 definitions added to schema.Standard()"},
	},
}

// fetch is the committed copy, or a download when the network is allowed;
// false skips the publication.
func fetch(t *testing.T, s source) ([]byte, bool) {
	t.Helper()
	var b []byte
	if s.file != "" {
		var err error
		if b, err = os.ReadFile(s.file); err != nil {
			t.Fatal(err)
		}
	} else {
		if os.Getenv("LDAP_SCHEMA_NETWORK") != "1" {
			return nil, false
		}
		req, err := http.NewRequest(http.MethodGet, s.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		// RENATER answers 403 to a client that does not name itself.
		req.Header.Set("User-Agent", "Mozilla/5.0 (go-authn/ldap schema tests)")
		c := &http.Client{Timeout: time.Minute}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", s.url, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %s", s.url, resp.Status)
		}
		if b, err = io.ReadAll(io.LimitReader(resp.Body, schema.MaxFileSize+1)); err != nil {
			t.Fatalf("%s: %v", s.url, err)
		}
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != s.sha256 {
		t.Fatalf("%s changed since %s: SHA-256 %s, recorded %s -- read the change, then record the new sum", s.url, s.fetched, got, s.sha256)
	}
	return b, true
}

// differences lists, by kind and name, the definitions two readings do not
// agree on, and the fields where they do not.
func differences(a, b *schema.Definitions) []string {
	var out []string
	if !reflect.DeepEqual(a.ObjectIdentifiers, b.ObjectIdentifiers) {
		out = append(out, "object identifiers")
	}
	out = append(out, diffKind("syntax", a.Syntaxes, b.Syntaxes)...)
	out = append(out, diffKind("matching rule", a.MatchingRules, b.MatchingRules)...)
	out = append(out, diffKind("attribute type", a.AttributeTypes, b.AttributeTypes)...)
	return append(out, diffKind("object class", a.ObjectClasses, b.ObjectClasses)...)
}

func diffKind[T any](kind string, a, b []*T) []string {
	var out []string
	byOID := map[string]*T{}
	for _, x := range b {
		byOID[oidOf(x)] = x
	}
	for _, x := range a {
		y, ok := byOID[oidOf(x)]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("%s %s: only in the first", kind, oidOf(x)))
		case !reflect.DeepEqual(x, y):
			out = append(out, fmt.Sprintf("%s %s: %s", kind, oidOf(x), strings.Join(fieldsThatDiffer(x, y), ", ")))
		}
		delete(byOID, oidOf(x))
	}
	for _, x := range b {
		if _, left := byOID[oidOf(x)]; left {
			out = append(out, fmt.Sprintf("%s %s: only in the second", kind, oidOf(x)))
		}
	}
	return out
}

func TestPublishedSchemas(t *testing.T) {
	for _, p := range publications {
		t.Run(p.name, func(t *testing.T) {
			data, ok := fetch(t, p.schema)
			if !ok {
				t.Skip("downloaded, and LDAP_SCHEMA_NETWORK is not 1")
			}
			name := filepath.Base(p.schema.file)
			if name == "." {
				name = p.name + ".schema"
			}
			defs, err := schema.Read(schema.File{Name: name, Data: data})
			if err != nil {
				t.Fatal(err)
			}
			if len(defs.AttributeTypes) != p.types || len(defs.ObjectClasses) != p.classes || len(defs.ObjectIdentifiers) != p.macros {
				t.Fatalf("read %d attribute types, %d object classes, %d macros; the file has %d, %d, %d",
					len(defs.AttributeTypes), len(defs.ObjectClasses), len(defs.ObjectIdentifiers), p.types, p.classes, p.macros)
			}

			// .schema -> HCL -> definitions, both ways of writing OIDs.
			for _, macros := range []bool{false, true} {
				h, err := hclschema.Encode(defs, hclschema.EncodeOptions{Macros: macros})
				if err != nil {
					t.Fatal(err)
				}
				back, err := hclschema.Decode(schema.File{Name: name + ".hcl", Data: h})
				if err != nil {
					t.Fatal(err)
				}
				if d := differences(defs, back); d != nil {
					t.Fatalf("macros=%v: .schema -> HCL -> definitions differs: %v", macros, d)
				}
				// HCL -> .schema -> definitions.
				text, err := back.Format(macros)
				if err != nil {
					t.Fatal(err)
				}
				again, err := schema.Read(schema.File{Name: "formatted", Data: text})
				if err != nil {
					t.Fatal(err)
				}
				if d := differences(defs, again); d != nil {
					t.Fatalf("macros=%v: HCL -> .schema -> definitions differs: %v", macros, d)
				}
				if !macros {
					t.Logf("%s: %d bytes of .schema -> %d bytes of HCL -> %d bytes of .schema, definitions equal", p.name, len(data), len(h), len(text))
				}
			}

			// The LDIF form against the .schema form.
			if ldif, ok := fetch(t, p.ldif); ok {
				fromLDIF, err := schema.Read(schema.File{Name: p.name + ".ldif", Data: ldif})
				if err != nil {
					t.Fatal(err)
				}
				d := differences(defs, fromLDIF)
				t.Logf("%s: LDIF vs .schema: %d differences %v", p.name, len(d), d)
				if !slices.Equal(d, p.ldifDiffers) {
					t.Errorf("LDIF vs .schema: %q, recorded %q", d, p.ldifDiffers)
				}
			}

			// check against schema.Standard().
			dir := t.TempDir()
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			var out, errw bytes.Buffer
			status := run([]string{"check", path}, &out, &errw)
			t.Logf("%s: ldapschema check: exit %d\n%s", p.name, status, out.String())
			if status != p.checkStatus {
				t.Errorf("check: exit %d, want %d; %s", status, p.checkStatus, errw.String())
			}
			for _, l := range p.checkLines {
				if !strings.Contains(out.String(), l+"\n") {
					t.Errorf("check does not say %q", l)
				}
			}
		})
	}
}
