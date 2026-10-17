// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"embed"
	"sync"
)

//go:embed defs/*.schema
var defs embed.FS

// standardFiles is the order they are read in. Build resolves references
// across files, so the order only decides what the subschema lists first.
var standardFiles = []string{
	"rfc4517.schema",     // syntaxes and matching rules
	"rfc4512.schema",     // the directory's own: top, subschema, operational
	"rfc3672.schema",     // subentry
	"rfc4519.schema",     // user applications: person, cn, sn, ...
	"rfc4524.schema",     // COSINE: account, mail, ...
	"rfc4523.schema",     // X.509: userCertificate
	"rfc2798.schema",     // inetOrgPerson
	"rfc2307.schema",     // NIS: posixAccount, posixGroup, ...
	"rfc3045.schema",     // vendorName, vendorVersion
	"openldap.schema",    // OpenLDAProotDSE, caseExactIA5SubstringsMatch
	"openssh-lpk.schema", // ldapPublicKey, sshPublicKey
}

// StandardFiles are the definitions Standard is built from, for a
// deployment that adds its own: Build(append(StandardFiles(), mine)...).
func StandardFiles() []File {
	out := make([]File, 0, len(standardFiles))
	for _, name := range standardFiles {
		b, err := defs.ReadFile("defs/" + name)
		if err != nil {
			panic(err) // embedded at compile time; a test reads every one
		}
		out = append(out, File{Name: name, Data: b})
	}
	return out
}

var standard = sync.OnceValues(func() (*Schema, error) { return Build(StandardFiles()...) })

// Standard is the schema of RFC 4512, 4517, 4519, 4523, 4524, 2798, 2307,
// 3672 and 3045, with openssh-lpk's ldapPublicKey and the two OpenLDAP
// definitions those need. It is built once and shared: a Schema is
// read-only.
func Standard() *Schema {
	s, err := standard()
	if err != nil {
		panic("schema: the embedded definitions do not build: " + err.Error())
	}
	return s
}
