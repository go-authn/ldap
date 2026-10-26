// SPDX-License-Identifier: BSD-3-Clause

// Package libldap holds OpenLDAP's schema parser (libldap's
// ldap_str2attributetype and ldap_str2objectclass) behind a Go API, so that
// a benchmark can compare it with this repository's parser on the same
// strings. It needs cgo and libldap's headers; see the repository's
// README.md, "Performance".
package libldap

/*
#cgo LDFLAGS: -lldap
#include <stdlib.h>
#include <ldap_schema.h>

static int parse_at(const char *s) {
	int code = 0; const char *errp = NULL;
	LDAPAttributeType *at = ldap_str2attributetype(s, &code, &errp, LDAP_SCHEMA_ALLOW_ALL);
	if (at == NULL) return code ? code : -1;
	ldap_attributetype_free(at);
	return 0;
}

static int parse_oc(const char *s) {
	int code = 0; const char *errp = NULL;
	LDAPObjectClass *oc = ldap_str2objectclass(s, &code, &errp, LDAP_SCHEMA_ALLOW_ALL);
	if (oc == NULL) return code ? code : -1;
	ldap_objectclass_free(oc);
	return 0;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Set is definitions converted to C strings once, so that only parsing,
// and freeing what was parsed, is timed.
type Set struct {
	ats, ocs []*C.char
}

// NewSet converts attribute type and object class definitions.
func NewSet(ats, ocs []string) *Set {
	s := &Set{}
	for _, a := range ats {
		s.ats = append(s.ats, C.CString(a))
	}
	for _, o := range ocs {
		s.ocs = append(s.ocs, C.CString(o))
	}
	return s
}

// ParseAll parses every definition with libldap and frees the result.
func (s *Set) ParseAll() error {
	for i, a := range s.ats {
		if rc := C.parse_at(a); rc != 0 {
			return fmt.Errorf("attribute type %d refused: %d", i, rc)
		}
	}
	for i, o := range s.ocs {
		if rc := C.parse_oc(o); rc != 0 {
			return fmt.Errorf("object class %d refused: %d", i, rc)
		}
	}
	return nil
}

// Free releases the C strings.
func (s *Set) Free() {
	for _, a := range s.ats {
		C.free(unsafe.Pointer(a))
	}
	for _, o := range s.ocs {
		C.free(unsafe.Pointer(o))
	}
}
