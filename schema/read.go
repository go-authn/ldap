// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// MaxFileSize bounds a File. The largest schema file OpenLDAP publishes,
// cosine.schema, is 75 KB; four megabytes is fifty times that, and a file
// past it is refused before it is read rather than parsed into memory.
const MaxFileSize = 4 << 20

// A File is a set of definitions, in one of two forms, told apart by the
// first line that is neither blank nor a comment:
//
//   - OpenLDAP's .schema form (slapd.conf(5)), which the embedded files use:
//     a definition starts with its kind -- objectidentifier, ldapsyntax,
//     matchingrule, attributetype or objectclass, in any case -- at the
//     start of a line, and continues on the lines that start with white
//     space; '#' starts a comment line. The continuation lines are joined
//     with ONE space, so a definition copied from an RFC keeps the RFC's
//     line breaks and reads as RFC 4512 4.1 wants it.
//   - LDIF (RFC 2849), when that first line is "name: value" -- "dn:",
//     "version:", or an attribute: OpenLDAP's cn=config form
//     (slapd-config(5): olcObjectIdentifier, olcLdapSyntaxes,
//     olcAttributeTypes, olcObjectClasses, each value perhaps after a {N}
//     ordering prefix), and the subschema subentry's own attributes (RFC
//     4512 4.2: ldapSyntaxes, matchingRules, attributeTypes, objectClasses),
//     which is the form a server publishes its definitions in.
//
// In both forms, and only there, the parser is as lenient as libldap is
// for slapd: tabs and newlines are white space, an OID may be quoted, and
// objectidentifier macros stand for OIDs (see macro.go). The Parse
// functions stay RFC 4512's.
type File struct {
	Name string
	Data []byte
}

// A FileError is a definition in a File that could not be read, and where.
type FileError struct {
	File string
	// Line is where the error is, 1-based: the line of the byte the parser
	// stopped at, or the first line of the definition.
	Line int
	// Column is the 1-based byte column of that byte, or 0 when the error
	// is the definition's as a whole.
	Column int
	Err    error
}

func (e *FileError) Error() string {
	if e.Column > 0 {
		return fmt.Sprintf("%s:%d:%d: %v", e.File, e.Line, e.Column, e.Err)
	}
	return fmt.Sprintf("%s:%d: %v", e.File, e.Line, e.Err)
}

func (e *FileError) Unwrap() error { return e.Err }

// Definitions are what files define, read and not yet linked, in the
// order they were read. Build links them into a Schema; package
// schema/hclschema reads and writes them as HCL.
//
// Every OID in them is numeric: a macro is expanded as it is read.
// ObjectIdentifiers keep the macros themselves, as they were written, so
// that they can be written out again.
type Definitions struct {
	ObjectIdentifiers []ObjectIdentifier
	Syntaxes          []*Syntax
	MatchingRules     []*MatchingRule
	AttributeTypes    []*AttributeType
	ObjectClasses     []*ObjectClass
}

// Read reads files, in order, into Definitions. A macro defined in one
// file may be used in the files after it, as slapd allows across include
// files.
func Read(files ...File) (*Definitions, error) {
	d := &Definitions{}
	m := &OIDMacros{}
	for _, f := range files {
		var err error
		switch {
		case len(f.Data) > MaxFileSize:
			err = &FileError{f.Name, 1, 0, fmt.Errorf("the file is %d bytes, more than the %d a schema file may have", len(f.Data), MaxFileSize)}
		case isLDIF(f.Data):
			err = d.readLDIF(f, m)
		default:
			err = d.readSchema(f, m)
		}
		if err != nil {
			return nil, err
		}
	}
	return d, nil
}

// A span maps the text of a definition, joined from several lines, back to
// the lines: the definition's byte off is at line, col.
type span struct{ off, line, col int }

type spans []span

func (s spans) at(off int) (line, col int) {
	i := 0
	for i+1 < len(s) && s[i+1].off <= off {
		i++
	}
	return s[i].line, s[i].col + off - s[i].off
}

func lines(data []byte) []string {
	ls := strings.Split(string(data), "\n")
	for i, l := range ls {
		ls[i] = strings.TrimSuffix(l, "\r")
	}
	return ls
}

// readSchema reads the .schema form. slapd's own reader is fp_getline in
// servers/slapd/config.c: a line that starts with white space continues
// the one before, and a blank or comment line ends a definition.
func (d *Definitions) readSchema(f File, m *OIDMacros) error {
	ls := lines(f.Data)
	for i := 0; i < len(ls); i++ {
		l := strings.TrimRight(ls[i], " \t")
		if l == "" || l[0] == '#' {
			continue
		}
		if l[0] == ' ' || l[0] == '\t' {
			return &FileError{f.Name, i + 1, 0, errors.New("a continuation line with no definition before it")}
		}
		kind, def := l, ""
		start := len(l)
		if k := strings.IndexAny(l, " \t"); k >= 0 {
			kind = l[:k]
			start = k + 1 + len(l[k+1:]) - len(strings.TrimLeft(l[k+1:], " \t"))
			def = l[start:]
		}
		at := spans{{0, i + 1, start + 1}}
		text := def
		for i+1 < len(ls) {
			n := strings.TrimRight(ls[i+1], " \t")
			if n == "" || (n[0] != ' ' && n[0] != '\t') {
				break
			}
			i++
			trimmed := strings.TrimLeft(n, " \t")
			text += " "
			at = append(at, span{len(text), i + 1, len(n) - len(trimmed) + 1})
			text += trimmed
		}
		if err := d.add(f.Name, strings.ToLower(kind), kind, text, at, m); err != nil {
			return err
		}
	}
	return nil
}

// add reads one definition of a kind, and positions an error in the file.
func (d *Definitions) add(file, kind, spelled, text string, at spans, m *OIDMacros) error {
	p := &parser{s: text, macros: m, openldap: true}
	var err error
	switch kind {
	case "objectidentifier":
		err = d.defineMacro(text, m)
	case "ldapsyntax":
		var x *Syntax
		if x, err = parseSyntax(p); err == nil {
			d.Syntaxes = append(d.Syntaxes, x)
		}
	case "matchingrule":
		var x *MatchingRule
		if x, err = parseMatchingRule(p); err == nil {
			d.MatchingRules = append(d.MatchingRules, x)
		}
	case "attributetype":
		var x *AttributeType
		if x, err = parseAttributeType(p); err == nil {
			d.AttributeTypes = append(d.AttributeTypes, x)
		}
	case "objectclass":
		var x *ObjectClass
		if x, err = parseObjectClass(p); err == nil {
			d.ObjectClasses = append(d.ObjectClasses, x)
		}
	default:
		err = fmt.Errorf("%q is not a kind of definition (objectidentifier, ldapsyntax, matchingrule, attributetype, objectclass)", spelled)
	}
	if err == nil {
		return nil
	}
	var pe *ParseError
	if errors.As(err, &pe) && at[0].col > 0 {
		line, col := at.at(pe.Offset)
		return &FileError{file, line, col, err}
	}
	return &FileError{file, at[0].line, 0, err}
}

// defineMacro is `objectidentifier <name> <oid>`: two arguments, split on
// white space as slapd's strtok_quote does (servers/slapd/config.c).
func (d *Definitions) defineMacro(args string, m *OIDMacros) error {
	f := strings.Fields(args)
	if len(f) != 2 {
		return fmt.Errorf("objectidentifier takes a name and an OID, and has %d arguments (slapd.conf(5))", len(f))
	}
	n := len(m.order)
	if err := m.Define(f[0], f[1]); err != nil {
		return err
	}
	if len(m.order) > n {
		d.ObjectIdentifiers = append(d.ObjectIdentifiers, ObjectIdentifier{Name: f[0], OID: f[1]})
	}
	return nil
}

// isLDIF is the first line that is neither blank nor a comment starting
// with "name:": no kind of .schema definition has a colon in it.
func isLDIF(data []byte) bool {
	for _, l := range lines(data) {
		t := strings.TrimSpace(l)
		if t == "" || t[0] == '#' || l[0] == ' ' || l[0] == '\t' {
			continue
		}
		w, _, _ := strings.Cut(t, " ")
		return strings.Contains(w, ":")
	}
	return false
}

// ldifKinds maps an LDIF attribute to the kind of definition its values
// are: OpenLDAP's cn=config names (slapd-config(5)) and the subschema
// subentry's (RFC 4512 4.2). "" is an attribute that is skipped.
var ldifKinds = map[string]string{
	"olcobjectidentifier": "objectidentifier",
	"olcldapsyntaxes":     "ldapsyntax", "ldapsyntaxes": "ldapsyntax",
	"matchingrules":     "matchingrule",
	"olcattributetypes": "attributetype", "attributetypes": "attributetype",
	"olcobjectclasses": "objectclass", "objectclasses": "objectclass",
	// RFC 4512 4.1.4: a server derives these from the rules and the
	// types, and so does Build.
	"matchingruleuse": "",
}

// unsupported are schema attributes this package has no model for.
var unsupported = map[string]bool{
	"olcditcontentrules": true, "ditcontentrules": true,
	"nameforms": true, "ditstructurerules": true,
}

// readLDIF reads RFC 2849 LDIF: a line that starts with ONE space
// continues the line before without it, "#" starts a comment, "name::"
// is followed by base64. Entries, change records of type add and modify,
// and "add:" operations are read alike; a deletion or a replacement of a
// definition is refused rather than half-applied.
func (d *Definitions) readLDIF(f File, m *OIDMacros) error {
	ls := lines(f.Data)
	for i := 0; i < len(ls); i++ {
		l := ls[i]
		if l == "" || l == "-" {
			continue
		}
		first := i + 1
		if l[0] == ' ' {
			return &FileError{f.Name, first, 0, errors.New("a continuation line with no line before it")}
		}
		comment := l[0] == '#'
		text := l
		var at spans
		colon := strings.IndexByte(l, ':')
		for i+1 < len(ls) && strings.HasPrefix(ls[i+1], " ") {
			i++
			at = append(at, span{len(text), i + 1, 2})
			text += ls[i][1:]
		}
		if comment {
			continue
		}
		if colon < 0 {
			return &FileError{f.Name, first, 0, fmt.Errorf("%q is not \"name: value\" (RFC 2849)", firstWord(l))}
		}
		name := strings.ToLower(text[:colon])
		if k := strings.IndexByte(name, ';'); k >= 0 {
			name = name[:k] // options, RFC 2849 attributeDescription
		}
		value, start := text[colon+1:], colon+1
		switch {
		case strings.HasPrefix(value, ":"):
			b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[1:]))
			if err != nil {
				return &FileError{f.Name, first, 0, fmt.Errorf("the base64 value of %s: %v", text[:colon], err)}
			}
			// A position in decoded bytes is no position in the file: an
			// error is placed on the line, without a column.
			value, at, start = string(b), nil, -1
		case strings.HasPrefix(value, "<"):
			return &FileError{f.Name, first, 0, fmt.Errorf("%s is a URL; this reader does not fetch values", text[:colon])}
		default:
			trimmed := strings.TrimLeft(value, " ")
			start += len(value) - len(trimmed)
			value = trimmed
		}
		if err := d.ldifLine(f.Name, name, text[:colon], value, start, first, at, m); err != nil {
			return err
		}
	}
	return nil
}

func firstWord(s string) string {
	w, _, _ := strings.Cut(s, " ")
	return w
}

func (d *Definitions) ldifLine(file, name, spelled, value string, start, line int, folds spans, m *OIDMacros) error {
	switch name {
	case "changetype":
		if v := strings.ToLower(value); v != "add" && v != "modify" {
			return &FileError{file, line, 0, fmt.Errorf("changetype %s: only definitions that are added can be read", value)}
		}
		return nil
	case "delete", "replace":
		if _, ok := ldifKinds[strings.ToLower(value)]; ok || unsupported[strings.ToLower(value)] {
			return &FileError{file, line, 0, fmt.Errorf("%s: %s: only definitions that are added can be read", spelled, value)}
		}
		return nil
	}
	if unsupported[name] {
		return &FileError{file, line, 0, fmt.Errorf("%s is not supported: this package has no DIT content rules, name forms or structure rules", spelled)}
	}
	kind, ok := ldifKinds[name]
	if !ok || kind == "" {
		return nil
	}
	// slapd-config(5): the values of a cn=config schema attribute carry
	// an "{N}" prefix that orders them (X-ORDERED 'VALUES').
	skip := 0
	if strings.HasPrefix(value, "{") {
		if end := strings.IndexByte(value, '}'); end > 1 && isNumber(value[1:end]) {
			skip = end + 1
		}
	}
	at := spans{{0, line, start + 1 + skip}}
	if start < 0 {
		at[0].col = 0
	}
	for _, f := range folds {
		at = append(at, span{f.off - start - skip, f.line, f.col})
	}
	return d.add(file, kind, spelled, value[skip:], at, m)
}
