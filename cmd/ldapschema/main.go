// SPDX-License-Identifier: BSD-3-Clause

// Command ldapschema converts LDAP schema definitions between OpenLDAP's
// files and HCL2, and checks them against the standard schema.
//
//	ldapschema to-hcl [--macros] FILE...     .schema, LDIF or RFC 4512 -> HCL
//	ldapschema to-schema [--macros] FILE...  HCL -> OpenLDAP .schema
//	ldapschema check FILE...                 build against schema.Standard()
//
// Output goes to stdout. The exit status is 0 when it worked, 1 when a
// file could not be read or a definition was refused, 2 on a usage error.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"

	"github.com/go-authn/ldap/schema"
	"github.com/go-authn/ldap/schema/hclschema"
	"github.com/spf13/cobra"
)

// osExit lets the tests run main.
var osExit = os.Exit

func main() { osExit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// A usageError is a command line that cannot be run: exit status 2.
type usageError struct{ error }

func usage(format string, args ...any) error { return usageError{fmt.Errorf(format, args...)} }

// run runs the command line and returns the exit status.
func run(args []string, stdout, stderr io.Writer) int {
	cmd := RootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	err := cmd.Execute()
	if err == nil {
		return 0
	}
	fmt.Fprintln(stderr, "ldapschema:", err)
	if errors.As(err, new(usageError)) {
		return 2
	}
	return 1
}

// RootCmd is the command tree, for the tests to drive.
func RootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "ldapschema",
		Short: "Convert LDAP schema definitions between OpenLDAP files and HCL2",
		Long: `ldapschema converts LDAP schema definitions (RFC 4512) between OpenLDAP's
.schema files, its cn=config LDIF, and HCL2, and checks them against the
standard schema of github.com/go-authn/ldap/schema.

Exit status: 0 when it worked, 1 when a file or a definition was refused,
2 on a usage error.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return usage("unknown command %q (to-hcl, to-schema, check)", args[0])
			}
			cmd.SetOut(cmd.ErrOrStderr())
			_ = cmd.Help()
			return usage("a command is needed")
		},
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageError{err} })
	root.AddCommand(toHCLCmd(), toSchemaCmd(), checkCmd())
	return root
}

func files(_ *cobra.Command, args []string) error {
	if len(args) == 0 {
		return usage("no FILE given")
	}
	return nil
}

func toHCLCmd() *cobra.Command {
	var macros bool
	cmd := &cobra.Command{
		Use:   "to-hcl [--macros] FILE...",
		Short: "Convert OpenLDAP .schema, cn=config LDIF or subschema LDIF to HCL",
		Long: `to-hcl reads the files in order, as slapd would include them, and writes
their definitions as HCL to stdout. OID macros (objectidentifier) are
expanded; --macros writes the OIDs back with them.`,
		Args: files,
		RunE: func(cmd *cobra.Command, args []string) error {
			defs, err := readSchemaFiles(args)
			if err != nil {
				return err
			}
			out, err := hclschema.Encode(defs, hclschema.EncodeOptions{Macros: macros})
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(out)
			return err
		},
	}
	cmd.Flags().BoolVarP(&macros, "macros", "m", false, "write OIDs with the OID macros that cover them")
	return cmd
}

func toSchemaCmd() *cobra.Command {
	var macros bool
	cmd := &cobra.Command{
		Use:   "to-schema [--macros] FILE...",
		Short: "Convert HCL to an OpenLDAP .schema file",
		Long: `to-schema decodes the HCL files together and writes their definitions as
an OpenLDAP .schema file (slapd.conf(5)) to stdout. --macros writes the
OIDs with the OID macros that cover them.`,
		Args: files,
		RunE: func(cmd *cobra.Command, args []string) error {
			defs, err := readHCLFiles(args)
			if err != nil {
				return err
			}
			out, err := defs.Format(macros)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(out)
			return err
		},
	}
	cmd.Flags().BoolVarP(&macros, "macros", "m", false, "write OIDs with the OID macros that cover them")
	return cmd
}

func checkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check FILE...",
		Short: "Check definitions against the standard schema",
		Long: `check reads the files -- HCL when the name ends in .hcl, OpenLDAP .schema or
LDIF otherwise -- and builds them on top of schema.Standard(). It reports
the definitions the standard schema already has (identical, or not), every
name they refer to that nothing defines, and the verdict of Build.`,
		Args: files,
		RunE: func(cmd *cobra.Command, args []string) error {
			var hcl, other []string
			for _, a := range args {
				if strings.HasSuffix(a, ".hcl") {
					hcl = append(hcl, a)
				} else {
					other = append(other, a)
				}
			}
			given, err := readSchemaFiles(other)
			if err != nil {
				return err
			}
			h, err := readHCLFiles(hcl)
			if err != nil {
				return err
			}
			return check(cmd.OutOrStdout(), merge(given, h))
		},
	}
}

func load(paths []string) ([]schema.File, error) {
	var out []schema.File
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if info.Size() > schema.MaxFileSize {
			return nil, fmt.Errorf("%s: %d bytes, more than the %d a schema file may have", p, info.Size(), schema.MaxFileSize)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, schema.File{Name: p, Data: b})
	}
	return out, nil
}

func readSchemaFiles(paths []string) (*schema.Definitions, error) {
	fs, err := load(paths)
	if err != nil {
		return nil, err
	}
	return schema.Read(fs...)
}

func readHCLFiles(paths []string) (*schema.Definitions, error) {
	fs, err := load(paths)
	if err != nil {
		return nil, err
	}
	return hclschema.Decode(fs...)
}

func merge(a, b *schema.Definitions) *schema.Definitions {
	return &schema.Definitions{
		ObjectIdentifiers: append(a.ObjectIdentifiers, b.ObjectIdentifiers...),
		Syntaxes:          append(a.Syntaxes, b.Syntaxes...),
		MatchingRules:     append(a.MatchingRules, b.MatchingRules...),
		AttributeTypes:    append(a.AttributeTypes, b.AttributeTypes...),
		ObjectClasses:     append(a.ObjectClasses, b.ObjectClasses...),
	}
}

// errCheck is a check that found something to refuse; what is printed it.
var errCheck = errors.New("the definitions do not build on schema.Standard()")

// check is the check command: the report goes to w, and an error means the
// definitions cannot be loaded on top of the standard schema.
func check(w io.Writer, given *schema.Definitions) error {
	std, _ := schema.Read(schema.StandardFiles()...) // embedded: a test proves it reads
	fmt.Fprintf(w, "read: %d object identifiers, %d syntaxes, %d matching rules, %d attribute types, %d object classes\n",
		len(given.ObjectIdentifiers), len(given.Syntaxes), len(given.MatchingRules), len(given.AttributeTypes), len(given.ObjectClasses))

	rest := &schema.Definitions{}
	var same, differ []string
	rest.Syntaxes = keepNew(std.Syntaxes, given.Syntaxes, func(x *schema.Syntax) string { return x.OID }, &same, &differ)
	rest.MatchingRules = keepNew(std.MatchingRules, given.MatchingRules, func(x *schema.MatchingRule) string { return x.Name() }, &same, &differ)
	rest.AttributeTypes = keepNew(std.AttributeTypes, given.AttributeTypes, func(x *schema.AttributeType) string { return x.Name() }, &same, &differ)
	rest.ObjectClasses = keepNew(std.ObjectClasses, given.ObjectClasses, func(x *schema.ObjectClass) string { return x.Name() }, &same, &differ)
	if len(same)+len(differ) > 0 {
		// OpenLDAP's copies of the RFC definitions prefix every DESC with
		// "RFC2256:" and the like: a difference in DESC alone is counted,
		// the others are listed.
		descOnly := 0
		for _, d := range differ {
			if !strings.HasSuffix(d, " (Desc)") {
				continue
			}
			descOnly++
		}
		fmt.Fprintf(w, "already in schema.Standard(), which is kept: %d identical, %d different (%d in DESC only)\n", len(same), len(differ), descOnly)
		for _, d := range differ {
			if !strings.HasSuffix(d, " (Desc)") {
				fmt.Fprintf(w, "  differs: %s\n", d)
			}
		}
	}

	missing := missingRefs(merge(std, rest))
	for _, m := range missing {
		fmt.Fprintf(w, "missing: %s\n", m)
	}
	if len(missing) > 0 {
		return errCheck
	}
	if _, err := schema.BuildFrom(std, rest); err != nil {
		fmt.Fprintf(w, "build: %v\n", err)
		return errCheck
	}
	fmt.Fprintf(w, "build: ok, %d definitions added to schema.Standard()\n",
		len(rest.Syntaxes)+len(rest.MatchingRules)+len(rest.AttributeTypes)+len(rest.ObjectClasses))
	return nil
}

// oidOf is the OID field every kind of element has.
func oidOf(x any) string { return reflect.ValueOf(x).Elem().FieldByName("OID").String() }

// keepNew drops from given what std already defines by OID, recording
// whether the two say the same, and which fields differ.
func keepNew[T any](std, given []*T, name func(*T) string, same, differ *[]string) []*T {
	byOID := map[string]*T{}
	for _, x := range std {
		byOID[oidOf(x)] = x
	}
	var out []*T
	for _, x := range given {
		s, dup := byOID[oidOf(x)]
		switch {
		case !dup:
			out = append(out, x)
		case len(fieldsThatDiffer(s, x)) == 0:
			*same = append(*same, name(x))
		default:
			*differ = append(*differ, fmt.Sprintf("%s (%s)", name(x), strings.Join(fieldsThatDiffer(s, x), ", ")))
		}
	}
	return out
}

// fieldsThatDiffer compares what two definitions say: Pos, where each was
// read from, is not part of a definition.
func fieldsThatDiffer(a, b any) []string {
	va, vb := reflect.ValueOf(a).Elem(), reflect.ValueOf(b).Elem()
	var out []string
	for i := range va.NumField() {
		f := va.Type().Field(i)
		if f.IsExported() && f.Name != "Pos" && !reflect.DeepEqual(va.Field(i).Interface(), vb.Field(i).Interface()) {
			out = append(out, f.Name)
		}
	}
	return out
}

// missingRefs lists every name a definition refers to that nothing
// defines, each with what refers to it -- all of them, where Build stops
// at the first.
func missingRefs(d *schema.Definitions) []string {
	syntaxes, rules, types, classes := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, x := range d.Syntaxes {
		syntaxes[x.OID] = true
	}
	index := func(set map[string]bool, oid string, names []string) {
		set[oid] = true
		for _, n := range names {
			set[strings.ToLower(n)] = true
		}
	}
	for _, x := range d.MatchingRules {
		index(rules, x.OID, x.Names)
	}
	for _, x := range d.AttributeTypes {
		index(types, x.OID, x.Names)
	}
	for _, x := range d.ObjectClasses {
		index(classes, x.OID, x.Names)
	}
	refs := map[string][]string{}
	var order []string
	need := func(set map[string]bool, what, name, by string) {
		if name == "" || set[strings.ToLower(name)] || set[name] {
			return
		}
		key := what + " " + name
		if refs[key] == nil {
			order = append(order, key)
		}
		refs[key] = append(refs[key], by)
	}
	for _, x := range d.MatchingRules {
		need(syntaxes, "syntax", x.Syntax, x.Name())
	}
	for _, x := range d.AttributeTypes {
		need(types, "attribute type", x.Sup, x.Name())
		need(rules, "matching rule", x.Equality, x.Name())
		need(rules, "matching rule", x.Ordering, x.Name())
		need(rules, "matching rule", x.Substr, x.Name())
		need(syntaxes, "syntax", x.Syntax, x.Name())
	}
	for _, x := range d.ObjectClasses {
		for _, s := range x.Sup {
			need(classes, "object class", s, x.Name())
		}
		for _, t := range slices.Concat(x.Must, x.May) {
			need(types, "attribute type", t, x.Name())
		}
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		out = append(out, fmt.Sprintf("%s, used by %s", k, strings.Join(slices.Compact(refs[k]), ", ")))
	}
	return out
}
