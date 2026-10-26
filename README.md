# go-authn/ldap

**A library, not a daemon.** It is the LDAP protocol half —
the wire, the filter, the operations — that
[go-authn/authnd](https://github.com/go-authn/authnd) runs. authnd stays the
server: it owns the configuration, the directory sources, the bind policy and
the MFA. This owns the bytes.

The same split as `go-filesystems/nfs` under `go-fileshare/fileshare`, and
`go-authn/kdc` under `authnd`. There is no second server here, and authnd
never had an LDAP implementation of its own to merge — it had **zero** lines
of wire code and rented the protocol from a fork of `glauth/ldap`. This
replaces the rental.

Written from RFC 4511 (the protocol), 4512 (the root DSE and the schema), 4513
(authentication), 4514 (DN string form), 4515 (filter string form),
4517 and 4518 (syntaxes, matching rules, string preparation),
4526 (absolute true and false filters), 2696 (paged
results), 3672 (subentries), 3673 (`+`, all operational attributes), 4527
(the read entry controls), 4532 (whoami) and 3045 (vendor attributes). The
schema package embeds the definitions of 4512, 4517, 4519, 4523, 4524,
2798, 2307, 3672 and 3045 -- see [Schema](#schema).

SASL binds are carried but not *understood*: RFC 4511 4.2 says a bind names a
mechanism and carries an octet string of that mechanism's own shape, so
`SASLBinder` hands both to the consumer and this package never learns which
mechanism it got. OAUTHBEARER (RFC 7628) is therefore **not** implemented
here — it lives in [authnd](https://github.com/go-authn/authnd), which is the
only place that can check a token. An earlier version of this file listed
7628 among the RFCs this package was written from, which was wrong.

A server with **no schema** (`Server.Schema` nil, the default) compares every
value case-insensitively: an attribute's matching rule decides that, and RFC
4517 has `caseExactMatch` too, but without a schema there is no way to know
which rule applies. For reading that is the safer of the two — it never
hides an entry an exact comparison would have found. A server WITH one uses
the rules; see [Schema](#schema).

Three more RFCs are *named* and deliberately **not** honoured: ManageDsaIT
(RFC 3296), password modify (RFC 3062) and cancel (RFC 3909). They are
constants because a client may send them, not because this answers them —
nothing here follows aliases or referrals, so a critical ManageDsaIT is
refused, which is the correct answer rather than a missing one.

The difference is not a footnote: the root DSE publishes exactly what this
server honours, under `supportedControl`, `supportedFeatures`,
`supportedExtension` and `supportedSASLMechanisms`. Advertising a control
nothing honours sends a client down a path that silently does the wrong
thing; honouring one never advertised means a client that discovers
capabilities properly will never ask. No cgo and no global state; package
`ldap` holds no client (the wire client the tests drive is `ldaptest`).

A `Server` is a set of handlers (`Bind`, `SASL`, `Search`, `Compare`,
`Extended`, `Add`, `Modify`, `Delete`, `ModifyDN`, `Abandon`), served with
`Serve(ln)` or `ListenAndServe(addr)`. `TLSConfig` makes StartTLS available;
**`RequireTLS`** refuses every operation on a connection that is not protected,
with `confidentialityRequired`. StartTLS is asked for by the CLIENT, so a server
that merely offers it has promised nothing: a client that does not ask sends
its bind password in the clear. `RequireTLS` turns the offer into a guarantee.

It exists because [go-authn/authnd](https://github.com/go-authn/authnd) was
built on a fork of `glauth/ldap`, and six defects turned up in the parts of it
that authnd actually used — five in the fifty lines of the bind path alone.
The one that decided this: `(uid=svc-*-prod)` was evaluated as `(uid=svc-*)`
and returned `svc-web-stage`. In a directory, answering a **broader** question
than the one you were asked is disclosure, and it is silent, because every
entry returned is a real entry.

## What is different here

**One filter, three renderings.** The library this replaces had three separate
implementations — decode-to-string, encode-from-string, and match-against-wire
— and they drifted apart. Here a filter is parsed or decoded **once** into a
tree, and `String`, `EncodeFilter` and `Matches` all read that tree. They
cannot disagree about what a filter means, because only one thing means it.
The tests assert that as a property: a filter must answer the same about every
entry in a corpus after a round trip through the string form *and* through the
wire.

That promise held only for names that are names. An attribute was taken from
the wire as raw octets and written back as it came, so a present filter on
the "attribute" `!x` printed as `(!x=*)`, which reads back as a NOT. A
consumer that logs a filter, or hands its string to another directory, would
have been handed a different question. Both `DecodeFilter` and `ParseFilter`
now refuse any attribute that is not an RFC 4512 §2.5 attribute description,
and any matching rule that is not an OID. RFC 4511 §4.1.4 already constrained
both. `FuzzMessage` found it in under two seconds and keeps the input as a
seed. It runs every message a client may send through the frame, the
decoders and that round trip, and its seeds run with every `go test`.

**Types that carry the protocol.** `Result` has `MatchedDN` and `Diagnostic`
as fields, because RFC 4511 4.1.9 says every result does. A server that cannot
set `MatchedDN` cannot tell a client how far along a DN its search base
stopped existing — the difference between "you have a typo in `ou=`" and "that
whole tree is gone".

**Writes that can be written correctly.** `ModifyRequest.Changes` is an
*ordered list*, because RFC 4511 4.6 says the modifications are "performed in
the order listed". Held as three buckets — add, delete, replace — the requests

    delete member=alice; add member=alice     (alice stays)
    add member=alice; delete member=alice     (alice goes)

arrive as the same thing, and the server cannot tell which was asked. That is
how a client reconciles a group membership.

**Bounded before it is trusted.** The frame length is read here rather than
left to the BER library, whose limit is a package-level global that two
servers in one process cannot set differently. A five-byte header claiming
four gigabytes is refused before anything is reserved for it (`MaxMessageSize`,
4 MiB by default), and filter nesting is bounded because a stack overflow in
Go kills the *process* — one unauthenticated packet must not take the
directory down.

Bytes are not memory: the decoder builds a packet of some 190 bytes for each
BER element, and an empty OCTET STRING is two bytes on the wire, so 4 MiB of
them held 373 MiB before any bind. The elements of a message are counted
first, by a walk that builds nothing, and one holding more than
`MaxMessageElements` (16384 by default) is refused before it is decoded.

Under that limit the body is read into a buffer that grows with what has
actually arrived, so a length prefix on its own reserves nothing. And a
connection is closed when a whole message has not arrived within
`IdleTimeout` of the previous one: **five minutes** by default
(`DefaultIdleTimeout`), a negative value for never. A client that sends a
length prefix and then nothing is closed on the same clock as one that sends
nothing at all.

Each operation runs in its own goroutine and keeps its decoded message, so
the number in flight is bounded too, as slapd bounds it (`conn_max_pending`
in slapd.conf(5)). `MaxPending` applies before a bind and `MaxPendingAuth`
after, defaulting to slapd's 100 and 1000; a negative value means no limit.
A connection that sends one more gets a `busy` notice of disconnection and
is closed. Any connection that ends (an unbind, an idle notice, too many
operations) is closed **before** this server waits for its operations, which
are cancelled. RFC 4511 §4.3 says an unbind "terminates any outstanding
operations". Before v0.6.0 the server waited first, so a connection told it
was ending stayed open for as long as its slowest operation took.

## Schema

Package [`schema`](schema) is the directory schema of RFC 4512 section 4,
and `Server.Schema` makes a server use it. Nil keeps a server exactly as it
was; nothing changes for a deployment that does not set it.

**What is there.**

- Types for syntaxes, matching rules, matching rule uses, attribute types,
  object classes, **DIT content rules, name forms and DIT structure rules**
  (RFC 4512 4.1.6, 4.1.7), and a parser and printer for their RFC 4512 4.1
  forms.
  The parser is strict -- terms in the ABNF's order, SP is spaces -- and a
  refusal says at which byte (`*schema.ParseError`). Files are read as
  slapd reads them; see
  [Schema files, OID macros and LDIF](#schema-files-oid-macros-and-ldif). Printing and parsing
  round-trip; `FuzzDefinition` checks it.
- `schema.Build(files...)` links definitions into a read-only `*Schema`:
  every SUP, rule, syntax, MUST and MAY must resolve, and RFC 4512's rules
  about which kind of class may derive from which, and about supertype
  usage, are enforced. Lookup is by any name or OID, without regard to case.
  EQUALITY, ORDERING, SUBSTR and SYNTAX are inherited through SUP; MUST and
  MAY through superclasses.
- A definition that does not build is a **`*schema.BuildError`**, found
  with `errors.As`; a program reports a refusal from its fields, never by
  matching the message. It carries:
  - `Kind`, one of every check Build makes: `UnknownReference`,
    `DuplicateOID`, `DuplicateName`, `SuperiorCycle`, `KindViolation`
    (RFC 4512 2.4.1-2.4.3; a content rule or name form for a class that is
    not structural, an AUX class that is not auxiliary), `UsageMismatch` and
    `CollectiveMismatch` (2.5.1), `UsageViolation` (4.1.2),
    `DuplicateMember` (a type listed twice in a rule, or in a name form's
    MUST and MAY, 4.1.7.2) and `PrecludedRequired` (a NOT naming a type the
    rule, its class or an AUX class requires, 4.1.6);
  - `Element` (syntax, matching rule, attribute type, object class, DIT
    content rule, name form, DIT structure rule), `OID` -- a structure
    rule's is its rule ID -- and `Name` (the first NAME) of the refused
    definition, and its `Pos`;
  - `Field`, the term at fault (`SUP`, `EQUALITY`, `SYNTAX`, `MUST`, `NAME`
    ...), and `Ref`: the undefined name or OID, or the other definition --
    for a duplicate the first one, for a kind or usage rule the superior --
    with its `RefOID` and `RefPos`.

  Build stops at the first refusal, so there is one BuildError. Its message
  is the one Build has always given, after the position, and a duplicate
  says where the first definition is:
  `site.schema:12:1: schema: the attribute type 2.5.4.3 is defined twice (first defined at rfc4519.schema:42:1)`.
- **Positions.** Every syntax, matching rule, attribute type and object class
  `schema.Read` returns has a `Pos` (`schema.Position`: file, line, column):
  the line its record **starts** on in the original file, column 1 -- the
  `.schema` keyword line, or the LDIF `attributeTypes:` line, before any
  continuation line, backslash join or RFC 2849 fold is joined to it, base64
  values included. `hclschema.Decode` gives the block's own line and column.
  A definition made in code or by the `Parse` functions has none. `Pos` is
  not part of what a definition says: `String` and `Format` leave it out,
  and two readings of different text compare equal once it is set aside.
- `schema.Standard()`: the definitions of RFC 4512 (the directory's own),
  4517 (syntaxes, matching rules), 4519 (person, cn, ...), 4524 (COSINE:
  account, mail, ...), 4523 (userCertificate), 2798 (inetOrgPerson), 2307
  (posixAccount, posixGroup, shadowAccount, ...), 3672 (subentry) and 3045
  (vendorName), plus openssh-lpk's `ldapPublicKey`/`sshPublicKey` and two
  OpenLDAP definitions they need (`OpenLDAProotDSE`,
  `caseExactIA5SubstringsMatch`). They are embedded at compile time and were
  **copied from the RFC text**, not retyped: each file in
  [`schema/defs`](schema/defs) names its source and section, and says where
  a definition had to be changed to be RFC 4512 at all (RFC 2307 predates
  it) and where OpenLDAP's schema files differ. `StandardFiles()` lets a
  deployment add its own (`Build(append(schema.StandardFiles(), mine)...)`).
- `(*Schema).Validate(entry)`, and `(*ldap.Entry).Validate(s)`: one
  structural chain with every superclass listed, every MUST present, nothing
  outside MUST/MAY unless `extensibleObject`, SINGLE-VALUE, known types,
  options and classes, distinct descriptions, no equivalent values, values of
  their syntax, and the RDN's values in the entry. Every problem is named.
- **DIT content rules are enforced by `Validate`** (RFC 4512 4.1.6), for the
  entry's structural class itself, not its superclasses: an auxiliary class
  not in the rule's AUX is refused (`AuxiliaryNotAllowed`), its MUST is
  required, its NOT is refused even in an `extensibleObject` (`Precluded`),
  its MAY is allowed. An OBSOLETE rule is not active. Without a rule,
  auxiliary classes are allowed, as slapd allows them;
  `ValidateWith(e, schema.ValidateOptions{StrictAuxiliary: true})` refuses
  them, as RFC 4512 2.4.3 says.
- **Name forms are enforced by `Validate`** (4.1.7.2): when the structural
  class has active name forms, the RDN uses all the MUST types of one of
  them and nothing outside its MUST and MAY (`NameFormViolation`).
- **DIT structure rules: `(*Schema).GoverningStructureRule(entry, superior)`**
  (4.1.7.1, X.501 13.7.5) returns the rule that governs an entry placed under
  an entry governed by `superior`, or, with `superior` nil, at the root of
  the subtree (a rule with no SUP). The rule's name form must be for the
  entry's structural class itself and allow its RDN. No rule is a
  `NoStructureRule` or `NameFormViolation` problem. A schema with no active
  structure rule governs nothing: the result is nil, nil. A server checks a
  tree from its root down, each entry's rule being its subordinates'
  `superior`:

  ```go
  root, err := s.GoverningStructureRule(suffix, nil)    // dc=example,dc=org
  people, err := s.GoverningStructureRule(ouPeople, root)
  _, err = s.GoverningStructureRule(alice, people)       // uid=alice,ou=people,...
  ```

  A rule may name itself in SUP (`ou` under `ou`). Rule IDs are at most
  `schema.MaxRuleID` (2^31-1), the same on 32-bit platforms.
- Matching rules (RFC 4517 4.2): caseIgnore, caseExact, caseIgnoreIA5,
  caseExactIA5, octetString, integer, numericString, distinguishedName,
  objectIdentifier, boolean, telephoneNumber, generalizedTime, bitString,
  caseIgnoreList, uniqueMember, the two first-component rules, word and
  keyword, and the ORDERING and SUBSTR rules the RFC defines for them, with
  RFC 4518 string preparation (map, NFKC, case folding, prohibited
  characters, and the three kinds of insignificant character handling, with
  verified errata 860, 1757 and 1758).

**What a server with a Schema does.**

- The root DSE carries `subschemaSubentry: cn=Subschema`, and so does every
  entry a search returns (operational, so only `+` or the name brings it).
- A base search of `cn=Subschema` (`ldap.SubschemaDN`) is answered by the
  library, like the root DSE: `objectClass: top, subentry, subschema`, `cn`,
  the operational `subtreeSpecification: {}` that RFC 3672's `subentry`
  requires, and `ldapSyntaxes`, `matchingRules`, `matchingRuleUse`,
  `attributeTypes` and `objectClasses` -- and `dITContentRules`, `nameForms`
  and `dITStructureRules` when the schema has any, since each is enforced --
  which come only when asked for by name or with `+`. The entry passes `Validate` against the schema it
  publishes. It is behind the `RequireTLS` gate; the root DSE alone is in
  front of it, because that is where StartTLS is advertised.
- Filters are evaluated with the schema's rules in RFC 4511's three-valued
  logic (`ldap.Evaluate`): an unknown attribute, an unrecognized option, a
  type with no rule for the match asked, an unimplemented rule or an invalid
  assertion value is **Undefined** -- never an error, as RFC 4511 4.5.1.7
  requires -- and `(!(x))` of an Undefined `(x)` is Undefined too. A filter
  on a type matches its subtypes. Extensible matches may name any
  implemented rule that applies to the type, omit the type, or set
  `dnAttributes`.
- The server re-checks every entry a handler sends and drops those the
  filter does not make TRUE. A handler should filter with
  `req.Matches(e)`, which uses the same schema; `req.Filter.Matches(e)`
  compares strings and may leave out an entry the schema would match.

⛔ **`(uidNumber>=1000)` compares integers**, and that is the one place the
embedded definitions depart from their RFC. RFC 2307 gives `uidNumber` and
`gidNumber` an EQUALITY rule and no ORDERING rule, which would make every
range filter on them Undefined (RFC 4511 4.5.1.7.3) — including the one SSSD
builds from `ldap_min_id`/`ldap_max_id`. slapd defines both types itself WITH
`ORDERING integerOrderingMatch` (`servers/slapd/schema_prep.c`; nis.schema
comments them out as "builtin"), and so does draft-howard-rfc2307bis-02, so
this follows them. An attribute with no ORDERING rule at all, such as `uid`,
still makes `>=` Undefined.

**What is deliberately not there.**

- By default, auxiliary classes on an entry whose structural class has no
  DIT content rule. RFC 4512 2.4.3 forbids them. slapd allows them: its
  check (`SLAP_DISALLOW_AUX_WO_CR`, `servers/slapd/schema_check.c`) is
  behind a flag no `disallow` verb of slapd.conf(5) sets. Refusing every
  posixAccount in a schema without rules would make the package useless, so
  this is the default, and `ValidateOptions.StrictAuxiliary` is the RFC.
- Name forms and structure rules in slapd's own files: slapd.conf(5) and
  slapd-config(5) have `ditcontentrule`/`olcDitContentRules` and nothing for
  the other two, which OpenLDAP does not implement. `Format` writes them with
  this package's keywords `nameform` and `ditstructurerule`, which `Read`
  reads and slapd refuses.
- Changing the schema over LDAP (Modify on `cn=Subschema`). A Schema is
  built from files and read-only.
- `directoryStringFirstComponentMatch` and RFC 4523's certificate rules are
  defined and not implemented: assertions that use them are Undefined.
- Collective attributes, `createTimestamp`/`modifyTimestamp` on the
  subschema subentry, the subentries control (RFC 3672 3), and options other
  than `lang-` (RFC 3866) and `binary` (RFC 4522).
- RFC 4518's repertoire is the Unicode version Go ships, not Unicode 3.2;
  case folding is full Unicode folding around NFKC, which is what RFC 3454
  table B.2 is built to give, not that table byte for byte.
- In HCL, two extensions with the same name in one definition. RFC 4512
  allows it, but one map cannot hold it, so `Encode` refuses it. None of the
  published files measured below does it.
- `include` directives and `ldapsyntax`'s `X-SUBST` substitution: a
  `.schema` file is read as definitions, and is not run as a slapd
  configuration.

### Schema files, OID macros and LDIF

`schema.Read(files...)` reads definitions without linking them
(`*schema.Definitions`), and `schema.BuildFrom(defs...)` links them with every
check `Build` makes. `Build` is `Read` followed by `BuildFrom`.
`(*Definitions).Format(macros)` writes them back as a `.schema` file that
`Read` reads back to the same values.

A file is read the way slapd reads it, because published files are written
for slapd:

- **Two forms.** A file whose first line that is not a comment is
  `name: value` is LDIF (RFC 2849). That covers OpenLDAP's cn=config form
  (`olcObjectIdentifier`, `olcLdapSyntaxes`, `olcAttributeTypes`,
  `olcObjectClasses`, `olcDitContentRules`, with the `{N}` prefix stripped,
  slapd-config(5)) and the subschema subentry's own attributes (RFC 4512
  4.2, `dITContentRules`, `nameForms` and `dITStructureRules` included).
  Anything else is the `.schema` form (slapd.conf(5)): `ditcontentrule` is
  slapd's keyword, `nameform` and `ditstructurerule` this package's.
- **Two kinds of line continuation.** In a `.schema` file, a line that starts
  with white space continues the line before it. slapd's `fp_getline`
  replaces that first white space character with one space and keeps the
  rest. A line that ends with a backslash joins the next one with nothing
  between them. Comments are removed after the lines are joined. In LDIF, a
  continuation line starts with exactly ONE space, and that space is
  removed. A DESC folded mid-word therefore reads differently in the two
  forms, and a test checks both. Base64 values (`attr::`) are decoded after
  the lines are joined.
- **The liberal parser.** libldap's own (`libraries/libldap/schema.c`:
  "Beyond this point we will be liberal and accept the items in any
  order"). Terms may come in any order, and a term given twice is refused.
  Tabs are white space. An OID may be quoted (REFEDS's `eduperson.ldif`
  writes `SYNTAX '1.3.6...'`). No space is needed after a quote (Samba's
  `samba.ldif` has `...Outgoing'DESC`). The exported `Parse*` functions,
  and what a server publishes, stay strict RFC 4512.
- **OID macros** (`objectidentifier name oid`, slapd.conf(5); `servers/slapd/oidm.c`):
  - `name:suffix` is the macro's OID, a dot, then the suffix.
  - Macros may chain, but only to macros defined EARLIER: the value is
    expanded once, when the macro is defined. So a cycle cannot be written.
  - Names are case-sensitive.
  - A name may be defined twice only to the same OID.
  - Unlike slapd, the suffix is checked to be numbers and dots.
  - A macro is expanded where slapd expands one: the OID of a definition and
    the SYNTAX of an attribute type. It is also expanded in the other
    numeric-OID positions of RFC 4512 4.1. It is never expanded in SUP,
    EQUALITY, MUST or MAY, which slapd looks up by name.
  - An undefined macro is refused with its file, line and column:
    `f:3:18: ... the OID macro "zz" is not defined before it is used`.
- **Bounds.** A file is at most 4 MiB (`schema.MaxFileSize`). A physical
  line in a `.schema` file is at most 2,000 bytes, as slapd.conf(5) says.
  `FuzzRead` and `FuzzMacros` fuzz the reader and the expander. The lines
  of a definition are joined in linear time: a 4 MiB file of short
  continuation lines took three minutes to read up to v0.10.0.

### Performance

The reference is OpenLDAP's own parser, libldap's `ldap_str2attributetype` and
`ldap_str2objectclass` (`libraries/libldap/schema.c`). Both parsers are given
the 41 attribute types and 13 object classes of OpenLDAP's `cosine.schema`,
printed in RFC 4512 form, on one core:

| one pass over the 54 definitions | time | allocations |
| --- | --- | --- |
| go-authn/ldap up to v0.10.0 | 84.0 µs ± 14% | 498, 49.1 KiB |
| go-authn/ldap now | 32.5 µs ± 19% | 147, 20.6 KiB |
| libldap (macOS system library) | 46.5 µs ± 7% | (malloc, not counted) |

⚠ The times were measured on an Apple M4 Max with a 1-minute load of 13 to
14, with `-cpu 1`, interleaving 6 runs of each binary. That is above the
load at which a ratio can be trusted, so treat them as provisional until a
measurement on a quiet machine is published. The allocation counts do not
depend on load.

The parser scans each definition once. A value is a slice of the input, not a
copy, unless a quoted string holds an escape. Lists are gathered on the stack
and copied out once. The terms a definition allows are a table built once per
kind of definition. What is left to allocate is the result: a definition and
its lists.

- `go test -bench ParseCosine -benchmem ./schema` times the parser alone, in
  pure Go. `BenchmarkReadCosine` times `schema.Read` on the whole file.
- `bench/libldap` is the comparison with libldap. It is a module of its own, so
  that this module stays free of cgo: `go build ./...`, `go vet ./...` and
  `go test ./...` here never see it. It needs cgo, a C compiler and libldap's
  headers (`ldap_schema.h`: present on macOS; `libldap-dev` on Debian and
  Ubuntu). `-count` repeats each sub-benchmark back to back, so to interleave
  the two, build the binary once and run it several times:

  ```sh
  cd bench/libldap
  CGO_ENABLED=1 go test -c -o /tmp/libldap.test .
  /tmp/libldap.test -test.run TestBothAccept -test.bench . -test.benchmem -test.cpu 1 -test.count 1
  ```

  `TestBothAccept` checks that both parsers accept every definition, so the
  timing compares like with like.

**The rule parsers** against libldap's `ldap_str2contentrule`,
`ldap_str2nameform` and `ldap_str2structurerule`, on a content rule, a name
form and a structure rule made from each of cosine.schema's 13 classes
(`BenchmarkParseRules`, no published file holds such rules), one core:

| one pass over the 39 rules | time | allocations |
| --- | --- | --- |
| go-authn/ldap v0.11.0 | 12.2 µs | 157, 18.6 KiB |
| libldap (macOS system library) | 21.2 µs | (malloc, not counted) |

⚠ One run each, at a 1-minute load of 18: provisional, like the table
above. ⛔ The structure rules carry no SUP, because
`ldap_str2structurerule` has no branch for SUP and refuses a rule that has
one, though RFC 4512 4.1.7.1 defines it and libldap's own
`ldap_structurerule2bv` writes it (`TestLibldapRefusesSUP`).

### Schemas in HCL: package `schema/hclschema`

`hclschema.Decode(files...)` reads HCL2 into the same `*schema.Definitions`.
`hclschema.Encode(defs, opts)` writes them back. The package is separate, so
`schema` itself has no HCL dependency.

```hcl
object_identifier "supann" {
  oid = "1.3.6.1.4.1.7135.1"
}

object_identifier "supannAttr" {
  oid = "supann:2.1"
}

attribute_type "supannEtablissement" {
  oid        = "supannAttr:14"
  desc       = "code d etablissement"
  equality   = "caseIgnoreMatch"
  syntax     = "1.3.6.1.4.1.1466.115.121.1.15"
  syntax_len = 128
}

object_class "supannPerson" {
  oid        = "supann:2.2.1"
  sup        = ["top"]
  kind       = "auxiliary"
  may        = ["supannEtablissement"]
  extensions = { "X-ORIGIN" = ["SUPANN 2021"] }
}
```

The example is the one `TestDecodeTheExample` decodes and builds.

- **One block per definition.** The block type is the kind of definition:
  `object_identifier`, `ldap_syntax`, `matching_rule`, `attribute_type`,
  `object_class`, `dit_content_rule`, `name_form` or `dit_structure_rule`:

  ```hcl
  dit_content_rule "accountRule" {
    oid  = "0.9.2342.19200300.100.4.5"   # the structural class's OID
    aux  = ["posixAccount", "shadowAccount"]
    must = ["description"]
    not  = ["seeAlso"]
  }

  name_form "accountForm" {
    oid  = "1.3.6.1.4.1.32473.1.2.3"
    oc   = "account"
    must = ["uid"]
  }

  dit_structure_rule "people" {
    id   = 3            # a rule ID, not an OID
    form = "accountForm"
    sup  = [2]
  }
  ```
- **The label** is the first NAME. `names` lists the others. A definition
  with no NAME is labelled with its OID and has no `oid`. A syntax never has
  a NAME. A structure rule is labelled the same way with its rule ID, and
  `id` is a number.
- **The attributes are RFC 4512 4.1's terms**, in lower case with
  underscores: `desc`, `obsolete`, `sup`, `equality`, `ordering`, `substr`,
  `syntax`, `single_value`, `collective`, `no_user_modification`, `usage`,
  `kind`, `must`, `may`, `aux`, `not`, `oc`, `form`. A structure rule's
  `sup` is a list of rule IDs.
  - A string that is not UTF-8 is refused (found by `FuzzDecode`: it
    decoded, then encoded to another string).
  - The `{len}` of noidlen is `syntax_len`, a number, because it is not part
    of the OID.
  - `extensions` maps each `X-` name to its list of strings. It is read item
    by item from the source, so its order survives.
  - A term left out has RFC 4512's default: STRUCTURAL, userApplications, not
    OBSOLETE. `Encode` leaves defaults out.
- **Literals only.** A value is a quoted string, a number, a boolean or a
  list of those. A variable, a function, an operator or a `${...}`/`%{...}`
  template is refused before evaluation, including `"${2}"`. `Encode`
  escapes `${`, `%{`, quotes, backslashes and control characters. A test
  round-trips a DESC that holds all of them.
- **Checks.** Each field is checked with the strict RFC 4512 parser itself,
  so HCL accepts exactly what RFC 4512 does. The checks that need positions
  are made at decode time, with the file, line and column:
  - a definition given twice;
  - an attribute type without SUP or SYNTAX;
  - COLLECTIVE that is not userApplications;
  - NO-USER-MODIFICATION on a user attribute;
  - unknown keys.

  `schema.BuildFrom` then makes the cross-reference checks.
- **Macros follow slapd's rule.** An `object_identifier` may be used after
  it is defined, in the order of the files and of the blocks in them.
  `Encode` writes numeric OIDs by default. A numeric OID is what a client
  sees in the subschema, it can be searched for, and a block that carries
  one can be moved on its own. `EncodeOptions{Macros: true}` writes
  `supannAttr:14` instead. The `object_identifier` blocks are written either
  way.
- **Deterministic output.** The same definitions always encode to the same
  bytes. Kinds come in the order above. Within a kind, definitions keep the
  order of their source. Within a block, terms come in RFC 4512's order.
  `FuzzDecode` checks that what decodes round-trips and re-encodes to the
  same bytes. Strings are NFC-normalised, as every HCL string is.

### The converter: `cmd/ldapschema`

```
go install github.com/go-authn/ldap/cmd/ldapschema@latest

ldapschema to-hcl [--macros] FILE...     .schema, cn=config LDIF or subschema LDIF -> HCL
ldapschema to-schema [--macros] FILE...  HCL -> OpenLDAP .schema
ldapschema check FILE...                 build on top of schema.Standard() and report
```

Output goes to stdout.

- **Exit status:** 0 when the command worked, 1 when a file or a definition
  is refused, 2 on a usage error.
- **`check`** reads `*.hcl` as HCL, and any other file as `.schema` or LDIF.
  It reports:
  - the definitions `schema.Standard()` already has, identical or not. A
    difference in DESC alone is counted; every other difference is listed
    with its fields.
  - EVERY reference that nothing defines, the rules' included (a class, a
    type, a name form, a superior rule ID). `Build` stops at the first.
  - the verdict of `BuildFrom`.

From `TestConvertBothWays`:

```
$ ldapschema to-schema --macros site.hcl
objectidentifier site 1.3.6.1.4.1.99999
objectidentifier siteAttr site:1

attributetype ( siteAttr:1
	NAME 'siteBadge'
	DESC 'the badge number'
	EQUALITY caseIgnoreMatch
	SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32}
	SINGLE-VALUE )
[...]
```

**Measured on the published files** (`cmd/ldapschema/published_test.go`).
For each file, three round trips give equal definition values:

- `.schema` -> HCL -> definitions;
- HCL -> `.schema` -> definitions;
- LDIF -> definitions, compared with `.schema` -> definitions.

| File | Definitions | LDIF vs `.schema` | `check` on Standard() |
|---|---|---|---|
| OpenLDAP core | 52 types, 27 classes, 47 macros | equal | 1: `presentationAddress` needs syntax ...1.43 and `presentationAddressMatch`, which slapd builds in |
| OpenLDAP cosine | 41 types, 13 classes | equal | 1: syntaxes ...1.19 and ...1.13 (dropped by RFC 4517), and `rfc822Mailbox`, `homeTelephoneNumber` and `dsa` |
| OpenLDAP inetorgperson | 9 types, 1 class | equal | 0: all already there |
| OpenLDAP nis | 25 types, 13 classes | equal | 0: all already there |
| SUPANN 2021 (RENATER) | 67 types, 8 classes | equal | 0: 75 added, no eduPerson needed |
| eduPerson (REFEDS) | 16 types, 1 class | the class differs: the `.schema` (202111) has `eduPersonAnalyticsTag` in MAY, and the `.ldif` (202208) does not | 0: 17 added |
| Samba | 58 types, 12 classes | equal | 0: 70 added |

Only OpenLDAP's files are committed, under the OpenLDAP Public License 2.8.

- SUPANN carries no licence.
- eduPerson is CC BY-NC-SA 4.0.
- Samba is GPL-3.0.

Those are downloaded when `LDAP_SCHEMA_NETWORK=1` is set, and each is checked
against a SHA-256 recorded with its URL and date. A change upstream is
reported, not tested silently.

**Why golang.org/x/text.** RFC 4518 2.3 requires NFKC, and 2.2 full case
folding. Without NFKC a precomposed `é` (U+00E9) and `e` + U+0301 -- what a
macOS client often sends -- do not match, and RFC 4518 says they must. NFKC
needs the Unicode decomposition and composition tables, and x/text is where
the Go project keeps them: pure Go, no dependencies of its own, and already
in authnd's module graph at the same version.

## Status

The server answers binds (simple and SASL), searches, compares, extended
operations, StartTLS, abandon, the **root DSE**, the **subschema subentry**
(with `Server.Schema`), all four writes, **paged results** (RFC 2696) and the
**read entry controls** (RFC 4527).

Coverage is **99.9%** (the CI floor is 99.7%; package `schema` alone is at 100%), and the three missing lines
are named rather than rounded away: the `EncodeFilter` error branch in
`ldaptest`'s `Search` (`Filter` is a sealed interface and `EncodeFilter` is
total over the ten types that satisfy it), and the two branches that handle `crypto/rand`
failing while making a paging cookie. Reaching those two would mean adding an
injection point for the sake of a number. They are kept because a cookie that
cannot be made must not be silently skipped — an empty cookie means "last
page", so skipping it would end the sequence and lose the rest of the
directory.

**Paged results** (RFC 2696) are here: a search answered a page at a time,
because a size limit is not an answer to "give me everybody" — a client that
truncates cannot tell that from a directory with fewer people in it. The
handler is left RUNNING between pages, parked on its next entry, which is
what keeps the result consistent: re-running the search per page and skipping
the first N is not only O(n²), it sends an entry twice or never when somebody
is added between two pages.

**The read entry controls** (RFC 4527) are here too: a write can report the
entry as it was before and as it became. They are answered by the HANDLER,
not by this package, and that is not a convenience — 4527 requires the read
and the update to be "one atomic action isolated from other update
operations", and a server that read, wrote, and read again would be doing
three things with gaps between them, so the copy it returned could be one
somebody else's write made. A lie in the shape of a confirmation.

⛔ This section said "at 100% coverage" and "still to come: the root DSE"
for about six hours, both written here by the same hands that then made them
false. A status line is a claim with an expiry date, and the ones in this
fleet have cost real work — a README that advertised a repository that did
not exist, a comment that invented an API nobody had written. It is checked
against the code when the code moves, not when somebody notices.

## The judge

OpenLDAP's own `ldapsearch` is the judge in CI, and **required** in every lane
that installs it: the Linux test lane, the race detector and coverage, where
`LDAP_REQUIRE_JUDGE=1` turns a missing client into a failure. macOS runs it
where the system ships it, Windows has none and skips those tests, and the
cross-architecture lanes neither install nor require it. A server tested only
by a client from this same module can agree with it about a misreading of the
protocol and both be wrong — which is exactly how the substring bug went
unnoticed.

`ldaptest` is the wire client in this module, and it is deliberately **not**
the judge: it is for the questions `ldapsearch` cannot ask, all about one
connection's state — two binds on a single socket, a SASL bind with an
arbitrary mechanism, and the difference between an absent `serverSaslCreds`
and an empty one.

## Licence

BSD-3-Clause.
