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

- Types for syntaxes, matching rules, matching rule uses, attribute types
  and object classes, and a parser and printer for their RFC 4512 4.1 forms.
  The parser is strict -- terms in the ABNF's order, SP is spaces -- and a
  refusal says at which byte (`*schema.ParseError`). Printing and parsing
  round-trip; `FuzzDefinition` checks it.
- `schema.Build(files...)` links definitions into a read-only `*Schema`:
  every SUP, rule, syntax, MUST and MAY must resolve, and RFC 4512's rules
  about which kind of class may derive from which, and about supertype
  usage, are enforced. Lookup is by any name or OID, without regard to case.
  EQUALITY, ORDERING, SUBSTR and SYNTAX are inherited through SUP; MUST and
  MAY through superclasses.
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
  `attributeTypes` and `objectClasses`, which come only when asked for by
  name or with `+`. The entry passes `Validate` against the schema it
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

- DIT content rules, DIT structure rules and name forms: not parsed, not
  enforced, not published. So `Validate` allows auxiliary classes, which RFC
  4512 2.4.3 strictly forbids when no DIT content rule exists -- every
  server in use does the same, and refusing every posixAccount would make
  the package useless. It is the one departure from the RFC's letter.
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
- OpenLDAP's `objectIdentifier` macros in `.schema` files.

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
