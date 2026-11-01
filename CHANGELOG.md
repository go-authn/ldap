# Changelog

Releases follow [semantic versioning](https://semver.org). Releases before
v0.11.0 are described on the repository's GitHub releases page.

## v0.12.0

Resource bounds for the server (go-authn/authnd#67). All additions; the zero
values keep the previous behaviour.

- `Server.MaxConnections` and `Server.MaxConnectionsPerIP`: connections over a
  cap get a `busy` notice of disconnection and are closed, never queued.
- `Server.Timeout` is now enforced by the server: at the deadline the client
  is answered `timeLimitExceeded` (3) for any operation, whether or not the
  handler returns. Previously a handler ignoring its context left the client
  waiting for ever, and only a search mapped a deadline to code 3 (a bind,
  compare or write answered `other`). A handler's `DeadlineExceeded` is mapped
  only when the operation's own context has expired.
- Such a handler still counts against `MaxPending`/`MaxPendingAuth` until it
  returns, so leaked goroutines are bounded per connection; its late result is
  discarded and its message id is refused (`protocolError`) meanwhile.
- The client's search `timeLimit` is applied to the handler's context.
- No handler interface changed: handlers already receive the context.
- Cost (`BenchmarkRun`, allocations per operation, exact): 3 before and now
  with no `Timeout`; with a `Timeout` 10 before, 16 now (the deadline watcher).

## v0.11.4

The module's `go` directive is `1.27.3` (was `1.27.1`): a program built with the
floor's own toolchain carried three standard-library vulnerabilities
(GO-2026-6809 in crypto/x509, GO-2026-6617 and GO-2026-6613 in net/http), fixed
in 1.27.2 and 1.27.3. CI takes its toolchain from go.mod (`go-version-file`)
and runs `govulncheck ./...`, which fails the build on any finding. Nothing
else changes.

## v0.11.3

Performance only; no API change and no change of result. `GoverningStructureRule`
of an account: 12 allocations before, 5 after (`BenchmarkGoverningStructureRule`);
`Validate` of a ten attribute entry: 12 at v0.11.2, 9 now
(`BenchmarkValidate`); the DN parser 6 -> 3 for a four-RDN DN.

### Changed

- `GoverningStructureRule` reads only the types of the RDN when the entry has a
  structural class: the comparison of the RDN's values only produced problems
  that the function drops in that case, and `Validate` makes it.
- The DN parser writes the values of all AVAs into one buffer.
- `Validate` no longer lets its working state escape to the heap, and keeps the
  name forms it considers in place.
- Proved equal to v0.11.2: `refGoverningStructureRule`, a copy of the v0.11.2
  function, and `TestGoverningStructureRuleMatchesReference` (30,000 random
  entries and every superior rule against a rules schema, the standard schema,
  and every shape the rules tests name; rule and the whole `*ValidationError`
  compared) and `FuzzGoverningStructureRuleMatchesReference`. A planted fault
  (the OBSOLETE name form ignored; the RDN types cut to one) fails it.

## v0.11.2

Performance only; no API change and no change of result. `Validate` of a ten
attribute entry: 76 allocations before, 12 after (`BenchmarkValidate`).

### Changed

- `AttributeType`, `ObjectClass` and `MatchingRule` look a name up without
  allocating a lower-case copy of an ASCII name of up to 64 bytes (anything
  else still takes `strings.ToLower`).
- `Describe` and `Validate` do not split and re-join a description that has
  no options.
- `Validate` keeps the classes, the MUSTs and the sets of descriptions and
  types it has seen in place for the usual entry (the sets move to a map past
  16 members), walks superclasses without a closure, checks a value of syntax
  Integer without building a `big.Int`, resolves an objectIdentifierMatch
  descriptor without a copy, and stops comparing RDN values once one matches.
- Proved equal to v0.11.1: a reference copy of `Validate` in the tests and
  `TestValidateMatchesReference` (random entries, both the standard and a
  rules schema, both `StrictAuxiliary` settings, the whole `*ValidationError`
  compared) and `FuzzValidateMatchesReference`; a planted fault (a MAY
  ignored) fails the first. `TestConcurrentValidateIsRaceFree` runs under
  `-race`.

## v0.11.1

Performance only; no API change and no change of result.

### Changed

- String matching rules (`schema.Schema.Equal`, `Less`, `Substrings`, and so
  `Validate`) prepare a value of printable ASCII (0x20-0x7E) without the
  `x/text` transform round trips: RFC 4518 2.2 maps none of those bytes, NFKC
  is the identity on them, 2.4 prohibits none of them, and case folding only
  lowers `A`-`Z`. At most one allocation for such a value, none when nothing
  changes. Any other string takes the general path, unchanged. The result is
  proved equal to v0.11.0's by an exhaustive test over every string of one or
  two bytes below 0x80 and every byte 0x80-0xFF, and by `FuzzPrepareMatchesReference`.
  `BenchmarkPrepareASCII`: 6-13 allocations per value before, 1-2 after.
- The DN parser puts the AVAs of all RDNs in one array: 11 allocations and
  392 B before, 6 and 280 B after, for a four-RDN DN
  (`BenchmarkParseDN`; `FuzzParseDNMatchesReference`).

## v0.11.0

The three kinds of definition RFC 4512 4.1.6 and 4.1.7 define, and this
package refused until now, are read, built, enforced and published.

### Added

- `schema.DITContentRule`, `schema.NameForm`, `schema.DITStructureRule`, and
  their parsers `ParseDITContentRule`, `ParseNameForm`,
  `ParseDITStructureRule` (strict RFC 4512, fuzzed by `FuzzDefinition`) and
  printers. `schema.MaxRuleID` bounds a rule ID to 2^31-1 on every platform.
- `schema.Read` reads them from `.schema` files (`ditcontentrule`, and this
  package's `nameform` and `ditstructurerule`: slapd has no directive for
  those two) and from LDIF (`olcDitContentRules`, `dITContentRules`,
  `nameForms`, `dITStructureRules`), terms in any order as libldap reads
  them. `Format` writes them back. These attributes were refused before.
- `Definitions.DITContentRules`, `NameForms`, `DITStructureRules`.
- `Build` links them: every class, type, name form and superior rule must be
  defined; a content rule is for a structural class and its AUX are
  auxiliary; a name form names a structural class; rule IDs and names are
  unique. New `BuildErrorKind`s `DuplicateMember` and `PrecludedRequired`,
  new `Element`s `ElementDITContentRule`, `ElementNameForm`,
  `ElementDITStructureRule`.
- `Schema.DITContentRules`, `NameForms`, `DITStructureRules`,
  `DITContentRule(name)`, `DITContentRuleOf(class)`, `NameForm(name)`,
  `DITStructureRule(id)`.
- `Validate` enforces the active DIT content rule of the entry's structural
  class (AUX, MUST, MAY, NOT) and its active name forms. New
  `ProblemKind`s `AuxiliaryNotAllowed`, `Precluded`, `NameFormViolation`,
  `NoStructureRule`.
- `ValidateWith(entry, ValidateOptions{StrictAuxiliary: true})`: no
  auxiliary class without a content rule, as RFC 4512 2.4.3 says.
- `Schema.GoverningStructureRule(entry, superior)`: the DIT structure rule
  governing an entry under a superior, or at the root of the subtree.
- Syntaxes 1.3.6.1.4.1.1466.115.121.1.16, .17 and .35 are checked.
- `cn=Subschema` publishes `dITContentRules`, `nameForms` and
  `dITStructureRules` when the schema has any.
- `hclschema`: blocks `dit_content_rule`, `name_form`, `dit_structure_rule`.
- `ldapschema` converts and checks them, and reports every missing
  reference they make.
- `bench/libldap` compares the three parsers with libldap's.

### Fixed

- `hclschema.Decode` accepted a string that is not UTF-8, which then
  encoded to another string (found by `FuzzDecode`). It is refused.

### Behaviour

- `Validate` gives the same result as before for a schema with no rules.
