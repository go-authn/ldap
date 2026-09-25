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

Written from RFC 4511, 4513, 4515 and 7628. No cgo, no client, no global
state.

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
four gigabytes is refused before anything is reserved for it, and filter
nesting is bounded because a stack overflow in Go kills the *process* — one
unauthenticated packet must not take the directory down.

## Status

The server answers binds (simple and SASL), searches, compares, extended
operations, StartTLS, abandon, the **root DSE**, all four writes, **paged
results** (RFC 2696) and the **read entry controls** (RFC 4527).

Coverage is **99.7%**, and the three missing lines are named rather than
rounded away: the `EncodeFilter` error branch in `ldaptest`'s `Search`
(`Filter` is a sealed interface and `EncodeFilter` is total over the nine
types that satisfy it), and the two branches that handle `crypto/rand`
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

OpenLDAP's own `ldapsearch` is the judge in CI, in **every** lane that runs
tests. A server tested only by a client from this same module can agree with
it about a misreading of the protocol and both be wrong — which is exactly
how the substring bug went unnoticed.

`ldaptest` is the wire client in this module, and it is deliberately **not**
the judge: it is for the questions `ldapsearch` cannot ask, all about one
connection's state — two binds on a single socket, a SASL bind with an
arbitrary mechanism, and the difference between an absent `serverSaslCreds`
and an empty one.

## Licence

BSD-3-Clause.
