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
operations, StartTLS, abandon and all four writes, at 100% coverage.

Still to come: the root DSE, the paged-results control (RFC 2696), and the
read controls (RFC 4527) that let a client see what its write actually did.

OpenLDAP's own `ldapsearch` is the judge in CI. A server tested only by a
client from this same module can agree with it about a misreading of the
protocol and both be wrong — which is exactly how the substring bug went
unnoticed.

## Licence

BSD-3-Clause.
