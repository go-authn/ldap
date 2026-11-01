// A module of its own so that the parent's `go build ./...`, `go vet ./...`
// and `go test ./...` never see it: it needs cgo and OpenLDAP's libldap,
// and the parent builds with CGO_ENABLED=0. See the repository's README.md,
// "Performance".
module github.com/go-authn/ldap/bench/libldap

go 1.27.3

require github.com/go-authn/ldap v0.11.4

require golang.org/x/text v0.43.0 // indirect

replace github.com/go-authn/ldap => ../..
