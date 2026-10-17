package schema

import (
	"fmt"
	"testing"
)

func TestZZQuick(t *testing.T) {
	s := Standard()
	e := Entry{DN: "uid=alice,ou=people,dc=example,dc=org", Attributes: []Attribute{
		{"objectClass", [][]byte{[]byte("top"), []byte("person"), []byte("posixAccount")}},
		{"uid", [][]byte{[]byte("alice")}},
		{"cn", [][]byte{[]byte("alice")}},
		{"sshPublicKey", [][]byte{[]byte("ssh-ed25519 AAAA")}},
	}}
	fmt.Println(s.Validate(e))
	ui := s.AttributeType("uidNumber")
	fmt.Println(s.Less(ui, []byte("999"), []byte("1000")), s.Equal(s.AttributeType("cn"), []byte(" Alice   Smith "), []byte("alice smith")))
	fmt.Println(s.matchDN([]byte("UID=Alice, OU=People"), []byte("uid=alice,ou=people")))
}
