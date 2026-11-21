// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// Regression tests for the client defects of the 2026-11-21 audit.

// ipOnlyCert is a certificate valid for the IP 127.0.0.1 and for NO DNS name.
func ipOnlyCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ip only"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// The URL names the host "localhost". The server's certificate does not: it is
// valid for the IP 127.0.0.1 only. ldaps:// refuses it (control). StartTLS
// accepts it, because it verifies the certificate against the peer's IP taken
// from RemoteAddr, never against the name the URL was written with.
func TestClientStartTLSVerifiesTheURLHost(t *testing.T) {
	cert, pool := ipOnlyCert(t)
	srvCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer nc.Close()
				buf := make([]byte, 4096)
				if _, err := nc.Read(buf); err != nil { // the StartTLS request
					return
				}
				if _, err := nc.Write(msgOf(1, tlv(0x78, resultBody(0, "", "")))); err != nil {
					return
				}
				tc := tls.Server(nc, srvCfg)
				if tc.Handshake() == nil {
					tc.Read(buf)
				}
			}()
		}
	}()

	// Control: the same certificate, the same name, over ldaps:// -> refused.
	tlsLn, err := tls.Listen("tcp4", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer tlsLn.Close()
	go func() {
		for {
			nc, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func() { nc.(*tls.Conn).Handshake(); nc.Close() }()
		}
	}()
	_, tlsPort, _ := net.SplitHostPort(tlsLn.Addr().String())
	if c, err := Dial(context.Background(), "ldaps://localhost:"+tlsPort, DialOptions{TLS: &tls.Config{RootCAs: pool}}); err == nil {
		c.Close()
		t.Fatal("control broken: ldaps://localhost accepted a certificate that does not name localhost")
	} else {
		t.Logf("control, ldaps://localhost: refused as expected: %v", err)
	}

	c, err := Dial(context.Background(), "ldap://localhost:"+port, DialOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.StartTLS(&tls.Config{RootCAs: pool}); err == nil {
		t.Errorf("StartTLS to ldap://localhost accepted a certificate valid for the IP 127.0.0.1 only: the URL's host is not what is verified")
	} else {
		t.Logf("refused: %v", err)
	}
}

// A server that accepts the TCP connection of an ldaps:// URL and never speaks:
// with a context that has no deadline (what ldapdir's refresh passes), neither
// the Dialer's timeout nor DialOptions.Timeout bounds the TLS handshake.
func TestClientLDAPSHandshakeIsBounded(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var held []net.Conn
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, nc) // accepted, never answered
		}
	}()
	done := make(chan error, 1)
	go func() {
		c, err := Dial(context.Background(), "ldaps://"+ln.Addr().String(), DialOptions{
			Timeout: 200 * time.Millisecond,
			Dialer:  &net.Dialer{Timeout: 200 * time.Millisecond},
		})
		if err == nil {
			c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a handshake with a silent server succeeded")
		}
	case <-time.After(20 * time.Second):
		t.Errorf("Dial(ldaps://) still in the TLS handshake after 20 s, with a 200 ms Dialer timeout and a 200 ms DialOptions.Timeout")
	}
}

// A server that answers a search with continuation references for ever: every
// limit is set to its smallest, and none of them counts a reference.
func TestClientSearchReferencesAreBounded(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	const many = 300_000
	var sent atomic.Int64
	go func() {
		buf := make([]byte, 1<<16)
		if _, err := b.Read(buf); err != nil {
			return
		}
		ref := msgOf(1, tlv(0x73, octets("ldap://elsewhere/")))
		for {
			if _, err := b.Write(ref); err != nil {
				return
			}
			sent.Add(1)
		}
	}()
	c := NewClientConn(a, DialOptions{Timeout: 2 * time.Second, Limits: ClientLimits{MaxMessage: 1 << 10, MaxEntries: 1, MaxBytes: 1, MaxPages: 1}})
	done := make(chan error, 1)
	go func() {
		_, err := c.Search(&SearchRequest{BaseObject: "dc=example,dc=org"}, 0)
		done <- err
	}()
	for sent.Load() < many {
		select {
		case err := <-done:
			t.Logf("refused after %d references: %v", sent.Load(), err)
			return
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Errorf("the search consumed %d continuation references and is still reading: MaxEntries=1 MaxBytes=1 MaxPages=1 bound none of them", sent.Load())
}

// StartTLS's handshake is bounded too: a server that accepts the StartTLS
// request and then says nothing must not hold the caller for ever.
func TestClientStartTLSHandshakeIsBounded(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		buf := make([]byte, 4096)
		if _, err := b.Read(buf); err != nil {
			return
		}
		b.Write(msgOf(1, tlv(0x78, resultBody(0, "", ""))))
		b.Read(buf) // the ClientHello, never answered
		select {}
	}()
	c := NewClientConn(a, DialOptions{Timeout: 200 * time.Millisecond})
	done := make(chan error, 1)
	go func() { done <- c.StartTLS(&tls.Config{ServerName: "example.org"}) }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a handshake with a silent server succeeded")
		}
	case <-time.After(20 * time.Second):
		t.Error("StartTLS still in the TLS handshake after 20 s, with a 200 ms Timeout")
	}
}
