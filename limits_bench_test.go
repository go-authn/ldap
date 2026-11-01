// SPDX-License-Identifier: BSD-3-Clause

package ldap

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// BenchmarkRun is the per-operation cost of the machinery around a handler:
// context, tracking and (with a Timeout) the deadline watcher.
func BenchmarkRun(b *testing.B) {
	for _, timeout := range []time.Duration{0, time.Minute} {
		b.Run(timeout.String(), func(b *testing.B) {
			x, y := net.Pipe()
			defer x.Close()
			defer y.Close()
			c := newConn(&Server{Timeout: timeout}, x)
			m := &message{id: 1, op: ber.Encode(ber.ClassApplication, ber.TypeConstructed, appSearchRequest, nil, "x")}
			var wg sync.WaitGroup
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c.run(&wg, m, func(context.Context) {})
				wg.Wait()
			}
		})
	}
}
