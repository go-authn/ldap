// SPDX-License-Identifier: BSD-3-Clause

package schema

import (
	"math/big"
	"time"
)

// parseGeneralizedTime is RFC 4517 3.3.13:
//
//	GeneralizedTime = century year month day hour
//	                     [ minute [ second / leap-second ] ]
//	                     [ fraction ]
//	                     g-time-zone
//
// It returns the instant, in UTC. "Such character strings [as February 31]
// SHOULD be considered invalid", and are.
func parseGeneralizedTime(v string) (time.Time, bool) {
	i := 0
	digits := func(n int) (int, bool) {
		if i+n > len(v) {
			return 0, false
		}
		x := 0
		for _, c := range []byte(v[i : i+n]) {
			if c < '0' || c > '9' {
				return 0, false
			}
			x = x*10 + int(c-'0')
		}
		i += n
		return x, true
	}
	isDigit := func() bool { return i < len(v) && v[i] >= '0' && v[i] <= '9' }

	year, ok1 := digits(4)
	month, ok2 := digits(2)
	day, ok3 := digits(2)
	hour, ok4 := digits(2)
	if !ok1 || !ok2 || !ok3 || !ok4 || month < 1 || month > 12 || day < 1 || hour > 23 {
		return time.Time{}, false
	}
	minute, second := 0, 0
	unit := time.Hour // what a fraction is a fraction of
	if isDigit() {
		var ok bool
		if minute, ok = digits(2); !ok || minute > 59 {
			return time.Time{}, false
		}
		unit = time.Minute
		if isDigit() {
			if second, ok = digits(2); !ok || second > 60 {
				return time.Time{}, false
			}
			unit = time.Second
		}
	}
	var frac time.Duration
	if i < len(v) && (v[i] == '.' || v[i] == ',') {
		i++
		start := i
		for isDigit() {
			i++
		}
		if i == start {
			return time.Time{}, false
		}
		// fraction * unit, exactly, then rounded down to a nanosecond.
		num, _ := new(big.Int).SetString(v[start:i], 10)
		den := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(i-start)), nil)
		num.Mul(num, big.NewInt(int64(unit)))
		frac = time.Duration(num.Quo(num, den).Int64())
	}
	if time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC).Day() != day {
		return time.Time{}, false // February 31
	}
	// A leap second (60) is the first instant of the next minute: Go's time
	// has no leap seconds, and it does compare after 59.
	t := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC).Add(frac)
	if i == len(v) {
		return time.Time{}, false // g-time-zone is not optional
	}
	switch v[i] {
	case 'Z':
		i++
	case '+', '-':
		sign := 1
		if v[i] == '-' {
			sign = -1
		}
		i++
		dh, ok := digits(2)
		if !ok || dh > 23 {
			return time.Time{}, false
		}
		dm := 0
		if i < len(v) {
			if dm, ok = digits(2); !ok || dm > 59 {
				return time.Time{}, false
			}
		}
		// "coordinated universal time can be calculated by subtracting the
		// differential from the local time"
		t = t.Add(-time.Duration(sign) * (time.Duration(dh)*time.Hour + time.Duration(dm)*time.Minute))
	default:
		return time.Time{}, false
	}
	if i != len(v) {
		return time.Time{}, false
	}
	return t, true
}
