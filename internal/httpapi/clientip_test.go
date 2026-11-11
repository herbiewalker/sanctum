package httpapi

import (
	"net/http/httptest"
	"testing"
)

// D03: X-Forwarded-For must not influence the rate-limit key.
func TestClientIP_IgnoresForwardedFor_D03(t *testing.T) {
	r := httptest.NewRequest("POST", "/unlock", nil)
	r.RemoteAddr = "192.168.1.50:5555"
	r.Header.Set("X-Forwarded-For", "10.9.9.9, 1.2.3.4")
	if got := clientIP(r); got != "192.168.1.50" {
		t.Fatalf("clientIP = %q, want the peer address", got)
	}
	r.RemoteAddr = "[fe80::1]:4444"
	if got := clientIP(r); got != "fe80::1" {
		t.Fatalf("ipv6 clientIP = %q", got)
	}
}

func TestLimiter_NotBypassedByForwardedFor_D03(t *testing.T) {
	l := newLimiter(unlockRate, nil)
	allowed := 0
	for i := 0; i < 50; i++ {
		r := httptest.NewRequest("POST", "/unlock", nil)
		r.RemoteAddr = "192.168.1.50:5555"
		r.Header.Set("X-Forwarded-For", "10.0.0."+string(rune('a'+i%26)))
		if l.Allow(clientIP(r)) {
			allowed++
		}
	}
	if allowed != unlockRate.Capacity {
		t.Fatalf("allowed %d attempts, want exactly the bucket capacity %d", allowed, unlockRate.Capacity)
	}
}
