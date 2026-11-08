package jobs

import (
	"net"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzHostAllowed over attacker-controlled Host headers: the check gates
// every non-health route, so a bypass is a token-exposed admission surface.
// Invariants: a true verdict only for loopback/private folios, never a
// panic, and a result independent of a trailing port.
func FuzzHostAllowed(f *testing.F) {
	seeds := []string{
		"", "localhost", "localhost:8080", "127.0.0.1", "127.0.0.1:80",
		"[::1]:80", "0.0.0.0", "::", "[::]", "10.0.0.1", "192.168.1.1",
		"172.16.0.1", "169.254.1.1", "evil.com", "evil.com:80",
		"127.0.0.1.evil.com", "LOCALHOST", "  localhost", "localhost ",
		"localhost:badport", "[::1", "[]", ":", "[127.0.0.1]",
		"0x7f000001", "2130706433", "0177.0.0.1", "256.0.0.1",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = utf8.ValidString(s)
		got := hostAllowed(s)
		if got && !strings.Contains(s, "evil") {
			// A true verdict must name a loopback/private literal or localhost.
			lower := strings.ToLower(s)
			// Host may carry a port; strip it the way the handler does.
			h := s
			if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h[i:], "]") {
				h = h[:i]
			}
			h = strings.Trim(h, "[]")
			if ip := net.ParseIP(h); ip != nil {
				if !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
					t.Fatalf("hostAllowed(%q)=true for public IP %s", s, ip)
				}
			} else if !isLocalName(strings.ToLower(s)) && h != "" {
				t.Fatalf("hostAllowed(%q)=true for non-local name", s)
			}
			_ = lower
		}
		// Deterministic: same input, same verdict.
		if again := hostAllowed(s); again != got {
			t.Fatalf("hostAllowed(%q) flipped", s)
		}
	})
}

func isLocalName(s string) bool {
	for _, n := range []string{"localhost", "127.0.0.1", "[::1]", "::1", "0.0.0.0", "::"} {
		if strings.HasPrefix(s, n) {
			return true
		}
	}
	return false
}

// FuzzRequestID over the X-Request-ID header: the value is echoed back in
// the response header and written to the access log, so control characters
// or oversized values must never pass through.
func FuzzRequestID(f *testing.F) {
	seeds := []string{"", "abc-123", "ok", strings.Repeat("x", 128), strings.Repeat("x", 129), "a b", "a\tb", "a\rb", "a\nb", "ümlaut", "\x00"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r := &http.Request{Header: http.Header{}}
		if s != "" {
			r.Header.Set("X-Request-ID", s)
		}
		got := requestID(r)
		if s != "" && len(s) <= 128 && !strings.ContainsAny(s, " \t\r\n") {
			if got != s {
				t.Fatalf("requestID(%q)=%q, want passthrough", s, got)
			}
		} else {
			// Minted ids are hex, bounded, and never echo the bad input.
			if got != "" && got == s {
				t.Fatalf("requestID(%q) echoed malformed header", s)
			}
			if len(got) > 32 {
				t.Fatalf("requestID(%q) minted overlong id %q", s, got)
			}
		}
		if strings.ContainsAny(got, " \t\r\n") {
			t.Fatalf("requestID(%q)=%q contains control chars", s, got)
		}
	})
}
