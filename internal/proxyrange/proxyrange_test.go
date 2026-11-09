package proxyrange

import (
	"net/netip"
	"strings"
	"testing"
)

func TestCloudflareEmbedded(t *testing.T) {
	s := Cloudflare()
	if len(s) < 20 {
		t.Fatalf("embedded list looks truncated: %d ranges", len(s))
	}
	tests := []struct {
		addr string
		want bool
	}{
		{"104.21.32.1", true},
		{"172.67.1.1", true},
		{"2606:4700::6810:84e5", true},
		{"::ffff:104.16.0.1", true},
		{"192.0.2.10", false},
		{"2001:db8::1", false},
	}
	for _, tt := range tests {
		if got := s.Contains(netip.MustParseAddr(tt.addr)); got != tt.want {
			t.Errorf("Contains(%s) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestParse(t *testing.T) {
	s, err := Parse(strings.NewReader("# comment\n\n10.0.0.1/8\n2001:db8::/32\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 2 || s[0].String() != "10.0.0.0/8" {
		t.Errorf("Parse = %v, want masked prefixes", s)
	}
	if _, err := Parse(strings.NewReader("10.0.0.0/8\nnot-a-cidr\n")); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("expected a line-numbered error, got %v", err)
	}
}

func TestContainsAll(t *testing.T) {
	s := Set{netip.MustParsePrefix("104.16.0.0/13")}
	in, out := netip.MustParseAddr("104.16.1.1"), netip.MustParseAddr("192.0.2.1")
	if s.ContainsAll(nil) {
		t.Error("an empty answer is not proxied")
	}
	if !s.ContainsAll([]netip.Addr{in}) || s.ContainsAll([]netip.Addr{in, out}) {
		t.Error("ContainsAll must require every address to be in range")
	}
}
