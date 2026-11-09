package rr

import (
	"errors"
	"slices"
	"testing"

	"github.com/miekg/dns"
)

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return r
}

func TestParseName(t *testing.T) {
	tests := []struct {
		in      string
		want    Name
		wantErr bool
	}{
		{in: "Example.COM", want: "example.com."},
		{in: "www.example.com.", want: "www.example.com."},
		{in: "  _dmarc.Example.com ", want: "_dmarc.example.com."},
		{in: ".", want: "."},
		{in: "", wantErr: true},
		{in: "a..b", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseName(tt.in)
		if tt.wantErr {
			if !errors.Is(err, ErrInvalidName) {
				t.Errorf("ParseName(%q) error = %v, want ErrInvalidName", tt.in, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("ParseName(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}

func TestNameRelations(t *testing.T) {
	n := Name("a.b.example.com.")
	if !n.In("example.com.") || !Name("example.com.").In("example.com.") {
		t.Error("In should accept the zone and names below it")
	}
	if Name("badexample.com.").In("example.com.") {
		t.Error("In must compare whole labels")
	}
	if got := n.Parent(); got != "b.example.com." {
		t.Errorf("Parent = %q", got)
	}
	if got := Name("com.").Parent(); got != "." {
		t.Errorf("Parent of TLD = %q", got)
	}
	if got := Name(".").Parent(); got != "." {
		t.Errorf("Parent of root = %q", got)
	}
	if got := Name("_dmarc.example.com.").FirstLabel(); got != "_dmarc" {
		t.Errorf("FirstLabel = %q", got)
	}
	if got, err := Name("example.com.").Child("WWW"); err != nil || got != "www.example.com." {
		t.Errorf("Child = %q, %v", got, err)
	}
}

func TestParseRelative(t *testing.T) {
	zone := Name("example.test.")
	for in, want := range map[string]Name{"@": zone, "www": "www.example.test.", "Mail.Example.Test.": "mail.example.test.", "_dmarc": "_dmarc.example.test."} {
		if got, err := ParseRelative(in, zone); err != nil || got != want {
			t.Errorf("ParseRelative(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseRelative("a..b", zone); !errors.Is(err, ErrInvalidName) {
		t.Errorf("err = %v", err)
	}
}

func TestParseType(t *testing.T) {
	tests := []struct {
		in   string
		want Type
		ok   bool
	}{
		{"mx", TypeMX, true},
		{"AAAA", TypeAAAA, true},
		{"TYPE65", Type(65), true},
		{"bogus", 0, false},
		{"TYPE99999", 0, false},
	}
	for _, tt := range tests {
		got, err := ParseType(tt.in)
		if tt.ok != (err == nil) || got != tt.want {
			t.Errorf("ParseType(%q) = %v, %v", tt.in, got, err)
		}
		if !tt.ok && !errors.Is(err, ErrUnknownType) {
			t.Errorf("ParseType(%q) error should wrap ErrUnknownType: %v", tt.in, err)
		}
	}
	if got := Type(65280).String(); got != "TYPE65280" {
		t.Errorf("unknown type String = %q", got)
	}
}

func TestCanonicalEquivalence(t *testing.T) {
	// Each pair is the same data written the way two different providers
	// might serve it.
	pairs := []struct {
		name string
		a, b string
	}{
		{"txt chunking", `x.example. 300 IN TXT "v=DKIM1; k=rsa; " "p=MIGfMA0GCSq"`, `x.example. 60 IN TXT "v=DKIM1; k=rsa; p=MIGf" "MA0GCSq"`},
		{"mx case", "example. IN MX 10 Mail.Example.", "example. IN MX 10 mail.example."},
		{"aaaa form", "x.example. IN AAAA 2001:db8:0:0::1", "x.example. IN AAAA 2001:db8::1"},
		{"caa tag case", `example. IN CAA 0 ISSUE "letsencrypt.org"`, `example. IN CAA 0 issue "letsencrypt.org"`},
		{"srv target case", "_sip._tls.example. IN SRV 100 1 443 SIP.Example.", "_sip._tls.example. IN SRV 100 1 443 sip.example."},
		{"ds digest case", "example. IN DS 1 13 2 ABCDEF", "example. IN DS 1 13 2 abcdef"},
	}
	for _, p := range pairs {
		ca, cb := Canonical(mustRR(t, p.a)), Canonical(mustRR(t, p.b))
		if ca != cb {
			t.Errorf("%s: %q != %q", p.name, ca, cb)
		}
	}
	if Canonical(mustRR(t, `x. IN TXT "ab" "c"`)) == Canonical(mustRR(t, `x. IN TXT "a" "bd"`)) {
		t.Error("different TXT values must not collapse")
	}
}

func TestCanonicalAFromWireAndZone(t *testing.T) {
	fromZone := mustRR(t, "x.example. IN A 192.0.2.1")
	fromWire := &dns.A{Hdr: dns.RR_Header{Name: "x.example.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: []byte{192, 0, 2, 1}}
	if a, b := Canonical(fromZone), Canonical(fromWire); a != b || a != "192.0.2.1" {
		t.Errorf("A canonical forms differ: %q vs %q", a, b)
	}
}

func TestNewSet(t *testing.T) {
	rrs := []dns.RR{
		mustRR(t, "www.example. 300 IN CNAME example."),
		mustRR(t, "Example. 300 IN A 192.0.2.2"),
		mustRR(t, "example. 120 IN A 192.0.2.1"),
		mustRR(t, "example. 300 IN A 192.0.2.2"),
		mustRR(t, "example. 300 IN AAAA 2001:db8::1"),
	}
	s := NewSet("example.", TypeA, rrs)
	if want := []string{"192.0.2.1", "192.0.2.2"}; !slices.Equal(s.Data, want) {
		t.Errorf("Data = %v, want %v", s.Data, want)
	}
	if s.TTL != 120 {
		t.Errorf("TTL = %d, want the smallest TTL 120", s.TTL)
	}
	if got := NewSet("example.", TypeMX, rrs); !got.Empty() {
		t.Errorf("expected empty MX set, got %v", got.Data)
	}
	reversed := slices.Clone(rrs)
	slices.Reverse(reversed)
	if !s.SameData(NewSet("example.", TypeA, reversed)) {
		t.Error("order of answers must not matter")
	}
}

func setOf(t Type, data ...string) Set { return Set{Type: t, Data: data} }

func TestTargetsAndAddrs(t *testing.T) {
	mx := setOf(TypeMX, "10 mail.example.", "20 backup.example.")
	if got := mx.Targets(); !slices.Equal(got, []Name{"mail.example.", "backup.example."}) {
		t.Errorf("MX targets = %v", got)
	}
	srv := setOf(TypeSRV, "0 0 443 autodiscover.example.")
	if got := srv.Targets(); !slices.Equal(got, []Name{"autodiscover.example."}) {
		t.Errorf("SRV targets = %v", got)
	}
	if got := setOf(TypeTXT, `"x"`).Targets(); got != nil {
		t.Errorf("TXT has no targets, got %v", got)
	}
	a := setOf(TypeA, "192.0.2.1", "198.51.100.7")
	if got := a.Addrs(); len(got) != 2 || got[1].String() != "198.51.100.7" {
		t.Errorf("Addrs = %v", got)
	}
}
