package inventory

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Santaniel0/dns-cutover/internal/dnsq"
	"github.com/Santaniel0/dns-cutover/internal/dnstest"
	"github.com/Santaniel0/dns-cutover/internal/rr"
)

const zone = rr.Name("example.test.")

func names(inv Inventory) []string {
	out := make([]string, 0, len(inv.Entries))
	for _, e := range inv.Entries {
		out = append(out, string(e.Name))
	}
	return out
}

func entry(inv Inventory, name rr.Name) (Entry, bool) {
	for _, e := range inv.Entries {
		if e.Name == name {
			return e, true
		}
	}
	return Entry{}, false
}

func TestReadZoneFile(t *testing.T) {
	const text = `
$ORIGIN example.test.
$TTL 3600
@        IN SOA ns1.olddns.test. hostmaster 1 7200 3600 1209600 300
@        IN NS  ns1.olddns.test.
@        IN MX  10 mail
@        IN DNSKEY 257 3 13 RH/Wk3/Dhcob8bRIhJ9VbfnkQuhImZKXAxHtFRgzljq4BbkL0kv2tTEcA82Mos7H7h6QqRan0JgRiVItfk+OCg==
mail     IN A   192.0.2.25
WWW      IN CNAME @
_25._tcp.mail IN TLSA 3 1 1 0123456789abcdef
sub      IN NS  ns1.elsewhere.test.
glue.other.test. IN A 192.0.2.1
`
	c := NewCollector(zone)
	if err := ReadZoneFile(strings.NewReader(text), "export.zone", c); err != nil {
		t.Fatal(err)
	}
	inv := c.Inventory(ProbeStats{})
	if inv.Skipped != 1 {
		t.Errorf("skipped = %d, want 1 out-of-zone record", inv.Skipped)
	}
	want := []string{"example.test.", "mail.example.test.", "_25._tcp.mail.example.test.", "sub.example.test.", "www.example.test."}
	if got := names(inv); !slices.Equal(got, want) {
		t.Fatalf("names = %v\nwant    %v", got, want)
	}
	apex, _ := entry(inv, zone)
	if !slices.Equal(apex.Types, []rr.Type{rr.TypeMX}) {
		t.Errorf("apex types = %v; SOA, apex NS and DNSKEY are left to the delegation checks", apex.Types)
	}
	if !slices.Equal(apex.Sources, []Source{FromApex, FromZoneFile}) {
		t.Errorf("apex sources = %v", apex.Sources)
	}
	tlsa, _ := entry(inv, "_25._tcp.mail.example.test.")
	if !slices.Equal(tlsa.Types, []rr.Type{rr.Type(dns.TypeTLSA)}) {
		t.Errorf("TLSA types = %v", tlsa.Types)
	}
	sub, _ := entry(inv, "sub.example.test.")
	if !slices.Equal(sub.Types, []rr.Type{rr.TypeNS}) {
		t.Errorf("a delegation's NS must be compared: %v", sub.Types)
	}
}

func TestReadZoneFileSyntaxError(t *testing.T) {
	c := NewCollector(zone)
	err := ReadZoneFile(strings.NewReader("www IN A not-an-ip\n"), "bad.zone", c)
	if err == nil || !strings.Contains(err.Error(), "bad.zone") {
		t.Fatalf("err = %v, want a parse error naming the file", err)
	}
}

func TestReadNames(t *testing.T) {
	c := NewCollector(zone)
	input := "# internal names\nvpn\n@\nintranet.example.test.\n  wiki   # trailing comment\n\n"
	if err := ReadNames(strings.NewReader(input), c); err != nil {
		t.Fatal(err)
	}
	got := names(c.Inventory(ProbeStats{}))
	want := []string{"example.test.", "intranet.example.test.", "vpn.example.test.", "wiki.example.test."}
	if !slices.Equal(got, want) {
		t.Errorf("names = %v, want %v", got, want)
	}

	err := ReadNames(strings.NewReader("ok\nwww.example.org.\n"), NewCollector(zone))
	if !errors.Is(err, ErrOutsideZone) || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("err = %v, want ErrOutsideZone on line 2", err)
	}
}

func TestDefaultWordlist(t *testing.T) {
	labels := DefaultWordlist()
	if len(labels) < 100 {
		t.Fatalf("wordlist has %d labels", len(labels))
	}
	seen := make(map[string]bool)
	for _, l := range labels {
		if seen[l] {
			t.Errorf("duplicate label %q", l)
		}
		seen[l] = true
		if _, err := zone.Child(l); err != nil {
			t.Errorf("label %q does not form a valid name: %v", l, err)
		}
	}
}

func startZone(t *testing.T, text string, hook dnstest.Hook) dnsq.Server {
	t.Helper()
	s, err := dnstest.Start(dnstest.Options{Zones: []*dnstest.Zone{dnstest.MustParseZone(string(zone), text)}, Hook: hook})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return dnsq.Server{Addr: s.Addr()}
}

const liveZone = `
$ORIGIN example.test.
@     300 IN SOA ns1 hostmaster 1 7200 3600 1209600 300
@     300 IN A 192.0.2.10
www   300 IN A 192.0.2.10
mail._domainkey 300 IN TXT "v=DKIM1; p=abc"
`

func TestProbeFindsLiveNames(t *testing.T) {
	srv := startZone(t, liveZone, nil)
	c := NewCollector(zone)
	_ = c.Add("www.example.test.", FromZoneFile)
	p := Prober{Querier: dnsq.NewClient(dnsq.Options{Timeout: 5 * time.Second}), Servers: []dnsq.Server{srv}, Concurrency: 4}
	stats, err := p.Run(context.Background(), []string{"www", "mail._domainkey", "ftp", "_domainkey", "bad..label"}, c)
	if err != nil {
		t.Fatal(err)
	}
	// www was already known; the empty non-terminal _domainkey answers
	// NOERROR and is kept, which costs a few queries but loses nothing.
	if stats.Candidates != 3 || stats.Found != 2 || stats.Failed != 0 || len(stats.Wildcard) != 0 {
		t.Errorf("stats = %+v", stats)
	}
	e, ok := entry(c.Inventory(stats), "mail._domainkey.example.test.")
	if !ok || !slices.Equal(e.Sources, []Source{FromProbe}) {
		t.Errorf("mail._domainkey entry = %+v, %v", e, ok)
	}
}

func TestProbeIgnoresWildcardEchoes(t *testing.T) {
	srv := startZone(t, liveZone+"* 300 IN A 192.0.2.99\nshop 300 IN CNAME shops.saas.test.\n", nil)
	c := NewCollector(zone)
	p := Prober{
		Querier:     dnsq.NewClient(dnsq.Options{Timeout: 5 * time.Second}),
		Servers:     []dnsq.Server{srv},
		Concurrency: 2,
		CanaryLabel: func() string { return "canary-fixed" },
	}
	stats, err := p.Run(context.Background(), []string{"ftp", "blog", "www", "shop"}, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Wildcard) != 1 {
		t.Fatalf("wildcard not detected: %+v", stats)
	}
	got := names(c.Inventory(stats))
	// ftp and blog only echo the wildcard. shop is a CNAME and www has its
	// own address, so both are real names.
	want := []string{"example.test.", "shop.example.test.", "www.example.test."}
	if !slices.Equal(got, want) {
		t.Errorf("names = %v, want %v", got, want)
	}
}

func TestProbeSkipsRefusingServer(t *testing.T) {
	refuse := func(context.Context, string, dns.Question) dnstest.Action { return dnstest.Refuse }
	bad := startZone(t, liveZone, refuse)
	good := startZone(t, liveZone, nil)
	c := NewCollector(zone)
	p := Prober{Querier: dnsq.NewClient(dnsq.Options{Timeout: 5 * time.Second}), Servers: []dnsq.Server{bad, good}, Concurrency: 2}
	stats, err := p.Run(context.Background(), []string{"www"}, c)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Found != 1 || stats.Failed != 1 || len(stats.Errors) != 1 || !strings.Contains(stats.Errors[0], "REFUSED") {
		t.Errorf("stats = %+v", stats)
	}
}
