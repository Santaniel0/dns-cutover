package compare

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Santaniel0/dns-cutover/internal/dnsq"
	"github.com/Santaniel0/dns-cutover/internal/dnstest"
	"github.com/Santaniel0/dns-cutover/internal/inventory"
	"github.com/Santaniel0/dns-cutover/internal/proxyrange"
	"github.com/Santaniel0/dns-cutover/internal/rr"
)

const oldZone = `
$ORIGIN example.test.
@     3600 IN SOA ns1.old.test. hostmaster 1 7200 3600 1209600 300
@     3600 IN NS ns1.old.test.
@     3600 IN A 192.0.2.10
@     3600 IN MX 10 mail
mail  3600 IN A 192.0.2.25
selector1._domainkey 3600 IN TXT "v=DKIM1; k=rsa; " "p=MIIBIjANBgkq"
_autodiscover._tcp 3600 IN SRV 0 0 443 autodiscover.mailhost.test.
sub   3600 IN NS ns1.elsewhere.test.
`

const newZone = `
$ORIGIN example.test.
@     300 IN SOA ada.ns.new.test. hostmaster 9 7200 3600 1209600 300
@     300 IN NS ada.ns.new.test.
@     3600 IN A 192.0.2.10
@     3600 IN MX 10 mail
mail  3600 IN A 104.16.1.1
selector1._domainkey 3600 IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkq"
sub   3600 IN NS ns1.elsewhere.test.
`

func startServer(t *testing.T, text string, hook dnstest.Hook) *dnstest.Server {
	t.Helper()
	s, err := dnstest.Start(dnstest.Options{Zones: []*dnstest.Zone{dnstest.MustParseZone("example.test.", text)}, Hook: hook})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func testInventory(t *testing.T) inventory.Inventory {
	t.Helper()
	c := inventory.NewCollector(apex)
	for _, n := range []rr.Name{mail, "selector1._domainkey.example.test.", "_autodiscover._tcp.example.test.", "sub.example.test."} {
		if err := c.Add(n, inventory.FromNamesFile); err != nil {
			t.Fatal(err)
		}
	}
	return c.Inventory(inventory.ProbeStats{})
}

func TestRunAgainstServers(t *testing.T) {
	oldSrv, newSrv := startServer(t, oldZone, nil), startServer(t, newZone, nil)
	cfg := Config{
		Zone:        apex,
		Old:         []dnsq.Server{{Host: "ns1.old.test.", Addr: oldSrv.Addr()}},
		New:         []dnsq.Server{{Host: "ada.ns.new.test.", Addr: newSrv.Addr()}},
		Concurrency: 8,
		Proxy:       proxyrange.Cloudflare(),
	}
	res, err := Run(context.Background(), dnsq.NewClient(dnsq.Options{Timeout: 5 * time.Second}), testInventory(t), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range res.Findings {
		got = append(got, f.Kind.String()+" "+string(f.Name)+" "+f.Type.String())
	}
	// The DKIM key is split differently on each side and must not show up;
	// neither must the delegation of sub, which both sides serve the same.
	want := []string{
		"MISSING _autodiscover._tcp.example.test. SRV",
		"PROXIED-TARGET mail.example.test. A",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("findings:\n got  %q\n want %q", got, want)
	}
	if res.Stats.RRsets != 6 || res.Stats.Matched != 4 {
		t.Errorf("stats = %+v", res.Stats)
	}
}

func TestQuestions(t *testing.T) {
	c := inventory.NewCollector(apex)
	_ = c.Add("_sip._tls.example.test.", inventory.FromProbe)
	_ = c.Add(apex, inventory.FromZoneFile, rr.TypeNS, rr.Type(dns.TypeTLSA))
	qs := Questions(c.Inventory(inventory.ProbeStats{}))
	var apexTypes, sipTypes []rr.Type
	for _, q := range qs {
		switch q.Name {
		case apex:
			apexTypes = append(apexTypes, q.Type)
		case "_sip._tls.example.test.":
			sipTypes = append(sipTypes, q.Type)
		}
	}
	if slices.Contains(apexTypes, rr.TypeNS) || !slices.Contains(apexTypes, rr.Type(dns.TypeTLSA)) {
		t.Errorf("apex types = %v: apex NS belongs to the delegation check, zone-file types are added", apexTypes)
	}
	if !slices.Contains(sipTypes, rr.TypeSRV) || !slices.Contains(sipTypes, rr.TypeNS) {
		t.Errorf("underscore name types = %v", sipTypes)
	}
}

// TestRunCancelStopsInFlightWork holds every query at the server until the
// test cancels, then checks that Run returns, that no more than Concurrency
// queries were ever in flight, and that nothing was sent after cancel.
func TestRunCancelStopsInFlightWork(t *testing.T) {
	const concurrency = 3
	var inFlight, peak atomic.Int32
	full := make(chan struct{})
	var fullOnce sync.Once
	hook := func(ctx context.Context, _ string, _ dns.Question) dnstest.Action {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		if n == concurrency {
			fullOnce.Do(func() { close(full) })
		}
		<-ctx.Done() // released when the server closes
		return dnstest.Drop
	}
	srv := startServer(t, oldZone, hook)

	cfg := Config{
		Zone:        apex,
		Old:         []dnsq.Server{{Host: "ns1.old.test.", Addr: srv.Addr()}},
		New:         []dnsq.Server{{Host: "ada.ns.new.test.", Addr: srv.Addr()}},
		Concurrency: concurrency,
	}
	// Attempts never time out on their own; only cancellation can end them.
	client := dnsq.NewClient(dnsq.Options{Timeout: time.Hour, Retries: 2})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Run(ctx, client, testInventory(t), cfg)
		done <- err
	}()

	<-full
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if p := peak.Load(); p != concurrency {
		t.Errorf("peak in-flight = %d, want %d", p, concurrency)
	}
	if n := srv.Queries(); n != concurrency {
		t.Errorf("server saw %d queries, want exactly the %d in flight at cancel", n, concurrency)
	}
}

func TestInterpret(t *testing.T) {
	q := dnsq.Question{Name: "sub.example.test.", Type: rr.TypeNS}
	ns, _ := dns.NewRR("sub.example.test. 300 IN NS ns1.elsewhere.test.")
	referral := dnsq.Response{Rcode: dnsq.RcodeSuccess, Authority: []dns.RR{ns}}
	if a := interpret(q, referral, nil); a.status != statusOK || !slices.Equal(a.set.Data, []string{"ns1.elsewhere.test."}) {
		t.Errorf("referral NS = %+v", a)
	}
	if a := interpret(dnsq.Question{Name: "x.sub.example.test.", Type: rr.TypeA}, referral, nil); a.status != statusOK || !a.set.Empty() {
		t.Errorf("name below a cut = %+v", a)
	}
	if a := interpret(q, dnsq.Response{Rcode: dnsq.RcodeSuccess}, nil); a.status != statusNotAuth {
		t.Errorf("non-AA answer = %+v", a)
	}
	if a := interpret(q, dnsq.Response{Rcode: dnsq.RcodeServFail}, nil); a.status != statusRcode || a.problem() != "SERVFAIL" {
		t.Errorf("servfail = %+v", a)
	}
}
