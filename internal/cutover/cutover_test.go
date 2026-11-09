package cutover

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Santaniel0/dns-cutover/internal/dnsq"
	"github.com/Santaniel0/dns-cutover/internal/dnstest"
	"github.com/Santaniel0/dns-cutover/internal/finding"
	"github.com/Santaniel0/dns-cutover/internal/inventory"
	"github.com/Santaniel0/dns-cutover/internal/lab"
	"github.com/Santaniel0/dns-cutover/internal/proxyrange"
	"github.com/Santaniel0/dns-cutover/internal/rr"
)

const labDir = "../../testdata/lab"

// noNetwork fails every lookup, so a test notices if the check tries to use
// the system resolver.
type noNetwork struct{}

var errNoNetwork = errors.New("lookups are disabled in tests")

func (noNetwork) LookupNS(context.Context, string) ([]*net.NS, error) { return nil, errNoNetwork }
func (noNetwork) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, errNoNetwork
}

func fixedClock() func() time.Time {
	t := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

func testDeps() Deps {
	return Deps{
		Querier:     dnsq.NewClient(dnsq.Options{Timeout: 5 * time.Second}),
		Locator:     noNetwork{},
		Now:         fixedClock(),
		CanaryLabel: func() string { return "canary" },
	}
}

func spec(s lab.Server) dnsq.Spec {
	ap := s.Addr()
	return dnsq.Spec{Host: rr.Name(s.Host), Addr: ap.Addr(), Port: ap.Port()}
}

func labConfig(t *testing.T, sc lab.Scenario) Config {
	t.Helper()
	l, err := lab.Start(labDir, sc, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	open := func(name string) *os.File {
		f, err := os.Open(filepath.Join(labDir, name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	cfg := Config{
		Zone:         lab.Zone,
		Parent:       []dnsq.Spec{spec(l.Parent)},
		Old:          []dnsq.Spec{spec(l.Old)},
		ZoneFile:     open("export.zone"),
		ZoneFileName: "export.zone",
		Names:        open("names.txt"),
		Probe:        true,
		Wordlist:     inventory.DefaultWordlist(),
		Concurrency:  8,
		Proxy:        proxyrange.Cloudflare(),
	}
	for _, s := range l.New {
		cfg.New = append(cfg.New, spec(s))
	}
	return cfg
}

func summary(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		line := f.Severity.String() + " " + f.Kind.String() + " " + string(f.Name)
		if f.Type != 0 {
			line += " " + f.Type.String()
		}
		if len(f.Servers) > 0 {
			line += " on " + strings.Join(f.Servers, ",")
		}
		out = append(out, line)
	}
	return out
}

func TestRunBrokenLab(t *testing.T) {
	res, err := Run(context.Background(), testDeps(), labConfig(t, lab.Broken))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"blocker MISSING _autodiscover._tcp.example.test. SRV",
		"blocker MISSING _dmarc.example.test. TXT on ns2.newdns.test.",
		"blocker MISSING mail._domainkey.example.test. TXT",
		"blocker DIFFERENT api.example.test. A",
		"blocker PROXIED-TARGET mail.example.test. A",
		"blocker APEX-NS example.test. NS",
		"blocker DNSSEC example.test. DS",
		"warning EXTRA staging.example.test. A",
		"warning TTL example.test. A",
		"warning SERIAL example.test. SOA",
		"info PROXIED www.example.test. CNAME",
		"info TIMING example.test. A",
		"info TIMING example.test. NS",
		"info TIMING example.test. SOA",
	}
	if got := summary(res.Findings); !slices.Equal(got, want) {
		t.Fatalf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if res.Verdict != NotReady || res.OldSource != OldFromFlag || res.Parent == nil {
		t.Errorf("verdict=%s old source=%s parent=%v", res.Verdict, res.OldSource, res.Parent)
	}
	// mail._domainkey is not in the export: only the probe can find it.
	if res.Inventory.Count(inventory.FromProbe) == 0 || res.Inventory.Count(inventory.FromNamesFile) != 1 {
		t.Errorf("inventory sources: probe=%d names=%d", res.Inventory.Count(inventory.FromProbe), res.Inventory.Count(inventory.FromNamesFile))
	}
	if res.Elapsed != 0 || res.Queries == 0 {
		t.Errorf("elapsed=%s queries=%d (clock is fixed, so elapsed must be 0)", res.Elapsed, res.Queries)
	}
}

func TestRunFixedLab(t *testing.T) {
	res, err := Run(context.Background(), testDeps(), labConfig(t, lab.Fixed))
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != Ready || res.Count(finding.Blocker) != 0 {
		t.Fatalf("verdict = %s, findings:\n%s", res.Verdict, strings.Join(summary(res.Findings), "\n"))
	}
}

func TestRunPolicies(t *testing.T) {
	cfg := labConfig(t, lab.Broken)
	cfg.TTL = TTLIgnore
	cfg.Ignore = []IgnoreRule{{Name: "api.example.test.", Type: rr.TypeA}, {Name: "staging.example.test."}}
	res, err := Run(context.Background(), testDeps(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.Kind == finding.TTLOnly {
			t.Errorf("TTL findings should be dropped with TTLIgnore: %+v", f)
		}
	}
	if res.Ignored() != 2 || res.Count(finding.Blocker) != 6 {
		t.Errorf("ignored=%d blockers=%d", res.Ignored(), res.Count(finding.Blocker))
	}
}

func TestRunParentUnreadable(t *testing.T) {
	cfg := labConfig(t, lab.Fixed)
	refuse := func(context.Context, string, dns.Question) dnstest.Action { return dnstest.Refuse }
	bad, err := dnstest.Start(dnstest.Options{Hook: refuse})
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	cfg.Parent = []dnsq.Spec{{Addr: bad.Addr().Addr(), Port: bad.Addr().Port()}}

	res, err := Run(context.Background(), testDeps(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	f := res.Findings[slices.IndexFunc(res.Findings, func(f finding.Finding) bool { return f.Kind == finding.Delegation })]
	if f.Severity != finding.Warning || !strings.Contains(f.Detail, "REFUSED") {
		t.Errorf("delegation finding = %+v", f)
	}
	if res.Parent != nil || res.Verdict != Ready {
		t.Errorf("parent=%v verdict=%s", res.Parent, res.Verdict)
	}

	cfg.Old = nil
	if _, err := Run(context.Background(), testDeps(), cfg); !errors.Is(err, ErrNoOldServers) {
		t.Errorf("without --old and without a parent: err = %v, want ErrNoOldServers", err)
	}
}

func TestRunWithoutZoneFileWarns(t *testing.T) {
	cfg := labConfig(t, lab.Fixed)
	cfg.ZoneFile = nil
	res, err := Run(context.Background(), testDeps(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(res.Findings, func(f finding.Finding) bool {
		return f.Kind == finding.Inventory && f.Severity == finding.Warning && strings.Contains(f.Detail, "no zone file")
	}) {
		t.Errorf("expected a probe-only inventory warning:\n%s", strings.Join(summary(res.Findings), "\n"))
	}
}

func TestRunCancel(t *testing.T) {
	entered := make(chan struct{}, 1)
	hold := func(ctx context.Context, _ string, _ dns.Question) dnstest.Action {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return dnstest.Drop
	}
	srv, err := dnstest.Start(dnstest.Options{Hook: hold})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ap := srv.Addr()
	pinned := dnsq.Spec{Host: "ns.test.", Addr: ap.Addr(), Port: ap.Port()}
	cfg := Config{Zone: "example.test.", Old: []dnsq.Spec{pinned}, New: []dnsq.Spec{pinned}, Parent: []dnsq.Spec{pinned}, Concurrency: 4}

	deps := testDeps()
	deps.Querier = dnsq.NewClient(dnsq.Options{Timeout: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Run(ctx, deps, cfg)
		done <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestParseIgnore(t *testing.T) {
	zone := rr.Name("example.test.")
	tests := []struct {
		in   string
		want IgnoreRule
		err  bool
	}{
		{in: "www A", want: IgnoreRule{Name: "www.example.test.", Type: rr.TypeA}},
		{in: "@ mx", want: IgnoreRule{Name: zone, Type: rr.TypeMX}},
		{in: "staging", want: IgnoreRule{Name: "staging.example.test."}},
		{in: "", err: true},
		{in: "www A extra", err: true},
		{in: "www NOPE", err: true},
	}
	for _, tt := range tests {
		got, err := ParseIgnore(tt.in, zone)
		if tt.err {
			if !errors.Is(err, ErrBadIgnore) {
				t.Errorf("ParseIgnore(%q) err = %v", tt.in, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("ParseIgnore(%q) = %+v, %v", tt.in, got, err)
		}
	}
}

func TestParseTTLPolicy(t *testing.T) {
	for in, want := range map[string]TTLPolicy{"warn": TTLWarn, "IGNORE": TTLIgnore, "fail": TTLFail} {
		if got, err := ParseTTLPolicy(in); err != nil || got != want {
			t.Errorf("ParseTTLPolicy(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseTTLPolicy("sometimes"); !errors.Is(err, ErrBadPolicy) {
		t.Errorf("err = %v", err)
	}
}

func TestApplyPolicies(t *testing.T) {
	ttl := finding.Finding{Kind: finding.TTLOnly, Severity: finding.Warning, Name: "a.example.test.", Type: rr.TypeA}
	missing := finding.Finding{Kind: finding.Missing, Severity: finding.Blocker, Name: "b.example.test.", Type: rr.TypeTXT}

	got := applyPolicies([]finding.Finding{ttl, missing}, Config{TTL: TTLFail})
	if got[0].Severity != finding.Blocker || got[1].Severity != finding.Blocker {
		t.Errorf("TTLFail should make TTL findings blockers: %+v", got)
	}
	got = applyPolicies([]finding.Finding{ttl, missing}, Config{Ignore: []IgnoreRule{{Name: "b.example.test.", Type: rr.TypeA}}})
	if len(got) != 2 || got[0].Ignored || got[1].Ignored {
		t.Errorf("a rule for another type must not match: %+v", got)
	}
	got = applyPolicies([]finding.Finding{ttl, missing}, Config{Ignore: []IgnoreRule{{Name: "b.example.test."}}})
	if !got[0].Ignored || got[0].Kind != finding.Missing {
		t.Errorf("a rule without type matches every type: %+v", got)
	}
}
