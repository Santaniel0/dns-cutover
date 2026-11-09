package delegation

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Santaniel0/dns-cutover/internal/dnsq"
	"github.com/Santaniel0/dns-cutover/internal/dnstest"
	"github.com/Santaniel0/dns-cutover/internal/finding"
	"github.com/Santaniel0/dns-cutover/internal/rr"
)

const zone = rr.Name("example.test.")

const (
	oldKey = "example.test. 3600 IN DNSKEY 257 3 13 D2ZxOKMcDgHyhrFXNuJbcFHQ5toN/LCirb1vX+JsgDdkNx/3ql8PavGYLS12nETwzApueZi5JY1NNexL2xFpbA=="
	oldDS  = "29212 13 2 DF74CEA5E9F8F95056E8245A1FD23D7728BE6997C5E6C19E3F18659EA1CBE384"
	newKey = "example.test. 3600 IN DNSKEY 257 3 13 RH/Wk3/Dhcob8bRIhJ9VbfnkQuhImZKXAxHtFRgzljq4BbkL0kv2tTEcA82Mos7H7h6QqRan0JgRiVItfk+OCg=="
	newDS  = "9736 13 2 7F4509B659BD78541B951D0AAC430AC3058900C1B7F9B301755320119EFCA15D"
)

func parentZone(ds string) string {
	z := `
$ORIGIN test.
@ 3600 IN SOA a.nic.test. hostmaster.nic.test. 1 7200 3600 1209600 3600
@ 3600 IN NS a.nic.test.
example 172800 IN NS ns1.olddns.test.
example 172800 IN NS ns2.olddns.test.
`
	if ds != "" {
		z += "example 86400 IN DS " + ds + "\n"
	}
	return z
}

func childZone(serial string, ns []string, extra ...string) string {
	z := "$ORIGIN example.test.\n@ 300 IN SOA ns.new.test. hostmaster " + serial + " 7200 3600 1209600 600\n"
	for _, n := range ns {
		z += "@ 300 IN NS " + n + "\n"
	}
	return z + strings.Join(extra, "\n") + "\n"
}

func start(t *testing.T, origin, text string, hook dnstest.Hook) netip.AddrPort {
	t.Helper()
	s, err := dnstest.Start(dnstest.Options{Zones: []*dnstest.Zone{dnstest.MustParseZone(origin, text)}, Hook: hook})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s.Addr()
}

func client() *dnsq.Client { return dnsq.NewClient(dnsq.Options{Timeout: 5 * time.Second}) }

func TestReadParent(t *testing.T) {
	addr := start(t, "test.", parentZone(oldDS), nil)
	p, err := ReadParent(context.Background(), client(), zone, []dnsq.Server{{Addr: addr}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.NS, []rr.Name{"ns1.olddns.test.", "ns2.olddns.test."}) || p.NSTTL != 172800 {
		t.Errorf("NS = %v ttl %d", p.NS, p.NSTTL)
	}
	if len(p.DS) != 1 || p.DS[0].String() != oldDS || p.DSTTL != 86400 {
		t.Errorf("DS = %v ttl %d", p.DS, p.DSTTL)
	}

	_, err = ReadParent(context.Background(), client(), "missing.test.", []dnsq.Server{{Addr: addr}})
	if !errors.Is(err, ErrNotDelegated) {
		t.Errorf("err = %v, want ErrNotDelegated", err)
	}
}

func TestReadParentFallsBackToNextServer(t *testing.T) {
	refuse := func(context.Context, string, dns.Question) dnstest.Action { return dnstest.Refuse }
	bad := start(t, "test.", parentZone(""), refuse)
	good := start(t, "test.", parentZone(""), nil)
	p, err := ReadParent(context.Background(), client(), zone, []dnsq.Server{{Addr: bad}, {Addr: good}})
	if err != nil || p.Server.Addr != good || len(p.DS) != 0 {
		t.Fatalf("p = %+v, err = %v", p, err)
	}
}

type result struct {
	kind     finding.Kind
	severity finding.Severity
}

func has(fs []finding.Finding, kind finding.Kind, sev finding.Severity) (finding.Finding, bool) {
	for _, f := range fs {
		if f.Kind == kind && f.Severity == sev {
			return f, true
		}
	}
	return finding.Finding{}, false
}

func TestCheck(t *testing.T) {
	newNS := []string{"ns1.newdns.test.", "ns2.newdns.test."}
	refuse := func(context.Context, string, dns.Question) dnstest.Action { return dnstest.Refuse }
	oldServers := []dnsq.Server{{Host: "ns1.olddns.test.", Addr: netip.MustParseAddrPort("127.0.0.1:1")}}

	tests := []struct {
		name     string
		parentDS string
		zones    []string // one zone text per new server
		hooks    []dnstest.Hook
		want     []result
		absent   []finding.Kind
		check    func(t *testing.T, fs []finding.Finding)
	}{
		{
			name:     "stale DS and unsigned new zone",
			parentDS: oldDS,
			zones:    []string{childZone("9", newNS), childZone("9", newNS)},
			want:     []result{{finding.DNSSEC, finding.Blocker}},
			absent:   []finding.Kind{finding.ApexNS, finding.SerialMismatch, finding.NotServing},
			check: func(t *testing.T, fs []finding.Finding) {
				f, _ := has(fs, finding.DNSSEC, finding.Blocker)
				if !strings.Contains(f.Detail, "unsigned") || !strings.Contains(f.Detail, "1d (86400s)") {
					t.Errorf("detail = %q", f.Detail)
				}
			},
		},
		{
			name:     "DS for the old key, new zone signed with another key",
			parentDS: oldDS,
			zones:    []string{childZone("9", newNS, newKey), childZone("9", newNS, newKey)},
			want:     []result{{finding.DNSSEC, finding.Blocker}},
			check: func(t *testing.T, fs []finding.Finding) {
				f, _ := has(fs, finding.DNSSEC, finding.Blocker)
				if !slices.Equal(f.New, []string{newDS}) || !slices.Equal(f.Old, []string{oldDS}) {
					t.Errorf("old=%v new=%v; the finding should show the DS to publish", f.Old, f.New)
				}
			},
		},
		{
			name:     "DS matches a new key",
			parentDS: newDS,
			zones:    []string{childZone("9", newNS, newKey), childZone("9", newNS, newKey)},
			want:     []result{{finding.DNSSEC, finding.Info}},
		},
		{
			name:  "signed new zone without DS",
			zones: []string{childZone("9", newNS, newKey), childZone("9", newNS, newKey)},
			want:  []result{{finding.DNSSEC, finding.Info}},
		},
		{
			name:  "old nameservers imported at the apex",
			zones: []string{childZone("9", []string{"ns1.olddns.test.", "ns2.olddns.test."}), childZone("9", []string{"ns1.olddns.test.", "ns2.olddns.test."})},
			want:  []result{{finding.ApexNS, finding.Blocker}, {finding.ApexNS, finding.Warning}},
		},
		{
			name:  "one new server refuses the zone",
			zones: []string{childZone("9", newNS), childZone("9", newNS)},
			hooks: []dnstest.Hook{nil, refuse},
			want:  []result{{finding.NotServing, finding.Blocker}},
			check: func(t *testing.T, fs []finding.Finding) {
				f, _ := has(fs, finding.NotServing, finding.Blocker)
				if !slices.Equal(f.Servers, []string{"ns2.newdns.test."}) || !strings.Contains(f.Detail, "REFUSED") {
					t.Errorf("finding = %+v", f)
				}
			},
		},
		{
			name:  "lagging serial",
			zones: []string{childZone("9", newNS), childZone("7", newNS)},
			want:  []result{{finding.SerialMismatch, finding.Warning}},
		},
		{
			name:  "timing facts",
			zones: []string{childZone("9", newNS), childZone("9", newNS)},
			want:  []result{{finding.Timing, finding.Info}},
			check: func(t *testing.T, fs []finding.Finding) {
				var details []string
				for _, f := range fs {
					if f.Kind == finding.Timing {
						details = append(details, f.Detail)
					}
				}
				joined := strings.Join(details, "\n")
				for _, w := range []string{"2d (172800s)", "5m (300s)", "1d (86400s)"} {
					if !strings.Contains(joined, w) {
						t.Errorf("timing findings lack %q:\n%s", w, joined)
					}
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent, err := ReadParent(context.Background(), client(), zone, []dnsq.Server{{Addr: start(t, "test.", parentZone(tt.parentDS), nil)}})
			if err != nil {
				t.Fatal(err)
			}
			var servers []dnsq.Server
			for i, z := range tt.zones {
				var hook dnstest.Hook
				if i < len(tt.hooks) {
					hook = tt.hooks[i]
				}
				servers = append(servers, dnsq.Server{Host: rr.Name(newNS[i]), Addr: start(t, string(zone), z, hook)})
			}
			fs, err := Check(context.Background(), client(), Input{
				Zone: zone, Old: oldServers, New: servers, Parent: &parent,
				MaxTTL: 86400, MaxTTLName: "www.example.test.", MaxTTLType: rr.TypeCNAME,
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range tt.want {
				if _, ok := has(fs, w.kind, w.severity); !ok {
					t.Errorf("missing %s/%s in %+v", w.kind, w.severity, fs)
				}
			}
			for _, k := range tt.absent {
				for _, f := range fs {
					if f.Kind == k {
						t.Errorf("unexpected %s: %+v", k, f)
					}
				}
			}
			if tt.check != nil {
				tt.check(t, fs)
			}
		})
	}
}

func TestCheckGlue(t *testing.T) {
	text := childZone("1", []string{"ns1.example.test.", "ns2.example.test."}, "ns1 300 IN A 192.0.2.53")
	addr := start(t, string(zone), text, nil)
	servers := []dnsq.Server{{Host: "ns1.example.test.", Addr: addr}, {Host: "ns2.example.test.", Addr: addr}}
	fs, err := Check(context.Background(), client(), Input{Zone: zone, New: servers})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range fs {
		if f.Kind == finding.Glue {
			got = append(got, f.Severity.String()+" "+string(f.Name))
		}
	}
	want := []string{"blocker ns2.example.test.", "warning ns1.example.test."}
	if !slices.Equal(got, want) {
		t.Errorf("glue findings = %v, want %v", got, want)
	}
}

func TestCheckCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	addr := start(t, string(zone), childZone("1", nil), nil)
	_, err := Check(ctx, client(), Input{Zone: zone, New: []dnsq.Server{{Addr: addr}}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

type fakeLocator struct {
	ns    map[string][]*net.NS
	hosts map[string][]netip.Addr
}

func (f fakeLocator) LookupNS(_ context.Context, name string) ([]*net.NS, error) {
	if v, ok := f.ns[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f fakeLocator) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if v, ok := f.hosts[host]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestFindParentServers(t *testing.T) {
	loc := fakeLocator{
		ns:    map[string][]*net.NS{"co.uk.": {{Host: "dns1.nic.uk."}, {Host: "broken.nic.uk."}}},
		hosts: map[string][]netip.Addr{"dns1.nic.uk": {netip.MustParseAddr("213.248.216.1")}},
	}
	servers, parent, err := FindParentServers(context.Background(), loc, "shop.example.co.uk.")
	if err != nil {
		t.Fatal(err)
	}
	if parent != "co.uk." || len(servers) != 1 || servers[0].Addr.String() != "213.248.216.1:53" {
		t.Errorf("parent=%s servers=%v", parent, servers)
	}
	if _, _, err := FindParentServers(context.Background(), fakeLocator{}, "example.test."); !errors.Is(err, ErrNoParent) {
		t.Errorf("err = %v, want ErrNoParent", err)
	}
}

func TestHuman(t *testing.T) {
	for in, want := range map[uint32]string{0: "0s", 45: "45s", 300: "5m (300s)", 7200: "2h (7200s)", 172800: "2d (172800s)", 3601: "3601s"} {
		if got := human(in); got != want {
			t.Errorf("human(%d) = %q, want %q", in, got, want)
		}
	}
}
