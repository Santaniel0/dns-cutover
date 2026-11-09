package compare

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Santaniel0/dns-cutover/internal/dnsq"
	"github.com/Santaniel0/dns-cutover/internal/finding"
	"github.com/Santaniel0/dns-cutover/internal/proxyrange"
	"github.com/Santaniel0/dns-cutover/internal/rr"
)

const (
	apex = rr.Name("example.test.")
	mail = rr.Name("mail.example.test.")
	www  = rr.Name("www.example.test.")
)

func server(host string, port uint16) dnsq.Server {
	return dnsq.Server{Host: rr.Name(host), Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
}

var testCfg = Config{
	Zone:  apex,
	Old:   []dnsq.Server{server("ns1.old.test.", 5301)},
	New:   []dnsq.Server{server("a.new.test.", 5302), server("b.new.test.", 5303)},
	Proxy: proxyrange.Set{netip.MustParsePrefix("104.16.0.0/13")},
}

func ok(ttl uint32, data ...string) answer {
	return answer{status: statusOK, set: rr.Set{TTL: ttl, Data: data}}
}

func refused() answer { return answer{status: statusRcode, rcode: dnsq.RcodeRefused} }

// obs builds an observation with one old answer and the given new answers.
// A single new answer is used for both new servers.
func obs(name rr.Name, t rr.Type, old answer, news ...answer) observation {
	if len(news) == 1 {
		news = append(news, news[0])
	}
	fix := func(a answer) answer {
		a.set.Name, a.set.Type = name, t
		return a
	}
	o := observation{q: dnsq.Question{Name: name, Type: t}, old: []answer{fix(old)}}
	for _, a := range news {
		o.new = append(o.new, fix(a))
	}
	return o
}

type want struct {
	kind     finding.Kind
	severity finding.Severity
	name     rr.Name
	typ      rr.Type
	servers  []string
}

func summarize(fs []finding.Finding) []want {
	out := make([]want, 0, len(fs))
	for _, f := range fs {
		out = append(out, want{f.Kind, f.Severity, f.Name, f.Type, f.Servers})
	}
	return out
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name  string
		obs   []observation
		want  []want
		match int
	}{
		{
			name:  "identical",
			obs:   []observation{obs(apex, rr.TypeA, ok(300, "192.0.2.10"), ok(300, "192.0.2.10"))},
			match: 1,
		},
		{
			name: "missing everywhere",
			obs:  []observation{obs(rr.Name("_dmarc.example.test."), rr.TypeTXT, ok(300, `"v=DMARC1"`), ok(0))},
			want: []want{{finding.Missing, finding.Blocker, "_dmarc.example.test.", rr.TypeTXT, nil}},
		},
		{
			name: "missing on a lagging server only",
			obs:  []observation{obs(www, rr.TypeA, ok(300, "192.0.2.10"), ok(300, "192.0.2.10"), ok(0))},
			want: []want{{finding.Missing, finding.Blocker, www, rr.TypeA, []string{"b.new.test."}}},
		},
		{
			name: "different data",
			obs:  []observation{obs(apex, rr.TypeMX, ok(300, "10 mx.yandex.net."), ok(300, "10 mail.example.test."))},
			want: []want{{finding.Different, finding.Blocker, apex, rr.TypeMX, nil}},
		},
		{
			name: "extra on new",
			obs:  []observation{obs(rr.Name("staging.example.test."), rr.TypeA, ok(0), ok(300, "10.0.0.5"))},
			want: []want{{finding.Extra, finding.Warning, "staging.example.test.", rr.TypeA, nil}},
		},
		{
			name: "ttl only",
			obs:  []observation{obs(apex, rr.TypeA, ok(3600, "192.0.2.10"), ok(300, "192.0.2.10"))},
			want: []want{{finding.TTLOnly, finding.Warning, apex, rr.TypeA, nil}},
		},
		{
			name: "proxied A",
			obs:  []observation{obs(apex, rr.TypeA, ok(300, "192.0.2.10"), ok(300, "104.21.32.1"))},
			want: []want{{finding.Proxied, finding.Info, apex, rr.TypeA, nil}},
		},
		{
			name: "proxied CNAME reported once",
			obs: []observation{
				obs(www, rr.TypeCNAME, ok(300, "example.test."), ok(0)),
				obs(www, rr.TypeA, ok(0), ok(300, "104.21.32.1")),
			},
			want: []want{{finding.Proxied, finding.Info, www, rr.TypeCNAME, nil}},
		},
		{
			name: "proxied MX target is a blocker",
			obs: []observation{
				obs(apex, rr.TypeMX, ok(300, "10 mail.example.test."), ok(300, "10 mail.example.test.")),
				obs(mail, rr.TypeA, ok(300, "192.0.2.25"), ok(300, "104.16.1.1")),
			},
			want:  []want{{finding.ProxiedTarget, finding.Blocker, mail, rr.TypeA, nil}},
			match: 1,
		},
		{
			name: "address outside proxy ranges stays different",
			obs:  []observation{obs(mail, rr.TypeA, ok(300, "192.0.2.25"), ok(300, "198.51.100.25"))},
			want: []want{{finding.Different, finding.Blocker, mail, rr.TypeA, nil}},
		},
		{
			name: "refusing new server",
			obs:  []observation{obs(apex, rr.TypeA, ok(300, "192.0.2.10"), ok(300, "192.0.2.10"), refused())},
			want: []want{{finding.QueryFailed, finding.Blocker, apex, 0, []string{"b.new.test."}}},
			// a answered and matched; b's failure is reported on its own.
			match: 1,
		},
		{
			name: "no old answer",
			obs:  []observation{obs(apex, rr.TypeA, refused(), ok(300, "192.0.2.10"))},
			want: []want{
				{finding.QueryFailed, finding.Blocker, apex, 0, nil},
				{finding.QueryFailed, finding.Warning, apex, 0, []string{"ns1.old.test."}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, stats := classify(testCfg, tt.obs)
			got := summarize(fs)
			if !slices.EqualFunc(got, tt.want, func(a, b want) bool {
				return a.kind == b.kind && a.severity == b.severity && a.name == b.name && a.typ == b.typ && slices.Equal(a.servers, b.servers)
			}) {
				t.Fatalf("findings:\n got  %+v\n want %+v", got, tt.want)
			}
			if stats.Matched != tt.match {
				t.Errorf("matched = %d, want %d", stats.Matched, tt.match)
			}
		})
	}
}

func TestClassifyDetails(t *testing.T) {
	fs, _ := classify(testCfg, []observation{
		obs(www, rr.TypeCNAME, ok(300, "example.test."), ok(0)),
		obs(www, rr.TypeA, ok(0), ok(300, "104.21.32.1")),
		obs(apex, rr.TypeA, ok(300, "192.0.2.10"), ok(300, "192.0.2.10"), answer{status: statusError, err: errors.New("udp: timed out")}),
	})
	var proxied, failed finding.Finding
	for _, f := range fs {
		switch f.Kind {
		case finding.Proxied:
			proxied = f
		case finding.QueryFailed:
			failed = f
		}
	}
	if !slices.Equal(proxied.New, []string{"104.21.32.1"}) || !slices.Equal(proxied.Old, []string{"example.test."}) {
		t.Errorf("proxied CNAME should show the old target and the proxy addresses: old=%v new=%v", proxied.Old, proxied.New)
	}
	if !strings.Contains(failed.Detail, "1 of 3 queries") || !strings.Contains(failed.Detail, "timed out") {
		t.Errorf("failure detail = %q", failed.Detail)
	}
}

func TestClassifyOldServersDisagree(t *testing.T) {
	cfg := testCfg
	cfg.Old = []dnsq.Server{server("ns1.old.test.", 5301), server("ns2.old.test.", 5304)}
	o := obs(www, rr.TypeA, ok(300, "192.0.2.10"), ok(300, "192.0.2.10"))
	o.old = append(o.old, answer{status: statusOK, set: rr.Set{Name: www, Type: rr.TypeA, TTL: 300}})
	fs, stats := classify(cfg, []observation{o})
	if len(fs) != 1 || fs[0].Kind != finding.OldInconsistent || !slices.Equal(fs[0].Servers, []string{"ns2.old.test."}) {
		t.Fatalf("findings = %+v", fs)
	}
	if !strings.Contains(fs[0].Detail, "answers nothing") {
		t.Errorf("detail = %q", fs[0].Detail)
	}
	if stats.Matched != 1 {
		t.Errorf("new servers match the reference, matched = %d", stats.Matched)
	}
}

func TestClassifyMaxTTL(t *testing.T) {
	_, stats := classify(testCfg, []observation{
		obs(apex, rr.TypeA, ok(300, "192.0.2.10"), ok(300, "192.0.2.10")),
		obs(www, rr.TypeCNAME, ok(86400, "example.test."), ok(86400, "example.test.")),
		obs(mail, rr.TypeMX, ok(0), ok(0)),
	})
	if stats.MaxTTL != 86400 || stats.MaxTTLName != www || stats.MaxTTLType != rr.TypeCNAME {
		t.Errorf("max ttl = %d %s %s", stats.MaxTTL, stats.MaxTTLName, stats.MaxTTLType)
	}
	if stats.RRsets != 2 || stats.Questions != 3 {
		t.Errorf("rrsets=%d questions=%d", stats.RRsets, stats.Questions)
	}
}
