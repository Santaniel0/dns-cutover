package delegation

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/Santaniel0/dns-cutover/internal/dnsq"
	"github.com/Santaniel0/dns-cutover/internal/finding"
	"github.com/Santaniel0/dns-cutover/internal/rr"
)

// Input is what Check needs.
type Input struct {
	Zone rr.Name
	Old  []dnsq.Server
	New  []dnsq.Server
	// Parent is nil when the parent zone could not be read; the checks
	// that depend on it are skipped and the caller reports why.
	Parent *Parent
	// MaxTTL and its owner come from the record comparison.
	MaxTTL     uint32
	MaxTTLName rr.Name
	MaxTTLType rr.Type
}

// Check runs the delegation checks against the new servers.
func Check(ctx context.Context, q querier, in Input) ([]finding.Finding, error) {
	c := checker{q: q, in: in, soa: make(map[int]*dns.SOA)}
	steps := []func(context.Context) error{c.checkServing, c.checkApexNS, c.checkDNSSEC, c.checkGlue}
	for _, step := range steps {
		if err := step(ctx); err != nil {
			return nil, err
		}
	}
	c.reportTiming()
	finding.Sort(c.out)
	return c.out, nil
}

type checker struct {
	q  querier
	in Input
	// serving lists new servers that answered SOA authoritatively, in
	// Input.New order.
	serving []int
	soa     map[int]*dns.SOA
	out     []finding.Finding
}

func (c *checker) add(f finding.Finding) {
	if f.Name == "" {
		f.Name = c.in.Zone
	}
	c.out = append(c.out, f)
}

func (c *checker) checkServing(ctx context.Context) error {
	for i, srv := range c.in.New {
		// Only cancellation aborts the checks; a failed query is a finding.
		resp, err := c.q.Query(ctx, srv, dnsq.Question{Name: c.in.Zone, Type: rr.TypeSOA})
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var problem string
		switch {
		case err != nil:
			problem = "no answer to the SOA query: " + err.Error()
		case resp.Rcode != dnsq.RcodeSuccess:
			problem = fmt.Sprintf("SOA query returned %s; the zone is not set up on this server", resp.Rcode)
		case !resp.Authoritative:
			problem = "SOA answer is not authoritative; the zone is not set up on this server"
		}
		var soa *dns.SOA
		if problem == "" {
			for _, rec := range resp.Answer {
				if s, ok := rec.(*dns.SOA); ok && rr.Name(dns.CanonicalName(s.Hdr.Name)) == c.in.Zone {
					soa = s
				}
			}
			if soa == nil {
				problem = "authoritative answer has no SOA record for the zone"
			}
		}
		if problem != "" {
			c.add(finding.Finding{Kind: finding.NotServing, Severity: finding.Blocker, Type: rr.TypeSOA, Servers: []string{srv.String()}, Detail: problem})
			continue
		}
		c.serving = append(c.serving, i)
		c.soa[i] = soa
	}

	serials := make(map[uint32][]string)
	for _, i := range c.serving {
		serials[c.soa[i].Serial] = append(serials[c.soa[i].Serial], c.in.New[i].String())
	}
	if len(serials) > 1 {
		var parts []string
		for _, i := range c.serving {
			parts = append(parts, fmt.Sprintf("%s=%d", c.in.New[i], c.soa[i].Serial))
		}
		c.add(finding.Finding{
			Kind: finding.SerialMismatch, Severity: finding.Warning, Type: rr.TypeSOA,
			Detail: "new servers return different SOA serials (" + strings.Join(parts, ", ") + "); one of them has not caught up yet",
		})
	}
	return nil
}

func hosts(servers []dnsq.Server) []rr.Name {
	var out []rr.Name
	for _, s := range servers {
		if s.Host != "" && !slices.Contains(out, s.Host) {
			out = append(out, s.Host)
		}
	}
	return out
}

func (c *checker) checkApexNS(ctx context.Context) error {
	expected := hosts(c.in.New)
	if len(expected) == 0 || len(c.serving) == 0 {
		return nil
	}
	var apex []rr.Name
	for _, i := range c.serving {
		resp, err := c.q.Query(ctx, c.in.New[i], dnsq.Question{Name: c.in.Zone, Type: rr.TypeNS})
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil || !resp.Authoritative {
			continue
		}
		for _, d := range rr.NewSet(c.in.Zone, rr.TypeNS, resp.Answer).Data {
			if !slices.Contains(apex, rr.Name(d)) {
				apex = append(apex, rr.Name(d))
			}
		}
	}
	slices.Sort(apex)

	old := hosts(c.in.Old)
	if c.in.Parent != nil {
		old = append(old, c.in.Parent.NS...)
	}
	var stale, foreign, missing []string
	for _, n := range apex {
		switch {
		case slices.Contains(expected, n):
		case slices.Contains(old, n):
			stale = append(stale, string(n))
		default:
			foreign = append(foreign, string(n))
		}
	}
	for _, n := range expected {
		if !slices.Contains(apex, n) {
			missing = append(missing, string(n))
		}
	}
	apexData := make([]string, 0, len(apex))
	for _, n := range apex {
		apexData = append(apexData, string(n))
	}
	if len(stale) > 0 {
		c.add(finding.Finding{
			Kind: finding.ApexNS, Severity: finding.Blocker, Type: rr.TypeNS, New: apexData,
			Detail: "the new zone still lists the old nameservers " + strings.Join(stale, ", ") +
				" at the apex; resolvers that take the zone's own NS set will keep going back to the old provider",
		})
	}
	if len(missing) > 0 && len(apex) > 0 {
		c.add(finding.Finding{
			Kind: finding.ApexNS, Severity: finding.Warning, Type: rr.TypeNS, New: apexData,
			Detail: "the registrar will delegate to " + strings.Join(missing, ", ") + " but the new zone's NS set does not include it",
		})
	}
	if len(foreign) > 0 {
		c.add(finding.Finding{
			Kind: finding.ApexNS, Severity: finding.Info, Type: rr.TypeNS, New: apexData,
			Detail: "the new zone also lists " + strings.Join(foreign, ", "),
		})
	}
	return nil
}

func (c *checker) checkDNSSEC(ctx context.Context) error {
	p := c.in.Parent
	if p == nil {
		return nil
	}
	var keys []*dns.DNSKEY
	for _, i := range c.serving {
		resp, err := c.q.Query(ctx, c.in.New[i], dnsq.Question{Name: c.in.Zone, Type: rr.TypeDNSKEY})
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil || !resp.Authoritative {
			continue
		}
		for _, rec := range resp.Answer {
			if k, ok := rec.(*dns.DNSKEY); ok && !slices.ContainsFunc(keys, func(o *dns.DNSKEY) bool { return o.PublicKey == k.PublicKey }) {
				keys = append(keys, k)
			}
		}
	}

	parentDS := make([]string, 0, len(p.DS))
	for _, d := range p.DS {
		parentDS = append(parentDS, d.String())
	}
	suggested := suggestDS(keys)
	ttl := human(p.DSTTL)

	switch {
	case len(p.DS) == 0 && len(keys) == 0:
		return nil
	case len(p.DS) == 0:
		c.add(finding.Finding{
			Kind: finding.DNSSEC, Severity: finding.Info, Type: rr.TypeDS, New: suggested,
			Detail: "the new zone is signed but the parent has no DS, so DNSSEC stays off; after the switch it can be enabled by publishing the DS shown",
		})
	case len(keys) == 0:
		c.add(finding.Finding{
			Kind: finding.DNSSEC, Severity: finding.Blocker, Type: rr.TypeDS, Old: parentDS,
			Detail: "the parent publishes DS but the new zone is unsigned; validating resolvers will return SERVFAIL for the whole domain. " +
				"Remove the DS at the registrar and wait " + ttl + " (the DS TTL) before changing NS",
		})
	default:
		matched := matchDS(p.DS, keys)
		if len(matched) == 0 {
			c.add(finding.Finding{
				Kind: finding.DNSSEC, Severity: finding.Blocker, Type: rr.TypeDS, Old: parentDS, New: suggested,
				Detail: "no DS at the parent matches a DNSKEY on the new servers; validating resolvers will return SERVFAIL. " +
					"Replace the DS at the registrar with the one shown (or remove it) and wait " + ttl + " (the DS TTL) before changing NS",
			})
			return nil
		}
		c.add(finding.Finding{
			Kind: finding.DNSSEC, Severity: finding.Info, Type: rr.TypeDS, Old: parentDS,
			Detail: "parent DS " + strings.Join(matched, ", ") + " matches a key served by the new servers",
		})
	}
	return nil
}

// matchDS returns the parent DS records that hash to one of keys.
func matchDS(ds []DSRecord, keys []*dns.DNSKEY) []string {
	var out []string
	for _, d := range ds {
		for _, k := range keys {
			if k.Algorithm != d.Algorithm || k.KeyTag() != d.KeyTag {
				continue
			}
			if got := k.ToDS(d.DigestType); got != nil && strings.EqualFold(got.Digest, d.Digest) {
				out = append(out, d.String())
				break
			}
		}
	}
	return out
}

// suggestDS computes SHA-256 DS records for the zone's key-signing keys, or
// for every key when none carries the SEP flag.
func suggestDS(keys []*dns.DNSKEY) []string {
	var sep []*dns.DNSKEY
	for _, k := range keys {
		if k.Flags&dns.SEP != 0 {
			sep = append(sep, k)
		}
	}
	if len(sep) == 0 {
		sep = keys
	}
	var out []string
	for _, k := range sep {
		if ds := k.ToDS(dns.SHA256); ds != nil {
			out = append(out, dsRecord(ds).String())
		}
	}
	slices.Sort(out)
	return out
}

func (c *checker) checkGlue(ctx context.Context) error {
	if len(c.serving) == 0 {
		return nil
	}
	srv := c.in.New[c.serving[0]]
	for _, h := range hosts(c.in.New) {
		if !h.In(c.in.Zone) {
			continue
		}
		var addrs []string
		for _, t := range []rr.Type{rr.TypeA, rr.TypeAAAA} {
			resp, err := c.q.Query(ctx, srv, dnsq.Question{Name: h, Type: t})
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err == nil && resp.Authoritative {
				addrs = append(addrs, rr.NewSet(h, t, resp.Answer).Data...)
			}
		}
		if len(addrs) == 0 {
			c.add(finding.Finding{
				Kind: finding.Glue, Severity: finding.Blocker, Name: h, Type: rr.TypeA,
				Detail: "nameserver is inside the zone but the new zone has no address for it",
			})
			continue
		}
		c.add(finding.Finding{
			Kind: finding.Glue, Severity: finding.Warning, Name: h, Type: rr.TypeA, New: addrs,
			Detail: "nameserver is inside the zone, so the registrar must publish glue for it with these addresses",
		})
	}
	return nil
}

func (c *checker) reportTiming() {
	if p := c.in.Parent; p != nil {
		if expected := hosts(c.in.New); len(expected) > 0 && sameNames(p.NS, expected) {
			c.add(finding.Finding{Kind: finding.Delegation, Severity: finding.Info, Type: rr.TypeNS,
				Detail: "the parent already delegates to the new servers"})
		}
		c.add(finding.Finding{Kind: finding.Timing, Severity: finding.Info, Type: rr.TypeNS,
			Detail: "parent NS TTL is " + human(p.NSTTL) + ": after the switch some resolvers keep asking the old servers that long, so leave the old zone unchanged until then"})
	}
	if len(c.serving) > 0 {
		neg := uint32(0)
		for n, i := range c.serving {
			s := c.soa[i]
			v := min(s.Hdr.Ttl, s.Minttl)
			if n == 0 || v < neg {
				neg = v
			}
		}
		c.add(finding.Finding{Kind: finding.Timing, Severity: finding.Info, Type: rr.TypeSOA,
			Detail: "negative-caching TTL of the new zone is " + human(neg) + ": a name missing at the switch stays missing in caches that long after it is added"})
	}
	if c.in.MaxTTL > 0 {
		c.add(finding.Finding{Kind: finding.Timing, Severity: finding.Info, Name: c.in.MaxTTLName, Type: c.in.MaxTTLType,
			Detail: "largest TTL on the old servers is " + human(c.in.MaxTTL) + ": a record changed during the move can be served stale that long after the switch"})
	}
}

func sameNames(a, b []rr.Name) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// human renders a TTL as "2d (172800s)" so both the size and the exact value
// are visible.
func human(sec uint32) string {
	units := []struct {
		size   uint32
		suffix string
	}{{86400, "d"}, {3600, "h"}, {60, "m"}}
	for _, u := range units {
		if sec != 0 && sec%u.size == 0 {
			return fmt.Sprintf("%d%s (%ds)", sec/u.size, u.suffix, sec)
		}
	}
	return fmt.Sprintf("%ds", sec)
}
