package inventory

import (
	"bufio"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/Santaniel0/dns-cutover/internal/dnsq"
	"github.com/Santaniel0/dns-cutover/internal/rr"
	"github.com/Santaniel0/dns-cutover/internal/workpool"
)

//go:embed wordlist.txt
var wordlist string

// DefaultWordlist returns the embedded labels: common host names, DKIM
// selectors used by large mail providers, and _service._proto names for mail,
// SIP and calendar autodiscovery.
func DefaultWordlist() []string {
	labels, _ := ParseWordlist(strings.NewReader(wordlist))
	return labels
}

// ParseWordlist reads one label per line; # starts a comment.
func ParseWordlist(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		text, _, _ := strings.Cut(sc.Text(), "#")
		if text = strings.TrimSpace(text); text != "" {
			out = append(out, text)
		}
	}
	return out, sc.Err()
}

type querier interface {
	Query(ctx context.Context, srv dnsq.Server, q dnsq.Question) (dnsq.Response, error)
}

// ProbeStats summarizes a probe run.
type ProbeStats struct {
	Candidates int `json:"candidates"`
	Found      int `json:"found"`
	Failed     int `json:"failed"`
	// Wildcard lists servers whose zone answers for random names. A probe
	// hit there counts only if its answer differs from the wildcard's.
	Wildcard []string `json:"wildcard,omitempty"`
	// Errors keeps the first few distinct failures for the report.
	Errors []string `json:"errors,omitempty"`
}

const maxProbeErrors = 3

func (s *ProbeStats) fail(err error) {
	s.Failed++
	if msg := err.Error(); len(s.Errors) < maxProbeErrors && !slices.Contains(s.Errors, msg) {
		s.Errors = append(s.Errors, msg)
	}
}

// Prober asks the given servers whether candidate names exist.
type Prober struct {
	Querier     querier
	Servers     []dnsq.Server
	Concurrency int
	// CanaryLabel returns a label that should not exist in the zone. Nil
	// means a random one; tests set it to get stable queries.
	CanaryLabel func() string
}

type probeJob struct {
	name   rr.Name
	server int
}

type probeResult struct {
	name   rr.Name
	exists bool
	err    error
}

// Run probes zone.<label> for each label not already collected and adds the
// names that exist on any server.
func (p *Prober) Run(ctx context.Context, labels []string, c *Collector) (ProbeStats, error) {
	var stats ProbeStats
	var candidates []rr.Name
	for _, l := range labels {
		name, err := c.zone.Child(l)
		if err != nil {
			continue
		}
		if _, known := c.entries[name]; known || slices.Contains(candidates, name) {
			continue
		}
		candidates = append(candidates, name)
	}
	stats.Candidates = len(candidates)

	wildcards := make(map[int]string)
	var usable []int
	for i, srv := range p.Servers {
		sig, wild, err := p.canary(ctx, c.zone, srv)
		if err != nil {
			if ctx.Err() != nil {
				return stats, ctx.Err()
			}
			stats.fail(err)
			continue
		}
		usable = append(usable, i)
		if wild {
			wildcards[i] = sig
			stats.Wildcard = append(stats.Wildcard, srv.String())
		}
	}

	jobs := make([]probeJob, 0, len(candidates)*len(usable))
	for _, name := range candidates {
		for _, i := range usable {
			jobs = append(jobs, probeJob{name: name, server: i})
		}
	}
	found := make(map[rr.Name]bool)
	probe := func(ctx context.Context, j probeJob) probeResult {
		resp, err := p.Querier.Query(ctx, p.Servers[j.server], dnsq.Question{Name: j.name, Type: rr.TypeA})
		if err != nil {
			return probeResult{name: j.name, err: err}
		}
		exists := resp.Rcode == dnsq.RcodeSuccess && (resp.Authoritative || resp.Referral())
		if sig, wild := wildcards[j.server]; exists && wild && signature(resp) == sig {
			exists = false
		}
		return probeResult{name: j.name, exists: exists}
	}
	collect := func(r probeResult) {
		if r.err != nil {
			stats.fail(r.err)
			return
		}
		if r.exists {
			found[r.name] = true
		}
	}
	if err := workpool.Run(ctx, p.Concurrency, jobs, probe, collect); err != nil {
		return stats, err
	}

	for _, name := range candidates {
		if found[name] {
			if err := c.Add(name, FromProbe); err != nil {
				return stats, err
			}
			stats.Found++
		}
	}
	return stats, nil
}

// canary queries a name that should not exist. NXDOMAIN means no wildcard;
// an authoritative NOERROR means a wildcard covers the zone, and its answer
// is remembered so probe hits that merely echo it can be told apart.
func (p *Prober) canary(ctx context.Context, zone rr.Name, srv dnsq.Server) (string, bool, error) {
	label := randomLabel
	if p.CanaryLabel != nil {
		label = p.CanaryLabel
	}
	name, err := zone.Child(label())
	if err != nil {
		return "", false, err
	}
	resp, err := p.Querier.Query(ctx, srv, dnsq.Question{Name: name, Type: rr.TypeA})
	if err != nil {
		return "", false, err
	}
	switch {
	case resp.Rcode == dnsq.RcodeNXDomain:
		return "", false, nil
	case resp.Rcode == dnsq.RcodeSuccess && resp.Authoritative:
		return signature(resp), true, nil
	case resp.Rcode == dnsq.RcodeSuccess:
		return "", false, fmt.Errorf("probe skipped %s: answer for %s is not authoritative", srv, name)
	default:
		return "", false, fmt.Errorf("probe skipped %s: canary query returned %s", srv, resp.Rcode)
	}
}

// signature is the answer with owner names and TTLs dropped, which is what a
// wildcard-synthesized answer has in common across names.
func signature(resp dnsq.Response) string {
	parts := make([]string, 0, len(resp.Answer))
	for _, rec := range resp.Answer {
		parts = append(parts, rr.Type(rec.Header().Rrtype).String()+" "+rr.Canonical(rec))
	}
	slices.Sort(parts)
	return strings.Join(parts, "\n")
}

func randomLabel() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "dnscutover-canary-" + hex.EncodeToString(b[:])
}
