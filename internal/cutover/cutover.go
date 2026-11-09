// Package cutover runs a whole check: it locates the servers, builds the
// name inventory, compares records, checks the delegation and decides
// whether the nameserver change is safe.
package cutover

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Santaniel0/dns-cutover/internal/compare"
	"github.com/Santaniel0/dns-cutover/internal/delegation"
	"github.com/Santaniel0/dns-cutover/internal/dnsq"
	"github.com/Santaniel0/dns-cutover/internal/finding"
	"github.com/Santaniel0/dns-cutover/internal/inventory"
	"github.com/Santaniel0/dns-cutover/internal/proxyrange"
	"github.com/Santaniel0/dns-cutover/internal/rr"
)

var (
	// ErrNoNewServers is returned when Config.New is empty.
	ErrNoNewServers = errors.New("no new servers given")
	// ErrNoOldServers is returned when --old is not given and the parent
	// delegation, which would name them, cannot be read.
	ErrNoOldServers = errors.New("old servers unknown")
	// ErrBadPolicy is returned for unknown --ttl values.
	ErrBadPolicy = errors.New("unknown TTL policy")
	// ErrBadIgnore is returned for malformed --ignore rules.
	ErrBadIgnore = errors.New("invalid ignore rule")
	// ErrNoProbeServers is returned when probing is on but no server to
	// probe was given.
	ErrNoProbeServers = errors.New("probing needs --old or --new")
)

// Querier sends one non-recursive query. *dnsq.Client satisfies it.
type Querier interface {
	Query(ctx context.Context, srv dnsq.Server, q dnsq.Question) (dnsq.Response, error)
}

// TTLPolicy says how differences in TTL alone are counted.
type TTLPolicy uint8

// TTL policies.
const (
	TTLWarn TTLPolicy = iota
	TTLIgnore
	TTLFail
)

func (p TTLPolicy) String() string {
	switch p {
	case TTLIgnore:
		return "ignore"
	case TTLFail:
		return "fail"
	default:
		return "warn"
	}
}

// ParseTTLPolicy accepts "warn", "ignore" or "fail".
func ParseTTLPolicy(s string) (TTLPolicy, error) {
	for _, p := range []TTLPolicy{TTLWarn, TTLIgnore, TTLFail} {
		if strings.EqualFold(s, p.String()) {
			return p, nil
		}
	}
	return 0, fmt.Errorf("%w %q (want warn, ignore or fail)", ErrBadPolicy, s)
}

// IgnoreRule accepts a known, intended difference.
type IgnoreRule struct {
	Name rr.Name
	// Type zero matches every type at Name.
	Type rr.Type
}

// ParseIgnore reads "name [TYPE]" with the name relative to zone, for
// example "www A" or "@ MX".
func ParseIgnore(s string, zone rr.Name) (IgnoreRule, error) {
	fields := strings.Fields(s)
	if len(fields) == 0 || len(fields) > 2 {
		return IgnoreRule{}, fmt.Errorf("%w %q: want \"name [TYPE]\"", ErrBadIgnore, s)
	}
	name, err := rr.ParseRelative(fields[0], zone)
	if err != nil {
		return IgnoreRule{}, fmt.Errorf("%w %q: %w", ErrBadIgnore, s, err)
	}
	rule := IgnoreRule{Name: name}
	if len(fields) == 2 {
		if rule.Type, err = rr.ParseType(fields[1]); err != nil {
			return IgnoreRule{}, fmt.Errorf("%w %q: %w", ErrBadIgnore, s, err)
		}
	}
	return rule, nil
}

func (r IgnoreRule) matches(f finding.Finding) bool {
	return f.Name == r.Name && (r.Type == 0 || r.Type == f.Type)
}

// Config describes one check.
type Config struct {
	Zone rr.Name
	New  []dnsq.Spec
	// Old defaults to the servers the parent currently delegates to.
	Old []dnsq.Spec
	// Parent overrides discovery of the parent zone's servers.
	Parent       []dnsq.Spec
	ZoneFile     io.Reader
	ZoneFileName string
	Names        io.Reader
	Probe        bool
	Wordlist     []string
	Concurrency  int
	Proxy        proxyrange.Set
	TTL          TTLPolicy
	Ignore       []IgnoreRule
}

// Deps are the outside world: the network and the clock.
type Deps struct {
	Querier Querier
	Locator delegation.Locator
	Now     func() time.Time
	// CanaryLabel is passed to the prober; nil means random.
	CanaryLabel func() string
}

// Verdict is the answer to "can I change the NS records now?".
type Verdict uint8

// Verdicts.
const (
	Ready Verdict = iota + 1
	NotReady
)

func (v Verdict) String() string {
	if v == Ready {
		return "READY"
	}
	return "NOT READY"
}

// MarshalText makes the verdict appear as text in JSON.
func (v Verdict) MarshalText() ([]byte, error) { return []byte(v.String()), nil }

// OldSource says where the old server list came from.
type OldSource uint8

// Old server sources.
const (
	OldFromFlag OldSource = iota + 1
	OldFromParent
)

func (s OldSource) String() string {
	if s == OldFromParent {
		return "parent delegation"
	}
	return "--old"
}

// MarshalText makes the source appear as text in JSON.
func (s OldSource) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Result is everything a report needs.
type Result struct {
	Zone      rr.Name
	Verdict   Verdict
	Old       []dnsq.Server
	OldSource OldSource
	New       []dnsq.Server
	// Parent is nil when the delegation could not be read.
	Parent    *delegation.Parent
	Inventory inventory.Inventory
	Stats     compare.Stats
	Findings  []finding.Finding
	Queries   int64
	Elapsed   time.Duration
}

// Count returns the number of findings of a severity that are not ignored.
func (r Result) Count(sev finding.Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == sev && !f.Ignored {
			n++
		}
	}
	return n
}

// Ignored returns the number of findings silenced by --ignore.
func (r Result) Ignored() int {
	n := 0
	for _, f := range r.Findings {
		if f.Ignored {
			n++
		}
	}
	return n
}

// counting wraps a Querier to report how many queries a run sent.
type counting struct {
	Querier
	n atomic.Int64
}

func (c *counting) Query(ctx context.Context, srv dnsq.Server, q dnsq.Question) (dnsq.Response, error) {
	c.n.Add(1)
	return c.Querier.Query(ctx, srv, q)
}

// Run performs the check. It returns an error only when the check cannot be
// carried out (bad input, no servers, cancellation); everything wrong with
// the zones themselves ends up in Result.Findings.
func Run(ctx context.Context, deps Deps, cfg Config) (Result, error) {
	start := deps.Now()
	q := &counting{Querier: deps.Querier}
	res := Result{Zone: cfg.Zone}
	var extra []finding.Finding

	if len(cfg.New) == 0 {
		return res, ErrNoNewServers
	}
	newServers, err := dnsq.Resolve(ctx, deps.Locator, cfg.New)
	if err != nil {
		return res, fmt.Errorf("new servers: %w", err)
	}
	res.New = newServers

	parent, parentErr := readParent(ctx, q, deps.Locator, cfg)
	if err := ctx.Err(); err != nil {
		return res, err
	}
	if parentErr == nil {
		res.Parent = &parent
	} else {
		extra = append(extra, finding.Finding{
			Kind: finding.Delegation, Severity: finding.Warning, Name: cfg.Zone,
			Detail: "could not read the delegation from the parent zone, so DS and delegation TTLs were not checked: " + parentErr.Error(),
		})
	}

	switch {
	case len(cfg.Old) > 0:
		res.OldSource = OldFromFlag
		res.Old, err = dnsq.Resolve(ctx, deps.Locator, cfg.Old)
	case res.Parent != nil:
		res.OldSource = OldFromParent
		specs := make([]dnsq.Spec, 0, len(parent.NS))
		for _, ns := range parent.NS {
			specs = append(specs, dnsq.Spec{Host: ns, Port: dnsq.DefaultPort})
		}
		res.Old, err = dnsq.Resolve(ctx, deps.Locator, specs)
	default:
		return res, fmt.Errorf("%w: pass --old (%w)", ErrNoOldServers, parentErr)
	}
	if err != nil {
		return res, fmt.Errorf("old servers: %w", err)
	}

	inv, invFindings, err := buildInventory(ctx, q, deps, cfg, []dnsq.Server{res.Old[0], res.New[0]})
	if err != nil {
		return res, err
	}
	res.Inventory = inv
	extra = append(extra, invFindings...)

	cmp, err := compare.Run(ctx, q, inv, compare.Config{
		Zone: cfg.Zone, Old: res.Old, New: res.New, Concurrency: cfg.Concurrency, Proxy: cfg.Proxy,
	})
	if err != nil {
		return res, err
	}
	res.Stats = cmp.Stats

	del, err := delegation.Check(ctx, q, delegation.Input{
		Zone: cfg.Zone, Old: res.Old, New: res.New, Parent: res.Parent,
		MaxTTL: cmp.Stats.MaxTTL, MaxTTLName: cmp.Stats.MaxTTLName, MaxTTLType: cmp.Stats.MaxTTLType,
	})
	if err != nil {
		return res, fmt.Errorf("delegation: %w", err)
	}

	res.Findings = applyPolicies(slices.Concat(cmp.Findings, del, extra), cfg)
	res.Verdict = Ready
	if res.Count(finding.Blocker) > 0 {
		res.Verdict = NotReady
	}
	res.Queries = q.n.Load()
	res.Elapsed = deps.Now().Sub(start)
	return res, nil
}

func readParent(ctx context.Context, q Querier, loc delegation.Locator, cfg Config) (delegation.Parent, error) {
	var (
		servers []dnsq.Server
		zone    rr.Name
		err     error
	)
	if len(cfg.Parent) > 0 {
		servers, err = dnsq.Resolve(ctx, loc, cfg.Parent)
	} else {
		servers, zone, err = delegation.FindParentServers(ctx, loc, cfg.Zone)
	}
	if err != nil {
		return delegation.Parent{}, err
	}
	p, err := delegation.ReadParent(ctx, q, cfg.Zone, servers)
	p.Zone = zone
	return p, err
}

// BuildInventory runs only the inventory step, for the inventory command.
// Probing uses the first --old and the first --new server that are given.
func BuildInventory(ctx context.Context, deps Deps, cfg Config) (inventory.Inventory, error) {
	var probeServers []dnsq.Server
	for _, specs := range [][]dnsq.Spec{cfg.Old, cfg.New} {
		if len(specs) == 0 {
			continue
		}
		servers, err := dnsq.Resolve(ctx, deps.Locator, specs[:1])
		if err != nil {
			return inventory.Inventory{}, err
		}
		probeServers = append(probeServers, servers...)
	}
	if cfg.Probe && len(probeServers) == 0 {
		return inventory.Inventory{}, ErrNoProbeServers
	}
	inv, _, err := buildInventory(ctx, deps.Querier, deps, cfg, probeServers)
	return inv, err
}

// buildInventory probes from the first old and the first new server only:
// probing every server would multiply queries for little gain, since the
// comparison afterwards asks all of them about every name found.
func buildInventory(ctx context.Context, q Querier, deps Deps, cfg Config, probeServers []dnsq.Server) (inventory.Inventory, []finding.Finding, error) {
	col := inventory.NewCollector(cfg.Zone)
	if cfg.ZoneFile != nil {
		if err := inventory.ReadZoneFile(cfg.ZoneFile, cfg.ZoneFileName, col); err != nil {
			return inventory.Inventory{}, nil, err
		}
	}
	if cfg.Names != nil {
		if err := inventory.ReadNames(cfg.Names, col); err != nil {
			return inventory.Inventory{}, nil, err
		}
	}
	var stats inventory.ProbeStats
	if cfg.Probe {
		p := inventory.Prober{
			Querier:     q,
			Servers:     probeServers,
			Concurrency: cfg.Concurrency,
			CanaryLabel: deps.CanaryLabel,
		}
		var err error
		if stats, err = p.Run(ctx, cfg.Wordlist, col); err != nil {
			return inventory.Inventory{}, nil, fmt.Errorf("probe: %w", err)
		}
	}
	inv := col.Inventory(stats)

	var fs []finding.Finding
	add := func(sev finding.Severity, detail string) {
		fs = append(fs, finding.Finding{Kind: finding.Inventory, Severity: sev, Name: cfg.Zone, Detail: detail})
	}
	if inv.Count(inventory.FromZoneFile) == 0 {
		add(finding.Warning, "no zone file given: only probed common labels and --names entries were compared, "+
			"so names nobody guessed are not checked; export the zone from the old provider and pass --zone-file")
	}
	if len(stats.Wildcard) > 0 {
		add(finding.Info, "wildcard records answer on "+strings.Join(stats.Wildcard, ", ")+
			"; probe hits identical to the wildcard answer were dropped")
	}
	if stats.Failed > 0 {
		add(finding.Warning, fmt.Sprintf("%d probe queries failed: %s", stats.Failed, strings.Join(stats.Errors, "; ")))
	}
	if inv.Skipped > 0 {
		add(finding.Info, fmt.Sprintf("%d records in the zone file are outside %s and were skipped", inv.Skipped, cfg.Zone))
	}
	return inv, fs, nil
}

func applyPolicies(fs []finding.Finding, cfg Config) []finding.Finding {
	out := fs[:0]
	for _, f := range fs {
		if f.Kind == finding.TTLOnly {
			switch cfg.TTL {
			case TTLIgnore:
				continue
			case TTLFail:
				f.Severity = finding.Blocker
			}
		}
		for _, r := range cfg.Ignore {
			if r.matches(f) {
				f.Ignored = true
			}
		}
		out = append(out, f)
	}
	finding.Sort(out)
	return out
}
