// Package compare asks every old and every new server about each name and
// type in the inventory and turns the differences into findings.
//
// Querying and classification are separate steps: Run fills a table of
// observations concurrently, and classify is a pure function over that table,
// so the rules can be tested without a network.
package compare

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/Santaniel0/dns-cutover/internal/dnsq"
	"github.com/Santaniel0/dns-cutover/internal/finding"
	"github.com/Santaniel0/dns-cutover/internal/inventory"
	"github.com/Santaniel0/dns-cutover/internal/proxyrange"
	"github.com/Santaniel0/dns-cutover/internal/rr"
	"github.com/Santaniel0/dns-cutover/internal/workpool"
)

type querier interface {
	Query(ctx context.Context, srv dnsq.Server, q dnsq.Question) (dnsq.Response, error)
}

// Config is what Run needs besides the inventory.
type Config struct {
	Zone        rr.Name
	Old, New    []dnsq.Server
	Concurrency int
	Proxy       proxyrange.Set
}

// Stats counts what was compared.
type Stats struct {
	Questions int `json:"questions"`
	// RRsets counts name/type pairs that have data on at least one side.
	RRsets int `json:"rrsets"`
	// Matched counts RRsets every answering new server serves exactly as
	// the old servers do, TTL included.
	Matched int `json:"matched"`
	// MaxTTL is the largest TTL among the old provider's RRsets: how long a
	// resolver may keep serving old data after a rollback.
	MaxTTL     uint32  `json:"max_ttl"`
	MaxTTLName rr.Name `json:"max_ttl_name,omitempty"`
	MaxTTLType rr.Type `json:"max_ttl_type,omitzero"`
}

// Result is the outcome of Run.
type Result struct {
	Findings []finding.Finding
	Stats    Stats
}

// baseTypes are queried at every name. NS is added below the apex (the apex
// NS set is checked by the delegation step) and SRV at underscore names.
var baseTypes = []rr.Type{rr.TypeA, rr.TypeAAAA, rr.TypeCNAME, rr.TypeMX, rr.TypeTXT, rr.TypeCAA}

// Questions lists the name/type pairs Run will ask every server about.
func Questions(inv inventory.Inventory) []dnsq.Question {
	var out []dnsq.Question
	for _, e := range inv.Entries {
		types := slices.Clone(baseTypes)
		if e.Name != inv.Zone {
			types = append(types, rr.TypeNS)
		}
		if strings.HasPrefix(e.Name.FirstLabel(), "_") {
			types = append(types, rr.TypeSRV)
		}
		for _, t := range e.Types {
			if t != rr.TypeSOA && (t != rr.TypeNS || e.Name != inv.Zone) {
				types = append(types, t)
			}
		}
		slices.Sort(types)
		for _, t := range slices.Compact(types) {
			out = append(out, dnsq.Question{Name: e.Name, Type: t})
		}
	}
	return out
}

type side uint8

const (
	oldSide side = iota
	newSide
)

type job struct {
	question int
	side     side
	server   int
}

type jobResult struct {
	job
	answer answer
}

// Run queries every server for every question and classifies the answers.
// Concurrency bounds the number of queries in flight across all servers.
func Run(ctx context.Context, q querier, inv inventory.Inventory, cfg Config) (Result, error) {
	questions := Questions(inv)
	obs := make([]observation, len(questions))
	jobs := make([]job, 0, len(questions)*(len(cfg.Old)+len(cfg.New)))
	for i, qu := range questions {
		obs[i] = observation{q: qu, old: make([]answer, len(cfg.Old)), new: make([]answer, len(cfg.New))}
		for s := range cfg.Old {
			jobs = append(jobs, job{question: i, side: oldSide, server: s})
		}
		for s := range cfg.New {
			jobs = append(jobs, job{question: i, side: newSide, server: s})
		}
	}

	ask := func(ctx context.Context, j job) jobResult {
		srv := cfg.Old[j.server]
		if j.side == newSide {
			srv = cfg.New[j.server]
		}
		resp, err := q.Query(ctx, srv, questions[j.question])
		return jobResult{job: j, answer: interpret(questions[j.question], resp, err)}
	}
	store := func(r jobResult) {
		if r.side == oldSide {
			obs[r.question].old[r.server] = r.answer
		} else {
			obs[r.question].new[r.server] = r.answer
		}
	}
	if err := workpool.Run(ctx, cfg.Concurrency, jobs, ask, store); err != nil {
		return Result{}, fmt.Errorf("compare: %w", err)
	}

	findings, stats := classify(cfg, obs)
	return Result{Findings: findings, Stats: stats}, nil
}

type status uint8

const (
	// statusOK is an authoritative answer, with or without data.
	statusOK status = iota
	// statusRcode is a REFUSED, SERVFAIL or other error rcode.
	statusRcode
	// statusNotAuth is NOERROR without the AA bit and without a referral:
	// the server is not authoritative for the zone.
	statusNotAuth
	// statusError means no reply at all.
	statusError
)

type answer struct {
	status status
	rcode  dnsq.Rcode
	set    rr.Set
	err    error
}

func (a answer) problem() string {
	switch a.status {
	case statusRcode:
		return a.rcode.String()
	case statusNotAuth:
		return "answer without the AA bit"
	case statusError:
		return a.err.Error()
	default:
		return ""
	}
}

func interpret(q dnsq.Question, resp dnsq.Response, err error) answer {
	if err != nil {
		return answer{status: statusError, err: err}
	}
	if resp.Rcode != dnsq.RcodeSuccess && resp.Rcode != dnsq.RcodeNXDomain {
		return answer{status: statusRcode, rcode: resp.Rcode}
	}
	switch {
	case resp.Authoritative:
		return answer{status: statusOK, set: rr.NewSet(q.Name, q.Type, resp.Answer)}
	case resp.Referral():
		// Below a zone cut the only data this zone owns is the delegation
		// NS set, which a referral carries in the authority section.
		if q.Type == rr.TypeNS {
			return answer{status: statusOK, set: rr.NewSet(q.Name, q.Type, resp.Authority)}
		}
		return answer{status: statusOK, set: rr.Set{Name: q.Name, Type: q.Type}}
	default:
		return answer{status: statusNotAuth}
	}
}
