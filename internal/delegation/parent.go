// Package delegation covers what happens at the moment of the switch: what
// the parent zone publishes (NS and DS), whether the new servers serve the
// zone at all, the NS set at the new apex, DNSSEC continuity and how long
// caches keep the old state.
package delegation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/Santaniel0/dns-cutover/internal/dnsq"
	"github.com/Santaniel0/dns-cutover/internal/rr"
)

var (
	// ErrNoParent is returned when no parent zone servers can be found.
	ErrNoParent = errors.New("parent zone servers not found")
	// ErrNotDelegated is returned when the parent has no NS records for the zone.
	ErrNotDelegated = errors.New("parent has no delegation for the zone")
)

type querier interface {
	Query(ctx context.Context, srv dnsq.Server, q dnsq.Question) (dnsq.Response, error)
}

// Locator finds servers through a recursive resolver. *net.Resolver
// satisfies it.
type Locator interface {
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	dnsq.HostLookup
}

// DSRecord is one DS record published by the parent.
type DSRecord struct {
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digest_type"`
	Digest     string `json:"digest"`
}

func (d DSRecord) String() string {
	return fmt.Sprintf("%d %d %d %s", d.KeyTag, d.Algorithm, d.DigestType, strings.ToUpper(d.Digest))
}

func dsRecord(ds *dns.DS) DSRecord {
	return DSRecord{KeyTag: ds.KeyTag, Algorithm: ds.Algorithm, DigestType: ds.DigestType, Digest: strings.ToLower(ds.Digest)}
}

// Parent is what the parent zone says about the delegation.
type Parent struct {
	// Zone is the parent zone found by FindParentServers; empty when the
	// parent server was given explicitly.
	Zone   rr.Name     `json:"zone,omitempty"`
	Server dnsq.Server `json:"-"`
	NS     []rr.Name   `json:"ns"`
	NSTTL  uint32      `json:"ns_ttl"`
	DS     []DSRecord  `json:"ds,omitempty"`
	DSTTL  uint32      `json:"ds_ttl,omitempty"`
}

// maxParentServers caps how many parent nameservers are resolved; the first
// one that answers is enough.
const maxParentServers = 3

// FindParentServers walks up from the zone's parent until the resolver
// returns NS records, then resolves a few of those servers.
func FindParentServers(ctx context.Context, loc Locator, zone rr.Name) ([]dnsq.Server, rr.Name, error) {
	for p := zone.Parent(); ; p = p.Parent() {
		nss, err := loc.LookupNS(ctx, string(p))
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, "", ctxErr
		}
		if err == nil && len(nss) > 0 {
			var servers []dnsq.Server
			for _, ns := range nss[:min(len(nss), maxParentServers)] {
				host, err := rr.ParseName(ns.Host)
				if err != nil {
					continue
				}
				got, err := dnsq.Resolve(ctx, loc, []dnsq.Spec{{Host: host, Port: dnsq.DefaultPort}})
				if err == nil {
					servers = append(servers, got...)
				}
			}
			if len(servers) > 0 {
				return servers, p, nil
			}
		}
		if p == "." {
			return nil, "", fmt.Errorf("%w for %s", ErrNoParent, zone)
		}
	}
}

// ReadParent asks the parent servers, in order, for the zone's NS and DS
// records and returns the first complete answer.
func ReadParent(ctx context.Context, q querier, zone rr.Name, servers []dnsq.Server) (Parent, error) {
	var lastErr error = ErrNoParent
	for _, srv := range servers {
		p, err := readParentFrom(ctx, q, zone, srv)
		if err == nil || errors.Is(err, ErrNotDelegated) {
			return p, err
		}
		if ctx.Err() != nil {
			return Parent{}, ctx.Err()
		}
		lastErr = err
	}
	return Parent{}, lastErr
}

func readParentFrom(ctx context.Context, q querier, zone rr.Name, srv dnsq.Server) (Parent, error) {
	resp, err := q.Query(ctx, srv, dnsq.Question{Name: zone, Type: rr.TypeNS})
	if err != nil {
		return Parent{}, err
	}
	switch resp.Rcode {
	case dnsq.RcodeSuccess:
	case dnsq.RcodeNXDomain:
		return Parent{}, fmt.Errorf("%w: %s answered NXDOMAIN for %s", ErrNotDelegated, srv, zone)
	default:
		return Parent{}, fmt.Errorf("parent %s answered %s for %s NS", srv, resp.Rcode, zone)
	}
	// A parent server that also hosts the child answers NS directly;
	// otherwise the delegation comes back as a referral.
	section := resp.Authority
	if resp.Authoritative {
		section = resp.Answer
	}
	nsSet := rr.NewSet(zone, rr.TypeNS, section)
	if nsSet.Empty() {
		return Parent{}, fmt.Errorf("%w: %s returned no NS records for %s", ErrNotDelegated, srv, zone)
	}
	p := Parent{Server: srv, NSTTL: nsSet.TTL}
	for _, d := range nsSet.Data {
		p.NS = append(p.NS, rr.Name(d))
	}

	resp, err = q.Query(ctx, srv, dnsq.Question{Name: zone, Type: rr.TypeDS})
	if err != nil {
		return Parent{}, err
	}
	if resp.Rcode != dnsq.RcodeSuccess {
		return Parent{}, fmt.Errorf("parent %s answered %s for %s DS", srv, resp.Rcode, zone)
	}
	for _, rec := range resp.Answer {
		ds, ok := rec.(*dns.DS)
		if !ok || rr.Name(dns.CanonicalName(ds.Hdr.Name)) != zone {
			continue
		}
		if len(p.DS) == 0 || ds.Hdr.Ttl < p.DSTTL {
			p.DSTTL = ds.Hdr.Ttl
		}
		p.DS = append(p.DS, dsRecord(ds))
	}
	slices.SortFunc(p.DS, func(a, b DSRecord) int { return strings.Compare(a.String(), b.String()) })
	return p, nil
}
