// Package inventory builds the list of names to compare. Public
// authoritative servers almost never allow zone transfers, so the list is
// assembled from what the user has (a zone file export, a list of names) and
// from probing common labels.
package inventory

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/Santaniel0/dns-cutover/internal/rr"
)

// ErrOutsideZone is returned for names that do not belong to the zone.
var ErrOutsideZone = errors.New("name is outside the zone")

// Source says how a name got into the inventory.
type Source uint8

// Sources of names.
const (
	FromApex Source = iota + 1
	FromZoneFile
	FromNamesFile
	FromProbe
)

func (s Source) String() string {
	switch s {
	case FromApex:
		return "apex"
	case FromZoneFile:
		return "zone-file"
	case FromNamesFile:
		return "names-file"
	case FromProbe:
		return "probe"
	default:
		return "unknown"
	}
}

// MarshalText makes sources appear as words in JSON.
func (s Source) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Entry is one name to compare.
type Entry struct {
	Name rr.Name `json:"name"`
	// Types are record types the zone file has at this name. They are
	// queried on top of the defaults, so rarer types (TLSA, SSHFP) are
	// compared when the export shows them.
	Types   []rr.Type `json:"types,omitempty"`
	Sources []Source  `json:"sources"`
}

// Inventory is the final, sorted name list.
type Inventory struct {
	Zone    rr.Name `json:"zone"`
	Entries []Entry `json:"entries"`
	// Skipped counts zone file records outside the zone.
	Skipped int        `json:"skipped_records,omitempty"`
	Probe   ProbeStats `json:"probe"`
}

// Count returns how many entries came from src (an entry can count for
// several sources).
func (inv Inventory) Count(src Source) int {
	n := 0
	for _, e := range inv.Entries {
		if slices.Contains(e.Sources, src) {
			n++
		}
	}
	return n
}

// Collector merges names from several sources.
type Collector struct {
	zone    rr.Name
	entries map[rr.Name]*Entry
	skipped int
}

// NewCollector starts an inventory for zone with the apex already in it.
func NewCollector(zone rr.Name) *Collector {
	c := &Collector{zone: zone, entries: make(map[rr.Name]*Entry)}
	c.entries[zone] = &Entry{Name: zone, Sources: []Source{FromApex}}
	return c
}

// Add records name as found by src, with any record types seen for it.
func (c *Collector) Add(name rr.Name, src Source, types ...rr.Type) error {
	if !name.In(c.zone) {
		return fmt.Errorf("%w: %s is not in %s", ErrOutsideZone, name, c.zone)
	}
	e, ok := c.entries[name]
	if !ok {
		e = &Entry{Name: name}
		c.entries[name] = e
	}
	if !slices.Contains(e.Sources, src) {
		e.Sources = append(e.Sources, src)
	}
	for _, t := range types {
		if !slices.Contains(e.Types, t) {
			e.Types = append(e.Types, t)
		}
	}
	return nil
}

// Inventory returns the collected names, apex first, then in DNS order of
// their labels read right to left, which keeps a subdomain next to its parent.
func (c *Collector) Inventory(probe ProbeStats) Inventory {
	inv := Inventory{Zone: c.zone, Probe: probe, Skipped: c.skipped, Entries: make([]Entry, 0, len(c.entries))}
	for _, e := range c.entries {
		slices.Sort(e.Types)
		slices.Sort(e.Sources)
		inv.Entries = append(inv.Entries, *e)
	}
	slices.SortFunc(inv.Entries, func(a, b Entry) int { return compareNames(a.Name, b.Name) })
	return inv
}

func compareNames(a, b rr.Name) int {
	la, lb := dns.SplitDomainName(string(a)), dns.SplitDomainName(string(b))
	slices.Reverse(la)
	slices.Reverse(lb)
	return slices.Compare(la, lb)
}

// skipType lists types that are not compared record by record: SOA and the
// DNSSEC records differ by design between providers, and the delegation
// checks look at the ones that matter (DNSKEY against the parent's DS).
func skipType(t uint16) bool {
	switch t {
	case dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM,
		dns.TypeDNSKEY, dns.TypeCDS, dns.TypeCDNSKEY, dns.TypeZONEMD:
		return true
	}
	return false
}

// ReadZoneFile adds every owner name in a BIND-format zone file. Records
// outside the zone (glue for other domains, stray lines from a combined
// export) are counted in Inventory.Skipped rather than failing the run.
func ReadZoneFile(r io.Reader, filename string, c *Collector) error {
	zp := dns.NewZoneParser(r, string(c.zone), filename)
	for rec, ok := zp.Next(); ok; rec, ok = zp.Next() {
		name := rr.Name(dns.CanonicalName(rec.Header().Name))
		if !name.In(c.zone) {
			c.skipped++
			continue
		}
		var err error
		t := rec.Header().Rrtype
		if skipType(t) || (t == dns.TypeNS && name == c.zone) {
			err = c.Add(name, FromZoneFile)
		} else {
			err = c.Add(name, FromZoneFile, rr.Type(t))
		}
		if err != nil {
			return err
		}
	}
	if err := zp.Err(); err != nil {
		return fmt.Errorf("zone file %s: %w", filename, err)
	}
	return nil
}

// ReadNames adds names listed one per line. Names without a trailing dot are
// relative to the zone, "@" is the apex, and # starts a comment.
func ReadNames(r io.Reader, c *Collector) error {
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		text, _, _ := strings.Cut(sc.Text(), "#")
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		name, err := rr.ParseRelative(text, c.zone)
		if err != nil {
			return fmt.Errorf("names line %d: %w", line, err)
		}
		if err := c.Add(name, FromNamesFile); err != nil {
			return fmt.Errorf("names line %d: %w", line, err)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read names: %w", err)
	}
	return nil
}
