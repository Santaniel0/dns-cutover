// Package finding defines the problems a cutover check reports.
package finding

import (
	"cmp"
	"slices"

	"github.com/Santaniel0/dns-cutover/internal/rr"
)

// Severity says whether a finding should stop the nameserver change.
type Severity uint8

// Severities, ordered so that a larger value is more serious.
const (
	Info Severity = iota + 1
	Warning
	Blocker
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "info"
	case Warning:
		return "warning"
	case Blocker:
		return "blocker"
	default:
		return "unknown"
	}
}

// MarshalText makes severities appear as words in JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Kind is what a finding is about.
type Kind uint8

// Kinds of findings.
const (
	// Missing: the old servers have the RRset, a new server does not.
	Missing Kind = iota + 1
	// Different: both sides have the RRset with different data.
	Different
	// Extra: only the new servers have the RRset.
	Extra
	// TTLOnly: same data, different TTL.
	TTLOnly
	// Proxied: the new answer consists of reverse-proxy addresses.
	Proxied
	// ProxiedTarget: a proxied name is an MX or SRV target, so non-HTTP
	// traffic to it breaks.
	ProxiedTarget
	// OldInconsistent: the old servers disagree with each other.
	OldInconsistent
	// QueryFailed: queries to a server failed, so the comparison is incomplete.
	QueryFailed
	// NotServing: a new server does not answer authoritatively for the zone.
	NotServing
	// SerialMismatch: new servers return different SOA serials.
	SerialMismatch
	// ApexNS: the NS RRset at the new zone apex does not match the new servers.
	ApexNS
	// DNSSEC: the DS at the parent and the new DNSKEYs do not line up.
	DNSSEC
	// Glue: a new nameserver lives inside the zone and needs glue.
	Glue
	// Delegation: facts about the parent delegation, or failure to read it.
	Delegation
	// Timing: TTLs that decide how long the switch takes to settle.
	Timing
	// Inventory: limits of the name list the comparison ran on.
	Inventory
)

var kindNames = map[Kind]string{
	Missing:         "MISSING",
	Different:       "DIFFERENT",
	Extra:           "EXTRA",
	TTLOnly:         "TTL",
	Proxied:         "PROXIED",
	ProxiedTarget:   "PROXIED-TARGET",
	OldInconsistent: "OLD-INCONSISTENT",
	QueryFailed:     "QUERY-FAILED",
	NotServing:      "NOT-SERVING",
	SerialMismatch:  "SERIAL",
	ApexNS:          "APEX-NS",
	DNSSEC:          "DNSSEC",
	Glue:            "GLUE",
	Delegation:      "DELEGATION",
	Timing:          "TIMING",
	Inventory:       "INVENTORY",
}

func (k Kind) String() string {
	if s, ok := kindNames[k]; ok {
		return s
	}
	return "UNKNOWN"
}

// MarshalText makes kinds appear as their report labels in JSON.
func (k Kind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// Finding is one reported problem or fact.
type Finding struct {
	Kind     Kind     `json:"kind"`
	Severity Severity `json:"severity"`
	Name     rr.Name  `json:"name,omitempty"`
	Type     rr.Type  `json:"type,omitzero"`
	// Servers lists the affected servers when only some of them show the
	// problem; empty means all servers on the side concerned.
	Servers []string `json:"servers,omitempty"`
	Old     []string `json:"old,omitempty"`
	New     []string `json:"new,omitempty"`
	OldTTL  uint32   `json:"old_ttl,omitempty"`
	NewTTL  uint32   `json:"new_ttl,omitempty"`
	Detail  string   `json:"detail,omitempty"`
	// Ignored is set when an --ignore rule matched; ignored findings do not
	// affect the verdict.
	Ignored bool `json:"ignored,omitempty"`
}

// Sort orders findings by severity (most serious first), then kind, name and
// type, so reports are stable from run to run.
func Sort(fs []Finding) {
	slices.SortStableFunc(fs, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(b.Severity, a.Severity),
			cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.Type, b.Type),
		)
	})
}
