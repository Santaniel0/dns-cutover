// Package rr holds the canonical forms the comparison works on: owner names,
// record types and RRsets reduced to order-independent presentation strings.
package rr

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

var (
	// ErrInvalidName is returned for strings that are not domain names.
	ErrInvalidName = errors.New("invalid domain name")
	// ErrUnknownType is returned for record type mnemonics miekg/dns does not know.
	ErrUnknownType = errors.New("unknown record type")
)

// Name is a fully qualified, lowercased domain name such as "www.example.com.".
type Name string

// ParseName validates s and returns its canonical form.
func ParseName(s string) (Name, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("%w: empty", ErrInvalidName)
	}
	if _, ok := dns.IsDomainName(s); !ok {
		return "", fmt.Errorf("%w: %q", ErrInvalidName, s)
	}
	return Name(dns.CanonicalName(s)), nil
}

func (n Name) String() string { return string(n) }

// In reports whether n is zone itself or lies below it.
func (n Name) In(zone Name) bool { return dns.IsSubDomain(string(zone), string(n)) }

// Parent returns n without its first label. The root is its own parent.
func (n Name) Parent() Name {
	off, end := dns.NextLabel(string(n), 0)
	if end {
		return "."
	}
	return n[off:]
}

// FirstLabel returns the leftmost label, or "" for the root.
func (n Name) FirstLabel() string {
	labels := dns.SplitDomainName(string(n))
	if len(labels) == 0 {
		return ""
	}
	return labels[0]
}

// ParseRelative reads a name the way zone files do: "@" is the zone itself,
// a name ending in a dot is absolute, anything else is relative to zone.
func ParseRelative(s string, zone Name) (Name, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "@":
		return zone, nil
	case strings.HasSuffix(s, "."):
		return ParseName(s)
	default:
		return zone.Child(s)
	}
}

// Child prepends label to n.
func (n Name) Child(label string) (Name, error) {
	if n == "." {
		return ParseName(label + ".")
	}
	return ParseName(label + "." + string(n))
}

// Type is a DNS RR type code.
type Type uint16

// The record types the tool queries by default or treats specially.
const (
	TypeA      = Type(dns.TypeA)
	TypeNS     = Type(dns.TypeNS)
	TypeCNAME  = Type(dns.TypeCNAME)
	TypeSOA    = Type(dns.TypeSOA)
	TypeMX     = Type(dns.TypeMX)
	TypeTXT    = Type(dns.TypeTXT)
	TypeAAAA   = Type(dns.TypeAAAA)
	TypeSRV    = Type(dns.TypeSRV)
	TypeDS     = Type(dns.TypeDS)
	TypeDNSKEY = Type(dns.TypeDNSKEY)
	TypeCAA    = Type(dns.TypeCAA)
)

func (t Type) String() string {
	if s, ok := dns.TypeToString[uint16(t)]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// MarshalText makes types appear as mnemonics in JSON.
func (t Type) MarshalText() ([]byte, error) { return []byte(t.String()), nil }

// ParseType accepts a mnemonic ("mx", "AAAA") or the RFC 3597 form "TYPE65".
func ParseType(s string) (Type, error) {
	u := strings.ToUpper(strings.TrimSpace(s))
	if v, ok := dns.StringToType[u]; ok {
		return Type(v), nil
	}
	if rest, ok := strings.CutPrefix(u, "TYPE"); ok {
		if v, err := strconv.ParseUint(rest, 10, 16); err == nil {
			return Type(v), nil
		}
	}
	return 0, fmt.Errorf("%w: %q", ErrUnknownType, s)
}

// Set is one RRset as one server returned it. Data holds canonical record
// data, sorted and deduplicated, so two sets compare equal regardless of answer
// order or of how a provider split a long TXT value into strings.
type Set struct {
	Name Name
	Type Type
	TTL  uint32
	Data []string
}

// NewSet builds the set for name and t out of rrs. Records with another owner
// or type are skipped: an A query for an alias returns the CNAME, which belongs
// to a different set.
func NewSet(name Name, t Type, rrs []dns.RR) Set {
	s := Set{Name: name, Type: t}
	for _, r := range rrs {
		h := r.Header()
		if Type(h.Rrtype) != t || Name(dns.CanonicalName(h.Name)) != name {
			continue
		}
		if len(s.Data) == 0 || h.Ttl < s.TTL {
			s.TTL = h.Ttl
		}
		s.Data = append(s.Data, Canonical(r))
	}
	slices.Sort(s.Data)
	s.Data = slices.Compact(s.Data)
	return s
}

// Empty reports whether the server had no records of this type at the name.
func (s Set) Empty() bool { return len(s.Data) == 0 }

// SameData reports whether both sets hold the same records, ignoring TTL.
func (s Set) SameData(o Set) bool { return slices.Equal(s.Data, o.Data) }

// Targets returns the host names MX, SRV, CNAME and NS records point at.
func (s Set) Targets() []Name {
	switch s.Type {
	case TypeMX, TypeSRV, TypeCNAME, TypeNS:
	default:
		return nil
	}
	out := make([]Name, 0, len(s.Data))
	for _, d := range s.Data {
		fields := strings.Fields(d)
		if len(fields) == 0 {
			continue
		}
		out = append(out, Name(fields[len(fields)-1]))
	}
	return out
}

// Addrs returns the addresses of an A or AAAA set.
func (s Set) Addrs() []netip.Addr {
	if s.Type != TypeA && s.Type != TypeAAAA {
		return nil
	}
	out := make([]netip.Addr, 0, len(s.Data))
	for _, d := range s.Data {
		if a, err := netip.ParseAddr(d); err == nil {
			out = append(out, a)
		}
	}
	return out
}

// Canonical renders the record data of r in a form where equal data gives
// equal strings: names lowercased, addresses normalized, TXT strings joined.
func Canonical(r dns.RR) string {
	switch v := r.(type) {
	case *dns.A:
		// Parsed zone files hold A data as 16-byte slices, wire data as 4 bytes.
		return addrString(v.A, true)
	case *dns.AAAA:
		return addrString(v.AAAA, false)
	case *dns.CNAME:
		return dns.CanonicalName(v.Target)
	case *dns.NS:
		return dns.CanonicalName(v.Ns)
	case *dns.PTR:
		return dns.CanonicalName(v.Ptr)
	case *dns.DNAME:
		return dns.CanonicalName(v.Target)
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, dns.CanonicalName(v.Mx))
	case *dns.SRV:
		return fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, dns.CanonicalName(v.Target))
	case *dns.TXT:
		// Character-strings are capped at 255 bytes, and providers cut long
		// values (DKIM keys) at different points. Consumers concatenate them,
		// so the joined value is what has to match.
		return `"` + strings.Join(v.Txt, "") + `"`
	case *dns.SPF:
		return `"` + strings.Join(v.Txt, "") + `"`
	case *dns.CAA:
		return fmt.Sprintf("%d %s %q", v.Flag, strings.ToLower(v.Tag), v.Value)
	case *dns.TLSA:
		return fmt.Sprintf("%d %d %d %s", v.Usage, v.Selector, v.MatchingType, strings.ToLower(v.Certificate))
	case *dns.DS:
		return fmt.Sprintf("%d %d %d %s", v.KeyTag, v.Algorithm, v.DigestType, strings.ToLower(v.Digest))
	default:
		return strings.TrimSpace(strings.TrimPrefix(r.String(), r.Header().String()))
	}
}

func addrString(ip []byte, unmap bool) string {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Sprintf("invalid(%x)", ip)
	}
	if unmap {
		a = a.Unmap()
	}
	return a.String()
}
