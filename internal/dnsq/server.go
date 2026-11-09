package dnsq

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Santaniel0/dns-cutover/internal/rr"
)

// DefaultPort is the DNS port used when a spec does not name one.
const DefaultPort = 53

var (
	// ErrBadSpec is returned for server specs that cannot be parsed.
	ErrBadSpec = errors.New("invalid server spec")
	// ErrNoAddress is returned when a server host name resolves to nothing.
	ErrNoAddress = errors.New("no address for server")
)

// Server is one nameserver the tool talks to directly.
type Server struct {
	// Host is the nameserver's host name. It is empty when the server was
	// given as a bare address, and then NS-name checks skip it.
	Host rr.Name        `json:"host,omitempty"`
	Addr netip.AddrPort `json:"addr"`
}

// String returns the host name when known, otherwise the address.
func (s Server) String() string {
	if s.Host != "" {
		return string(s.Host)
	}
	return s.Addr.String()
}

// Spec is a server as written on the command line, before host names are
// resolved. Accepted forms: "ns1.example.net", "ns1.example.net:5353",
// "192.0.2.1", "192.0.2.1:5353", "[2001:db8::1]:53" and
// "ns1.example.net=127.0.0.1:5302" (a host name pinned to an address, which
// is how the lab and split-horizon setups name servers).
type Spec struct {
	Host rr.Name
	Addr netip.Addr
	Port uint16
}

// ParseSpec parses one server spec.
func ParseSpec(s string) (Spec, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Spec{}, fmt.Errorf("%w: empty", ErrBadSpec)
	}
	if host, addr, ok := strings.Cut(s, "="); ok {
		name, err := rr.ParseName(host)
		if err != nil {
			return Spec{}, fmt.Errorf("%w %q: %w", ErrBadSpec, s, err)
		}
		a, port, err := parseAddr(addr)
		if err != nil {
			return Spec{}, fmt.Errorf("%w %q: address after '=' must be an IP: %w", ErrBadSpec, s, err)
		}
		return Spec{Host: name, Addr: a, Port: port}, nil
	}
	if a, port, err := parseAddr(s); err == nil {
		return Spec{Addr: a, Port: port}, nil
	}
	host, port := s, uint16(DefaultPort)
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 {
			return Spec{}, fmt.Errorf("%w %q: bad port", ErrBadSpec, s)
		}
		host, port = h, uint16(n)
	}
	name, err := rr.ParseName(host)
	if err != nil {
		return Spec{}, fmt.Errorf("%w %q: %w", ErrBadSpec, s, err)
	}
	return Spec{Host: name, Port: port}, nil
}

// ParseSpecs parses a comma-separated list of specs.
func ParseSpecs(list string) ([]Spec, error) {
	var out []Spec
	for part := range strings.SplitSeq(list, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		sp, err := ParseSpec(part)
		if err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, nil
}

func parseAddr(s string) (netip.Addr, uint16, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		if ap.Port() == 0 {
			return netip.Addr{}, 0, errors.New("port 0")
		}
		return ap.Addr().Unmap(), ap.Port(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	return a.Unmap(), DefaultPort, nil
}

// HostLookup resolves host names. *net.Resolver satisfies it.
type HostLookup interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Resolve turns specs into servers, looking up host names that came without
// an address. A host with several addresses becomes one server, preferring
// IPv4, because the checks are about the provider's data, not about each of
// its anycast addresses.
func Resolve(ctx context.Context, lookup HostLookup, specs []Spec) ([]Server, error) {
	out := make([]Server, 0, len(specs))
	for _, sp := range specs {
		if sp.Addr.IsValid() {
			out = append(out, Server{Host: sp.Host, Addr: netip.AddrPortFrom(sp.Addr, sp.Port)})
			continue
		}
		addrs, err := lookup.LookupNetIP(ctx, "ip", strings.TrimSuffix(string(sp.Host), "."))
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", sp.Host, err)
		}
		a, ok := pickAddr(addrs)
		if !ok {
			return nil, fmt.Errorf("resolve %s: %w", sp.Host, ErrNoAddress)
		}
		out = append(out, Server{Host: sp.Host, Addr: netip.AddrPortFrom(a, sp.Port)})
	}
	return out, nil
}

func pickAddr(addrs []netip.Addr) (netip.Addr, bool) {
	for _, a := range addrs {
		if a.Unmap().Is4() {
			return a.Unmap(), true
		}
	}
	if len(addrs) > 0 {
		return addrs[0], true
	}
	return netip.Addr{}, false
}
