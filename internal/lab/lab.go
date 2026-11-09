// Package lab starts the fake DNS world from testdata/lab: a parent zone, an
// old provider with one server and a new provider with two. The dnslab
// command serves it for people to try dnscutover; end-to-end tests use it so
// the README demo and the tests run on the same data.
package lab

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/Santaniel0/dns-cutover/internal/dnstest"
	"github.com/Santaniel0/dns-cutover/internal/rr"
)

// Zone is the zone being moved in the lab.
const Zone rr.Name = "example.test."

// Scenario picks which version of the new provider's zone is served.
type Scenario uint8

// Scenarios.
const (
	// Broken is the zone as first imported into the new provider.
	Broken Scenario = iota + 1
	// Fixed is the same zone after the owner fixed what dnscutover reported.
	Fixed
)

func (s Scenario) String() string {
	switch s {
	case Broken:
		return "broken"
	case Fixed:
		return "fixed"
	default:
		return "unknown"
	}
}

// ParseScenario accepts "broken" or "fixed".
func ParseScenario(s string) (Scenario, error) {
	for _, sc := range []Scenario{Broken, Fixed} {
		if strings.EqualFold(s, sc.String()) {
			return sc, nil
		}
	}
	return 0, fmt.Errorf("unknown scenario %q (want broken or fixed)", s)
}

// Server is one running lab server.
type Server struct {
	Role string
	// Host is empty for the parent, which is addressed by IP only.
	Host rr.Name
	Zone rr.Name
	srv  *dnstest.Server
}

// Addr is where the server listens.
func (s Server) Addr() netip.AddrPort { return s.srv.Addr() }

// Lab is a running set of servers.
type Lab struct {
	Dir     string
	Parent  Server
	Old     Server
	New     []Server
	servers []*dnstest.Server
}

// Start loads the zones from dir and serves them on 127.0.0.1. With basePort
// 0 every server gets a free port; otherwise they take basePort..basePort+3.
func Start(dir string, sc Scenario, basePort int) (*Lab, error) {
	l := &Lab{Dir: dir}
	plan := []struct {
		dst        *Server
		role       string
		host, zone rr.Name
		file       string
	}{
		{&l.Parent, "parent", "", "test.", filepath.Join(dir, sc.String(), "parent.zone")},
		{&l.Old, "old", "ns1.olddns.test.", Zone, filepath.Join(dir, "old.zone")},
		{nil, "new", "ns1.newdns.test.", Zone, filepath.Join(dir, sc.String(), "new-a.zone")},
		{nil, "new", "ns2.newdns.test.", Zone, filepath.Join(dir, sc.String(), "new-b.zone")},
	}
	for i, p := range plan {
		z, err := dnstest.LoadZone(string(p.zone), p.file)
		if err != nil {
			return nil, errors.Join(err, l.Close())
		}
		addr := "127.0.0.1:0"
		if basePort != 0 {
			addr = fmt.Sprintf("127.0.0.1:%d", basePort+i)
		}
		srv, err := dnstest.Start(dnstest.Options{Addr: addr, Zones: []*dnstest.Zone{z}})
		if err != nil {
			return nil, errors.Join(err, l.Close())
		}
		l.servers = append(l.servers, srv)
		s := Server{Role: p.role, Host: p.host, Zone: p.zone, srv: srv}
		if p.dst != nil {
			*p.dst = s
		} else {
			l.New = append(l.New, s)
		}
	}
	return l, nil
}

// Close stops every server.
func (l *Lab) Close() error {
	var errs []error
	for _, s := range l.servers {
		errs = append(errs, s.Close())
	}
	return errors.Join(errs...)
}

// CheckArgs returns the dnscutover arguments that point a check at the lab.
func (l *Lab) CheckArgs() []string {
	pin := func(s Server) string { return strings.TrimSuffix(string(s.Host), ".") + "=" + s.Addr().String() }
	news := make([]string, 0, len(l.New))
	for _, s := range l.New {
		news = append(news, pin(s))
	}
	return []string{
		"check", strings.TrimSuffix(string(Zone), "."),
		"--parent", l.Parent.Addr().String(),
		"--old", pin(l.Old),
		"--new", strings.Join(news, ","),
		"--zone-file", filepath.ToSlash(filepath.Join(l.Dir, "export.zone")),
		"--names", filepath.ToSlash(filepath.Join(l.Dir, "names.txt")),
	}
}
