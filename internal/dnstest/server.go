// Package dnstest runs small authoritative DNS servers on the loopback
// interface. Tests and the lab command use them in place of real providers.
//
// The server implements the parts of RFC 1034 answer selection the checks
// depend on: AA answers, NODATA vs NXDOMAIN, CNAME at a name, wildcards via
// the closest encloser, referrals at zone cuts and DS served by the parent.
package dnstest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

// Action tells the server what to do with one query.
type Action uint8

// Actions a Hook can return.
const (
	Answer Action = iota
	Drop
	Refuse
	ServFail
)

// Hook runs before every reply. It may block; ctx is canceled when the server
// closes, so a blocking hook must watch it.
type Hook func(ctx context.Context, network string, q dns.Question) Action

// Options configures a Server.
type Options struct {
	// Addr is the UDP and TCP listen address. Empty means 127.0.0.1 on a
	// free port.
	Addr  string
	Zones []*Zone
	// TruncateUDP sets TC on every UDP reply that carries records, which
	// forces clients over to TCP.
	TruncateUDP bool
	Hook        Hook
}

// Server is a running fake authoritative server.
type Server struct {
	addr     netip.AddrPort
	udp, tcp *dns.Server
	zones    []*Zone
	truncate bool
	hook     Hook
	ctx      context.Context
	cancel   context.CancelFunc
	queries  atomic.Int64
}

// Start listens on UDP and TCP and serves until Close.
func Start(opts Options) (*Server, error) {
	addr := opts.Addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	pc, ln, err := listenBoth(addr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		addr:     pc.LocalAddr().(*net.UDPAddr).AddrPort(),
		zones:    opts.Zones,
		truncate: opts.TruncateUDP,
		hook:     opts.Hook,
		ctx:      ctx,
		cancel:   cancel,
	}
	started := make(chan struct{}, 2)
	notify := func() { started <- struct{}{} }
	s.udp = &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(s.serve), NotifyStartedFunc: notify}
	s.tcp = &dns.Server{Listener: ln, Handler: dns.HandlerFunc(s.serve), NotifyStartedFunc: notify}
	errs := make(chan error, 2)
	for _, srv := range []*dns.Server{s.udp, s.tcp} {
		go func() { errs <- srv.ActivateAndServe() }()
	}
	for range 2 {
		select {
		case <-started:
		case err := <-errs:
			cancel()
			pc.Close()
			ln.Close()
			return nil, fmt.Errorf("dnstest: serve: %w", err)
		}
	}
	return s, nil
}

// listenBoth binds UDP first and then TCP on the same port. With port 0 the
// kernel may hand out a UDP port whose TCP twin is taken, so retry a few times.
func listenBoth(addr string) (net.PacketConn, net.Listener, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, nil, fmt.Errorf("dnstest: %w", err)
	}
	var lastErr error
	for range 10 {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return nil, nil, fmt.Errorf("dnstest: listen udp %s: %w", addr, err)
		}
		bound := pc.LocalAddr().(*net.UDPAddr).AddrPort().Port()
		ln, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprint(bound)))
		if err == nil {
			return pc, ln, nil
		}
		pc.Close()
		lastErr = err
		if port != "0" {
			break
		}
	}
	return nil, nil, fmt.Errorf("dnstest: listen tcp: %w", lastErr)
}

// Addr is the address the server listens on for both UDP and TCP.
func (s *Server) Addr() netip.AddrPort { return s.addr }

// Queries counts the queries received so far, dropped ones included.
func (s *Server) Queries() int64 { return s.queries.Load() }

// Close releases blocked hooks and stops both listeners.
func (s *Server) Close() error {
	s.cancel()
	return errors.Join(s.udp.Shutdown(), s.tcp.Shutdown())
}

func (s *Server) serve(w dns.ResponseWriter, req *dns.Msg) {
	s.queries.Add(1)
	network := w.LocalAddr().Network()
	resp := new(dns.Msg)
	resp.SetReply(req)
	if len(req.Question) != 1 {
		resp.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(resp)
		return
	}
	q := req.Question[0]
	action := Answer
	if s.hook != nil {
		action = s.hook(s.ctx, network, q)
	}
	switch action {
	case Drop:
		return
	case Refuse:
		resp.Rcode = dns.RcodeRefused
	case ServFail:
		resp.Rcode = dns.RcodeServerFailure
	default:
		s.answer(resp, q)
	}

	size := dns.MinMsgSize
	if opt := req.IsEdns0(); opt != nil {
		size = int(opt.UDPSize())
		resp.SetEdns0(opt.UDPSize(), false)
	}
	if network == "udp" {
		if s.truncate && len(resp.Answer)+len(resp.Ns) > 0 {
			resp.Truncated = true
			resp.Answer, resp.Ns = nil, nil
		} else {
			resp.Truncate(size)
		}
	}
	_ = w.WriteMsg(resp)
}

func (s *Server) answer(resp *dns.Msg, q dns.Question) {
	qname := dns.CanonicalName(q.Name)
	var best *Zone
	for _, z := range s.zones {
		if dns.IsSubDomain(z.origin, qname) && (best == nil || len(z.origin) > len(best.origin)) {
			best = z
		}
	}
	if best == nil {
		resp.Rcode = dns.RcodeRefused
		return
	}
	best.resolve(resp, qname, q.Qtype)
}

// Zone is the data for one zone, indexed for lookups.
type Zone struct {
	origin string
	soa    []dns.RR
	byName map[string][]dns.RR
	// exists holds owner names and the empty non-terminals above them.
	exists map[string]bool
}

// ParseZone reads RFC 1035 zone text for origin.
func ParseZone(origin string, r io.Reader) (*Zone, error) {
	origin = dns.CanonicalName(origin)
	z := &Zone{origin: origin, byName: make(map[string][]dns.RR), exists: map[string]bool{origin: true}}
	zp := dns.NewZoneParser(r, origin, "")
	for rec, ok := zp.Next(); ok; rec, ok = zp.Next() {
		name := dns.CanonicalName(rec.Header().Name)
		if !dns.IsSubDomain(origin, name) {
			continue
		}
		rec.Header().Name = name
		z.byName[name] = append(z.byName[name], rec)
		if rec.Header().Rrtype == dns.TypeSOA && name == origin {
			z.soa = append(z.soa, rec)
		}
		for n := name; n != origin; n = parent(n) {
			z.exists[n] = true
		}
	}
	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("dnstest: zone %s: %w", origin, err)
	}
	return z, nil
}

// MustParseZone is ParseZone for zone text embedded in tests.
func MustParseZone(origin, text string) *Zone {
	z, err := ParseZone(origin, strings.NewReader(text))
	if err != nil {
		panic(err)
	}
	return z
}

// LoadZone reads a zone file from disk.
func LoadZone(origin, path string) (*Zone, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("dnstest: %w", err)
	}
	defer f.Close()
	return ParseZone(origin, f)
}

func (z *Zone) resolve(resp *dns.Msg, qname string, qtype uint16) {
	if cut, ns := z.cut(qname); cut != "" && (qtype != dns.TypeDS || qname != cut) {
		resp.Ns = ns
		resp.Extra = z.glue(ns)
		return
	}
	resp.Authoritative = true
	recs, ok := z.byName[qname]
	if !ok && !z.exists[qname] {
		wild, found := z.wildcard(qname)
		if !found {
			resp.Rcode = dns.RcodeNameError
			resp.Ns = z.soa
			return
		}
		recs = wild
	}
	ans := ofType(recs, qtype)
	if len(ans) == 0 && qtype != dns.TypeCNAME {
		ans = ofType(recs, dns.TypeCNAME)
	}
	if len(ans) == 0 {
		resp.Ns = z.soa
		return
	}
	resp.Answer = ans
}

// cut finds the delegation point at or above qname, below the apex.
func (z *Zone) cut(qname string) (string, []dns.RR) {
	var labels []string
	for n := qname; n != z.origin && dns.IsSubDomain(z.origin, n); n = parent(n) {
		labels = append(labels, n)
	}
	// Walk top-down so the highest cut wins, as it does in a real server.
	for i := len(labels) - 1; i >= 0; i-- {
		if ns := ofType(z.byName[labels[i]], dns.TypeNS); len(ns) > 0 {
			return labels[i], ns
		}
	}
	return "", nil
}

func (z *Zone) glue(ns []dns.RR) []dns.RR {
	var out []dns.RR
	for _, r := range ns {
		target := dns.CanonicalName(r.(*dns.NS).Ns)
		out = append(out, ofType(z.byName[target], dns.TypeA)...)
		out = append(out, ofType(z.byName[target], dns.TypeAAAA)...)
	}
	return out
}

// wildcard applies RFC 4592: find the closest encloser of qname and look for
// a "*" child of it.
func (z *Zone) wildcard(qname string) ([]dns.RR, bool) {
	encloser := parent(qname)
	for !z.exists[encloser] && encloser != z.origin {
		encloser = parent(encloser)
	}
	src, ok := z.byName["*."+encloser]
	if !ok {
		return nil, false
	}
	out := make([]dns.RR, 0, len(src))
	for _, r := range src {
		c := dns.Copy(r)
		c.Header().Name = qname
		out = append(out, c)
	}
	return out, true
}

func ofType(rrs []dns.RR, t uint16) []dns.RR {
	var out []dns.RR
	for _, r := range rrs {
		if r.Header().Rrtype == t {
			out = append(out, r)
		}
	}
	return out
}

func parent(name string) string {
	off, end := dns.NextLabel(name, 0)
	if end {
		return "."
	}
	return name[off:]
}
