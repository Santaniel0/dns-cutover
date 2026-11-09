// Package dnsq sends non-recursive queries to specific authoritative servers:
// UDP with EDNS0, TCP when the reply is truncated, bounded retries, a
// per-server rate limit and prompt cancellation.
package dnsq

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/Santaniel0/dns-cutover/internal/rr"
)

// ErrTimeout is wrapped by errors for attempts that got no reply in time.
var ErrTimeout = errors.New("timed out")

// Question is a name and type to ask about.
type Question struct {
	Name rr.Name
	Type rr.Type
}

func (q Question) String() string { return string(q.Name) + " " + q.Type.String() }

// Rcode is a DNS response code.
type Rcode int

// Response codes the checks branch on.
const (
	RcodeSuccess  = Rcode(dns.RcodeSuccess)
	RcodeNXDomain = Rcode(dns.RcodeNameError)
	RcodeServFail = Rcode(dns.RcodeServerFailure)
	RcodeRefused  = Rcode(dns.RcodeRefused)
)

func (r Rcode) String() string {
	if s, ok := dns.RcodeToString[int(r)]; ok {
		return s
	}
	return "RCODE" + strconv.Itoa(int(r))
}

// Response is the part of a reply the checks look at.
type Response struct {
	Rcode         Rcode
	Authoritative bool
	Answer        []dns.RR
	Authority     []dns.RR
	// TCP is set when the reply came over TCP after a truncated UDP reply.
	TCP bool
}

// Referral reports whether the reply hands the question off to a delegated
// child zone instead of answering it.
func (r Response) Referral() bool {
	if r.Authoritative || r.Rcode != RcodeSuccess || len(r.Answer) > 0 {
		return false
	}
	for _, rec := range r.Authority {
		if rec.Header().Rrtype == dns.TypeNS {
			return true
		}
	}
	return false
}

// QueryError describes a query that got no usable reply.
type QueryError struct {
	Server   Server
	Question Question
	Err      error
}

func (e *QueryError) Error() string {
	return fmt.Sprintf("query %s at %s: %v", e.Question, e.Server, e.Err)
}

func (e *QueryError) Unwrap() error { return e.Err }

// Options tunes a Client. Zero fields take the defaults noted below.
type Options struct {
	// Timeout bounds one attempt. Default 2s.
	Timeout time.Duration
	// Retries is the number of extra attempts after a failed one.
	Retries int
	// Backoff is the pause before retry n, multiplied by n.
	Backoff time.Duration
	// QPS caps queries per second to each server. Zero disables the cap.
	QPS float64
	// UDPSize is the EDNS0 buffer size advertised. Default 1232, the size
	// recommended by DNS Flag Day 2020 to avoid fragmentation.
	UDPSize uint16
}

// transport performs one exchange over one network. It exists so retry and
// fallback logic can be tested without real timeouts.
type transport interface {
	exchange(ctx context.Context, m *dns.Msg, network string, addr netip.AddrPort) (*dns.Msg, error)
}

// Client sends queries. It is safe for concurrent use.
type Client struct {
	opts Options
	tr   transport
	now  func() time.Time

	mu       sync.Mutex
	limiters map[netip.AddrPort]*limiter
}

// NewClient returns a Client that talks to the network.
func NewClient(opts Options) *Client {
	return newClient(opts, netTransport{}, time.Now)
}

func newClient(opts Options, tr transport, now func() time.Time) *Client {
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Second
	}
	if opts.Retries < 0 {
		opts.Retries = 0
	}
	if opts.UDPSize == 0 {
		opts.UDPSize = 1232
	}
	return &Client{opts: opts, tr: tr, now: now, limiters: make(map[netip.AddrPort]*limiter)}
}

// Query asks srv about q with recursion disabled.
func (c *Client) Query(ctx context.Context, srv Server, q Question) (Response, error) {
	fail := func(err error) (Response, error) {
		return Response{}, &QueryError{Server: srv, Question: q, Err: err}
	}
	var lastErr error
	for attempt := 0; attempt <= c.opts.Retries; attempt++ {
		if attempt > 0 && c.opts.Backoff > 0 {
			if err := sleep(ctx, c.opts.Backoff*time.Duration(attempt)); err != nil {
				return fail(err)
			}
		}
		if err := c.limiterFor(srv.Addr).wait(ctx, c.now); err != nil {
			return fail(err)
		}
		resp, err := c.attempt(ctx, srv.Addr, q)
		if err == nil {
			return resp, nil
		}
		if ctx.Err() != nil {
			return fail(ctx.Err())
		}
		lastErr = err
	}
	return fail(lastErr)
}

func (c *Client) attempt(ctx context.Context, addr netip.AddrPort, q Question) (Response, error) {
	m := new(dns.Msg)
	m.SetQuestion(string(q.Name), uint16(q.Type))
	m.RecursionDesired = false
	m.SetEdns0(c.opts.UDPSize, false)

	r, err := c.exchangeOnce(ctx, m, "udp", addr)
	if err != nil {
		return Response{}, err
	}
	tcp := false
	if r.Truncated {
		m.Id = dns.Id()
		if r, err = c.exchangeOnce(ctx, m, "tcp", addr); err != nil {
			return Response{}, fmt.Errorf("tcp after truncated udp reply: %w", err)
		}
		tcp = true
	}
	return Response{
		Rcode:         Rcode(r.Rcode),
		Authoritative: r.Authoritative,
		Answer:        r.Answer,
		Authority:     r.Ns,
		TCP:           tcp,
	}, nil
}

func (c *Client) exchangeOnce(ctx context.Context, m *dns.Msg, network string, addr netip.AddrPort) (*dns.Msg, error) {
	actx, cancel := context.WithTimeout(ctx, c.opts.Timeout)
	defer cancel()
	r, err := c.tr.exchange(actx, m, network, addr)
	if err == nil {
		return r, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return nil, fmt.Errorf("%s: %w after %s", network, ErrTimeout, c.opts.Timeout)
	}
	return nil, fmt.Errorf("%s: %w", network, err)
}

func (c *Client) limiterFor(addr netip.AddrPort) *limiter {
	c.mu.Lock()
	defer c.mu.Unlock()
	l, ok := c.limiters[addr]
	if !ok {
		l = newLimiter(c.opts.QPS)
		c.limiters[addr] = l
	}
	return l
}

// netTransport dials a fresh socket per exchange. miekg/dns only honors
// deadlines while reading, so cancellation is wired up by closing the socket.
type netTransport struct{}

func (netTransport) exchange(ctx context.Context, m *dns.Msg, network string, addr netip.AddrPort) (*dns.Msg, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	client := dns.Client{Net: network}
	r, _, err := client.ExchangeWithConnContext(ctx, m, &dns.Conn{Conn: conn})
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return r, err
}

// limiter spaces queries to one server evenly at no more than qps per second.
type limiter struct {
	interval time.Duration

	mu   sync.Mutex
	next time.Time
}

func newLimiter(qps float64) *limiter {
	if qps <= 0 {
		return &limiter{}
	}
	return &limiter{interval: time.Duration(float64(time.Second) / qps)}
}

// reserve books the next send slot and returns how long to wait for it.
func (l *limiter) reserve(now time.Time) time.Duration {
	if l.interval == 0 {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	return wait
}

func (l *limiter) wait(ctx context.Context, now func() time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return sleep(ctx, l.reserve(now()))
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
