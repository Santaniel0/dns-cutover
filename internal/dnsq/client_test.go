package dnsq

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/Santaniel0/dns-cutover/internal/dnstest"
	"github.com/Santaniel0/dns-cutover/internal/rr"
)

const zoneText = `
$ORIGIN example.test.
@   300 IN SOA ns1 hostmaster 1 7200 3600 1209600 300
@   300 IN NS ns1
@   300 IN A 192.0.2.10
`

var apexA = Question{Name: "example.test.", Type: rr.TypeA}

// scripted replays canned results, one per exchange, and records which
// network each exchange used.
type scripted struct {
	mu       sync.Mutex
	networks []string
	steps    []func(m *dns.Msg) (*dns.Msg, error)
}

func (s *scripted) exchange(_ context.Context, m *dns.Msg, network string, _ netip.AddrPort) (*dns.Msg, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := len(s.networks)
	s.networks = append(s.networks, network)
	if i >= len(s.steps) {
		return nil, errors.New("unexpected extra exchange")
	}
	return s.steps[i](m)
}

func timeoutStep(*dns.Msg) (*dns.Msg, error) { return nil, context.DeadlineExceeded }

func replyStep(truncated bool) func(*dns.Msg) (*dns.Msg, error) {
	return func(m *dns.Msg) (*dns.Msg, error) {
		r := new(dns.Msg)
		r.SetReply(m)
		r.Authoritative = true
		r.Truncated = truncated
		if !truncated {
			rec, _ := dns.NewRR("example.test. 300 IN A 192.0.2.10")
			r.Answer = []dns.RR{rec}
		}
		return r, nil
	}
}

var testServer = Server{Addr: netip.MustParseAddrPort("127.0.0.1:53")}

func TestQueryRetriesAfterTimeout(t *testing.T) {
	tr := &scripted{steps: []func(*dns.Msg) (*dns.Msg, error){timeoutStep, replyStep(false)}}
	c := newClient(Options{Retries: 2}, tr, time.Now)
	resp, err := c.Query(context.Background(), testServer, apexA)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 || len(tr.networks) != 2 {
		t.Errorf("answers=%d exchanges=%d, want 1 answer after 2 exchanges", len(resp.Answer), len(tr.networks))
	}
}

func TestQueryGivesUp(t *testing.T) {
	tr := &scripted{steps: []func(*dns.Msg) (*dns.Msg, error){timeoutStep, timeoutStep, timeoutStep}}
	c := newClient(Options{Retries: 2}, tr, time.Now)
	_, err := c.Query(context.Background(), testServer, apexA)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	var qe *QueryError
	if !errors.As(err, &qe) || qe.Question != apexA || qe.Server != testServer {
		t.Fatalf("err should be a *QueryError naming the query: %#v", err)
	}
	if len(tr.networks) != 3 {
		t.Errorf("exchanges = %d, want 1 + 2 retries", len(tr.networks))
	}
}

func TestTruncatedReplyGoesToTCP(t *testing.T) {
	tr := &scripted{steps: []func(*dns.Msg) (*dns.Msg, error){replyStep(true), replyStep(false)}}
	c := newClient(Options{}, tr, time.Now)
	resp, err := c.Query(context.Background(), testServer, apexA)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.TCP || len(resp.Answer) != 1 {
		t.Errorf("TCP=%v answers=%d", resp.TCP, len(resp.Answer))
	}
	if got := tr.networks; len(got) != 2 || got[0] != "udp" || got[1] != "tcp" {
		t.Errorf("networks = %v, want [udp tcp]", got)
	}
}

func TestLimiterSpacing(t *testing.T) {
	l := newLimiter(4) // one slot every 250ms
	t0 := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	got := []time.Duration{l.reserve(t0), l.reserve(t0), l.reserve(t0)}
	want := []time.Duration{0, 250 * time.Millisecond, 500 * time.Millisecond}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("reserve #%d = %v, want %v", i, got[i], want[i])
		}
	}
	// After an idle second the schedule restarts from now instead of
	// letting a burst of queued slots through.
	if d := l.reserve(t0.Add(2 * time.Second)); d != 0 {
		t.Errorf("reserve after idle = %v, want 0", d)
	}
	if d := newLimiter(0).reserve(t0); d != 0 {
		t.Errorf("unlimited limiter waited %v", d)
	}
}

func TestRealServerTCPFallback(t *testing.T) {
	s, err := dnstest.Start(dnstest.Options{Zones: []*dnstest.Zone{dnstest.MustParseZone("example.test.", zoneText)}, TruncateUDP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	c := NewClient(Options{Timeout: 5 * time.Second})
	resp, err := c.Query(context.Background(), Server{Addr: s.Addr()}, apexA)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.TCP || !resp.Authoritative || len(resp.Answer) != 1 {
		t.Errorf("got TCP=%v AA=%v answers=%d", resp.TCP, resp.Authoritative, len(resp.Answer))
	}
}

func TestRealServerTimeout(t *testing.T) {
	drop := func(context.Context, string, dns.Question) dnstest.Action { return dnstest.Drop }
	s, err := dnstest.Start(dnstest.Options{Zones: []*dnstest.Zone{dnstest.MustParseZone("example.test.", zoneText)}, Hook: drop})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	c := NewClient(Options{Timeout: 50 * time.Millisecond})
	_, err = c.Query(context.Background(), Server{Addr: s.Addr()}, apexA)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
}

func TestCancelUnblocksPendingRead(t *testing.T) {
	entered := make(chan struct{}, 1)
	block := func(ctx context.Context, _ string, _ dns.Question) dnstest.Action {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return dnstest.Drop
	}
	s, err := dnstest.Start(dnstest.Options{Zones: []*dnstest.Zone{dnstest.MustParseZone("example.test.", zoneText)}, Hook: block})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// The attempt timeout is far beyond the test's patience, so only
	// cancellation can end the query.
	c := NewClient(Options{Timeout: time.Hour, Retries: 3})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.Query(ctx, Server{Addr: s.Addr()}, apexA)
		done <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Query did not return after cancel")
	}
}

func TestQueryWithCanceledContextSendsNothing(t *testing.T) {
	tr := &scripted{}
	c := newClient(Options{}, tr, time.Now)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Query(ctx, testServer, apexA); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if len(tr.networks) != 0 {
		t.Errorf("sent %d exchanges on a canceled context", len(tr.networks))
	}
}
