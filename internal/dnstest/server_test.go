package dnstest

import (
	"testing"

	"github.com/miekg/dns"
)

const parentZone = `
$ORIGIN test.
@        3600 IN SOA a.nic.test. hostmaster.nic.test. 1 7200 3600 1209600 300
@        3600 IN NS a.nic.test.
a.nic    3600 IN A 127.0.0.1
example 172800 IN NS ns1.example.test.
example 172800 IN DS 29212 13 2 DF74CEA5E9F8F95056E8245A1FD23D7728BE6997C5E6C19E3F18659EA1CBE384
ns1.example 172800 IN A 192.0.2.53
`

const childZone = `
$ORIGIN example.test.
@     300 IN SOA ns1 hostmaster 7 7200 3600 1209600 300
@     300 IN NS ns1
@     300 IN A 192.0.2.10
www   300 IN CNAME @
*.wild 300 IN A 192.0.2.99
deep.a.b 300 IN TXT "leaf"
`

func exchange(t *testing.T, s *Server, network, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	c := dns.Client{Net: network}
	r, _, err := c.Exchange(m, s.Addr().String())
	if err != nil {
		t.Fatalf("exchange %s %s: %v", name, dns.TypeToString[qtype], err)
	}
	return r
}

func TestAnswerSelection(t *testing.T) {
	s, err := Start(Options{Zones: []*Zone{MustParseZone("test.", parentZone), MustParseZone("example.test.", childZone)}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	tests := []struct {
		name      string
		qname     string
		qtype     uint16
		rcode     int
		aa        bool
		answers   int
		authority int
		answerTyp uint16
	}{
		{"apex A", "example.test.", dns.TypeA, dns.RcodeSuccess, true, 1, 0, dns.TypeA},
		{"nodata", "example.test.", dns.TypeMX, dns.RcodeSuccess, true, 0, 1, 0},
		{"nxdomain", "nope.example.test.", dns.TypeA, dns.RcodeNameError, true, 0, 1, 0},
		{"cname for other type", "www.example.test.", dns.TypeA, dns.RcodeSuccess, true, 1, 0, dns.TypeCNAME},
		{"wildcard", "anything.wild.example.test.", dns.TypeA, dns.RcodeSuccess, true, 1, 0, dns.TypeA},
		{"empty non-terminal is nodata", "a.b.example.test.", dns.TypeA, dns.RcodeSuccess, true, 0, 1, 0},
		{"no wildcard below an existing name", "x.a.b.example.test.", dns.TypeA, dns.RcodeNameError, true, 0, 1, 0},
		{"foreign zone refused", "example.org.", dns.TypeA, dns.RcodeRefused, false, 0, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := exchange(t, s, "udp", tt.qname, tt.qtype)
			if r.Rcode != tt.rcode || r.Authoritative != tt.aa || len(r.Answer) != tt.answers || len(r.Ns) != tt.authority {
				t.Fatalf("rcode=%d aa=%v answers=%d ns=%d\n%v", r.Rcode, r.Authoritative, len(r.Answer), len(r.Ns), r)
			}
			if tt.answers > 0 && r.Answer[0].Header().Rrtype != tt.answerTyp {
				t.Errorf("answer type %s, want %s", dns.TypeToString[r.Answer[0].Header().Rrtype], dns.TypeToString[tt.answerTyp])
			}
			if tt.name == "wildcard" && r.Answer[0].Header().Name != tt.qname {
				t.Errorf("wildcard answer owner %q, want synthesized %q", r.Answer[0].Header().Name, tt.qname)
			}
		})
	}
}

func TestParentOnlyServer(t *testing.T) {
	s, err := Start(Options{Zones: []*Zone{MustParseZone("test.", parentZone)}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	r := exchange(t, s, "udp", "example.test.", dns.TypeNS)
	if r.Authoritative || len(r.Answer) != 0 || len(r.Ns) != 1 || len(r.Extra) == 0 {
		t.Fatalf("want a referral with glue, got %v", r)
	}
	r = exchange(t, s, "udp", "example.test.", dns.TypeDS)
	if !r.Authoritative || len(r.Answer) != 1 || r.Answer[0].Header().Rrtype != dns.TypeDS {
		t.Fatalf("parent must answer DS authoritatively, got %v", r)
	}
	r = exchange(t, s, "udp", "www.example.test.", dns.TypeA)
	if r.Authoritative || len(r.Ns) != 1 {
		t.Fatalf("names below the cut get a referral, got %v", r)
	}
}

func TestTruncateUDP(t *testing.T) {
	s, err := Start(Options{Zones: []*Zone{MustParseZone("example.test.", childZone)}, TruncateUDP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if r := exchange(t, s, "udp", "example.test.", dns.TypeA); !r.Truncated || len(r.Answer) != 0 {
		t.Fatalf("udp reply should be truncated and empty: %v", r)
	}
	if r := exchange(t, s, "tcp", "example.test.", dns.TypeA); r.Truncated || len(r.Answer) != 1 {
		t.Fatalf("tcp reply should be complete: %v", r)
	}
	if got := s.Queries(); got != 2 {
		t.Errorf("Queries = %d, want 2", got)
	}
}
