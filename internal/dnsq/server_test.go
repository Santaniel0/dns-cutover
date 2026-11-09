package dnsq

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestParseSpec(t *testing.T) {
	tests := []struct {
		in   string
		want Spec
		err  bool
	}{
		{in: "ns1.reg.ru", want: Spec{Host: "ns1.reg.ru.", Port: 53}},
		{in: "NS1.Example.net.:5353", want: Spec{Host: "ns1.example.net.", Port: 5353}},
		{in: "192.0.2.1", want: Spec{Addr: netip.MustParseAddr("192.0.2.1"), Port: 53}},
		{in: "192.0.2.1:5302", want: Spec{Addr: netip.MustParseAddr("192.0.2.1"), Port: 5302}},
		{in: "[2001:db8::1]:53", want: Spec{Addr: netip.MustParseAddr("2001:db8::1"), Port: 53}},
		{in: "2001:db8::1", want: Spec{Addr: netip.MustParseAddr("2001:db8::1"), Port: 53}},
		{in: "ns1.newdns.test=127.0.0.1:5302", want: Spec{Host: "ns1.newdns.test.", Addr: netip.MustParseAddr("127.0.0.1"), Port: 5302}},
		{in: "ns1.newdns.test=ns2.other.test", err: true},
		{in: "", err: true},
		{in: "ns1.example.net:99999", err: true},
		{in: "127.0.0.1:0", err: true},
	}
	for _, tt := range tests {
		got, err := ParseSpec(tt.in)
		if tt.err {
			if !errors.Is(err, ErrBadSpec) {
				t.Errorf("ParseSpec(%q) err = %v, want ErrBadSpec", tt.in, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("ParseSpec(%q) = %+v, %v; want %+v", tt.in, got, err, tt.want)
		}
	}
}

func TestParseSpecs(t *testing.T) {
	got, err := ParseSpecs("ns1.a.test, ns2.a.test,,")
	if err != nil || len(got) != 2 || got[1].Host != "ns2.a.test." {
		t.Fatalf("ParseSpecs = %+v, %v", got, err)
	}
}

type fakeLookup map[string][]netip.Addr

func (f fakeLookup) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func TestResolve(t *testing.T) {
	lookup := fakeLookup{
		"ns1.reg.ru": {netip.MustParseAddr("2001:db8::53"), netip.MustParseAddr("194.58.117.17")},
		"v6only.net": {netip.MustParseAddr("2001:db8::1")},
		"empty.net":  {},
	}
	specs := []Spec{
		{Host: "ns1.reg.ru.", Port: 53},
		{Host: "v6only.net.", Port: 53},
		{Host: "pinned.test.", Addr: netip.MustParseAddr("127.0.0.1"), Port: 5302},
	}
	got, err := Resolve(context.Background(), lookup, specs)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"194.58.117.17:53", "[2001:db8::1]:53", "127.0.0.1:5302"}
	for i, w := range want {
		if got[i].Addr.String() != w {
			t.Errorf("server %d addr = %s, want %s", i, got[i].Addr, w)
		}
	}
	if got[2].String() != "pinned.test." {
		t.Errorf("String() = %q", got[2].String())
	}
	if _, err := Resolve(context.Background(), lookup, []Spec{{Host: "empty.net.", Port: 53}}); !errors.Is(err, ErrNoAddress) {
		t.Errorf("err = %v, want ErrNoAddress", err)
	}
}
