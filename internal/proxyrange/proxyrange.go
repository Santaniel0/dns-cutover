// Package proxyrange recognizes addresses that belong to a reverse proxy, so
// that "the new A record points at the proxy" is not reported as a plain
// difference.
package proxyrange

import (
	"bufio"
	_ "embed"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

//go:embed cloudflare.txt
var cloudflareList string

// Set is a list of address ranges.
type Set []netip.Prefix

// Cloudflare returns the embedded Cloudflare ranges. The source URL and fetch
// date are recorded at the top of cloudflare.txt.
func Cloudflare() Set {
	s, err := Parse(strings.NewReader(cloudflareList))
	if err != nil {
		panic("proxyrange: embedded cloudflare.txt is invalid: " + err.Error())
	}
	return s
}

// Parse reads one CIDR per line. Blank lines and lines starting with # are
// skipped.
func Parse(r io.Reader) (Set, error) {
	var s Set
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		p, err := netip.ParsePrefix(text)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		s = append(s, p.Masked())
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read proxy ranges: %w", err)
	}
	return s, nil
}

// Contains reports whether a is inside any range.
func (s Set) Contains(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ContainsAll reports whether addrs is non-empty and every address is inside
// the set.
func (s Set) ContainsAll(addrs []netip.Addr) bool {
	if len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		if !s.Contains(a) {
			return false
		}
	}
	return true
}
