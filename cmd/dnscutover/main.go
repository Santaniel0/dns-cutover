// Command dnscutover checks a DNS zone before its nameservers are changed:
// it queries the old and the new authoritative servers directly, compares
// every record it can find, and checks the delegation and DNSSEC.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/Santaniel0/dns-cutover/internal/cutover"
	"github.com/Santaniel0/dns-cutover/internal/dnsq"
	"github.com/Santaniel0/dns-cutover/internal/inventory"
	"github.com/Santaniel0/dns-cutover/internal/proxyrange"
	"github.com/Santaniel0/dns-cutover/internal/report"
	"github.com/Santaniel0/dns-cutover/internal/rr"
)

const (
	exitReady    = 0
	exitNotReady = 1
	exitError    = 2
)

const usageText = `dnscutover checks a DNS zone before its nameservers are changed. It queries
the old and the new authoritative servers directly, compares every record it
can find, and checks the delegation and DNSSEC.

Usage:
  dnscutover check <zone> --new <servers> [flags]
  dnscutover inventory <zone> [flags]
  dnscutover version

Servers are comma-separated: ns1.example.net, ns1.example.net:5353,
192.0.2.1, 192.0.2.1:5353 or ns1.example.net=192.0.2.1:5353.

Exit status: 0 ready, 1 blockers found, 2 the check could not run.
Run "dnscutover check -h" for the flags.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return exitError
	}
	switch args[0] {
	case "check":
		return runCheck(ctx, args[1:], stdout, stderr)
	case "inventory":
		return runInventory(ctx, args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, "dnscutover", buildVersion())
		return exitReady
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usageText)
		return exitReady
	default:
		fmt.Fprintf(stderr, "dnscutover: unknown command %q\n\n%s", args[0], usageText)
		return exitError
	}
}

func buildVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}

type specList []dnsq.Spec

func (s *specList) String() string {
	parts := make([]string, 0, len(*s))
	for _, sp := range *s {
		parts = append(parts, fmt.Sprintf("%s=%s:%d", sp.Host, sp.Addr, sp.Port))
	}
	return strings.Join(parts, ",")
}

func (s *specList) Set(v string) error {
	specs, err := dnsq.ParseSpecs(v)
	if err != nil {
		return err
	}
	*s = append(*s, specs...)
	return nil
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, "; ") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

type options struct {
	old, new, parent specList
	zoneFile         string
	names            string
	probe            bool
	wordlist         string
	proxyRanges      string
	resolver         string
	ttl              string
	ignore           stringList
	qps              float64
	concurrency      int
	timeout          time.Duration
	retries          int
	format           string
}

func (o *options) register(fs *flag.FlagSet, check bool) {
	fs.Var(&o.old, "old", "old provider's servers (default: the servers the parent delegates to now)")
	fs.Var(&o.new, "new", "new provider's servers")
	fs.StringVar(&o.zoneFile, "zone-file", "", "BIND zone file exported from the old provider")
	fs.StringVar(&o.names, "names", "", "file with extra names, one per line, relative to the zone")
	fs.BoolVar(&o.probe, "probe", true, "probe common labels and DKIM selectors on the first old and new server")
	fs.StringVar(&o.wordlist, "wordlist", "", "file with labels to probe instead of the built-in list")
	fs.StringVar(&o.resolver, "resolver", "", "recursive resolver ip[:port] used only to find servers (default: system)")
	fs.Float64Var(&o.qps, "qps", 50, "maximum queries per second to each server, 0 for no limit")
	fs.IntVar(&o.concurrency, "concurrency", 16, "queries in flight across all servers")
	fs.DurationVar(&o.timeout, "timeout", 2*time.Second, "timeout of one query attempt")
	fs.IntVar(&o.retries, "retries", 2, "extra attempts after a failed query")
	fs.StringVar(&o.format, "format", "text", "output format: text or json")
	if check {
		fs.Var(&o.parent, "parent", "parent zone server to read NS and DS from (default: found via the resolver)")
		fs.StringVar(&o.proxyRanges, "proxy-ranges", "", "file with proxy CIDRs, or \"none\" (default: built-in Cloudflare list)")
		fs.StringVar(&o.ttl, "ttl", "warn", "how TTL-only differences count: warn, ignore or fail")
		fs.Var(&o.ignore, "ignore", "accept a known difference, \"name [TYPE]\" relative to the zone (repeatable)")
	}
}

// parseInterspersed lets flags follow the zone argument, as in
// "dnscutover check example.com --new ...", which the flag package alone
// does not allow.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

func parseZoneArg(fs *flag.FlagSet, args []string, stderr io.Writer) (rr.Name, int, bool) {
	positional, err := parseInterspersed(fs, args)
	if errors.Is(err, flag.ErrHelp) {
		return "", exitReady, false
	}
	if err != nil {
		return "", exitError, false
	}
	if len(positional) != 1 {
		fmt.Fprintf(stderr, "dnscutover %s: want exactly one zone, got %d arguments\n", fs.Name(), len(positional))
		return "", exitError, false
	}
	zone, err := rr.ParseName(positional[0])
	if err != nil {
		fmt.Fprintf(stderr, "dnscutover %s: %v\n", fs.Name(), err)
		return "", exitError, false
	}
	return zone, 0, true
}

func newFlagSet(name string, stderr io.Writer, synopsis string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: %s\n\nFlags:\n", synopsis)
		fs.PrintDefaults()
	}
	return fs
}

func runCheck(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var o options
	fs := newFlagSet("check", stderr, "dnscutover check <zone> --new <servers> [flags]")
	o.register(fs, true)
	zone, code, ok := parseZoneArg(fs, args, stderr)
	if !ok {
		return code
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "dnscutover check: %v\n", err)
		return exitError
	}
	if o.format != "text" && o.format != "json" {
		return fail(fmt.Errorf("unknown format %q", o.format))
	}
	cfg, closeFiles, err := o.config(zone)
	if err != nil {
		return fail(err)
	}
	defer closeFiles()

	res, err := cutover.Run(ctx, o.deps(), cfg)
	if err != nil {
		return fail(err)
	}
	if o.format == "json" {
		err = report.JSON(stdout, res)
	} else {
		err = report.Text(stdout, res)
	}
	if err != nil {
		return fail(err)
	}
	if res.Verdict == cutover.Ready {
		return exitReady
	}
	return exitNotReady
}

func runInventory(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var o options
	fs := newFlagSet("inventory", stderr, "dnscutover inventory <zone> [--zone-file f] [--names f] [--old s] [--new s] [flags]")
	o.register(fs, false)
	zone, code, ok := parseZoneArg(fs, args, stderr)
	if !ok {
		return code
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "dnscutover inventory: %v\n", err)
		return exitError
	}
	cfg, closeFiles, err := o.config(zone)
	if err != nil {
		return fail(err)
	}
	defer closeFiles()

	inv, err := cutover.BuildInventory(ctx, o.deps(), cfg)
	if err != nil {
		return fail(err)
	}
	if o.format == "json" {
		err = report.InventoryJSON(stdout, inv)
	} else {
		err = report.InventoryText(stdout, inv)
	}
	if err != nil {
		return fail(err)
	}
	return exitReady
}

// config opens the input files; the returned func closes them.
func (o *options) config(zone rr.Name) (cutover.Config, func(), error) {
	var files []*os.File
	closeAll := func() {
		for _, f := range files {
			f.Close()
		}
	}
	open := func(path string) (*os.File, error) {
		f, err := os.Open(path)
		if err == nil {
			files = append(files, f)
		}
		return f, err
	}

	cfg := cutover.Config{
		Zone:        zone,
		Old:         o.old,
		New:         o.new,
		Parent:      o.parent,
		Probe:       o.probe,
		Concurrency: o.concurrency,
	}
	if o.ttl != "" {
		var err error
		if cfg.TTL, err = cutover.ParseTTLPolicy(o.ttl); err != nil {
			return cfg, closeAll, err
		}
	}
	for _, s := range o.ignore {
		rule, err := cutover.ParseIgnore(s, zone)
		if err != nil {
			return cfg, closeAll, err
		}
		cfg.Ignore = append(cfg.Ignore, rule)
	}
	if o.zoneFile != "" {
		f, err := open(o.zoneFile)
		if err != nil {
			return cfg, closeAll, err
		}
		cfg.ZoneFile, cfg.ZoneFileName = f, o.zoneFile
	}
	if o.names != "" {
		f, err := open(o.names)
		if err != nil {
			return cfg, closeAll, err
		}
		cfg.Names = f
	}
	cfg.Wordlist = inventory.DefaultWordlist()
	if o.wordlist != "" {
		f, err := open(o.wordlist)
		if err != nil {
			return cfg, closeAll, err
		}
		if cfg.Wordlist, err = inventory.ParseWordlist(f); err != nil {
			return cfg, closeAll, fmt.Errorf("wordlist: %w", err)
		}
	}
	switch o.proxyRanges {
	case "":
		cfg.Proxy = proxyrange.Cloudflare()
	case "none":
	default:
		f, err := open(o.proxyRanges)
		if err != nil {
			return cfg, closeAll, err
		}
		if cfg.Proxy, err = proxyrange.Parse(f); err != nil {
			return cfg, closeAll, fmt.Errorf("proxy ranges: %w", err)
		}
	}
	return cfg, closeAll, nil
}

func (o *options) deps() cutover.Deps {
	return cutover.Deps{
		Querier: dnsq.NewClient(dnsq.Options{Timeout: o.timeout, Retries: o.retries, QPS: o.qps}),
		Locator: resolverFor(o.resolver),
		Now:     time.Now,
	}
}

// resolverFor returns the system resolver, or one that sends every lookup
// to addr when it is set.
func resolverFor(addr string) *net.Resolver {
	if addr == "" {
		return net.DefaultResolver
	}
	target := addr
	if a, err := netip.ParseAddr(addr); err == nil {
		target = netip.AddrPortFrom(a, dnsq.DefaultPort).String()
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, target)
		},
	}
}
