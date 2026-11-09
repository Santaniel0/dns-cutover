// Command dnslab serves a fake DNS world on 127.0.0.1 so dnscutover can be
// tried without real providers: the parent zone "test.", the old provider of
// example.test and two servers of the new provider.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Santaniel0/dns-cutover/internal/lab"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "dnslab:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("dnslab", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "testdata/lab", "directory with the lab zone files")
	scenario := fs.String("scenario", "broken", "new provider's zone: broken (as imported) or fixed")
	port := fs.Int("port", 5300, "first of four consecutive ports on 127.0.0.1")
	if err := fs.Parse(args); err != nil {
		return err
	}
	sc, err := lab.ParseScenario(*scenario)
	if err != nil {
		return err
	}
	l, err := lab.Start(*dir, sc, *port)
	if err != nil {
		return err
	}
	defer l.Close()

	fmt.Fprintf(stdout, "dnslab: scenario %s, zone %s\n", sc, lab.Zone)
	for _, s := range append([]lab.Server{l.Parent, l.Old}, l.New...) {
		name := s.Host
		if name == "" {
			name = "zone " + s.Zone
		}
		fmt.Fprintf(stdout, "  %-7s %-18s %s\n", s.Role, name, s.Addr())
	}
	fmt.Fprintf(stdout, "\nTry:\n  dnscutover %s\n\nCtrl-C stops the lab.\n", strings.Join(l.CheckArgs(), " "))
	<-ctx.Done()
	return nil
}
