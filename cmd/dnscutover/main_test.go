package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Santaniel0/dns-cutover/internal/lab"
)

var update = flag.Bool("update", false, "rewrite golden files")

const labDir = "../../testdata/lab"

func startLab(t *testing.T, sc lab.Scenario) *lab.Lab {
	t.Helper()
	l, err := lab.Start(labDir, sc, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

var (
	portRe    = regexp.MustCompile(`127\.0\.0\.1:\d+`)
	elapsedRe = regexp.MustCompile(`queries in [0-9.]+[µm]?s`)
)

// normalize removes what changes from run to run: free ports and timing.
func normalize(s string) string {
	s = portRe.ReplaceAllString(s, "127.0.0.1:PORT")
	return elapsedRe.ReplaceAllString(s, "queries in TIME")
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if got != string(want) {
		t.Errorf("output differs from %s (run with -update after checking the diff)\n--- got\n%s", path, got)
	}
}

func TestCheckLab(t *testing.T) {
	tests := []struct {
		scenario lab.Scenario
		code     int
	}{
		{lab.Broken, exitNotReady},
		{lab.Fixed, exitReady},
	}
	for _, tt := range tests {
		t.Run(tt.scenario.String(), func(t *testing.T) {
			l := startLab(t, tt.scenario)
			args := append(l.CheckArgs(), "--qps", "0")
			code, out, errOut := runCLI(t, args...)
			if code != tt.code {
				t.Fatalf("exit code %d, want %d\nstderr: %s\nstdout:\n%s", code, tt.code, errOut, out)
			}
			golden(t, tt.scenario.String()+".golden", normalize(out))
		})
	}
}

func TestCheckJSON(t *testing.T) {
	l := startLab(t, lab.Broken)
	code, out, errOut := runCLI(t, append(l.CheckArgs(), "--qps", "0", "--format", "json", "--ignore", "staging")...)
	if code != exitNotReady {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var doc struct {
		Verdict string `json:"verdict"`
		Counts  struct {
			Blockers, Warnings, Ignored int
		} `json:"counts"`
		Parent struct {
			DS []struct {
				KeyTag uint16 `json:"key_tag"`
			} `json:"ds"`
		} `json:"parent"`
		Findings []struct {
			Kind     string   `json:"kind"`
			Severity string   `json:"severity"`
			Name     string   `json:"name"`
			Type     string   `json:"type"`
			Old      []string `json:"old"`
			Ignored  bool     `json:"ignored"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if doc.Verdict != "NOT READY" || doc.Counts.Blockers != 7 || doc.Counts.Ignored != 1 {
		t.Errorf("verdict=%q counts=%+v", doc.Verdict, doc.Counts)
	}
	if len(doc.Parent.DS) != 1 || doc.Parent.DS[0].KeyTag != 29212 {
		t.Errorf("parent DS = %+v", doc.Parent.DS)
	}
	for _, f := range doc.Findings {
		// The text report shortens long values; JSON must keep them whole.
		if f.Kind == "MISSING" && f.Name == "mail._domainkey.example.test." && (len(f.Old) != 1 || strings.HasSuffix(f.Old[0], "...")) {
			t.Errorf("DKIM value was shortened in JSON: %v", f.Old)
		}
		if f.Name == "staging.example.test." && !f.Ignored {
			t.Errorf("staging should be ignored: %+v", f)
		}
	}
}

func TestInventoryCommand(t *testing.T) {
	l := startLab(t, lab.Broken)
	code, out, errOut := runCLI(t, "inventory", "example.test",
		"--old", "ns1.olddns.test="+l.Old.Addr().String(),
		"--zone-file", labDir+"/export.zone", "--names", labDir+"/names.txt", "--qps", "0")
	if code != exitReady {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"billing.example.test.", "names-file", "mail._domainkey.example.test.", "probe"} {
		if !strings.Contains(out, want) {
			t.Errorf("inventory output lacks %q:\n%s", want, out)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
		msg  string
	}{
		{"no command", nil, exitError, "Usage:"},
		{"unknown command", []string{"frobnicate"}, exitError, "unknown command"},
		{"help", []string{"help"}, exitReady, ""},
		{"check help", []string{"check", "-h"}, exitReady, ""},
		{"no zone", []string{"check", "--new", "192.0.2.1"}, exitError, "want exactly one zone"},
		{"two zones", []string{"check", "a.test", "b.test"}, exitError, "want exactly one zone"},
		{"no new servers", []string{"check", "example.test", "--old", "192.0.2.1", "--parent", "192.0.2.2", "--timeout", "1ms", "--retries", "0"}, exitError, "no new servers"},
		{"bad server spec", []string{"check", "example.test", "--new", "a=b"}, exitError, "invalid server spec"},
		{"bad format", []string{"check", "example.test", "--new", "192.0.2.1", "--format", "xml"}, exitError, "unknown format"},
		{"bad ttl policy", []string{"check", "example.test", "--new", "192.0.2.1", "--ttl", "maybe"}, exitError, "unknown TTL policy"},
		{"bad ignore", []string{"check", "example.test", "--new", "192.0.2.1", "--ignore", "www BOGUS"}, exitError, "invalid ignore rule"},
		{"missing zone file", []string{"check", "example.test", "--new", "192.0.2.1", "--zone-file", "does-not-exist.zone"}, exitError, "does-not-exist.zone"},
		{"inventory probe without servers", []string{"inventory", "example.test"}, exitError, "probing needs --old or --new"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, errOut := runCLI(t, tt.args...)
			if code != tt.code {
				t.Fatalf("exit %d, want %d; stderr: %s", code, tt.code, errOut)
			}
			if tt.msg != "" && !strings.Contains(errOut, tt.msg) {
				t.Errorf("stderr %q lacks %q", errOut, tt.msg)
			}
		})
	}
}

func TestFlagsAfterZone(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	n := fs.Int("n", 0, "")
	pos, err := parseInterspersed(fs, []string{"-n", "1", "zone.test", "-n", "2"})
	if err != nil || len(pos) != 1 || pos[0] != "zone.test" || *n != 2 {
		t.Fatalf("pos=%v n=%d err=%v", pos, *n, err)
	}
}
