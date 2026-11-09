// Package report renders check results for people (text) and for scripts
// (JSON).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Santaniel0/dns-cutover/internal/compare"
	"github.com/Santaniel0/dns-cutover/internal/cutover"
	"github.com/Santaniel0/dns-cutover/internal/delegation"
	"github.com/Santaniel0/dns-cutover/internal/dnsq"
	"github.com/Santaniel0/dns-cutover/internal/finding"
	"github.com/Santaniel0/dns-cutover/internal/inventory"
	"github.com/Santaniel0/dns-cutover/internal/rr"
)

const (
	kindWidth  = 16
	valueWidth = 72
	lineWidth  = 78
)

// errWriter remembers the first write error so rendering code can stay
// linear.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err == nil {
		_, e.err = fmt.Fprintf(e.w, format, args...)
	}
}

// Text writes the human-readable report.
func Text(w io.Writer, r cutover.Result) error {
	ew := &errWriter{w: w}
	ew.printf("zone       %s\n", r.Zone)
	writeServers(ew, "old", r.Old, " (from "+r.OldSource.String()+")")
	writeServers(ew, "new", r.New, "")
	if p := r.Parent; p != nil {
		ew.printf("parent     %s NS %s (TTL %d)", p.Server.Addr, joinNames(p.NS), p.NSTTL)
		if len(p.DS) > 0 {
			tags := make([]string, 0, len(p.DS))
			for _, d := range p.DS {
				tags = append(tags, fmt.Sprintf("%d/%d/%d", d.KeyTag, d.Algorithm, d.DigestType))
			}
			ew.printf(", DS %s (TTL %d)", strings.Join(tags, " "), p.DSTTL)
		}
		ew.printf("\n")
	}
	ew.printf("inventory  %s\n", inventorySummary(r.Inventory))
	ew.printf("compared   %d questions, %d RRsets, %d identical; %d queries in %s\n",
		r.Stats.Questions, r.Stats.RRsets, r.Stats.Matched, r.Queries, r.Elapsed.Round(10*time.Millisecond))

	sections := []struct {
		title string
		sev   finding.Severity
	}{{"BLOCKERS", finding.Blocker}, {"WARNINGS", finding.Warning}, {"INFO", finding.Info}}
	for _, s := range sections {
		if n := r.Count(s.sev); n > 0 {
			ew.printf("\n%s (%d)\n", s.title, n)
			for _, f := range r.Findings {
				if f.Severity == s.sev && !f.Ignored {
					writeFinding(ew, f)
				}
			}
		}
	}
	if n := r.Ignored(); n > 0 {
		ew.printf("\nIGNORED (%d)\n", n)
		for _, f := range r.Findings {
			if f.Ignored {
				ew.printf("  %-*s%s %s\n", kindWidth, f.Kind, f.Name, typeLabel(f.Type))
			}
		}
	}

	ew.printf("\nRESULT: %s (%s, %s, %d info)\n", r.Verdict,
		plural(r.Count(finding.Blocker), "blocker"), plural(r.Count(finding.Warning), "warning"), r.Count(finding.Info))
	return ew.err
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func writeServers(ew *errWriter, label string, servers []dnsq.Server, suffix string) {
	for i, s := range servers {
		head := ""
		if i == 0 {
			head = label
		}
		host := string(s.Host)
		if host == "" {
			host = "-"
		}
		tail := ""
		if i == 0 {
			tail = suffix
		}
		ew.printf("%-10s %s %s%s\n", head, host, s.Addr, tail)
	}
}

func inventorySummary(inv inventory.Inventory) string {
	parts := []string{}
	for _, src := range []inventory.Source{inventory.FromZoneFile, inventory.FromNamesFile, inventory.FromProbe} {
		if n := inv.Count(src); n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, src))
		}
	}
	s := fmt.Sprintf("%d names", len(inv.Entries))
	if len(parts) > 0 {
		s += ": " + strings.Join(parts, ", ")
	}
	if inv.Probe.Candidates > 0 {
		s += fmt.Sprintf(" (%d labels probed)", inv.Probe.Candidates)
	}
	return s
}

func typeLabel(t rr.Type) string {
	if t == 0 {
		return ""
	}
	return t.String()
}

func writeFinding(ew *errWriter, f finding.Finding) {
	head := strings.TrimSpace(fmt.Sprintf("%s %s", f.Name, typeLabel(f.Type)))
	if len(f.Servers) > 0 {
		head += "  on " + strings.Join(f.Servers, ", ")
	}
	ew.printf("  %-*s%s\n", kindWidth, f.Kind, head)
	pad := strings.Repeat(" ", 2+kindWidth)

	switch f.Kind {
	case finding.TTLOnly:
		ew.printf("%sttl  %d on old, %d on new\n", pad, f.OldTTL, f.NewTTL)
		writeValues(ew, pad, "data", f.Old)
	case finding.Missing, finding.Different, finding.Extra, finding.Proxied, finding.ProxiedTarget:
		writeValues(ew, pad, "old ", orNone(f.Old))
		writeValues(ew, pad, "new ", orNone(f.New))
	default:
		writeValues(ew, pad, "old ", f.Old)
		writeValues(ew, pad, "new ", f.New)
	}
	if f.Detail != "" {
		for _, line := range wrap(f.Detail, lineWidth-len(pad)) {
			ew.printf("%s%s\n", pad, line)
		}
	}
}

func orNone(v []string) []string {
	if len(v) == 0 {
		return []string{"(none)"}
	}
	return v
}

func writeValues(ew *errWriter, pad, label string, values []string) {
	for i, v := range values {
		if i > 0 {
			label = strings.Repeat(" ", len(label))
		}
		ew.printf("%s%s %s\n", pad, label, shorten(v, valueWidth-len(pad)))
	}
}

// shorten keeps long values such as DKIM keys to one line; the JSON output
// has them in full.
func shorten(s string, width int) string {
	if len(s) <= width {
		return s
	}
	return s[:width-3] + "..."
}

func wrap(text string, width int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		if line != "" && len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

func joinNames(names []rr.Name) string {
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, string(n))
	}
	return strings.Join(parts, ", ")
}

type jsonCounts struct {
	Blockers int `json:"blockers"`
	Warnings int `json:"warnings"`
	Info     int `json:"info"`
	Ignored  int `json:"ignored"`
}

type jsonParent struct {
	Server dnsq.Server `json:"server"`
	*delegation.Parent
}

type jsonInventory struct {
	Names     int                  `json:"names"`
	ZoneFile  int                  `json:"zone_file"`
	NamesFile int                  `json:"names_file"`
	Probe     int                  `json:"probe"`
	Skipped   int                  `json:"skipped_records"`
	Probing   inventory.ProbeStats `json:"probing"`
}

type jsonReport struct {
	Zone      rr.Name           `json:"zone"`
	Verdict   cutover.Verdict   `json:"verdict"`
	Counts    jsonCounts        `json:"counts"`
	Old       []dnsq.Server     `json:"old"`
	OldSource cutover.OldSource `json:"old_source"`
	New       []dnsq.Server     `json:"new"`
	Parent    *jsonParent       `json:"parent,omitempty"`
	Inventory jsonInventory     `json:"inventory"`
	Stats     compare.Stats     `json:"stats"`
	Queries   int64             `json:"queries"`
	ElapsedMS int64             `json:"elapsed_ms"`
	Findings  []finding.Finding `json:"findings"`
}

// JSON writes the full result as one JSON document.
func JSON(w io.Writer, r cutover.Result) error {
	out := jsonReport{
		Zone:    r.Zone,
		Verdict: r.Verdict,
		Counts: jsonCounts{
			Blockers: r.Count(finding.Blocker),
			Warnings: r.Count(finding.Warning),
			Info:     r.Count(finding.Info),
			Ignored:  r.Ignored(),
		},
		Old:       r.Old,
		OldSource: r.OldSource,
		New:       r.New,
		Inventory: jsonInventory{
			Names:     len(r.Inventory.Entries),
			ZoneFile:  r.Inventory.Count(inventory.FromZoneFile),
			NamesFile: r.Inventory.Count(inventory.FromNamesFile),
			Probe:     r.Inventory.Count(inventory.FromProbe),
			Skipped:   r.Inventory.Skipped,
			Probing:   r.Inventory.Probe,
		},
		Stats:     r.Stats,
		Queries:   r.Queries,
		ElapsedMS: r.Elapsed.Milliseconds(),
		Findings:  r.Findings,
	}
	if r.Parent != nil {
		out.Parent = &jsonParent{Server: r.Parent.Server, Parent: r.Parent}
	}
	if out.Findings == nil {
		out.Findings = []finding.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// InventoryText lists the names a check would compare and where each came
// from.
func InventoryText(w io.Writer, inv inventory.Inventory) error {
	ew := &errWriter{w: w}
	width := 0
	for _, e := range inv.Entries {
		width = max(width, len(e.Name))
	}
	for _, e := range inv.Entries {
		sources := make([]string, 0, len(e.Sources))
		for _, s := range e.Sources {
			sources = append(sources, s.String())
		}
		types := ""
		if len(e.Types) > 0 {
			names := make([]string, 0, len(e.Types))
			for _, t := range e.Types {
				names = append(names, t.String())
			}
			types = "  " + strings.Join(names, " ")
		}
		ew.printf("%-*s  %s%s\n", width, e.Name, strings.Join(sources, ","), types)
	}
	ew.printf("\n%s\n", inventorySummary(inv))
	if len(inv.Probe.Wildcard) > 0 {
		ew.printf("wildcard on %s\n", strings.Join(inv.Probe.Wildcard, ", "))
	}
	for _, e := range inv.Probe.Errors {
		ew.printf("probe error: %s\n", e)
	}
	return ew.err
}

// InventoryJSON writes the inventory as JSON.
func InventoryJSON(w io.Writer, inv inventory.Inventory) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(inv)
}
