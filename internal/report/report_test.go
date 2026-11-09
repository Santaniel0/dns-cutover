package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/Santaniel0/dns-cutover/internal/cutover"
	"github.com/Santaniel0/dns-cutover/internal/dnsq"
	"github.com/Santaniel0/dns-cutover/internal/finding"
	"github.com/Santaniel0/dns-cutover/internal/inventory"
	"github.com/Santaniel0/dns-cutover/internal/rr"
)

func sampleResult() cutover.Result {
	srv := dnsq.Server{Host: "ns1.newdns.test.", Addr: netip.MustParseAddrPort("192.0.2.53:53")}
	return cutover.Result{
		Zone:      "example.test.",
		Verdict:   cutover.NotReady,
		Old:       []dnsq.Server{{Addr: netip.MustParseAddrPort("198.51.100.53:53")}},
		OldSource: cutover.OldFromFlag,
		New:       []dnsq.Server{srv},
		Findings: []finding.Finding{
			{Kind: finding.Missing, Severity: finding.Blocker, Name: "mail._domainkey.example.test.", Type: rr.TypeTXT,
				Old: []string{`"v=DKIM1; k=rsa; p=` + strings.Repeat("A", 200) + `"`}},
			{Kind: finding.TTLOnly, Severity: finding.Warning, Name: "example.test.", Type: rr.TypeA,
				Old: []string{"192.0.2.10"}, OldTTL: 3600, NewTTL: 300},
			{Kind: finding.Extra, Severity: finding.Warning, Name: "staging.example.test.", Type: rr.TypeA,
				New: []string{"10.0.0.5"}, Ignored: true},
		},
	}
}

func TestText(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"old        - 198.51.100.53:53 (from --old)",
		"BLOCKERS (1)",
		"new  (none)",
		"ttl  3600 on old, 300 on new",
		"IGNORED (1)",
		"RESULT: NOT READY (1 blocker, 1 warning, 0 info)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if len(line) > lineWidth+2 {
			t.Errorf("line longer than %d columns: %q", lineWidth, line)
		}
	}
	if strings.Contains(out, "WARNINGS (2)") {
		t.Error("ignored findings must not be counted in their severity section")
	}
}

type failingWriter struct{}

var errDiskFull = errors.New("disk full")

func (failingWriter) Write([]byte) (int, error) { return 0, errDiskFull }

func TestTextReportsWriteErrors(t *testing.T) {
	if err := Text(failingWriter{}, sampleResult()); !errors.Is(err, errDiskFull) {
		t.Errorf("err = %v, want the writer's error", err)
	}
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(compact.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if string(doc["verdict"]) != `"NOT READY"` {
		t.Errorf("verdict = %s", doc["verdict"])
	}
	if !strings.Contains(string(doc["counts"]), `"ignored":1`) {
		t.Errorf("counts = %s", doc["counts"])
	}
	if !strings.Contains(string(doc["findings"]), `"type":"TXT"`) || !strings.Contains(string(doc["findings"]), `"severity":"blocker"`) {
		t.Errorf("findings should use readable enums: %s", doc["findings"])
	}
	if !strings.Contains(string(doc["new"]), `"addr":"192.0.2.53:53"`) {
		t.Errorf("new servers = %s", doc["new"])
	}

	buf.Reset()
	empty := cutover.Result{Zone: "example.test.", Verdict: cutover.Ready}
	if err := JSON(&buf, empty); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Errorf("no findings should encode as [], not null:\n%s", buf.String())
	}
}

func TestWrapAndShorten(t *testing.T) {
	lines := wrap("one two three four five six", 9)
	if strings.Join(lines, "|") != "one two|three|four five|six" {
		t.Errorf("wrap = %q", lines)
	}
	if got := shorten("abcdefghij", 8); got != "abcde..." {
		t.Errorf("shorten = %q", got)
	}
	if got := shorten("abc", 8); got != "abc" {
		t.Errorf("shorten short = %q", got)
	}
}

func TestInventoryText(t *testing.T) {
	c := inventory.NewCollector("example.test.")
	_ = c.Add("www.example.test.", inventory.FromZoneFile, rr.TypeCNAME)
	_ = c.Add("www.example.test.", inventory.FromProbe)
	var buf bytes.Buffer
	if err := InventoryText(&buf, c.Inventory(inventory.ProbeStats{Candidates: 5, Wildcard: []string{"ns1.test."}})); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"www.example.test.  zone-file,probe  CNAME", "2 names: 1 zone-file, 1 probe (5 labels probed)", "wildcard on ns1.test."} {
		if !strings.Contains(out, want) {
			t.Errorf("inventory text lacks %q:\n%s", want, out)
		}
	}
}
