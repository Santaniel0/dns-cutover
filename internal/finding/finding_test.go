package finding

import (
	"encoding/json"
	"testing"

	"github.com/Santaniel0/dns-cutover/internal/rr"
)

func TestSort(t *testing.T) {
	fs := []Finding{
		{Kind: Timing, Severity: Info, Name: "example.test."},
		{Kind: Missing, Severity: Blocker, Name: "www.example.test.", Type: rr.TypeA},
		{Kind: Extra, Severity: Warning, Name: "a.example.test."},
		{Kind: Missing, Severity: Blocker, Name: "api.example.test.", Type: rr.TypeTXT},
		{Kind: Missing, Severity: Blocker, Name: "api.example.test.", Type: rr.TypeA},
		{Kind: DNSSEC, Severity: Blocker, Name: "example.test."},
	}
	Sort(fs)
	want := []string{
		"MISSING api.example.test. A",
		"MISSING api.example.test. TXT",
		"MISSING www.example.test. A",
		"DNSSEC example.test. None",
		"EXTRA a.example.test. None",
		"TIMING example.test. None",
	}
	for i, f := range fs {
		if got := f.Kind.String() + " " + string(f.Name) + " " + f.Type.String(); got != want[i] {
			t.Errorf("position %d: %s, want %s", i, got, want[i])
		}
	}
}

func TestJSONEnums(t *testing.T) {
	b, err := json.Marshal(Finding{Kind: ProxiedTarget, Severity: Blocker, Name: "mail.example.test.", Type: rr.TypeA})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"kind":"PROXIED-TARGET","severity":"blocker","name":"mail.example.test.","type":"A"}`
	if string(b) != want {
		t.Errorf("json = %s\nwant   %s", b, want)
	}
	if b, _ := json.Marshal(Finding{Kind: Timing, Severity: Info}); string(b) != `{"kind":"TIMING","severity":"info"}` {
		t.Errorf("zero type and empty fields should be omitted: %s", b)
	}
}
