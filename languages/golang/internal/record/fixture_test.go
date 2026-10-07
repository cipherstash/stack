package record

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The segment rule is one rule in two languages. Rust's
// plain_text_and_label_segments_are_one_rule reads the same fixture, so a
// change to either implementation that the other does not follow fails here
// or there.
func TestSegmentRuleMatchesTheSharedFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "packages", "stack-encrypt", "tests", "fixtures", "label_segments.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Plain    []string `json:"plain"`
		NotPlain []string `json:"not_plain"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Plain) == 0 || len(fixture.NotPlain) == 0 {
		t.Fatalf("fixture is empty: %+v", fixture)
	}
	for _, ok := range fixture.Plain {
		if err := CheckSegment(ok); err != nil {
			t.Errorf("CheckSegment(%q) = %v, want ok", ok, err)
		}
	}
	for _, bad := range fixture.NotPlain {
		if err := CheckSegment(bad); err == nil {
			t.Errorf("CheckSegment(%q) succeeded; want a refusal", bad)
		}
	}
}
