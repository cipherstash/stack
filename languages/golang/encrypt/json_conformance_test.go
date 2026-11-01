package encrypt_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type jsonConformanceCorpus struct {
	Version          int      `json:"version"`
	Documents        []string `json:"documents"`
	InvalidDocuments []struct {
		Text   string `json:"text"`
		Reason string `json:"reason"`
	} `json:"invalid_documents"`
	PredicateRefusals []struct {
		ID        string          `json:"id"`
		Predicate string          `json:"predicate"`
		Vars      json.RawMessage `json:"vars"`
		Reason    string          `json:"reason"`
		Construct string          `json:"construct"`
		At        int             `json:"at"`
		AtText    string          `json:"at_text"`
	} `json:"predicate_refusals"`
}

func jsonConformanceCases(t *testing.T) jsonConformanceCorpus {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "stack-encrypt", "v1", "eql-json.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases jsonConformanceCorpus
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if cases.Version != 1 || len(cases.Documents) == 0 || len(cases.InvalidDocuments) == 0 || len(cases.PredicateRefusals) == 0 {
		t.Fatal("empty or unsupported JSON conformance corpus")
	}
	return cases
}
