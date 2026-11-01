package encrypt_test

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
)

// All conformance runners use the same missing-guest policy. Other errors
// remain failures in the caller, including errors wrapping neither sentinel.
func skipMissingConformanceGuest(t *testing.T, err error) {
	t.Helper()
	if (errors.Is(err, encrypt.ErrGuestNotBuilt) || errors.Is(err, encrypt.ErrDeterministicGuestNotBuilt)) && os.Getenv("STACK_CONFORMANCE_REQUIRED") != "1" {
		t.Skip(err)
	}
}

// Exercise the real fixture entry points in an isolated tree with their frozen
// inputs but no guest. Check every indexed test's outcome, so a missing compiled
// test also fails this guard. A missing guest must never make conformance green.
func TestFixtureConformanceRequiresGuest(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	workdir := filepath.Join(root, "languages", "golang", "encrypt")
	fixtures := filepath.Join("packages", "stack-encrypt", "tests", "fixtures")
	for _, dir := range []string{workdir, filepath.Join(root, fixtures)} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	var index struct {
		Profiles []struct {
			Fixture      string `json:"fixture"`
			Requirements []struct {
				GoTests []string `json:"go_tests"`
			} `json:"requirements"`
		} `json:"profiles"`
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "stack-encrypt", "v1", "fixture-profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &index); err != nil {
		t.Fatal(err)
	}
	names := make(map[string]bool)
	for _, profile := range index.Profiles {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", profile.Fixture))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, profile.Fixture), data, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, requirement := range profile.Requirements {
			for _, name := range requirement.GoTests {
				names[name] = true
			}
		}
	}
	if len(names) == 0 {
		t.Fatal("fixture index selects no Go tests")
	}
	// These full-suite tests also share queryFixtureClient's required-mode policy;
	// they remain outside the shared fixture requirements and aggregate selection.
	names["TestContextConformance"] = true
	names["TestContextBoundaries"] = true
	names["TestAQueryTheFieldDoesNotAnswerIsRefused"] = true
	names["TestAMatchesQueryNeverPrintsItsText"] = true
	tests := make([]string, 0, len(names))
	for name := range names {
		tests = append(tests, name)
	}
	slices.Sort(tests)
	patterns := make([]string, len(tests))
	for i, name := range tests {
		patterns[i] = regexp.QuoteMeta(name)
	}
	for _, required := range []string{"0", "1"} {
		t.Run("required="+required, func(t *testing.T) {
			t.Setenv("STACK_CONFORMANCE_REQUIRED", required)
			cmd := exec.CommandContext(t.Context(), binary, "-test.v", "-test.timeout=30s", "-test.run=^("+strings.Join(patterns, "|")+")$")
			cmd.Dir = workdir
			out, err := cmd.CombinedOutput()
			marker := "--- SKIP: "
			if required == "1" {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 1 {
					t.Fatalf("required fixtures must fail: %v\n%s", err, out)
				}
				marker = "--- FAIL: "
			} else if err != nil {
				t.Fatalf("optional fixtures must skip: %v\n%s", err, out)
			}
			for _, test := range tests {
				if !strings.Contains(string(out), marker+test) {
					t.Errorf("missing %q result for %s:\n%s", marker, test, out)
				}
			}
			if !strings.Contains(string(out), "deterministic guest not built") {
				t.Errorf("expected missing-guest diagnostic:\n%s", out)
			}
		})
	}
}
