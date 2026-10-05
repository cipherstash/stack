// Package plantest checks in what a [plan.Policy] stores each field as, so
// a change to a field's encryption context fails a test instead of the
// data.
//
// A field's context is bound into every ciphertext and query term written
// under it. A policy derives contexts from names, so an ordinary rename —
// a proto field, a Go struct field, a table — can change one with no error
// on the write path: rows already written stop decrypting, and their terms
// stop matching queries. [Golden] makes that a test failure:
//
//	func TestIndividualsPolicy(t *testing.T) {
//	    plantest.Golden(t, source, policy.Individuals)
//	}
//
// The first run with -update writes the snapshot to
// testdata/TestIndividualsPolicy.golden; check it in. From then on Golden
// builds the plan the way [plan.MustPlanFor] does at startup, and fails
// when the plan no longer matches the snapshot, naming each change and
// calling out a changed context apart from the rest: a changed context is
// data loss, while a changed target (its index terms, or encrypting a
// field that was plaintext) is a migration. When a rename changed a
// context, the failure names the [plan.Column] (or [plan.Identity]) pin
// that keeps it, checked by building the plan with that pin.
//
// # The snapshot
//
// The snapshot records what a policy stores, not what the schema calls it:
// per message its [plan.Table]; per encrypted field its column (the record
// key), its context, whether its target is EQL (the context is the column
// identity) or Custom (the target supplies it), its index terms and its
// facts; per field decided
// [plan.Plaintext], its name and its facts. Fields with no facts that no
// rule names are not the policy's concern and are left out. Encrypted
// fields are named by column, so a schema rename that the policy pins
// leaves the snapshot byte-for-byte unchanged, which is how a reviewer
// tells a safe rename from one that loses data.
//
// The text is line-oriented and deterministic across runs and platforms:
// fields are sorted, facts are sorted, line endings are "\n" (a checkout
// that converted them to "\r\n" still compares equal), and any value that
// is not a plain identifier is quoted as a Go string literal. It is meant
// to be read by people as well as compared: the list of classified fields,
// what protects each, and the identifier it is bound to.
//
// # The -update flag
//
// plantest registers the conventional -update test flag, as a bool on the
// default flag set, when no package it imports has done so already. A test
// package that defines its own -update panics with "flag redefined";
// read plantest's instead, with flag.Lookup("update").
package plantest

import (
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/stackencrypt/plan"
)

func init() {
	if flag.Lookup("update") == nil {
		flag.Bool("update", false, "rewrite plantest golden snapshots (testdata/*.golden) from the policy")
	}
}

// lookupFlag finds a flag on the default flag set. It is a variable so a
// test can read -update from a flag set of its own instead of setting the
// one the whole test binary shares.
var lookupFlag = flag.Lookup

// updating reports whether the test binary was run with -update.
func updating() bool {
	f := lookupFlag("update")
	if f == nil {
		return false
	}
	g, ok := f.Value.(flag.Getter)
	if !ok {
		return false
	}
	on, ok := g.Get().(bool)
	return ok && on
}

// Golden builds m's plan over src's facts, as [plan.PlanFor] does, and
// checks what it stores each field as against the snapshot checked in at
// testdata/<test name>.golden (a subtest's name is a path below
// testdata). With -update it writes the snapshot instead, logging what
// changed.
//
// The test fails when the policy does not build (a classified field no
// rule decides, a [plan.Fail], a plan that does not bind to the message),
// when there is no snapshot yet, and when the plan differs from it. A
// message the policy encrypts nothing of is not a failure: its snapshot
// lists the fields it decided Plaintext.
//
// A [plan.Source] is expected to be pure, as a policy is: Golden reads the
// facts more than once.
func Golden(t testing.TB, src plan.Source, m plan.Message) {
	t.Helper()
	logs, err := check(goldenPath(t.Name()), src, m, updating(), rerun(t.Name()))
	if logs != "" {
		t.Log(logs)
	}
	if err != nil {
		t.Error(err)
	}
}

// goldenPath is the snapshot file for a test: testdata/<name>.golden, a
// subtest's name a path below it. A character a file system could refuse
// is spelled '_', and so is a trailing dot, which Windows drops. A name
// spelled differently from the test's, or one Windows reserves as a device
// (CON, NUL.x, COM1), takes '~' and a hash of the test's spelling before
// its first dot, so two tests never share a snapshot: "a:b" and "a?b" are
// a_b~<hash>.golden with different hashes, and no name spelled as it is
// contains '~'. Every platform spells a name the same way, so a snapshot
// written on one is found on another.
func goldenPath(name string) string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		parts[i] = strings.Map(func(r rune) rune {
			if r < 0x80 && (r == '-' || r == '_' || r == '.' || r == '+' ||
				'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9') {
				return r
			}
			return '_'
		}, p)
		if strings.Trim(parts[i], ".") == "" {
			parts[i] = strings.Repeat("_", len(parts[i])+1)
		}
		trimmed := strings.TrimRight(parts[i], ".")
		parts[i] = trimmed + strings.Repeat("_", len(parts[i])-len(trimmed))
		stem, ext, dotted := strings.Cut(parts[i], ".")
		if parts[i] != p || windowsDevice(stem) {
			h := fnv.New32a()
			_, _ = h.Write([]byte(p)) // a hash.Hash never returns an error
			parts[i] = fmt.Sprintf("%s~%08x", stem, h.Sum32())
			if dotted {
				parts[i] += "." + ext
			}
		}
	}
	return filepath.Join(append([]string{"testdata"}, parts...)...) + ".golden"
}

// windowsDevice reports whether Windows reserves name as a device, with or
// without an extension.
func windowsDevice(name string) bool {
	switch strings.ToUpper(name) {
	case "CON", "PRN", "AUX", "NUL",
		"COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	}
	return false
}

// rerun is the command that runs just this test with -update.
func rerun(name string) string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		parts[i] = "^" + regexp.QuoteMeta(p) + "$"
	}
	return fmt.Sprintf("go test -run '%s' -update", strings.Join(parts, "/"))
}

// check is Golden without the testing.TB: it compares (or, updating,
// writes) the snapshot at path, and returns what to log and what failed.
func check(path string, src plan.Source, m plan.Message, update bool, rerun string) (string, error) {
	cur, facts, err := take(src, m)
	if err != nil {
		return "", fmt.Errorf("plantest: the policy does not build, so there is nothing to snapshot: %w", err)
	}
	got := cur.render()
	path = filepath.Clean(path)
	want, readErr := os.ReadFile(path)
	if readErr != nil && !errors.Is(readErr, fs.ErrNotExist) {
		return "", fmt.Errorf("plantest: %w", readErr)
	}
	same := readErr == nil && string(normalize(want)) == string(got)

	if update {
		if same {
			return "", nil
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return "", fmt.Errorf("plantest: %w", err)
		}
		// A snapshot is checked in, not secret; git records no mode but
		// the executable bit.
		if err := os.WriteFile(path, got, 0o644); err != nil { //nolint:gosec // see above
			return "", fmt.Errorf("plantest: %w", err)
		}
		if readErr != nil {
			return fmt.Sprintf("plantest: wrote %s; review it and check it in", path), nil
		}
		return fmt.Sprintf("plantest: updated %s, recording:\n\n%s", path, strings.TrimRight(explain(want, cur, facts, m), "\n")), nil
	}

	if readErr != nil {
		return "", fmt.Errorf("plantest: no snapshot at %s. Write it with\n\n\t%s\n\nthen review it and check it in", path, rerun)
	}
	if same {
		return "", nil
	}
	return "", fmt.Errorf("plantest: %s no longer matches the policy.\n\n%sIf every change is intended (no row has been written under a changed context yet, or a migration ships with it), record them with\n\n\t%s\n\n%s",
		path, explain(want, cur, facts, m), rerun, diff(path, normalize(want), got))
}

// normalize undoes a checkout's "\r\n" line endings.
func normalize(b []byte) []byte {
	return []byte(strings.ReplaceAll(string(b), "\r\n", "\n"))
}
