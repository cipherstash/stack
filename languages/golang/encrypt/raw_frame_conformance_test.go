package encrypt_test

import (
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
)

type rawFrameCase struct {
	ID         string                         `json:"id"`
	Read       readDeclaration                `json:"read"`
	FrameHex   string                         `json:"frame_hex"`
	Class      string                         `json:"class"`
	Retrievals int                            `json:"retrievals"`
	Expected   *declarationError              `json:"expected"`
	Rows       *[]map[string]conformanceInput `json:"rows"`
	// What the native engine refuses when a frame the codec refuses is read
	// leniently: a Rust observation. The binding never reaches the engine
	// with such a frame, so it is parsed here and not executed.
	NativeTree *declarationError `json:"native_tree"`
}

func TestRawFrameConformance(t *testing.T) {
	var corpus struct {
		Version              int               `json:"version"`
		Profile              string            `json:"profile"`
		Seed                 string            `json:"seed"`
		RequiredCapabilities []string          `json:"required_capabilities"`
		BoundaryError        *declarationError `json:"boundary_error"`
		Cases                []rawFrameCase    `json:"cases"`
	}
	readConformanceJSON(t, filepath.Join("..", "..", "..", "conformance", "stack-encrypt", "v1", "record-raw-frames-v1.cases.json"), &corpus)
	if corpus.Version != 1 || corpus.Profile != "record-raw-frames-v1" || len(corpus.Cases) == 0 || corpus.BoundaryError == nil {
		t.Fatal("unsupported or empty raw-frame corpus")
	}
	if !reflect.DeepEqual(corpus.RequiredCapabilities, []string{"records", "raw-frames", "read-shapes", "authenticated-types"}) {
		t.Fatal("unsupported capabilities")
	}
	seed, err := hex.DecodeString(corpus.Seed)
	if err != nil || len(seed) != 32 {
		t.Fatal("expected a 32-byte deterministic seed")
	}
	ctx := context.Background()
	client, err := encrypt.NewDeterministicClient(ctx, [32]byte(seed))
	skipMissingConformanceGuest(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	wasm, err := encrypt.DeterministicGuest()
	if err != nil {
		t.Fatal(err)
	}
	checker, err := encrypt.NewCheckerOver(ctx, wasm)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = checker.Close() })
	cipher := client.DefaultKeyset()
	seen := map[string]bool{}
	for _, c := range corpus.Cases {
		if c.ID == "" || seen[c.ID] {
			t.Fatalf("empty or repeated ID %q", c.ID)
		}
		seen[c.ID] = true
		t.Run(c.ID, func(t *testing.T) {
			frame, err := hex.DecodeString(c.FrameHex)
			if err != nil {
				t.Fatal(err)
			}
			refused := c.Class != "success"
			switch c.Class {
			case "transport", "leaf", "shape", "authenticated", "success":
			default:
				t.Fatalf("unknown class %q", c.Class)
			}
			if (c.Expected == nil) != (c.Class == "success" || c.Class == "transport") || (c.Rows == nil) == (c.Class == "success") {
				t.Fatal("a case says exactly what its class needs")
			}
			if c.NativeTree != nil && c.Class != "transport" {
				t.Fatal("a native tree belongs to a frame the codec refuses")
			}
			if c.Retrievals != 0 && c.Class != "authenticated" && c.Class != "success" {
				t.Fatal("retrieval only once the shape has passed")
			}
			want := c.Expected
			if c.Class == "transport" {
				want = corpus.BoundaryError
				// The host's own tree codec refuses what the guest's does.
				if _, err := encrypt.UnmarshalCipherTextForTest(frame); err == nil {
					t.Fatal("a transport refusal requires a frame the codec refuses")
				}
			}
			plan := readPlan(c.Read, false, "")
			// Without a cipher, the guest decodes and preflights the frame.
			// A frame that passes preflight reaches the state boundary.
			_, err = checker.OpenFrameForTest(ctx, frame, 1, plan, "")
			if c.Class == "authenticated" || c.Class == "success" {
				if !errors.Is(err, encrypt.ErrState) {
					t.Fatalf("expected the state boundary after preflight, got %v", err)
				}
			} else {
				readRefusal(t, err, want)
			}
			out, err := cipher.OpenFrameForTest(ctx, frame, 1, plan)
			if refused {
				// An authentication failure is held to its code and fields
				// like any other refusal, under ErrAuthentication.
				readRefusal(t, err, want)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(out, runtimeRows(t, *c.Rows)) {
				t.Fatalf("typed rows differ: %#v", out)
			}
		})
	}
}
