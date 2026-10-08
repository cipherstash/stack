package encrypt

import (
	"context"
	"errors"
	"testing"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
)

// wantDiagnostic asserts that err carries a *Diagnostic with code and a
// message, and returns it.
func wantDiagnostic(t *testing.T, err error, code string) *Diagnostic {
	t.Helper()
	var d *Diagnostic
	if !errors.As(err, &d) {
		t.Fatalf("%v carries no Diagnostic", err)
	}
	if d.Code != code {
		t.Fatalf("code = %q, want %q (%v)", d.Code, code, err)
	}
	if d.Message == "" {
		t.Fatalf("%s has no message", code)
	}
	return d
}

// wantCode is wantDiagnostic for a test that needs only the code.
func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	_ = wantDiagnostic(t, err, code)
}

// The guest's own refusals, which no ZeroKMS stub reaches: input that is
// not the codec, and an operation before init.
func TestGuestRefusalsCarryTheirDiagnostic(t *testing.T) {
	ctx := context.Background()
	c := rawInstance(t)
	_, err := c.call(ctx, func(inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.planCheck, buf([]byte{0xff}))
	})
	if !errors.Is(err, ErrEncoding) {
		t.Fatalf("plan check of bytes that are not the codec: %v, want ErrEncoding", err)
	}
	wantCode(t, err, "stack_guest_abi::malformed_input")

	selector, err := vcffi.Marshal(KeysetName("tenant-b").selector())
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.call(ctx, func(inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.keyset, buf(selector))
	})
	if !errors.Is(err, ErrState) {
		t.Fatalf("a keyset before init: %v, want ErrState", err)
	}
	if d := wantDiagnostic(t, err, "stack_guest_abi::out_of_order"); d.Help == "" {
		t.Error("an out-of-order call gives no help")
	}
}

// A guest built before se_last_error fails as it always did: the bare
// sentinel, and nothing else.
func TestAGuestWithoutLastErrorFailsWithTheBareSentinel(t *testing.T) {
	ctx := context.Background()
	c := rawInstance(t)
	c.inst.exports.LastError = nil
	_, err := c.call(ctx, func(inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.planCheck, buf([]byte{0xff}))
	})
	if err != ErrEncoding {
		t.Fatalf("err = %#v, want the bare ErrEncoding", err)
	}
	var d *Diagnostic
	if errors.As(err, &d) {
		t.Fatalf("a Diagnostic from a guest with no se_last_error: %+v", d)
	}
}
