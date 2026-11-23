package encrypt_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// countYields counts the steps of c's operations that pause to yield, from
// now on.
func countYields(c *encrypt.Client) *atomic.Uint64 {
	var n atomic.Uint64
	encrypt.OnYield(c, func() { n.Add(1) })
	return &n
}

// A batch yields to the host between chunks of its rows, so the Go runtime
// gets control back while the guest seals or opens it (the garbage
// collector's stop-the-world pause cannot preempt a running guest call),
// and the batch still comes back whole and in order.
//
// The count is exact. A User takes three data keys (Age, Email, Notes), and
// a column yields once its items have taken 64 keys or more and items
// remain: every 22 rows (66 keys). So 200 rows yield after rows 22, 44, ...,
// 198, nine times each way. The guest's chunking runs only in wasm, where
// no Rust test reaches it, so this count is what pins it.
func TestABigBatchYieldsAndRoundTrips(t *testing.T) {
	const wantYields = 9
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	yields := countYields(c)

	rows := make([]testusers.User, 200)
	for i := range rows {
		rows[i] = testusers.User{ID: int64(i), Age: uint32(20 + i%50), Email: fmt.Sprintf("user%d@example.com", i), Notes: "notes"}
	}
	encrypted, err := testusers.Encrypt(ctx, cipher, rows)
	if err != nil {
		t.Fatal(err)
	}
	if n := yields.Swap(0); n != wantYields {
		t.Errorf("sealing 200 rows yielded %d times, want %d", n, wantYields)
	}
	back, err := testusers.Decrypt(ctx, cipher, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if n := yields.Load(); n != wantYields {
		t.Errorf("opening 200 rows yielded %d times, want %d", n, wantYields)
	}
	if !reflect.DeepEqual(back, rows) {
		t.Fatal("the rows did not round-trip")
	}
}

// A batch small enough for one chunk does not yield.
func TestASmallBatchDoesNotYield(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	yields := countYields(c)
	encrypted, err := testusers.Encrypt(ctx, cipher, people[:2])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testusers.Decrypt(ctx, cipher, encrypted); err != nil {
		t.Fatal(err)
	}
	if n := yields.Load(); n != 0 {
		t.Errorf("two rows yielded %d times", n)
	}
}

// A batch whose caller gives up at a yield is dropped in the guest between
// two chunks, and dropping it wipes the plaintext it held: the rows not yet
// sealed, and the work of the chunk before. The guest's chunking runs only
// in wasm, so only a call through the real guest reaches that drop.
//
// The call fails with the context's error alone: a yield sent no request,
// so it is not a transport failure. Afterwards the client still works.
//
// Encrypt, not Decrypt: after Decrypt, copies of an opened string remain in
// the guest's shadow stack for a reason outside this code (see
// TestPlaintextDoesNotRemainInGuestMemoryAfterDecrypt).
func TestABatchCancelledAtAYieldLeavesNoPlaintextInGuestMemory(t *testing.T) {
	const marker = "yield-cancel-probe-"
	c := deterministicClient(t)
	cipher := c.DefaultKeyset()
	rows := make([]testusers.User, 200)
	for i := range rows {
		rows[i] = testusers.User{
			ID:    int64(i),
			Age:   uint32(20 + i%50),
			Email: fmt.Sprintf("%s%03d@example.com", marker, i),
			Notes: fmt.Sprintf("%snotes-%03d-b1c2d3e4f5", marker, i),
		}
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var yields atomic.Uint64
	var atYield int
	encrypt.OnYield(c, func() {
		if yields.Add(1) == 1 {
			// The operation is paused here with its rows in the guest:
			// this is what the drop has to wipe.
			atYield = bytes.Count(encrypt.GuestMemory(t, c), []byte(marker))
			cancel()
		}
	})
	_, err := testusers.Encrypt(ctx, cipher, rows)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Encrypt cancelled at a yield: %v, want context.Canceled", err)
	}
	if errors.Is(err, encrypt.ErrTransport) {
		t.Errorf("Encrypt cancelled at a yield: %v matches ErrTransport, but a yield sends no request", err)
	}
	if n := yields.Load(); n != 1 {
		t.Fatalf("the batch yielded %d times, want 1: it was not dropped at its first yield", n)
	}
	if atYield == 0 {
		t.Fatalf("no %q in guest memory at the yield: this test would not see plaintext left behind", marker)
	}

	mem := encrypt.GuestMemory(t, c)
	if n := bytes.Count(mem, []byte(marker)); n != 0 {
		t.Errorf("%q found %d times in guest memory after the batch was dropped (%d at the yield)", marker, n, atYield)
	}
	for _, r := range rows {
		for _, needle := range []string{r.Email, r.Notes} {
			if bytes.Contains(mem, []byte(needle)) {
				t.Errorf("%q remains in guest memory after the batch was dropped", needle)
			}
		}
	}

	// The drop left the guest able to run the next call, and the call gave
	// its paused slot back.
	encrypt.OnYield(c, nil)
	encrypted, err := testusers.Encrypt(t.Context(), cipher, people[:2])
	if err != nil {
		t.Fatalf("Encrypt after the dropped batch: %v", err)
	}
	back, err := testusers.Decrypt(t.Context(), cipher, encrypted)
	if err != nil {
		t.Fatalf("Decrypt after the dropped batch: %v", err)
	}
	want := append([]testusers.User(nil), people[:2]...)
	for i := range want {
		want[i].Internal = ""
	}
	if !reflect.DeepEqual(back, want) {
		t.Fatalf("round trip after the dropped batch: got %+v, want %+v", back, want)
	}
}
