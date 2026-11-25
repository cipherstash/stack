package encrypt_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

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
// gets control back while the guest builds the batch and while it seals or
// opens it (the garbage collector's stop-the-world pause cannot preempt a
// running guest call), and the batch still comes back whole and in order.
//
// The count is exact. A User takes three data keys (Age, Email, Notes), and
// a chunk ends once its rows have taken 64 keys or more and rows remain:
// every 22 rows (66 keys). So 200 rows yield after rows 22, 44, ..., 198,
// nine times while the batch is built and nine more while it is sealed or
// opened: eighteen each way. A Rust test runs the build's chunks natively,
// but a column is sealed or opened in chunks only in wasm, where no Rust
// test reaches it, so this count is what pins the sealing and opening
// yields, and the whole count in the guest.
func TestABigBatchYieldsAndRoundTrips(t *testing.T) {
	const wantYields = 2 * 9
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

// A batch whose rows fall in two groups, because every third row leaves
// out its optional fields, is built in chunks that run across both groups,
// and still comes back whole and in order. The rows of the two groups carry
// a different number of EQL fields, so each row must take back its own EQL
// values: a whole row has DOB, Born and Joined, and a row that leaves out
// its optional fields has DOB and Born. Every date is different, so a value
// given to the wrong row or field does not come back as it was.
//
// The count is exact. A Person's record takes a data key for Age, Score
// and Nick, so a whole row takes three and a row that leaves out Score and
// Nick takes one. Its EQL fields take a key each, but are not built in
// chunks. A batch builds group by group:
//
//   - the build: the 200 whole rows, 22 to a chunk (66 keys), fill nine
//     chunks. The tenth takes the last 2 whole rows and 58 of the others
//     (64 keys), and the eleventh the last 42. Ten yields.
//   - the sealing or opening: the whole rows' column yields nine times
//     (after every 22 rows), the other group's column once (after 64
//     rows), and the column of the 800 EQL fields twelve times (after every
//     64). Twenty-two yields.
func TestABigBatchInTwoGroupsYieldsAndRoundTrips(t *testing.T) {
	const wantYields = 10 + 22
	c := deterministicEQLClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	yields := countYields(c)

	rows := make([]testusers.Person, 300)
	for i := range rows {
		day := func(year int) *encrypt.Date {
			return &encrypt.Date{Year: year + i, Month: time.Month(1 + i%12), Day: 1 + i%28}
		}
		rows[i] = testusers.Person{ID: int64(i), Age: ptr(int32(i)), DOB: day(1600), Born: day(1300)}
		if i%3 != 2 {
			rows[i].Score = ptr(int64(i))
			rows[i].Nick = ptr(fmt.Sprintf("nick-%03d", i))
			rows[i].Joined = day(1000)
		}
	}
	encrypted, err := testusers.EncryptPerson(ctx, cipher, rows)
	if err != nil {
		t.Fatal(err)
	}
	if n := yields.Swap(0); n != wantYields {
		t.Errorf("sealing 300 rows in two groups yielded %d times, want %d", n, wantYields)
	}
	if encrypted[1].Score == nil || encrypted[1].Joined == nil || encrypted[2].Score != nil || encrypted[2].Nick != nil || encrypted[2].Joined != nil {
		t.Fatalf("every third row leaves out Score, Nick and Joined, and the others store them: %+v, %+v", encrypted[1], encrypted[2])
	}
	back, err := testusers.DecryptPerson(ctx, cipher, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if n := yields.Load(); n != wantYields {
		t.Errorf("opening 300 rows in two groups yielded %d times, want %d", n, wantYields)
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
// two chunks, and dropping it wipes the plaintext it held. 200 rows yield
// nine times while they are built and nine times while they are sealed
// (see TestABigBatchYieldsAndRoundTrips), and each kind of yield drops
// something different:
//
//   - at a build yield, the rows not built yet, and the rows built so far,
//     each waiting to be sealed;
//   - at a sealing yield, a column sealed part way: the rows sealed so far,
//     and the rows not sealed yet.
//
// Only a call through the real guest drops a column part way: natively a
// column is sealed in one pass, with no yield.
//
// The call fails with the context's error alone: a yield sent no request,
// so it is not a transport failure. Afterwards the client still works.
//
// Encrypt, not Decrypt: after Decrypt, copies of an opened string remain in
// the guest's shadow stack for a reason outside this code (see
// TestPlaintextDoesNotRemainInGuestMemoryAfterDecrypt).
func TestABatchCancelledAtAYieldLeavesNoPlaintextInGuestMemory(t *testing.T) {
	for _, tc := range []struct {
		name string
		// at is the yield the caller gives up at, counted from one.
		at uint64
	}{
		{"at the first build yield", 1},
		{"at the first sealing yield", 10},
	} {
		t.Run(tc.name, func(t *testing.T) { cancelAtYield(t, tc.at) })
	}
}

// cancelAtYield encrypts 200 rows, gives up at yield at, and checks that
// none of their plaintext remains in guest memory.
func cancelAtYield(t *testing.T, at uint64) {
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
		if yields.Add(1) == at {
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
	if n := yields.Load(); n != at {
		t.Fatalf("the batch yielded %d times, want %d: it was not dropped at that yield", n, at)
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
