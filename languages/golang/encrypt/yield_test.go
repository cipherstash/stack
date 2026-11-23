package encrypt_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// A batch yields to the host between chunks of its rows, so the Go runtime
// gets control back while the guest seals or opens it (the garbage
// collector's stop-the-world pause cannot preempt a running guest call),
// and the batch still comes back whole and in order.
func TestABigBatchYieldsAndRoundTrips(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()

	rows := make([]testusers.User, 200)
	for i := range rows {
		rows[i] = testusers.User{ID: int64(i), Age: uint32(20 + i%50), Email: fmt.Sprintf("user%d@example.com", i), Notes: "notes"}
	}
	before := encrypt.Yields(c)
	encrypted, err := testusers.Encrypt(ctx, cipher, rows)
	if err != nil {
		t.Fatal(err)
	}
	sealing := encrypt.Yields(c) - before
	if sealing == 0 {
		t.Error("sealing 200 rows did not yield")
	}
	before = encrypt.Yields(c)
	back, err := testusers.Decrypt(ctx, cipher, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if encrypt.Yields(c)-before == 0 {
		t.Error("opening 200 rows did not yield")
	}
	if !reflect.DeepEqual(back, rows) {
		t.Fatal("the rows did not round-trip")
	}
	t.Logf("yields: %d sealing, %d opening", sealing, encrypt.Yields(c)-before)
}

// A batch small enough for one chunk does not yield.
func TestASmallBatchDoesNotYield(t *testing.T) {
	c := deterministicClient(t)
	ctx := context.Background()
	cipher := c.DefaultKeyset()
	before := encrypt.Yields(c)
	encrypted, err := testusers.Encrypt(ctx, cipher, people[:2])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testusers.Decrypt(ctx, cipher, encrypted); err != nil {
		t.Fatal(err)
	}
	if n := encrypt.Yields(c) - before; n != 0 {
		t.Errorf("two rows yielded %d times", n)
	}
}
