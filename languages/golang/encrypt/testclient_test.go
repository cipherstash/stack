package encrypt

import (
	"context"
	"errors"
	"testing"
)

// The constructor package encrypttest reaches is harmless over the guests
// this package and package eql embed for production: they take a client key,
// and refuse a bare seed as malformed config before any key exists.
func TestAProductionGuestRefusesASeed(t *testing.T) {
	plain, err := PlainGuest()
	if errors.Is(err, ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	guests := map[string][]byte{"the guest without the EQL types": plain}
	if withEQL, err := EmbeddedGuest(); err == nil {
		guests["the guest the program runs"] = withEQL
	}
	for name, wasm := range guests {
		c, err := seededClient(context.Background(), wasm, [32]byte{7})
		if err == nil {
			_ = c.Close()
			t.Fatalf("%s took a seed in place of a client key", name)
		}
		if !errors.Is(err, ErrEncoding) {
			t.Fatalf("%s: %v, want ErrEncoding", name, err)
		}
	}
}
