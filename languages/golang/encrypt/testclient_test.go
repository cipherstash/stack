package encrypt

import (
	"context"
	"errors"
	"testing"
)

// The constructor package encrypttest reaches is harmless over the guests
// this package and package eql embed for production: they take a client key,
// and refuse a bare seed as malformed config before any key exists. Each
// build is its own subtest, so a build that is absent shows as a skip and
// never drops out of the check unseen.
func TestAProductionGuestRefusesASeed(t *testing.T) {
	for _, build := range []struct {
		name   string
		load   func() ([]byte, error)
		absent error
	}{
		{"without the EQL types", plainGuest, ErrGuestNotBuilt},
		{"with the EQL types", eqlGuest, ErrEQLGuestNotBuilt},
	} {
		t.Run(build.name, func(t *testing.T) {
			wasm, err := build.load()
			if errors.Is(err, build.absent) {
				t.Skip(err)
			}
			if err != nil {
				t.Fatal(err)
			}
			c, err := seededClient(context.Background(), wasm, [32]byte{7})
			if err == nil {
				_ = c.Close()
				t.Fatal("a production guest took a seed in place of a client key")
			}
			if !errors.Is(err, ErrEncoding) {
				t.Fatalf("%v, want ErrEncoding", err)
			}
		})
	}
}
