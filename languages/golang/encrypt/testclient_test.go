package encrypt

import (
	"context"
	"errors"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt/internal/eqlguest"
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

// When package eql is linked, a client runs the build with the EQL types and
// only that build. Its absence is an error, never the plain build in its
// place: every encrypt_into call would fail there. This test binary links
// eql, as the external tests' generated types name EQL types.
func TestSelectBuildNeverFallsBackFromTheEQLBuild(t *testing.T) {
	if !eqlguest.Linked() {
		t.Fatal("this test binary should link package eql")
	}
	plain := func() ([]byte, error) { return []byte("plain"), nil }
	absent := func() ([]byte, error) { return nil, ErrEQLGuestNotBuilt }
	wasm, err := selectBuild(plain, absent)
	if !errors.Is(err, ErrEQLGuestNotBuilt) || wasm != nil {
		t.Fatalf("selectBuild = %q, %v; want ErrEQLGuestNotBuilt and no build", wasm, err)
	}
	withEQL := func() ([]byte, error) { return []byte("eql"), nil }
	if wasm, err := selectBuild(plain, withEQL); err != nil || string(wasm) != "eql" {
		t.Fatalf("selectBuild = %q, %v; want the EQL build", wasm, err)
	}
}
