package frame

import "testing"

// This test calls eagerCap directly, as the eager_capacity test of the Rust
// transport codec does. The limit only changes the capacity that the decoder
// reserves. A test that encodes a value and decodes it again cannot observe
// the limit. The test checks three cases:
//
//   - A count below maxEagerCapacity is returned unchanged.
//   - A count above maxEagerCapacity returns maxEagerCapacity.
//   - A negative count returns zero. On a 32-bit GOARCH, a 32-bit count of
//     2^31 or more converts to a negative int. Such a count must never reach
//     make.
//
// The test also checks the value of the constant, so a change to the
// constant fails here.
func TestEagerCapClampsOnlyAboveThreshold(t *testing.T) {
	if maxEagerCapacity != 1024 {
		t.Fatalf("maxEagerCapacity: got %d, want 1024", maxEagerCapacity)
	}
	cases := []struct{ in, want int }{
		{-1, 0},
		{0, 0},
		{5, 5},
		{maxEagerCapacity, maxEagerCapacity},
		{maxEagerCapacity + 1, maxEagerCapacity},
		{1 << 30, maxEagerCapacity},
	}
	for _, c := range cases {
		if got := eagerCap(c.in); got != c.want {
			t.Fatalf("eagerCap(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}
