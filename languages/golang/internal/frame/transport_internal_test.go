package vcffi

import "testing"

// White-box pin for eagerCap, mirroring the Rust transport codec's
// eager_capacity test: the clamp is a capacity hint invisible to round-trip
// tests, so assert the function directly — identity below the threshold,
// flat at maxEagerCapacity above it, and zero for negative counts (a u32
// prefix >= 2^31 coerced to int on 32-bit GOARCH, which must not reach
// make()). The constant itself is pinned so a silent bump shows up here.
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
