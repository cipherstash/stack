package vcvalue

import (
	"errors"
	"testing"
	"time"
)

func TestInteger128Boundaries(t *testing.T) {
	for _, text := range []string{"0", "-1", "170141183460469231731687303715884105727", "-170141183460469231731687303715884105728"} {
		v, err := ParseInt128(text)
		if err != nil || v.String() != text {
			t.Fatalf("%s: %v %s", text, err, v.String())
		}
	}
	for _, text := range []string{"0", "1", "340282366920938463463374607431768211455"} {
		v, err := ParseUint128(text)
		if err != nil || v.String() != text {
			t.Fatalf("%s: %v %s", text, err, v.String())
		}
	}
	for _, text := range []string{"bad", "170141183460469231731687303715884105728", "-170141183460469231731687303715884105729"} {
		if _, err := ParseInt128(text); !errors.Is(err, ErrIntegerRange) {
			t.Fatalf("accepted %s", text)
		}
	}
	for _, text := range []string{"bad", "-1", "340282366920938463463374607431768211456"} {
		if _, err := ParseUint128(text); !errors.Is(err, ErrIntegerRange) {
			t.Fatalf("accepted %s", text)
		}
	}
}

func TestDecimalExactness(t *testing.T) {
	for _, text := range []string{"0", "1.50", "-79228162514264337593543950335", "0.0000000000000000000000000001"} {
		v, err := ParseDecimal(text)
		if err != nil || v.String() != text {
			t.Fatalf("%s: %v %s", text, err, v.String())
		}
	}
	// A zero has no sign: the scale is kept and the sign is dropped (ADR 0001).
	for _, text := range []string{"-0", "-0.00", "+0.0"} {
		v, err := ParseDecimal(text)
		if err != nil || v.Negative || !v.IsZero() {
			t.Fatalf("%s: %v %#v", text, err, v)
		}
	}
	if v, _ := ParseDecimal("-0.00"); v.String() != "0.00" {
		t.Fatalf("negative zero prints as %s", v.String())
	}
	if n := (Decimal{Negative: true, Scale: 2}).Normalized(); n.Negative {
		t.Fatal("Normalized kept the sign of a zero")
	}
	if n := (Decimal{Negative: true, Scale: 2, Coefficient: [12]byte{1}}).Normalized(); !n.Negative {
		t.Fatal("Normalized dropped the sign of a nonzero")
	}
	for _, text := range []string{"NaN", "+nan", "-NaN", "inf", "+Infinity", "-Infinity"} {
		if _, err := ParseDecimal(text); !errors.Is(err, ErrNonFiniteDecimal) {
			t.Fatalf("%s: %v", text, err)
		}
	}
	for _, text := range []string{"", ".1", "1.", "1.2.3", "1e2", "1_0", " 1", "a", "0.00000000000000000000000000001", "79228162514264337593543950336"} {
		if _, err := ParseDecimal(text); !errors.Is(err, ErrInvalidDecimal) {
			t.Fatalf("accepted %s", text)
		}
	}
}

func TestDatesAndTimestampBounds(t *testing.T) {
	for _, d := range []Date{{1, 1, 1}, {0, 1, 1}, {2024, 2, 29}, {-9999, 1, 1}, {9999, 12, 31}} {
		days, err := d.DaysFromCE()
		if err != nil {
			t.Fatal(err)
		}
		got, err := DateFromDaysCE(days)
		if err != nil || got != d {
			t.Fatalf("%v: %v %v", d, got, err)
		}
	}
	for _, d := range []Date{{2023, 2, 29}, {2024, 0, 1}, {2024, 13, 1}, {2024, 1, 0}, {2024, 1, 32}, {-10000, 12, 31}, {10000, 1, 1}} {
		if d.Validate() == nil {
			t.Fatalf("accepted %v", d)
		}
	}
	// The ends of the wire's range, which is jiff's.
	first := time.Date(-9999, 1, 2, 1, 59, 59, 0, time.UTC).Unix()
	last := time.Date(9999, 12, 30, 22, 0, 0, 0, time.UTC).Unix()
	for _, ts := range []Timestamp{{0, 0}, {-1, 999999999}, {59, 123456789}, {first, 0}, {last, 999999999}} {
		if ts.Validate() != nil {
			t.Fatalf("rejected %v", ts)
		}
	}
	// A leap second has no count since the epoch and is refused (ADR 0001).
	// So is an instant past either end of the range.
	for _, ts := range []Timestamp{{0, 1000000000}, {59, 1123456789}, {59, 2000000000}, {first - 1, 999999999}, {last + 1, 0}, {time.Date(12000, 1, 1, 0, 0, 0, 0, time.UTC).Unix(), 0}, {1<<63 - 1, 0}} {
		if ts.Validate() == nil {
			t.Fatalf("accepted %v", ts)
		}
	}
}

func TestUUIDSpelling(t *testing.T) {
	text := "123e4567-e89b-12d3-a456-426614174000"
	u, err := ParseUUID(text)
	if err != nil || u.String() != text {
		t.Fatalf("%s: %v %s", text, err, u.String())
	}
	if u[0] != 0x12 || u[15] != 0x00 || u[4] != 0xe8 {
		t.Fatalf("bytes %x", u[:])
	}
	if upper, err := ParseUUID("123E4567-E89B-12D3-A456-426614174000"); err != nil || upper != u {
		t.Fatalf("upper case: %v", err)
	}
	for _, bad := range []string{"", "123e4567e89b12d3a456426614174000", "{123e4567-e89b-12d3-a456-426614174000}", "123e4567-e89b-12d3-a456-42661417400g", "123e4567-e89b-12d3-a456-4266141740000",
		"123e4567-e89b-12d3-a456-42661417400-", // a fifth hyphen at the end
		"123e4567-e89b-12d3-a456-4266-4174000", // a fifth hyphen inside the last group
	} {
		if _, err := ParseUUID(bad); !errors.Is(err, ErrInvalidUUID) {
			t.Fatalf("accepted %q", bad)
		}
	}
}
