package encrypt

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cipherstash/stack/languages/golang/internal/guest"

	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

// Pure Go: no guest needed.

func TestKeysetIDRoundTripsCanonicalForm(t *testing.T) {
	const s = "6a70bd18-99ac-4650-b104-37eec3a15b09"
	id, err := ParseKeysetID(s)
	if err != nil {
		t.Fatal(err)
	}
	if got := id.String(); got != s {
		t.Fatalf("String() = %q, want %q", got, s)
	}
	for _, bad := range []string{"", "6a70bd18", "6a70bd18-99ac-4650-b104-37eec3a15b0g", "6a70bd1899ac4650b10437eec3a15b09"} {
		if _, err := ParseKeysetID(bad); err == nil {
			t.Errorf("ParseKeysetID(%q) accepted", bad)
		}
	}
}

func TestSelectorsSpellEveryVariant(t *testing.T) {
	id := KeysetID{1, 2, 3}
	cases := []struct {
		sel  KeysetSelector
		want map[string]any
	}{
		{defaultKeyset{}, map[string]any{"default": map[string]any{}}},
		{KeysetName("acme"), map[string]any{"name": "acme"}},
		{id, map[string]any{"id": id[:]}},
		{anyKeyset{}, map[string]any{"any": map[string]any{}}},
	}
	for _, tc := range cases {
		if got := tc.sel.selector(); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%T: got %v, want %v", tc.sel, got, tc.want)
		}
		if _, err := vcffi.Marshal(options(tc.sel)); err != nil {
			t.Errorf("%T options do not marshal: %v", tc.sel, err)
		}
	}
}

// The request body wipes its buffer when closed, not before: reads up to
// Close see the bytes, Close zeroes them, a read after Close is an error
// rather than zeros, and a second Close is harmless.
func TestRequestBodyWipesOnClose(t *testing.T) {
	src := []byte(`{"client_id":"abc"}`)
	b := newRequestBody(src)
	wipe(src) // the guest wipes its own buffer on return; the copy must not notice
	got, err := io.ReadAll(b)
	if err != nil || string(got) != `{"client_id":"abc"}` {
		t.Fatalf("ReadAll = %q, %v", got, err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bytes.Equal(b.buf, make([]byte, len(b.buf))) {
		t.Errorf("buffer after Close = %q, want zeros", b.buf)
	}
	if _, err := b.Read(make([]byte, 1)); !errors.Is(err, errRequestBodyClosed) {
		t.Errorf("Read after Close: %v, want errRequestBodyClosed", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// A close before the send is complete fails the send rather than
	// letting zeros through as the request.
	b = newRequestBody([]byte("0123456789"))
	if n, err := b.Read(make([]byte, 4)); n != 4 || err != nil {
		t.Fatalf("partial Read = %d, %v", n, err)
	}
	_ = b.Close()
	if _, err := io.ReadAll(b); !errors.Is(err, errRequestBodyClosed) {
		t.Errorf("ReadAll after an early Close: %v, want errRequestBodyClosed", err)
	}
}

func TestHeadersRoundTrip(t *testing.T) {
	h := http.Header{}
	h.Add("Content-Type", "application/json")
	h.Add("X-Multi", "a")
	h.Add("X-Multi", "b")
	buf := encodeHeaders(h)
	if string(buf) != "Content-Type: application/json\nX-Multi: a\nX-Multi: b" {
		t.Fatalf("encoded %q", buf)
	}
	back := parseHeaders(append([]byte("garbage line\n"), buf...))
	if got := back.Get("content-type"); got != "application/json" {
		t.Fatalf("parsed content-type %q", got)
	}
	if got := back.Values("X-Multi"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("parsed multi %v", got)
	}
}

func TestTermsAndLeavesScanAndValue(t *testing.T) {
	var eq EqualityTerm
	if err := eq.Scan([]byte{1, 2}); err != nil || !eq.Equal(EqualityTerm{1, 2}) {
		t.Fatalf("scan/equal: %v %v", err, eq)
	}
	if eq.Equal(EqualityTerm{1, 3}) {
		t.Fatal("unequal terms compared equal")
	}
	var m MatchTerm = []byte{1, 0, 2, 0}
	pos, err := m.Positions()
	if err != nil || !reflect.DeepEqual(pos, []uint16{1, 2}) {
		t.Fatalf("positions %v %v", pos, err)
	}
	if _, err := (MatchTerm{1}).Positions(); err == nil {
		t.Fatal("odd match term accepted")
	}
	var s Ciphertext
	if err := s.Scan(nil); err == nil {
		t.Fatal("NULL scanned into Ciphertext")
	}
	if err := s.Scan("ab"); err != nil || string(s) != "ab" {
		t.Fatalf("string scan: %v %q", err, s)
	}
	src := []byte{7}
	if err := s.Scan(src); err != nil {
		t.Fatal(err)
	}
	src[0] = 8
	if s[0] != 7 {
		t.Fatal("Scan aliased the driver's slice")
	}
	v, err := s.Value()
	if err != nil || string(v.([]byte)) != "\x07" {
		t.Fatalf("Value: %v %v", v, err)
	}
}

func TestLeafSetKeepsStackEncryptLeavesDistinct(t *testing.T) {
	ct := map[string]any{
		"a": Ciphertext{1},
		"b": otherLeaf{kind: vcffi.LeafNone, bytes: []byte{2}},
		"c": otherLeaf{kind: vcffi.LeafEmptySeq, bytes: []byte{3}},
		"d": otherLeaf{kind: vcffi.LeafEmptyMap, bytes: []byte{4}},
		"p": vcvalue.Plain{V: "clear"},
	}
	encoded, err := marshalCipherText(ct)
	if err != nil {
		t.Fatal(err)
	}
	back, err := unmarshalCipherText(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, ct) {
		t.Fatalf("round trip %#v", back)
	}
	// A vitaminc leaf is not a stack-encrypt node.
	if _, err := marshalCipherText(map[string]any{"a": vcvalue.Sealed{1}}); err == nil {
		t.Fatal("vcvalue.Sealed accepted as a stack-encrypt leaf")
	}
	if _, err := vcffi.MarshalCipherText(vcffi.VCValueLeaves(), Ciphertext{1}); err == nil {
		t.Fatal("encrypt.Ciphertext accepted as a vitaminc leaf")
	}
}

// This package's sentinels are the shared table's: a packed status decodes
// to the error this package names for it.
func TestStatusMappingIsTotal(t *testing.T) {
	for status, want := range map[uint32]error{
		1: ErrAuthentication, 2: ErrEncoding, 3: ErrState, 4: ErrInternal,
		5: ErrUnauthorized, 6: ErrForbidden, 7: ErrNotFound, 8: ErrConflict,
		9: ErrTransport, 10: ErrKMS, 11: ErrTerm, 12: ErrForeignKeyset,
	} {
		if _, _, got := guest.PackedResult(uint64(status)); !errors.Is(got, want) {
			t.Errorf("status %d: %v", status, got)
		}
	}
	if _, _, got := guest.PackedResult(99); !errors.Is(got, ErrInternal) {
		t.Errorf("unknown status: %v", got)
	}
}

// The Go ordering of ORE and OPE terms agrees with Rust's Ord: testdata
// holds ciphertexts the cllw-ore crate produced, each group in ascending
// plaintext order, and every pair must order the same way here.
func TestTermOrderingAgreesWithRust(t *testing.T) {
	f, err := os.Open("testdata/cllw_order.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	groups := map[string][][]byte{}
	var order []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Fields(line)
		kind, typ, raw := parts[0], parts[1], parts[len(parts)-1]
		if raw == "-" {
			raw = ""
		}
		term, err := hex.DecodeString(raw)
		if err != nil {
			t.Fatal(err)
		}
		key := kind + " " + typ
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], term)
	}
	if len(order) != 4 {
		t.Fatalf("expected 4 vector groups, found %v", order)
	}
	for _, key := range order {
		terms := groups[key]
		compare := func(i, j int) int {
			if strings.HasPrefix(key, "ope") {
				return OpeTerm(terms[i]).Compare(OpeTerm(terms[j]))
			}
			return OreTerm(terms[i]).Compare(OreTerm(terms[j]))
		}
		for i := range terms {
			for j := range terms {
				want := 0
				if i < j {
					want = -1
				} else if i > j {
					want = 1
				}
				if got := compare(i, j); got != want {
					t.Errorf("%s: compare(%d, %d) = %d, want %d", key, i, j, got, want)
				}
			}
		}
		if strings.HasPrefix(key, "ore") && !OreTerm(terms[0]).Less(OreTerm(terms[1])) {
			t.Errorf("%s: Less disagrees with Compare", key)
		}
	}
	// A different length that shares no prefix bytes still orders by the
	// first difference, and an empty term is less than any other.
	if OreTerm(nil).Compare(OreTerm{1}) != -1 || (OreTerm{1}).Compare(OreTerm(nil)) != 1 || OreTerm(nil).Compare(OreTerm(nil)) != 0 {
		t.Error("empty ORE terms do not order by length")
	}
}
