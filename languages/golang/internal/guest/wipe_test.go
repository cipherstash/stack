package guest_test

import (
	"bytes"
	"testing"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

func TestWipeDecodedZeroesEveryBytesLeafAtAnyDepth(t *testing.T) {
	secret := func() []byte { return []byte("secret") }
	raw, err := vcffi.Marshal(vcvalue.Object{
		{Key: "top", Value: secret()},
		{Key: "text", Value: "kept"},
		{Key: "n", Value: uint64(7)},
		{Key: "list", Value: []any{secret(), "kept", []any{secret()}}},
		{Key: "object", Value: vcvalue.Object{
			{Key: "inner", Value: secret()},
			{Key: "deeper", Value: vcvalue.Object{{Key: "leaf", Value: secret()}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := vcffi.Unmarshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var leaves [][]byte
	var collect func(any)
	collect = func(v any) {
		switch v := v.(type) {
		case []byte:
			leaves = append(leaves, v)
		case []any:
			for _, item := range v {
				collect(item)
			}
		case vcvalue.Object:
			for _, f := range v {
				collect(f.Value)
			}
		}
	}
	collect(decoded)
	if len(leaves) != 5 {
		t.Fatalf("decoded %d bytes leaves, want 5", len(leaves))
	}
	guest.WipeDecoded(decoded)
	for i, leaf := range leaves {
		if !bytes.Equal(leaf, make([]byte, len(leaf))) {
			t.Errorf("bytes leaf %d was not wiped", i)
		}
	}
	obj := decoded.(vcvalue.Object)
	if obj[1].Value != "kept" || obj[2].Value != uint64(7) {
		t.Error("a value that is not bytes changed")
	}
}

func TestWipeDecodedTakesAnyValue(t *testing.T) {
	for _, v := range []any{nil, "text", uint64(1), true, []byte{}, []any{}, vcvalue.Object{}} {
		guest.WipeDecoded(v)
	}
	b := []byte("secret")
	guest.WipeDecoded(b)
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatal("a bare []byte was not wiped")
	}
}
