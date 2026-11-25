package encrypt_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// fakeZeroKMS answers the default keyset's load and generate-data-key with
// material derived from what it is asked, as ZeroKMS derives the same key
// for the same IV, so a client can be built and encrypt with no service.
// Every data-key request panics while panics is set.
type fakeZeroKMS struct {
	panics atomic.Bool
}

func fakeMaterial(seed []byte) []byte {
	out := make([]byte, 0, 17*sha256.Size)
	for j := range 17 {
		h := sha256.New()
		h.Write([]byte("material"))
		h.Write(seed)
		h.Write([]byte{byte(j)})
		out = h.Sum(out)
	}
	return out[:528]
}

func (f *fakeZeroKMS) RoundTrip(r *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString
	var answer any
	switch path := r.URL.Path; {
	case strings.HasSuffix(path, "load-keyset"):
		const id = "3f8a7c1e-6b2d-4e59-9a14-2c7d5e0f8b31"
		answer = map[string]any{
			"partial_index_key": map[string]any{"key_material": b64(fakeMaterial([]byte("index" + id)))},
			"dataset":           map[string]any{"id": id, "name": "default", "description": "", "is_disabled": false, "is_default": true},
		}
	case strings.HasSuffix(path, "generate-data-key"):
		if f.panics.Load() {
			panic("roundtripper panic")
		}
		var req struct {
			Keys []struct {
				IV string `json:"iv"`
			} `json:"keys"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			return nil, err
		}
		keys := make([]any, 0, len(req.Keys))
		for _, k := range req.Keys {
			iv, err := base64.StdEncoding.DecodeString(k.IV)
			if err != nil {
				return nil, err
			}
			tag := sha256.Sum256(append([]byte("tag"), iv...))
			keys = append(keys, map[string]any{"key_material": b64(fakeMaterial(iv)), "tag": b64(tag[:])})
		}
		answer = map[string]any{"keys": keys}
	default:
		return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(path))}, nil
	}
	b, err := json.Marshal(answer)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(b))}, nil
}

// More encrypts than the guest has paused slots, each ended by a panic in
// the RoundTripper that the caller recovers: none of them leaves its
// operation paused in the guest, so the call after them still reaches
// ZeroKMS. Left paused, the 65th would fail with "too many operations are
// paused" before any request.
func TestAClientServesCallsAfterMoreRecoveredPanicsThanThePausedCap(t *testing.T) {
	ctx := context.Background()
	kms := &fakeZeroKMS{}
	c, err := encrypt.NewClient(ctx, encrypt.WithCredentials(encrypt.FixedCredentials()),
		encrypt.WithZeroKMSURL("http://zerokms.invalid"), encrypt.WithTransport(kms))
	if errors.Is(err, encrypt.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cipher := c.DefaultKeyset()
	users := []testusers.User{{Age: 30, Email: "a@example.com", Notes: "n"}}
	encryptRecovering := func() (p any, err error) {
		defer func() { p = recover() }()
		_, err = testusers.Encrypt(ctx, cipher, users)
		return nil, err
	}
	kms.panics.Store(true)
	for i := range encrypt.MaxPaused + 1 {
		if p, err := encryptRecovering(); p != "roundtripper panic" {
			t.Fatalf("encrypt %d: got panic %v (err %v), want the RoundTripper's panic", i, p, err)
		}
	}
	kms.panics.Store(false)
	if _, err := testusers.Encrypt(ctx, cipher, users); err != nil {
		t.Fatalf("an encrypt after the panics: %v", err)
	}
}
