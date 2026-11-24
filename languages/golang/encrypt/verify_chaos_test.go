package encrypt_test

// Verification of #1773, not for merge as is.
//
// Many goroutines share one Client and encrypt then decrypt batches of
// random size while every ZeroKMS request may be slow, fail, come back
// truncated or a key short, or panic, and some callers give up at a random
// moment. Every call must return the right plaintexts, or an error (or a
// panic the caller recovers), never wrong data or a partial result; nothing
// may race, hang or leak; and once the faults stop the client must work.
//
//	VERIFY_CHAOS=10m go test ./encrypt/ -race -run TestVerifyChaos -timeout 60m -v
//
// By default ZeroKMS is a fake that answers each key with material derived
// from its IV, as the real one derives the same key for the same IV, so no
// credentials are needed. VERIFY_CHAOS_LIVE=1 uses real ZeroKMS and the
// default credentials (the environment, then the developer profile).
//
// VERIFY_WORKERS (default 24), VERIFY_MAX_DELAY_MS (default 500) and
// VERIFY_PANIC_PER_MILLE (default 1) tune it.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"runtime/pprof"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
)

// ---------------------------------------------------------- a fake ZeroKMS

func materialFor(iv []byte) []byte {
	out := make([]byte, 0, 17*32)
	for j := range 17 {
		h := sha256.New()
		h.Write([]byte("material"))
		h.Write(iv)
		h.Write([]byte{byte(j)})
		out = h.Sum(out)
	}
	return out[:528]
}

func tagFor(iv []byte) []byte {
	h := sha256.Sum256(append([]byte("tag"), iv...))
	return h[:]
}

func jsonResponse(v any) (*http.Response, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(b)),
	}, nil
}

// fakeKMS answers load-keyset, generate and retrieve.
type fakeKMS struct{}

func (fakeKMS) RoundTrip(r *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	var req struct {
		Keys []struct {
			IV string `json:"iv"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString
	path := r.URL.Path
	switch {
	case strings.HasSuffix(path, "load-keyset"):
		return jsonResponse(map[string]any{
			"partial_index_key": map[string]any{"key_material": b64(materialFor([]byte("index")))},
			"dataset": map[string]any{
				"id": "3f8a7c1e-6b2d-4e59-9a14-2c7d5e0f8b31", "name": "default",
				"description": "", "is_disabled": false, "is_default": true,
			},
		})
	case strings.HasSuffix(path, "generate-data-key"),
		strings.HasSuffix(path, "retrieve-data-key"),
		strings.HasSuffix(path, "retrieve-data-key-fallible"):
		keys := make([]any, 0, len(req.Keys))
		for _, k := range req.Keys {
			iv, err := base64.StdEncoding.DecodeString(k.IV)
			if err != nil {
				return nil, err
			}
			key := map[string]any{"key_material": b64(materialFor(iv))}
			switch {
			case strings.HasSuffix(path, "generate-data-key"):
				key["tag"] = b64(tagFor(iv))
				keys = append(keys, key)
			case strings.HasSuffix(path, "fallible"):
				keys = append(keys, map[string]any{"Ok": key})
			default:
				keys = append(keys, key)
			}
		}
		return jsonResponse(map[string]any{"keys": keys})
	}
	return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("no such endpoint " + path))}, nil
}

// ------------------------------------------------------------- the faults

type chaos struct {
	next     http.RoundTripper
	on       atomic.Bool
	maxDelay time.Duration
	panicPM  int

	requests, delayed, status5xx, netErr, truncated, shortKey, panics atomic.Int64
}

func (c *chaos) RoundTrip(r *http.Request) (*http.Response, error) {
	isKMS := strings.Contains(r.URL.Path, "data-key")
	if !c.on.Load() || !isKMS {
		return c.next.RoundTrip(r)
	}
	c.requests.Add(1)
	if c.maxDelay > 0 {
		d := time.Duration(rand.Int64N(int64(c.maxDelay)))
		c.delayed.Add(1)
		select {
		case <-time.After(d):
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	roll := rand.IntN(1000)
	switch {
	case roll < c.panicPM:
		c.panics.Add(1)
		panic("chaos: injected RoundTripper panic")
	case roll < c.panicPM+40:
		c.status5xx.Add(1)
		code := []int{http.StatusInternalServerError, http.StatusServiceUnavailable}[rand.IntN(2)]
		return &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("injected"))}, nil
	case roll < c.panicPM+70:
		c.netErr.Add(1)
		return nil, errors.New("chaos: injected network error")
	}
	resp, err := c.next.RoundTrip(r)
	if err != nil || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	switch {
	case roll < c.panicPM+100:
		// Truncate the body.
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		c.truncated.Add(1)
		resp.Body = io.NopCloser(bytes.NewReader(b[:rand.IntN(len(b))]))
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
	case roll < c.panicPM+130:
		// Remove one key.
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		var v map[string]any
		if err := json.Unmarshal(b, &v); err == nil {
			if keys, ok := v["keys"].([]any); ok && len(keys) > 0 {
				i := rand.IntN(len(keys))
				v["keys"] = slices.Delete(keys, i, i+1)
				b, _ = json.Marshal(v)
				c.shortKey.Add(1)
			}
		}
		resp.Body = io.NopCloser(bytes.NewReader(b))
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
	}
	return resp, nil
}

// ---------------------------------------------------------------- the test

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return def
}

type tally struct {
	mu   sync.Mutex
	kind map[string]int
}

func (t *tally) add(k string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.kind[k]++
}

// classify names an error for the tally, coarsely.
func classify(op string, err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return op + ": context canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return op + ": deadline exceeded"
	case strings.Contains(err.Error(), "too many operations"):
		return op + ": TOO MANY OPERATIONS PAUSED"
	case errors.Is(err, encrypt.ErrTransport):
		msg := err.Error()
		for _, s := range []string{"InvalidNumberOfKeys", "invalid number of keys", "500", "503", "network error", "ParseResponse", "parse", "EOF", "unexpected end"} {
			if strings.Contains(msg, s) {
				return op + ": ErrTransport (" + s + ")"
			}
		}
		return op + ": ErrTransport (other)"
	case errors.Is(err, encrypt.ErrState):
		return op + ": ErrState: " + err.Error()
	}
	return op + ": " + digits.ReplaceAllString(err.Error(), "N")
}

var digits = regexp.MustCompile(`[0-9]+`)

func genUsers(r *rand.Rand, n int) []testusers.User {
	out := make([]testusers.User, n)
	for i := range out {
		out[i] = testusers.User{
			ID:    int64(i),
			Age:   r.Uint32N(120),
			Email: fmt.Sprintf("u%d-%x@example.com", i, r.Uint64()),
			Notes: strings.Repeat(string(rune('a'+r.IntN(26))), r.IntN(40)),
		}
	}
	return out
}

func batchSize(r *rand.Rand) int {
	// Rows of 3 keys each, weighted to the 500-key request boundary and
	// its multiples.
	switch r.IntN(4) {
	case 0:
		return []int{1, 166, 167, 333, 334, 499, 500, 501, 834}[r.IntN(9)]
	default:
		return 1 + r.IntN(900)
	}
}

// guarded runs f, turning a panic into a value.
func guarded(f func() error) (err error, p any) {
	defer func() { p = recover() }()
	return f(), nil
}

func TestVerifyChaos(t *testing.T) {
	dur, err := time.ParseDuration(os.Getenv("VERIFY_CHAOS"))
	if err != nil {
		t.Skip("set VERIFY_CHAOS to a duration to run")
	}
	live := os.Getenv("VERIFY_CHAOS_LIVE") == "1"
	workers := envInt("VERIFY_WORKERS", 24)
	ch := &chaos{
		next:     fakeKMS{},
		maxDelay: time.Duration(envInt("VERIFY_MAX_DELAY_MS", 500)) * time.Millisecond,
		panicPM:  envInt("VERIFY_PANIC_PER_MILLE", 1),
	}
	ctx := context.Background()
	var client *encrypt.Client
	if live {
		ch.next = http.DefaultTransport
		client, err = encrypt.NewClient(ctx, encrypt.WithTransport(ch))
	} else {
		client, err = encrypt.NewClient(ctx, encrypt.WithCredentials(encrypt.VerifyTestCredentials()),
			encrypt.WithZeroKMSURL("https://zerokms.fake"), encrypt.WithTransport(ch))
	}
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	cipher := client.DefaultKeyset()

	// One clean round trip, which also loads the keyset.
	check := func(ctx context.Context, r *rand.Rand, n int) error {
		users := genUsers(r, n)
		enc, err := testusers.Encrypt(ctx, cipher, users)
		if err != nil {
			return err
		}
		dec, err := testusers.Decrypt(ctx, cipher, enc)
		if err != nil {
			return err
		}
		if len(dec) != len(users) {
			return fmt.Errorf("WRONG: %d records back, want %d", len(dec), len(users))
		}
		for i := range users {
			if dec[i] != users[i] {
				return fmt.Errorf("WRONG: record %d of %d decrypted to another value", i, n)
			}
		}
		return nil
	}
	if err := check(ctx, rand.New(rand.NewPCG(1, 2)), 600); err != nil {
		t.Fatalf("before the faults: %v", err)
	}
	runtime.GC()
	before := runtime.NumGoroutine()

	ch.on.Store(true)
	deadline := time.Now().Add(dur)
	tl := &tally{kind: map[string]int{}}
	var calls, wrong, hung atomic.Int64
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			r := rand.New(rand.NewPCG(uint64(w), uint64(time.Now().UnixNano())))
			for time.Now().Before(deadline) {
				n := batchSize(r)
				callCtx, cancel := context.WithCancel(ctx)
				cancels := r.IntN(10) == 0
				if cancels {
					time.AfterFunc(time.Duration(r.Int64N(int64(1500*time.Millisecond))), cancel)
				}
				done := make(chan struct{})
				go func() {
					select {
					case <-done:
					case <-time.After(5 * time.Minute):
						hung.Add(1)
						var b strings.Builder
						_ = pprof.Lookup("goroutine").WriteTo(&b, 1)
						t.Errorf("a call of %d rows ran 5 minutes:\n%s", n, b.String())
					}
				}()
				calls.Add(1)
				err, p := guarded(func() error { return check(callCtx, r, n) })
				close(done)
				cancel()
				switch {
				case p != nil:
					tl.add(fmt.Sprintf("panic recovered: %v", p))
				case err == nil:
					tl.add("ok")
				case strings.HasPrefix(err.Error(), "WRONG"):
					wrong.Add(1)
					t.Errorf("%v", err)
				default:
					c := classify("call", err)
					if cancels && !strings.Contains(c, "context canceled") {
						c += " (cancelling call)"
					}
					tl.add(c)
				}
			}
		})
	}
	wg.Wait()
	ch.on.Store(false)

	// The client still works.
	after := func() error { return check(ctx, rand.New(rand.NewPCG(3, 4)), 900) }
	err, p := guarded(after)

	// Goroutines settle back to where they were.
	var now int
	for range 50 {
		runtime.GC()
		if now = runtime.NumGoroutine(); now <= before {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	kinds := make([]string, 0, len(tl.kind))
	for k := range tl.kind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	t.Logf("calls %d over %v with %d workers (live=%v)", calls.Load(), dur, workers, live)
	for _, k := range kinds {
		t.Logf("  %6d  %s", tl.kind[k], k)
	}
	t.Logf("faults: %d KMS requests, %d 5xx, %d network errors, %d truncated, %d short a key, %d panics",
		ch.requests.Load(), ch.status5xx.Load(), ch.netErr.Load(), ch.truncated.Load(), ch.shortKey.Load(), ch.panics.Load())
	t.Logf("goroutines: %d before, %d after", before, now)
	if wrong.Load() > 0 {
		t.Errorf("%d calls returned wrong data", wrong.Load())
	}
	if hung.Load() > 0 {
		t.Errorf("%d calls hung", hung.Load())
	}
	if p != nil || err != nil {
		t.Errorf("after the faults stopped, the client failed: err %v, panic %v", err, p)
	}
	if now > before {
		var b strings.Builder
		_ = pprof.Lookup("goroutine").WriteTo(&b, 1)
		t.Errorf("goroutines leaked: %d before, %d after:\n%s", before, now, b.String())
	}
}
