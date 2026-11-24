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
// VERIFY_KEYSETS names keysets, comma-separated, to spread the calls
// over with the default keyset: live, keysets the credentials are granted;
// the fake answers any name. VERIFY_WORKERS (default 24),
// VERIFY_MAX_DELAY_MS (default 500) and VERIFY_PANIC_PER_MILLE (default 1)
// tune it.

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

const fakeDefaultKeyset = "3f8a7c1e-6b2d-4e59-9a14-2c7d5e0f8b31"

// fakeKeysetID is the id the fake gives the keyset called name.
func fakeKeysetID(name string) string {
	h := sha256.Sum256([]byte("keyset" + name))
	h[6] = h[6]&0x0f | 0x40
	h[8] = h[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// fakeKMS answers load-keyset, generate and retrieve.
type fakeKMS struct{}

func (fakeKMS) RoundTrip(r *http.Request) (*http.Response, error) {
	// A RoundTripper closes the request body on every path, errors
	// included: the client wipes its copy of the body when it is closed.
	if r.Body != nil {
		defer r.Body.Close()
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	var req struct {
		Keys []struct {
			IV string `json:"iv"`
		} `json:"keys"`
		Keyset *struct {
			Name string `json:"Name"`
			UUID string `json:"Uuid"`
		} `json:"keyset_id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString
	path := r.URL.Path
	switch {
	case strings.HasSuffix(path, "load-keyset"):
		// The default keyset, or one named or given by id: each its own id
		// and index key.
		id, name, isDefault := fakeDefaultKeyset, "default", true
		if k := req.Keyset; k != nil {
			isDefault = false
			switch {
			case k.Name != "":
				id, name = fakeKeysetID(k.Name), k.Name
			case k.UUID == fakeDefaultKeyset:
				isDefault = true
			default:
				id, name = k.UUID, "keyset-"+k.UUID
			}
		}
		return jsonResponse(map[string]any{
			"partial_index_key": map[string]any{"key_material": b64(materialFor([]byte("index" + id)))},
			"dataset": map[string]any{
				"id": id, "name": name,
				"description": "", "is_disabled": false, "is_default": isDefault,
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

// fault is what chaos does to one ZeroKMS request.
type fault int

const (
	faultNone     fault = iota
	faultPanic          // RoundTrip panics
	fault5xx            // a 500 or 503 response
	faultNetErr         // RoundTrip returns an error
	faultTruncate       // the response body is cut short
	faultShortKey       // the response is one key short
	faultCount
)

var faultNames = [faultCount]string{"untouched", "panics", "5xx", "network errors", "truncated", "short a key"}

// chaosRates is each fault's share of ZeroKMS requests, per mille. The
// panic rate comes from VERIFY_PANIC_PER_MILLE. The other requests are
// untouched.
var chaosRates = [faultCount]int{
	fault5xx:      40,
	faultNetErr:   30,
	faultTruncate: 30,
	faultShortKey: 30,
}

type chaos struct {
	next     http.RoundTripper
	on       atomic.Bool
	maxDelay time.Duration
	rates    [faultCount]int // per mille; faultNone's is unused

	requests, delayed atomic.Int64
	injected          [faultCount]atomic.Int64
}

// pick draws the fault for one request from c.rates.
func (c *chaos) pick() fault {
	roll := rand.IntN(1000)
	for f := faultNone + 1; f < faultCount; f++ {
		if roll < c.rates[f] {
			return f
		}
		roll -= c.rates[f]
	}
	return faultNone
}

func (c *chaos) RoundTrip(r *http.Request) (*http.Response, error) {
	isKMS := strings.Contains(r.URL.Path, "data-key")
	if !c.on.Load() || !isKMS {
		return c.next.RoundTrip(r)
	}
	// A RoundTripper closes the request body on every path. The paths that
	// never hand r to c.next close it here.
	closeBody := func() {
		if r.Body != nil {
			_ = r.Body.Close()
		}
	}
	c.requests.Add(1)
	if c.maxDelay > 0 {
		d := time.Duration(rand.Int64N(int64(c.maxDelay)))
		c.delayed.Add(1)
		select {
		case <-time.After(d):
		case <-r.Context().Done():
			closeBody()
			return nil, r.Context().Err()
		}
	}
	f := c.pick()
	switch f {
	case faultPanic:
		c.injected[f].Add(1)
		closeBody()
		panic("chaos: injected RoundTripper panic")
	case fault5xx:
		c.injected[f].Add(1)
		closeBody()
		code := []int{http.StatusInternalServerError, http.StatusServiceUnavailable}[rand.IntN(2)]
		return &http.Response{StatusCode: code, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("injected"))}, nil
	case faultNetErr:
		c.injected[f].Add(1)
		closeBody()
		return nil, errors.New("chaos: injected network error")
	}
	resp, err := c.next.RoundTrip(r)
	if err != nil || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	switch f {
	case faultTruncate:
		b, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		c.injected[f].Add(1)
		resp.Body = io.NopCloser(bytes.NewReader(b[:rand.IntN(len(b))]))
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
	case faultShortKey:
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
				c.injected[f].Add(1)
			}
		}
		resp.Body = io.NopCloser(bytes.NewReader(b))
		resp.ContentLength = -1
		resp.Header.Del("Content-Length")
	}
	return resp, nil
}

// summary is the request and fault counts, for the log.
func (c *chaos) summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d KMS requests, %d delayed", c.requests.Load(), c.delayed.Load())
	for f := faultNone + 1; f < faultCount; f++ {
		fmt.Fprintf(&b, ", %d %s", c.injected[f].Load(), faultNames[f])
	}
	return b.String()
}

// ---------------------------------------------------------------- the test

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return def
}

// tally counts the calls' outcomes by kind, and keeps the failures the
// workers find, for the test goroutine to report: a worker still blocked
// when the test ends must not call t.
type tally struct {
	mu       sync.Mutex
	kind     map[string]int
	failures []string
}

func (t *tally) add(k string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.kind[k]++
}

func (t *tally) fail(msg string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failures = append(t.failures, msg)
}

// errorMarkers name an error by a phrase in its text, most specific first.
// Each phrase is one a fault's error carries, never a bare status code,
// which other text can contain.
var errorMarkers = []struct{ phrase, name string }{
	{"too many operations", "TOO MANY OPERATIONS PAUSED"},
	{"invalid number of keys", "a key short"},
	{"InvalidNumberOfKeys", "a key short"},
	{"ParseResponse", "unparseable response"},
	{"Failed to deserialize", "unparseable response"},
	{"unexpected end", "unparseable response"},
	{"Server returned failure response", "server error"},
	{"injected network error", "network error"},
	{"Host transport reported a failure", "host transport failure"},
	{"injected RoundTripper panic", "RoundTripper panic"},
}

// classify names an error for the tally, coarsely: by its sentinel, then
// by the first marker its text carries. Only the tally reads it.
func classify(op string, err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return op + ": context canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return op + ": deadline exceeded"
	case errors.Is(err, encrypt.ErrState):
		return op + ": ErrState: " + err.Error()
	}
	sentinel := "error"
	switch {
	case errors.Is(err, encrypt.ErrTransport):
		sentinel = "ErrTransport"
	case errors.Is(err, encrypt.ErrKMS):
		sentinel = "ErrKMS"
	}
	msg := err.Error()
	for _, m := range errorMarkers {
		if strings.Contains(msg, m.phrase) {
			return op + ": " + sentinel + " (" + m.name + ")"
		}
	}
	return op + ": " + sentinel + ": " + digits.ReplaceAllString(msg, "N")
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
func guarded(f func() error) (p any, err error) {
	defer func() { p = recover() }()
	return nil, f()
}

// hangAfter is how long a call may run before the test reports it hung and
// cancels it. A call that still does not return within hangGrace of that
// is left blocked, and the test ends without waiting for it.
const (
	hangAfter = 5 * time.Minute
	hangGrace = hangAfter / 5
)

func TestVerifyChaos(t *testing.T) {
	dur, err := time.ParseDuration(os.Getenv("VERIFY_CHAOS"))
	if err != nil {
		t.Skip("set VERIFY_CHAOS to a duration to run")
	}
	live := os.Getenv("VERIFY_CHAOS_LIVE") == "1"
	workers := envInt("VERIFY_WORKERS", 24)
	faults := &chaos{
		next:     fakeKMS{},
		maxDelay: time.Duration(envInt("VERIFY_MAX_DELAY_MS", 500)) * time.Millisecond,
		rates:    chaosRates,
	}
	faults.rates[faultPanic] = envInt("VERIFY_PANIC_PER_MILLE", 1)
	ctx := context.Background()
	var client *encrypt.Client
	if live {
		faults.next = http.DefaultTransport
		client, err = encrypt.NewClient(ctx, encrypt.WithTransport(faults))
	} else {
		client, err = encrypt.NewClient(ctx, encrypt.WithCredentials(encrypt.VerifyTestCredentials()),
			encrypt.WithZeroKMSURL("https://zerokms.fake"), encrypt.WithTransport(faults))
	}
	if err != nil {
		t.Fatal(err)
	}
	// A call still blocked when the test ends may hold the client's lock,
	// and Close would wait for it.
	stuck := false
	defer func() {
		if !stuck {
			_ = client.Close()
		}
	}()

	// The default keyset and each keyset VERIFY_KEYSETS names, each keyset
	// once: a name given twice, or one naming the default keyset, would
	// make "another keyset" the same keyset. Each call encrypts under one
	// chosen at random.
	labels := []string{"default"}
	candidates := []*encrypt.Cipher{client.DefaultKeyset()}
	if names := os.Getenv("VERIFY_KEYSETS"); names != "" {
		for _, name := range strings.Split(names, ",") {
			labels = append(labels, name)
			candidates = append(candidates, client.Keyset(encrypt.KeysetName(name)))
		}
	}
	var ciphers []*encrypt.Cipher
	seen := map[encrypt.KeysetID]string{}
	for i, cipher := range candidates {
		id, err := cipher.KeysetID(ctx)
		if err != nil {
			t.Fatalf("keyset %s: %v", labels[i], err)
		}
		if first, ok := seen[id]; ok {
			t.Logf("keyset %s is keyset %s (%v): it is used once", labels[i], first, id)
			continue
		}
		seen[id] = labels[i]
		ciphers = append(ciphers, cipher)
	}

	// One round trip under a random keyset. The decrypt goes through that
	// keyset's cipher or through the client, which opens each record under
	// the keyset that sealed it. With more than one keyset, a call in ten
	// first checks that another keyset's cipher refuses the records with
	// ErrForeignKeyset.
	// refusals counts the times another keyset's cipher refused, as it must.
	var refusals atomic.Int64
	check := func(ctx context.Context, r *rand.Rand, n int) error {
		i := r.IntN(len(ciphers))
		cipher := ciphers[i]
		users := genUsers(r, n)
		enc, err := testusers.Encrypt(ctx, cipher, users)
		if err != nil {
			return err
		}
		if len(ciphers) > 1 && r.IntN(10) == 0 {
			other := ciphers[(i+1+r.IntN(len(ciphers)-1))%len(ciphers)]
			_, err := testusers.Decrypt(ctx, other, enc)
			switch {
			case errors.Is(err, encrypt.ErrForeignKeyset):
				// Refused, as it must be.
				refusals.Add(1)
			case err == nil:
				return fmt.Errorf("WRONG: another keyset's cipher opened %d records", n)
			case ctx.Err() != nil:
				// The call was cancelled before the refusal was checked.
				return err
			default:
				return fmt.Errorf("WRONG: another keyset's cipher refused %d records with %w, want ErrForeignKeyset", n, err)
			}
		}
		var d encrypt.Decrypter = cipher
		if r.IntN(2) == 0 {
			d = client
		}
		dec, err := testusers.Decrypt(ctx, d, enc)
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

	faults.on.Store(true)
	deadline := time.Now().Add(dur)
	outcomes := &tally{kind: map[string]int{}}
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
					case <-time.After(hangAfter):
						hung.Add(1)
						var b strings.Builder
						_ = pprof.Lookup("goroutine").WriteTo(&b, 1)
						outcomes.fail(fmt.Sprintf("a call of %d rows ran %v, and is cancelled:\n%s", n, hangAfter, b.String()))
						cancel()
					}
				}()
				calls.Add(1)
				p, err := guarded(func() error { return check(callCtx, r, n) })
				close(done)
				cancel()
				switch {
				case p != nil:
					outcomes.add(fmt.Sprintf("panic recovered: %v", p))
				case err == nil:
					outcomes.add("ok")
				case strings.HasPrefix(err.Error(), "WRONG"):
					wrong.Add(1)
					outcomes.fail(err.Error())
				default:
					kind := classify("call", err)
					if cancels && !strings.Contains(kind, "context canceled") {
						kind += " (cancelling call)"
					}
					outcomes.add(kind)
				}
			}
		})
	}
	// Every call starts before the deadline, so hangAfter after it every
	// call still running has been reported hung and cancelled. One that has
	// not returned hangGrace later is left blocked, and so is the client.
	workersDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(workersDone)
	}()
	select {
	case <-workersDone:
	case <-time.After(time.Until(deadline) + hangAfter + hangGrace):
		stuck = true
	}
	faults.on.Store(false)

	outcomes.mu.Lock()
	kinds := make([]string, 0, len(outcomes.kind))
	for k := range outcomes.kind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	t.Logf("calls %d over %v with %d workers (live=%v)", calls.Load(), dur, workers, live)
	for _, k := range kinds {
		t.Logf("  %6d  %s", outcomes.kind[k], k)
	}
	failures := slices.Clone(outcomes.failures)
	outcomes.mu.Unlock()
	t.Logf("faults: %s", faults.summary())
	if len(ciphers) > 1 {
		t.Logf("another keyset's cipher refused with ErrForeignKeyset %d times", refusals.Load())
	}
	for _, f := range failures {
		t.Error(f)
	}
	if wrong.Load() > 0 {
		t.Errorf("%d calls went WRONG", wrong.Load())
	}
	if hung.Load() > 0 {
		t.Errorf("%d calls hung", hung.Load())
	}
	if stuck {
		t.Errorf("calls still blocked %v after they were cancelled: the client is not checked again, closed, or checked for leaks", hangGrace)
		return
	}

	// The client still works.
	after := func() error { return check(ctx, rand.New(rand.NewPCG(3, 4)), 900) }
	p, err := guarded(after)
	if p != nil || err != nil {
		t.Errorf("after the faults stopped, the client failed: err %v, panic %v", err, p)
	}

	// Goroutines settle back to where they were.
	var now int
	for range 50 {
		runtime.GC()
		if now = runtime.NumGoroutine(); now <= before {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("goroutines: %d before, %d after", before, now)
	if now > before {
		var b strings.Builder
		_ = pprof.Lookup("goroutine").WriteTo(&b, 1)
		t.Errorf("goroutines leaked: %d before, %d after:\n%s", before, now, b.String())
	}
}
