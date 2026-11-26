package encrypt_test

// Verification of #1773, not for merge as is.
//
// How a batch goes through the guest, step by step: how many steps send
// requests and how many requests each sends, how many yield, and how long
// the steps are. A step is a call of an operation export or of se_resume.
// ZeroKMS is the fake in verify_chaos_test.go, answering every request
// after a fixed delay. Each request is put down to the step that sent it
// by counting the steps that had returned when it arrived, so no timing
// decides which step a request belongs to.
//
// Asserted, for every call: the call sends one request per keysPerRequest
// keys; every step that sends requests sends requestsAtOnce of them,
// except the last, which sends what is left; every step either sends
// requests, yields, or ends the call; and every call of one case yields
// as often as the others, and at least once per yieldEvery keys derived.
// The exact yield count is not asserted: the guest also yields while it
// fills each column, and how often depends on the record's layout. The
// timings are only logged.
//
//	VERIFY_STEPS=1 go test ./encrypt/ -run TestVerifySteps -v

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testusers"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
)

// The guest's batching: stack-kms's default request size, the number of
// requests the Go guest sends at once, and stack-kms's YIELD_EVERY, the
// keys it derives between yields.
const (
	keysPerRequest = 500
	requestsAtOnce = 3
	yieldEvery     = 64
)

// stepTimer times every outermost call of a guest step export.
type stepTimer struct {
	mu    sync.Mutex
	depth int
	start time.Time
	steps []time.Duration
}

// returned is the number of steps that have returned.
func (t *stepTimer) returned() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.steps)
}

type stepListener struct{ t *stepTimer }

func (l stepListener) Before(context.Context, api.Module, api.FunctionDefinition, []uint64, experimental.StackIterator) {
	l.t.mu.Lock()
	if l.t.depth == 0 {
		l.t.start = time.Now()
	}
	l.t.depth++
	l.t.mu.Unlock()
}

func (l stepListener) After(context.Context, api.Module, api.FunctionDefinition, []uint64) {
	l.t.mu.Lock()
	l.t.depth--
	if l.t.depth == 0 {
		l.t.steps = append(l.t.steps, time.Since(l.t.start))
	}
	l.t.mu.Unlock()
}

func (l stepListener) Abort(ctx context.Context, m api.Module, d api.FunctionDefinition, _ error) {
	l.After(ctx, m, d, nil)
}

func (t *stepTimer) NewFunctionListener(def api.FunctionDefinition) experimental.FunctionListener {
	// Export names survive a stripped name section; DebugName does not.
	for _, name := range def.ExportNames() {
		switch name {
		case "se_decrypt_record", "se_encrypt_record", "se_resume":
			return stepListener{t}
		}
	}
	return nil
}

// delayed answers every request after delay, and records for each the
// step that sent it: the host performs a step's requests after the step
// returns and before the next one starts, so it is the step whose number
// is the count of steps returned when the request arrives.
type delayed struct {
	delay time.Duration
	timer *stepTimer
	mu    sync.Mutex
	sent  []int
}

func (d *delayed) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.Contains(r.URL.Path, "data-key") {
		d.mu.Lock()
		d.sent = append(d.sent, d.timer.returned())
		d.mu.Unlock()
		time.Sleep(d.delay)
	}
	return fakeKMS{}.RoundTrip(r)
}

// perStep counts the requests each step sent, in step order, from the step
// each request was sent by.
func perStep(sent []int) []int {
	var out []int
	for i, s := range sent {
		if i == 0 || s != sent[i-1] {
			out = append(out, 0)
		}
		out[len(out)-1]++
	}
	return out
}

// wantPerStep is the requests per step a call of keys keys sends.
func wantPerStep(keys int) []int {
	requests := (keys + keysPerRequest - 1) / keysPerRequest
	var out []int
	for ; requests > requestsAtOnce; requests -= requestsAtOnce {
		out = append(out, requestsAtOnce)
	}
	return append(out, requests)
}

func percentile(ds []time.Duration, p float64) time.Duration {
	s := slices.Clone(ds)
	slices.Sort(s)
	if len(s) == 0 {
		return 0
	}
	return s[min(len(s)-1, int(p*float64(len(s))))]
}

func TestVerifySteps(t *testing.T) {
	if os.Getenv("VERIFY_STEPS") == "" {
		t.Skip("set VERIFY_STEPS=1 to run")
	}
	const delay = 40 * time.Millisecond
	timer := &stepTimer{}
	rt := &delayed{delay: delay, timer: timer}
	ctx := experimental.WithFunctionListenerFactory(context.Background(), timer)
	client, err := encrypt.NewClient(ctx, encrypt.WithCredentials(encrypt.VerifyTestCredentials()),
		encrypt.WithZeroKMSURL("https://zerokms.fake"), encrypt.WithTransport(rt))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var yields atomic.Int64
	encrypt.OnYield(client, func() { yields.Add(1) })
	cipher := client.DefaultKeyset()
	run := context.Background()
	const calls = 5

	// User has three sealed fields, one key each.
	for _, rows := range []int{467, 3334} {
		keys := 3 * rows
		users := genUsers(rand.New(rand.NewPCG(9, uint64(rows))), rows)
		sealed, err := testusers.Encrypt(run, cipher, users)
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range []string{"decrypt", "encrypt"} {
			call := func() error {
				if op == "encrypt" {
					_, err := testusers.Encrypt(run, cipher, users)
					return err
				}
				_, err := testusers.Decrypt(run, cipher, sealed)
				return err
			}
			if err := call(); err != nil { // warm up
				t.Fatal(err)
			}
			var steps []time.Duration
			var sizes []int
			var nSteps, nYields int
			var longestAt []string
			firstYields := -1
			for c := range calls {
				timer.mu.Lock()
				timer.steps = nil
				timer.mu.Unlock()
				rt.mu.Lock()
				rt.sent = nil
				rt.mu.Unlock()
				yields.Store(0)
				if err := call(); err != nil {
					t.Fatal(err)
				}
				timer.mu.Lock()
				callSteps := slices.Clone(timer.steps)
				timer.mu.Unlock()
				rt.mu.Lock()
				callSizes := perStep(rt.sent)
				rt.mu.Unlock()
				callYields := int(yields.Load())

				if want := wantPerStep(keys); !slices.Equal(callSizes, want) {
					t.Errorf("%s %d keys, call %d: requests per request step %v, want %v", op, keys, c, callSizes, want)
				}
				if want := len(callSizes) + callYields + 1; len(callSteps) != want {
					t.Errorf("%s %d keys, call %d: %d steps, want %d request steps + %d yields + 1 = %d",
						op, keys, c, len(callSteps), len(callSizes), callYields, want)
				}
				if least := (keys - 1) / yieldEvery; callYields < least {
					t.Errorf("%s %d keys, call %d: %d yields, want at least %d", op, keys, c, callYields, least)
				}
				if firstYields < 0 {
					firstYields = callYields
				} else if callYields != firstYields {
					t.Errorf("%s %d keys, call %d: %d yields, the first call %d", op, keys, c, callYields, firstYields)
				}

				if len(callSteps) > 0 {
					at := 0
					for i, d := range callSteps {
						if d > callSteps[at] {
							at = i
						}
					}
					longestAt = append(longestAt, fmt.Sprintf("%d/%d", at+1, len(callSteps)))
				}
				steps = append(steps, callSteps...)
				nSteps += len(callSteps)
				sizes = append(sizes, callSizes...)
				nYields += callYields
			}
			hist := map[int]int{}
			for _, s := range sizes {
				hist[s]++
			}
			t.Logf("RESULT %s %d values: %.1f steps/call, %.1f request steps/call, requests per request step %v, %.1f yields/call, longest step %.2f ms, p99 %.2f ms, median %.3f ms",
				op, keys, float64(nSteps)/calls, float64(len(sizes))/calls, fmtHist(hist, calls), float64(nYields)/calls,
				ms(slices.Max(steps)), ms(percentile(steps, 0.99)), ms(percentile(steps, 0.5)))
			t.Logf("RESULT %s %d values: the longest step of each call is step (index/steps) %v", op, keys, longestAt)
		}
	}
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func fmtHist(h map[int]int, calls int) string {
	keys := make([]int, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%d×%.1f ", k, float64(h[k])/float64(calls))
	}
	return strings.TrimSpace(b.String())
}
