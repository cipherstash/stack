package encrypt_test

// Verification of #1773, not for merge as is.
//
// How a batch goes through the guest, step by step: how many steps send
// requests and how many requests each sends, how many yield, and how long
// the steps are. ZeroKMS is the fake in verify_chaos_test.go, answering
// every request after a fixed delay, so the requests one step sends arrive
// together and steps are told apart by the gaps between them. A step is a
// call of an operation export or of se_resume.
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

// stepTimer times every outermost call of a guest step export.
type stepTimer struct {
	mu    sync.Mutex
	depth int
	start time.Time
	steps []time.Duration
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

// delayed answers every request after delay, and records when each
// arrived.
type delayed struct {
	delay    time.Duration
	mu       sync.Mutex
	arrivals []time.Time
}

func (d *delayed) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.Contains(r.URL.Path, "data-key") {
		d.mu.Lock()
		d.arrivals = append(d.arrivals, time.Now())
		d.mu.Unlock()
		time.Sleep(d.delay)
	}
	return fakeKMS{}.RoundTrip(r)
}

// groups splits arrivals into the steps that sent them: a gap longer than
// half the delay starts a new step.
func groups(arrivals []time.Time, delay time.Duration) []int {
	var out []int
	for i, a := range arrivals {
		if i == 0 || a.Sub(arrivals[i-1]) > delay/2 {
			out = append(out, 0)
		}
		out[len(out)-1]++
	}
	return out
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
	rt := &delayed{delay: delay}
	ctx := experimental.WithFunctionListenerFactory(context.Background(), timer)
	client, err := encrypt.NewClient(ctx, encrypt.WithCredentials(encrypt.VerifyTestCredentials()),
		encrypt.WithZeroKMSURL("https://zerokms.fake"), encrypt.WithTransport(rt))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var yields atomic.Int64
	encrypt.VerifySetOnYield(client, func() { yields.Add(1) })
	cipher := client.DefaultKeyset()
	run := context.Background()
	const calls = 5

	// User has three sealed fields, one key each.
	for _, rows := range []int{467, 3334} {
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
			for range calls {
				timer.mu.Lock()
				timer.steps = nil
				timer.mu.Unlock()
				rt.mu.Lock()
				rt.arrivals = nil
				rt.mu.Unlock()
				yields.Store(0)
				if err := call(); err != nil {
					t.Fatal(err)
				}
				timer.mu.Lock()
				if len(timer.steps) > 0 {
					at := 0
					for i, d := range timer.steps {
						if d > timer.steps[at] {
							at = i
						}
					}
					longestAt = append(longestAt, fmt.Sprintf("%d/%d", at+1, len(timer.steps)))
				}
				steps = append(steps, timer.steps...)
				nSteps += len(timer.steps)
				timer.mu.Unlock()
				rt.mu.Lock()
				sizes = append(sizes, groups(rt.arrivals, delay)...)
				rt.mu.Unlock()
				nYields += int(yields.Load())
			}
			hist := map[int]int{}
			for _, s := range sizes {
				hist[s]++
			}
			t.Logf("RESULT %s %d values: %.1f steps/call, %.1f request steps/call, requests per request step %v, %.1f yields/call, longest step %.2f ms, p99 %.2f ms, median %.3f ms",
				op, 3*rows, float64(nSteps)/calls, float64(len(sizes))/calls, fmtHist(hist, calls), float64(nYields)/calls,
				ms(slices.Max(steps)), ms(percentile(steps, 0.99)), ms(percentile(steps, 0.5)))
			t.Logf("RESULT %s %d values: the longest step of each call is step (index/steps) %v", op, 3*rows, longestAt)
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
