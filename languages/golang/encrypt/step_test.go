package encrypt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/cipherstash/vitaminc/bindings/go/vcffi"
)

// The step loop, driven hermetically: the guest's init pauses on its
// load-keyset request, which a stub ZeroKMS holds until the test releases
// it.

// heldStub answers every request with 401 once released, and reports each
// request as it arrives.
type heldStub struct {
	*httptest.Server
	arrived chan struct{}
	release chan struct{}
}

func newHeldStub(t *testing.T) *heldStub {
	t.Helper()
	s := &heldStub{arrived: make(chan struct{}, 8), release: make(chan struct{})}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		s.arrived <- struct{}{}
		select {
		case <-s.release:
		case <-r.Context().Done():
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "nope")
	}))
	t.Cleanup(func() {
		select {
		case <-s.release:
		default:
			close(s.release)
		}
		s.Close()
	})
	return s
}

// stepClient is a client over a fresh instance whose init has not run.
func stepClient(t *testing.T, token tokenSource) *Client {
	t.Helper()
	tr := &transport{rt: http.DefaultTransport, token: token}
	inst, err := newInstance(context.Background(), guestOrSkip(t), tr, guest.BestEffort)
	if err != nil {
		t.Fatal(err)
	}
	c := newClient(inst, tr)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func initStep(t *testing.T, url string) stepFunc {
	t.Helper()
	encoded, err := encodeConfig(testInit(url))
	if err != nil {
		t.Fatal(err)
	}
	return func(ctx context.Context, inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.cipherInit, buf(encoded))
	}
}

func targetsStep(ctx context.Context, inst *instance) ([]byte, error) {
	return inst.call(ctx, inst.targets)
}

func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// While an operation's request is in flight the guest is not running, and
// the client's lock is free: another call runs to completion meanwhile.
func TestAStepDoesNotHoldTheLockWhileItsRequestRuns(t *testing.T) {
	stub := newHeldStub(t)
	c := stepClient(t, staticToken("stub-token"))
	done := make(chan error, 1)
	go func() {
		_, err := c.callKMS(context.Background(), initStep(t, stub.URL))
		done <- err
	}()
	waitFor(t, stub.arrived, "the init's request")
	if _, err := c.call(context.Background(), targetsStep); err != nil {
		t.Fatalf("a call while the init's request is in flight: %v", err)
	}
	close(stub.release)
	if err := <-done; !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("init: %v, want ErrUnauthorized", err)
	}
}

// The guest refuses an operation past its cap of paused operations, so the
// client never starts one: a caller past the cap waits for a slot, leaves
// the queue when its context ends, and runs once a slot is free. Here the
// cap is one, so the paused init holds the only slot.
func TestACallerPastThePausedCapWaitsForASlot(t *testing.T) {
	stub := newHeldStub(t)
	c := stepClient(t, staticToken("stub-token"))
	if got := cap(c.paused); got != maxPaused {
		t.Fatalf("paused slots: %d, want maxPaused (%d)", got, maxPaused)
	}
	c.paused = make(chan struct{}, 1)
	first := make(chan error, 1)
	go func() {
		_, err := c.callKMS(context.Background(), initStep(t, stub.URL))
		first <- err
	}()
	waitFor(t, stub.arrived, "the first init's request")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := c.callKMS(ctx, initStep(t, stub.URL)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a call past the cap: %v, want context.DeadlineExceeded (it waited)", err)
	}

	second := make(chan error, 1)
	go func() {
		_, err := c.callKMS(context.Background(), initStep(t, stub.URL))
		second <- err
	}()
	select {
	case <-stub.arrived:
		t.Fatal("a call past the cap sent a request while the slot was held")
	case <-time.After(100 * time.Millisecond):
	}
	close(stub.release)
	if err := <-first; !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("first init: %v, want ErrUnauthorized", err)
	}
	if err := <-second; !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("the waiting init: %v, want ErrUnauthorized (it ran once the slot was free)", err)
	}
	if n := len(c.paused); n != 0 {
		t.Fatalf("%d slots still held after every call ended", n)
	}
}

// maxPaused is the guest's MAX_OPEN, written twice: a Go bound above the
// guest's cap lets the guest refuse a caller the client should have
// queued.
func TestMaxPausedIsTheGuestsCap(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "stack-guest-abi", "src", "step.rs"))
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("stack-guest-abi's source is not beside this module")
	}
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`pub const MAX_OPEN: usize = (\d+);`).FindSubmatch(src)
	if m == nil {
		t.Fatal("MAX_OPEN not found in stack-guest-abi's step.rs")
	}
	if got := string(m[1]); got != strconv.Itoa(maxPaused) {
		t.Fatalf("the guest's MAX_OPEN is %s, maxPaused is %d", got, maxPaused)
	}
}

// A caller that gives up while its request is in flight returns with its
// context's error. The operation is aborted in the guest, so its handle is
// spent and a new init may start; the client stays open.
func TestACallerThatGivesUpBetweenStepsAbortsTheOperation(t *testing.T) {
	stub := newHeldStub(t)
	c := stepClient(t, staticToken("stub-token"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := c.callKMS(ctx, initStep(t, stub.URL))
		done <- err
	}()
	waitFor(t, stub.arrived, "the init's request")
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled init: %v, want context.Canceled", err)
	}
	if c.closed || c.inst.module.IsClosed() {
		t.Fatal("giving up closed the client")
	}
	if _, err := c.inst.call(context.Background(), c.inst.abort, scalar(1)); !errors.Is(err, ErrState) {
		t.Fatalf("the aborted operation's handle: %v, want ErrState (already dropped)", err)
	}
	close(stub.release)
	if _, err := c.callKMS(context.Background(), initStep(t, stub.URL)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("an init after the aborted one: %v, want ErrUnauthorized (it runs)", err)
	}
}

// A context that has already ended never reaches the guest.
func TestACallWhoseContextHasEndedNeverStarts(t *testing.T) {
	stub := newStub(t, http.StatusUnauthorized, "", "nope")
	c := stepClient(t, staticToken("stub-token"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.callKMS(ctx, initStep(t, stub.URL)); !errors.Is(err, context.Canceled) {
		t.Fatalf("init under an ended context: %v, want context.Canceled", err)
	}
	if len(stub.requests) != 0 {
		t.Fatalf("%d requests sent for a call that never started", len(stub.requests))
	}
}

// lockProbe is a token source that records whether the client's lock was
// free when it was asked.
type lockProbe struct {
	c           **Client
	asked, held atomic.Int32
}

func (p *lockProbe) Token(context.Context) (string, error) {
	p.asked.Add(1)
	if !(*p.c).mu.TryLock() {
		p.held.Add(1)
	} else {
		(*p.c).mu.Unlock()
	}
	return "stub-token", nil
}

// The token is fetched once per operation, before its first step and
// outside the client's lock, so a refresh that waits on the network holds
// up no other caller.
func TestTheTokenIsFetchedOutsideTheLock(t *testing.T) {
	stub := newStub(t, http.StatusUnauthorized, "", "nope")
	var c *Client
	probe := &lockProbe{c: &c}
	c = stepClient(t, probe)
	if _, err := c.callKMS(context.Background(), initStep(t, stub.URL)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("init: %v", err)
	}
	if probe.asked.Load() == 0 {
		t.Fatal("the token source was never asked")
	}
	if n := probe.held.Load(); n != 0 {
		t.Fatalf("the token was fetched %d times under the client's lock", n)
	}
	if got := stub.requests[0].auth; got != "Bearer stub-token" {
		t.Fatalf("the request carried %q", got)
	}
}

// An operation paused on its request and then aborted leaves neither the
// client key nor the bearer token in guest memory: dropping it wipes what
// it held.
func TestAnAbortedInitLeavesNoKeyInGuestMemory(t *testing.T) {
	stub := newHeldStub(t)
	c := stepClient(t, staticToken("stub-token"))
	ctx := context.Background()
	out, step, err := c.step(ctx, "stub-token", nil, initStep(t, stub.URL))
	if err != nil || step == nil {
		t.Fatalf("the init's first step: %v, %v; want a pause", out, err)
	}
	if len(step.requests) != 1 || !bytes.Contains(step.requests[0].headers, []byte("Bearer stub-token")) {
		t.Fatalf("the init's step: %+v", step.requests)
	}
	step.wipe()
	c.abort(step.handle)
	mem := c.inst.module.Memory()
	view, ok := mem.Read(0, mem.Size())
	if !ok {
		t.Fatal("cannot read guest memory")
	}
	for name, needle := range map[string][]byte{
		"key hex":   []byte(testClientKey),
		"key bytes": mustHex(testClientKey),
		"bearer":    []byte("stub-token"),
	} {
		if n := bytes.Count(view, needle); n != 0 {
			t.Errorf("%s found %d times in guest memory after an aborted init", name, n)
		}
	}
}

// A step the host cannot decode is refused, never performed.
func TestAMalformedStepIsRefused(t *testing.T) {
	for _, raw := range [][]byte{nil, {0xff}, marshalStep(t, map[string]any{"handle": uint64(1)})} {
		if _, err := decodeStep(raw); !errors.Is(err, errMalformedStep) {
			t.Errorf("decodeStep(%x): %v, want errMalformedStep", raw, err)
		}
	}
}

func marshalStep(t *testing.T, v any) []byte {
	t.Helper()
	b, err := vcffi.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
