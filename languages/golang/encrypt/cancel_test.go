package encrypt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/auth"
	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/cipherstash/stack/languages/golang/internal/record"
)

// One encrypt.Client serves every request in a service, so a caller's
// context ending must fail that caller's call and nothing else. These tests
// pin that contract, and the one case that still closes the client: a guest
// that runs on long after its caller gave up.

// unauthorized answers every ZeroKMS request with a 401: a full round trip
// through the guest's network path that ends in a status the client can
// tell apart from ErrState.
func unauthorized(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader("nope")), Header: http.Header{}}, nil
}

// switchable is a RoundTripper whose behaviour a test changes between calls.
type switchable struct {
	mu   sync.Mutex
	rt   roundTripFunc
	sent atomic.Int32
}

func (s *switchable) set(rt roundTripFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rt = rt
}

func (s *switchable) RoundTrip(r *http.Request) (*http.Response, error) {
	s.sent.Add(1)
	s.mu.Lock()
	rt := s.rt
	s.mu.Unlock()
	return rt(r)
}

// cancelClient is a guest not yet given a key, whose ZeroKMS requests go to
// rt and whose token comes from token. Its se_cipher_init is the call the
// tests drive: it pauses on a load-keyset request, so it reaches the
// network between two steps.
func cancelClient(t *testing.T, rt http.RoundTripper, token tokenSource) *Client {
	t.Helper()
	tr := &transport{rt: rt, token: token}
	inst, err := newInstance(context.Background(), guestOrSkip(t), tr, guest.BestEffort)
	if err != nil {
		t.Fatal(err)
	}
	c := newClient(inst, tr)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// cipherInit runs se_cipher_init on c under ctx.
func cipherInit(ctx context.Context, c *Client) error {
	encoded, err := encodeConfig(testInit("http://zerokms.invalid"))
	if err != nil {
		return err
	}
	defer wipe(encoded)
	_, err = c.callKMS(ctx, func(ctx context.Context, inst *instance) ([]byte, error) {
		return inst.call(ctx, inst.cipherInit, buf(encoded))
	})
	return err
}

// wantOpen fails the test unless c is still open: its next call reaches
// ZeroKMS and comes back with ZeroKMS's answer, not ErrState.
func wantOpen(t *testing.T, c *Client, rt *switchable) {
	t.Helper()
	if c.closed || c.inst.module.IsClosed() {
		t.Fatal("the client was closed")
	}
	rt.set(unauthorized)
	if err := cipherInit(context.Background(), c); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("the next call: %v, want ErrUnauthorized from ZeroKMS", err)
	}
}

// The request runs between two steps, under the caller's context, with the
// guest paused: cancelling it ends the call and aborts the paused
// operation, and the client stays open.
func TestACallCancelledBetweenStepsFailsOnlyItself(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := &switchable{rt: func(r *http.Request) (*http.Response, error) {
		// The caller gives up once its request is in flight.
		cancel()
		<-r.Context().Done()
		return nil, r.Context().Err()
	}}
	c := cancelClient(t, rt, staticToken("t"))
	err := cipherInit(ctx, c)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrTransport) {
		t.Fatalf("cancelled call: %v, want context.Canceled and ErrTransport", err)
	}
	wantOpen(t, c, rt)
}

// The token is fetched before the operation's first step: a caller that
// gives up waiting on it never starts the operation.
func TestACallCancelledDuringATokenFetchFailsOnlyItself(t *testing.T) {
	rt := &switchable{rt: unauthorized}
	var blocking atomic.Bool
	blocking.Store(true)
	token := tokenFunc(func(ctx context.Context) (string, error) {
		if blocking.Load() {
			<-ctx.Done()
			return "", ctx.Err()
		}
		return "t", nil
	})
	c := cancelClient(t, rt, token)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	err := cipherInit(ctx, c)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrState) {
		t.Fatalf("cancelled call: %v, want context.Canceled", err)
	}
	if n := rt.sent.Load(); n != 0 {
		t.Fatalf("%d request(s) sent without a token", n)
	}
	blocking.Store(false)
	wantOpen(t, c, rt)
}

func TestACallWhoseContextEndsInTheQueueNeverReachesTheGuest(t *testing.T) {
	rt := &switchable{rt: unauthorized}
	c := cancelClient(t, rt, staticToken("t"))

	t.Run("ends while waiting", func(t *testing.T) {
		// Another call holds the client: the slow ZeroKMS round trip the
		// queue is waiting behind.
		if err := c.mu.Acquire(context.Background()); err != nil {
			t.Fatal(err)
		}
		released := make(chan struct{})
		time.AfterFunc(200*time.Millisecond, func() { c.mu.Unlock(); close(released) })
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		err := cipherInit(ctx, c)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("queued call: %v, want the deadline", err)
		}
		// It left at its deadline, not when the lock came free.
		select {
		case <-released:
			t.Error("the queued call waited past its deadline for the lock")
		default:
		}
		<-released
	})
	t.Run("already ended", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := cipherInit(ctx, c); !errors.Is(err, context.Canceled) {
			t.Fatalf("call with an ended context: %v, want context.Canceled", err)
		}
	})
	if n := rt.sent.Load(); n != 0 {
		t.Fatalf("%d request(s) reached ZeroKMS from calls whose context had ended", n)
	}
	wantOpen(t, c, rt)
}

// The backstop: a step still running long after its caller gave up is a
// guest or host function that ignores cancellation. Its state is unknown,
// so the client closes, and says so. The step here waits out its caller's
// context and the backstop and only then enters the guest, as a guest
// stuck in a loop would still be running when the backstop fired.
func TestAStepThatRunsOnAfterItsContextEndsClosesTheClient(t *testing.T) {
	rt := &switchable{rt: unauthorized}
	c := cancelClient(t, rt, staticToken("t"))
	c.stuck = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := c.call(ctx, func(run context.Context, inst *instance) ([]byte, error) {
		cancel()
		<-run.Done()
		return inst.call(run, inst.targets)
	})
	if err == nil || !strings.Contains(err.Error(), "the client is closed") {
		t.Fatalf("stuck call: %v, want the client closed", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("stuck call: %v, want it to match context.Canceled", err)
	}
	if err := cipherInit(context.Background(), c); !errors.Is(err, ErrState) {
		t.Fatalf("a call after the close: %v, want ErrState", err)
	}
}

// A request that ignores its context holds up only its own call: the guest
// is paused while it runs, so nothing is stuck, and the client stays open.
func TestARequestThatIgnoresItsContextLeavesTheClientOpen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := &switchable{rt: func(*http.Request) (*http.Response, error) {
		// The caller gives up once its request is in flight, and the
		// request runs on past the backstop regardless.
		cancel()
		time.Sleep(100 * time.Millisecond)
		return unauthorized(nil)
	}}
	c := cancelClient(t, rt, staticToken("t"))
	c.stuck = 20 * time.Millisecond
	if err := cipherInit(ctx, c); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrTransport) {
		t.Fatalf("call: %v, want context.Canceled and ErrTransport", err)
	}
	wantOpen(t, c, rt)
}

// A call that finishes in time stops the backstop: the client stays open
// however long after the call its context ends.
func TestAFinishedCallStopsTheBackstop(t *testing.T) {
	rt := &switchable{rt: unauthorized}
	c := cancelClient(t, rt, staticToken("t"))
	c.stuck = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	if err := cipherInit(ctx, c); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("call: %v, want ErrUnauthorized", err)
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
	wantOpen(t, c, rt)
}

// Work the guest does without the network runs on through a cancellation,
// so a call can succeed after its caller gave up. It still fails with the
// context's error, and the output nobody will read is wiped.
func TestACallThatSucceedsAfterItsContextEndsFailsWithIt(t *testing.T) {
	rt := &switchable{rt: unauthorized}
	c := cancelClient(t, rt, staticToken("t"))
	ctx, cancel := context.WithCancel(context.Background())
	plaintext := []byte("plaintext")
	out, err := c.call(ctx, func(context.Context, *instance) ([]byte, error) {
		cancel()
		return plaintext, nil
	})
	if !errors.Is(err, context.Canceled) || out != nil {
		t.Fatalf("call: %q, %v, want no output and context.Canceled", out, err)
	}
	if string(plaintext) != string(make([]byte, len(plaintext))) {
		t.Error("the discarded output was not wiped")
	}
	wantOpen(t, c, rt)
}

// A step that pauses after its caller gave up sends no request: the
// operation is aborted in the guest, so its handle is spent, and the call
// fails with the context's error.
func TestAStepThatPausesAfterItsContextEndsSendsNothing(t *testing.T) {
	rt := &switchable{rt: unauthorized}
	c := cancelClient(t, rt, staticToken("t"))
	encoded, err := encodeConfig(testInit("http://zerokms.invalid"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	_, err = c.callKMS(ctx, func(run context.Context, inst *instance) ([]byte, error) {
		cancel()
		return inst.call(run, inst.cipherInit, buf(encoded))
	})
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrTransport) {
		t.Fatalf("call: %v, want context.Canceled and ErrTransport", err)
	}
	if n := rt.sent.Load(); n != 0 {
		t.Fatalf("%d request(s) sent for a caller that had given up", n)
	}
	if _, err := c.inst.call(context.Background(), c.inst.abort, scalar(1)); !errors.Is(err, ErrState) {
		t.Fatalf("the paused operation's handle: %v, want ErrState (already dropped)", err)
	}
	wantOpen(t, c, rt)
}

// A caller whose context ends while its resume waits for the client never
// resumes: the paused operation is still aborted in the guest once the
// client is free.
func TestAResumeWhoseContextEndsInTheQueueAbortsTheOperation(t *testing.T) {
	stub := newHeldStub(t)
	c := stepClient(t, staticToken("stub-token"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := c.callKMS(ctx, initStep(t, stub.URL))
		done <- err
	}()
	waitFor(t, stub.arrived, "the init's request")
	// Another call holds the client when the response comes back.
	if err := c.mu.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(stub.release)
	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond)
	c.mu.Unlock()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("call: %v, want context.Canceled", err)
	}
	if _, err := c.inst.call(context.Background(), c.inst.abort, scalar(1)); !errors.Is(err, ErrState) {
		t.Fatalf("the paused operation's handle: %v, want ErrState (already dropped)", err)
	}
	if c.closed || c.inst.module.IsClosed() {
		t.Fatal("giving up closed the client")
	}
}

// A closed module is ErrState, and Close still releases the runtime.
func TestAClosedModuleIsState(t *testing.T) {
	ctx := context.Background()
	c := rawInstance(t)
	if err := c.inst.module.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Keyset(KeysetName("k")).KeysetID(ctx); !errors.Is(err, ErrState) {
		t.Fatalf("Keyset on a closed module: %v, want ErrState", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close after the module closed: %v", err)
	}
	// The close must reach the runtime. A stuck call closes the module and
	// marks the client closed; a Close that treated that as "already done"
	// would leave the runtime and the host module it carries allocated for
	// the life of the process.
	if !c.released {
		t.Error("Close after the module closed left the runtime unreleased")
	}
	if m := c.inst.runtime.Module(transportModule); m != nil {
		t.Errorf("host module %s is still registered after Close", transportModule)
	}
	// Still idempotent.
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// Many callers share one client, as a service's requests do, and each call
// gets a deadline: none, already passed, or one that may pass in the queue
// or in the guest. The client never closes, every call whose context did
// not end succeeds, and nothing is left running afterwards.
func TestManyCallersCancellingAtRandomShareOneClient(t *testing.T) {
	c, err := NewDeterministicClient(context.Background(), [32]byte{7})
	if errors.Is(err, ErrDeterministicGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cipher := c.DefaultKeyset()
	plan := usersPlan()
	before := runtime.NumGoroutine()

	const callers, calls = 16, 40
	var succeeded atomic.Int32
	var wg sync.WaitGroup
	for g := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := rand.New(rand.NewPCG(uint64(g), 1))
			for i := range calls {
				ctx, cancel := context.Background(), context.CancelFunc(func() {})
				switch r.IntN(4) {
				case 0: // no deadline
				case 1:
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				default:
					ctx, cancel = context.WithTimeout(ctx, time.Duration(r.IntN(2000))*time.Microsecond)
				}
				rows := []record.Source{usersRow(uint32(i), "user@example.com")}
				_, err := cipher.Seal(ctx, plan, rows)
				ended := ctx.Err() != nil
				cancel()
				switch {
				case errors.Is(err, ErrState):
					t.Errorf("the client closed: %v", err)
					return
				case err == nil:
					succeeded.Add(1)
				case !ended:
					t.Errorf("a call whose context did not end failed: %v", err)
				case !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded):
					t.Errorf("a cancelled call: %v, want the context's error", err)
				}
			}
		}()
	}
	wg.Wait()
	if succeeded.Load() == 0 {
		t.Fatal("no call succeeded")
	}
	if _, err := cipher.Seal(context.Background(), plan, []record.Source{usersRow(1, "a@example.com")}); err != nil {
		t.Fatalf("a call after the load: %v", err)
	}
	// Every backstop timer and context watcher has stopped.
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		t.Errorf("%d goroutines after the load, %d before", n, before)
	}
}

// The encrypt client and the auth profile fail together or not at all: a
// call cancelled while the auth strategy exchanges its access key for a
// token leaves both open, and the next call gets a token and reaches
// ZeroKMS.
func TestACallCancelledDuringATokenExchangeLeavesTheProfileOpen(t *testing.T) {
	var hold atomic.Bool
	done := make(chan struct{})
	var jwt string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if hold.Load() {
			select {
			case <-r.Context().Done():
			case <-done:
				t.Error("a held token request was never cancelled")
			}
			return
		}
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, jwt, time.Now().Add(time.Hour).Unix())
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(done) })
	jwt = authJWT(t, server.URL, "ZVATKW3VHMFG27DY")

	store, err := auth.OpenWithoutProfile(context.Background())
	if errors.Is(err, auth.ErrGuestNotBuilt) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	strategy, err := store.AccessKey(context.Background(), testCRN, auth.NewAccessKey([]byte(testAccessKey)), auth.WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()

	rt := &switchable{rt: unauthorized}
	c := cancelClient(t, rt, strategy)
	hold.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := cipherInit(ctx, c); !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrState) {
		t.Fatalf("call cancelled during the exchange: %v, want the deadline", err)
	}
	hold.Store(false)
	wantOpen(t, c, rt)
	if n := rt.sent.Load(); n != 1 {
		t.Fatalf("%d ZeroKMS request(s), want the one after the token arrived", n)
	}
}
