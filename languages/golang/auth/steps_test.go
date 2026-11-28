package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/internal/frame"
	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/tetratelabs/wazero/api"
)

// Tests of a token operation's steps: a caller leaving, Close, a refresh
// of a token that still works, a step the host cannot read, a stuck step,
// and the guest's limit on paused operations. Some replace one of the
// guest's exports with a wrapper, to land a caller's context, a failure or
// a hang at a chosen point between two steps.

// cancelAfter runs the export it wraps, then ends the caller's context: a
// deadline that expires as the export returns.
type cancelAfter struct {
	api.Function
	cancel context.CancelFunc
}

func (f cancelAfter) Call(ctx context.Context, params ...uint64) ([]uint64, error) {
	res, err := f.Function.Call(ctx, params...)
	f.cancel()
	return res, err
}

// F1: a caller whose context ends as its first step pauses must fail on
// its own. The step it left is taken (sa_auth_io) under that ended
// context, and wazero closes a module called under an ended context, so
// the profile closed for every strategy of it.
func TestACallerWhoseContextEndsAsItsFirstStepPausesLeavesTheProfileOpen(t *testing.T) {
	guestOrSkip(t)
	var hold atomic.Bool
	server := tokenServer(t, &hold)
	profile, strategy := heldAccessKey(t, server)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	real := profile.root.inst.authToken
	profile.root.inst.authToken = cancelAfter{Function: real, cancel: cancel}
	if _, err := strategy.Token(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Token: %v, want context.Canceled", err)
	}
	strategy.inflight.Wait()
	profile.root.inst.authToken = real

	wantProfileOpen(t, profile)
	if token, err := strategy.Token(context.Background()); err != nil || token == "" {
		t.Fatalf("the next Token: %q, %v", subject(token), err)
	}
}

// F2: ProfileStore.Close while a device session's refresh request is in
// flight. The service rotates the refresh token when it answers, so the
// answer must still be saved: Close waits for it, as it did when the
// request ran inside a guest call under the profile's lock.
func TestClosingTheProfileDuringARefreshKeepsTheRotatedRefreshToken(t *testing.T) {
	guestOrSkip(t)
	dir, _ := expiredDeviceProfile(t)
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-release
		fmt.Fprint(w, `{"access_token":"fresh","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-2"}`)
	}))
	t.Cleanup(server.Close)
	profile, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := profile.WorkspaceStore(context.Background(), wsA)
	if err != nil {
		t.Fatal(err)
	}
	strategy, err := ws.DeviceSession(context.Background(), WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}

	refreshed := make(chan error, 1)
	go func() {
		_, err := strategy.Token(context.Background())
		refreshed <- err
	}()
	<-started
	closed := make(chan error, 1)
	go func() { closed <- profile.Close() }()
	// Give a Close that does not wait the time to return first.
	time.Sleep(200 * time.Millisecond)
	close(release)
	if err := <-refreshed; err != nil {
		t.Logf("the refreshing Token: %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	_ = strategy.Close()

	data, err := os.ReadFile(filepath.Join(dir, "workspaces", wsA, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if stored["refresh_token"] != "refresh-2" {
		t.Fatal("auth.json does not hold the rotated refresh token: the service's answer was dropped when the profile closed")
	}
}

// F3: a device session's token inside the 90-second refresh window still
// works. While one caller refreshes it, every other caller gets it at
// once, as for the other strategies.
func TestDeviceSessionCallersDoNotWaitBehindARefreshOfAValidToken(t *testing.T) {
	guestOrSkip(t)
	const delay = time.Second
	dir := t.TempDir()
	workspaceDir := filepath.Join(dir, "workspaces", wsA)
	if err := os.MkdirAll(workspaceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(workspaceDir, "auth.json"), fmt.Sprintf(
		`{"access_token":"old","refresh_token":"refresh-1","token_type":"Bearer","expires_at":%d,"region":"ap-southeast-2.aws","client_id":"client-1"}`,
		time.Now().Add(60*time.Second).Unix()))
	refreshing := make(chan struct{}, 16)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		requests.Add(1)
		refreshing <- struct{}{}
		time.Sleep(delay)
		fmt.Fprint(w, `{"access_token":"fresh","token_type":"Bearer","expires_in":3600,"refresh_token":"refresh-2"}`)
	}))
	t.Cleanup(server.Close)
	profile, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	ws, err := profile.WorkspaceStore(context.Background(), wsA)
	if err != nil {
		t.Fatal(err)
	}
	strategy, err := ws.DeviceSession(context.Background(), WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer strategy.Close()

	refreshed := make(chan string, 1)
	go func() {
		token, err := strategy.Token(context.Background())
		if err != nil {
			t.Errorf("the refreshing Token: %v", err)
		}
		refreshed <- token
	}()
	select {
	case <-refreshing:
	case <-time.After(5 * time.Second):
		t.Fatal("no refresh started")
	}
	const callers = 8
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() {
			start := time.Now()
			token, err := strategy.Token(context.Background())
			if waited := time.Since(start); waited > delay/4 {
				t.Errorf("caller %d waited %v behind the refresh", i, waited)
			}
			if err != nil || token != "old" {
				t.Errorf("caller %d got %q, %v, want the current token, %q", i, token, err, "old")
			}
		})
	}
	wg.Wait()
	if token := <-refreshed; token != "fresh" {
		t.Fatalf("the refreshing Token got %q, want the refreshed one", token)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("%d refresh requests, want 1", n)
	}
}

// noStep takes the step a paused export left, and hands Go nothing: a step
// the host cannot read.
type noStep struct{ api.Function }

func (f noStep) Call(ctx context.Context, params ...uint64) ([]uint64, error) {
	if _, err := f.Function.Call(ctx, params...); err != nil {
		return nil, err
	}
	return []uint64{0}, nil
}

// F4: a step the host cannot read fails its caller, and must not leave the
// operation behind in the guest. There, an exchange holds stack-auth's
// lock, so the next caller parked behind it until its own deadline.
func TestAStepTheHostCannotReadLeavesNoOperationBehind(t *testing.T) {
	guestOrSkip(t)
	var hold atomic.Bool
	server := tokenServer(t, &hold)
	profile, strategy := heldAccessKey(t, server)

	real := profile.root.inst.authIO
	profile.root.inst.authIO = noStep{real}
	if _, err := strategy.Token(context.Background()); !errors.Is(err, ErrInternal) {
		t.Fatalf("Token with an unreadable step: %v, want ErrInternal", err)
	}
	profile.root.inst.authIO = real

	const deadline = 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	start := time.Now()
	_, err := strategy.Token(ctx)
	if waited := time.Since(start); errors.Is(err, context.DeadlineExceeded) || waited > deadline/2 {
		t.Fatalf("the next Token waited %v and got %v: it parked behind the operation the failed step left in the guest", waited, err)
	}
}

// stuckResume stands in for a guest that never returns from a resume: it
// runs until its call's context ends, as wazero ends a call, or for
// fallback.
type stuckResume struct {
	api.Function
	fallback time.Duration
	started  chan time.Time
	ended    chan time.Time
}

func (f stuckResume) Call(ctx context.Context, _ ...uint64) ([]uint64, error) {
	f.started <- time.Now()
	select {
	case <-ctx.Done():
	case <-time.After(f.fallback):
	}
	f.ended <- time.Now()
	return nil, errors.New("the guest did not return")
}

// F6: a resume that never returns, after its caller gave up, is ended by
// the stuck-call backstop, as every other guest call is, rather than
// holding the profile's lock for good.
func TestAStuckResumeIsEndedByTheBackstop(t *testing.T) {
	guestOrSkip(t)
	server, _, started, release := heldServer(t)
	defer close(release)
	profile, strategy := heldAccessKey(t, server)
	profile.root.stuck = 50 * time.Millisecond
	stuck := stuckResume{
		Function: profile.root.inst.authResume, fallback: 4 * time.Second,
		started: make(chan time.Time, 1), ended: make(chan time.Time, 1),
	}
	profile.root.inst.authResume = stuck

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	go func() { _, _ = strategy.Token(ctx) }()
	<-started
	resumed := <-stuck.started
	ended := <-stuck.ended
	if took := ended.Sub(resumed); took > 2*time.Second {
		t.Fatalf("the stuck resume ran %v: no backstop ended it", took)
	}
}

// F5: maxPaused is the guest's own limit on open operations (MAX_OPEN in
// stack-guest-abi's step loop). The starts are driven directly, past the
// wait for an operation to end (startUnlock): one exchange in flight,
// maxPaused-1 callers parked behind it, and the next start refused. A guest
// that held more or fewer fails here.
func TestMaxPausedIsTheGuestsLimit(t *testing.T) {
	guestOrSkip(t)
	server, _, _, release := heldServer(t)
	defer close(release)
	profile, strategy := heldAccessKey(t, server)
	ctx := context.Background()
	start := func(i *instance) api.Function { return i.authToken }
	arg := guest.BufArg([]byte(strategy.handle))

	profile.root.mu.Lock()
	defer profile.root.mu.Unlock()
	var handles []uint64
	defer func() {
		for _, h := range handles {
			profile.abortLocked(ctx, h)
		}
	}()
	_, step, err := profile.stepLocked(ctx, false, start, arg)
	if err != nil || step == nil || step.parked {
		t.Fatalf("the first start: %+v, %v, want an exchange in flight", step, err)
	}
	handles = append(handles, step.handle)
	for i := 1; i < maxPaused; i++ {
		_, step, err := profile.stepLocked(ctx, false, start, arg)
		if err != nil || step == nil || !step.parked {
			t.Fatalf("start %d of %d: %+v, %v, want it parked: the guest holds fewer than maxPaused", i+1, maxPaused, step, err)
		}
		handles = append(handles, step.handle)
	}
	if _, step, err := profile.stepLocked(ctx, false, start, arg); !errors.Is(err, ErrState) {
		if step != nil {
			handles = append(handles, step.handle)
		}
		t.Fatalf("start %d: %+v, %v, want ErrState: the guest holds more than maxPaused", maxPaused+1, step, err)
	}
}

// Strategy.Close and ProfileStore.Close, in either order or at once, while
// a token request is in flight: both return once it is answered.
func TestStrategyAndProfileCloseInAnyOrderReturn(t *testing.T) {
	guestOrSkip(t)
	for _, order := range []string{"strategy first", "profile first", "at once"} {
		t.Run(order, func(t *testing.T) {
			server, _, started, release := heldServer(t)
			profile, strategy := heldAccessKey(t, server)
			done := make(chan error, 1)
			go func() {
				_, err := strategy.Token(context.Background())
				done <- err
			}()
			<-started
			closes := map[string]func() error{"strategy": strategy.Close, "profile": profile.Close}
			names := map[string][]string{
				"strategy first": {"strategy", "profile"},
				"profile first":  {"profile", "strategy"},
				"at once":        {"strategy", "profile"},
			}[order]
			closed := make(chan error, 2)
			if order == "at once" {
				for _, n := range names {
					go func() { closed <- closes[n]() }()
				}
			} else {
				go func() {
					for _, n := range names {
						closed <- closes[n]()
					}
				}()
			}
			time.Sleep(50 * time.Millisecond)
			close(release)
			for range names {
				select {
				case err := <-closed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("a Close did not return")
				}
			}
			if err := <-done; err != nil {
				t.Fatalf("the Token in flight: %v", err)
			}
			if _, err := strategy.Token(context.Background()); !errors.Is(err, ErrState) {
				t.Fatalf("a Token after both Closes: %v, want ErrState", err)
			}
		})
	}
}

// A token read for a device session is refused unless the frame has both
// fields, with the right types, and nothing else. The codec refuses a
// duplicate key before decodeDeviceToken receives the frame.
func TestDecodeDeviceTokenRefusesAnyOtherShape(t *testing.T) {
	type f = frame.Field
	encode := func(t *testing.T, v any) []byte {
		t.Helper()
		raw, err := frame.Marshal(v)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		return raw
	}
	token, refresh, err := decodeDeviceToken(encode(t, frame.Object{
		{Key: "access_token", Value: "Zq7-secret"}, {Key: "refresh_required", Value: true},
	}))
	if err != nil || token != "Zq7-secret" || !refresh {
		t.Fatalf("decodeDeviceToken(good frame) = %q, %v, %v", token, refresh, err)
	}
	for name, raw := range map[string][]byte{
		"empty":           {},
		"not a map":       encode(t, []any{}),
		"no token":        encode(t, frame.Object{f{Key: "refresh_required", Value: false}}),
		"no flag":         encode(t, frame.Object{f{Key: "access_token", Value: "Zq7-secret"}}),
		"empty token":     encode(t, frame.Object{f{Key: "access_token", Value: ""}, f{Key: "refresh_required", Value: false}}),
		"token not text":  encode(t, frame.Object{f{Key: "access_token", Value: int64(1)}, f{Key: "refresh_required", Value: false}}),
		"flag not a bool": encode(t, frame.Object{f{Key: "access_token", Value: "Zq7-secret"}, f{Key: "refresh_required", Value: "no"}}),
		"an extra field":  encode(t, frame.Object{f{Key: "access_token", Value: "Zq7-secret"}, f{Key: "refresh_required", Value: false}, f{Key: "extra", Value: true}}),
	} {
		_, _, err := decodeDeviceToken(raw)
		if !errors.Is(err, ErrInternal) {
			t.Errorf("%s: decodeDeviceToken = %v, want ErrInternal", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "Zq7-secret") {
			t.Errorf("%s: the error quotes the frame: %v", name, err)
		}
	}
}

// One strategy's callers, parked behind its exchange as many as the guest
// holds, must not hold up a second strategy of the same profile whose
// token is cached: a call that never pauses takes no slot.
func TestParkedCallersOfOneStrategyDoNotHoldUpAnother(t *testing.T) {
	guestOrSkip(t)
	server, _, started, release := heldServer(t)
	profile, a := heldAccessKey(t, server)
	serverB, _, startedB, releaseB := heldServer(t)
	close(releaseB)
	b, err := profile.AccessKey(context.Background(), testCRN, "CSAKotherKeyId.otherSecret", WithBaseURL(serverB.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-startedB

	var wg sync.WaitGroup
	defer wg.Wait()
	defer close(release)
	for range maxPaused {
		wg.Go(func() { _, _ = a.Token(context.Background()) })
	}
	<-started
	awaitParked(t, profile, maxPaused-1)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := b.Token(ctx); err != nil {
		t.Fatalf("the second strategy's cached token, after %v: %v", time.Since(start), err)
	}
}

// A Close that finds another Close already running waits for it, and
// returns what it returned: the provider is no longer called once any
// Close has returned.
func TestASecondStrategyCloseWaitsForTheFirst(t *testing.T) {
	guestOrSkip(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		fmt.Fprintf(w, `{"accessToken":%q,"expiry":%d}`, testJWT(t, "https://cts.example"), time.Now().Add(time.Hour).Unix())
	}))
	defer server.Close()
	profile, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profile.Close()
	entered := make(chan struct{})
	release := make(chan struct{})
	var returned atomic.Bool
	strategy, err := profile.OIDC(context.Background(), testCRN, OIDCProviderFunc(func(context.Context) (string, error) {
		close(entered)
		<-release
		returned.Store(true)
		return "idp-token", nil
	}), WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	tokenDone := make(chan struct{})
	go func() { _, _ = strategy.Token(context.Background()); close(tokenDone) }()
	<-entered

	first := make(chan error, 1)
	go func() { first <- strategy.Close() }()
	time.Sleep(50 * time.Millisecond)
	second := make(chan error, 1)
	go func() { second <- strategy.Close() }()
	select {
	case err := <-second:
		close(release)
		<-tokenDone
		t.Fatalf("the second Close returned %v while the first was still waiting for the provider", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	<-tokenDone
	firstErr, secondErr := <-first, <-second
	if !returned.Load() || firstErr != secondErr {
		t.Fatalf("Closes returned %v and %v (provider returned: %v)", firstErr, secondErr, returned.Load())
	}
}

// byteLeaves is every []byte in a decoded frame.
func byteLeaves(v any) [][]byte {
	switch v := v.(type) {
	case []byte:
		return [][]byte{v}
	case []any:
		var out [][]byte
		for _, item := range v {
			out = append(out, byteLeaves(item)...)
		}
		return out
	case frame.Object:
		var out [][]byte
		for _, f := range v {
			out = append(out, byteLeaves(f.Value)...)
		}
		return out
	}
	return nil
}

// A step the decoder refuses is wiped whole: every request's headers and
// body, wherever the refusal comes, carry a credential.
func TestARefusedStepIsWipedWhole(t *testing.T) {
	marker := func() []byte { return []byte("leak-marker-credential") }
	request := func(fields ...frame.Field) frame.Object { return frame.Object(fields) }
	good := func() frame.Object {
		return request(
			frame.Field{Key: "method", Value: "POST"},
			frame.Field{Key: "url", Value: "https://cts.example/api/authorise"},
			frame.Field{Key: "headers", Value: marker()},
			frame.Field{Key: "body", Value: marker()},
		)
	}
	for name, step := range map[string]frame.Object{
		"a field refused before the requests": {
			{Key: "handle", Value: uint64(1)},
			{Key: "unknown", Value: true},
			{Key: "parked", Value: false},
			{Key: "requests", Value: []any{good()}},
		},
		"the requests after a refused one": {
			{Key: "handle", Value: uint64(1)},
			{Key: "parked", Value: false},
			{Key: "requests", Value: []any{request(frame.Field{Key: "method", Value: uint64(5)}), good()}},
		},
		"the fields after a refused one": {
			{Key: "handle", Value: uint64(1)},
			{Key: "parked", Value: false},
			{Key: "requests", Value: []any{request(
				frame.Field{Key: "method", Value: marker()},
				frame.Field{Key: "url", Value: "https://cts.example"},
				frame.Field{Key: "headers", Value: marker()},
				frame.Field{Key: "body", Value: marker()},
			)}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := frame.Marshal(step)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := frame.Unmarshal(raw)
			if err != nil {
				t.Fatal(err)
			}
			leaves := byteLeaves(decoded)
			if len(leaves) == 0 {
				t.Fatal("the frame decoded with no bytes")
			}
			if _, err := authStepFrom(decoded); err == nil {
				t.Fatal("the step was accepted")
			}
			for i, leaf := range leaves {
				if strings.Contains(string(leaf), "leak-marker") {
					t.Errorf("bytes leaf %d of %d still holds the credential", i+1, len(leaves))
				}
			}
		})
	}
}

// stuckIO takes the step, then stands in for a guest that never returns
// from sa_auth_io: it runs until its call's context ends, or for fallback.
type stuckIO struct {
	stuckResume
}

func (f stuckIO) Call(ctx context.Context, params ...uint64) ([]uint64, error) {
	_, _ = f.Function.Call(context.WithoutCancel(ctx), params...)
	return f.stuckResume.Call(ctx)
}

// Taking a step is a guest call like any other: one that never returns,
// after its caller gave up, is ended by the stuck-call backstop.
func TestAStuckStepTakeIsEndedByTheBackstop(t *testing.T) {
	guestOrSkip(t)
	server, _, _, release := heldServer(t)
	defer close(release)
	profile, strategy := heldAccessKey(t, server)
	profile.root.stuck = 50 * time.Millisecond
	stuck := stuckIO{stuckResume{
		Function: profile.root.inst.authIO, fallback: 4 * time.Second,
		started: make(chan time.Time, 1), ended: make(chan time.Time, 1),
	}}
	profile.root.inst.authIO = stuck

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	go func() { _, _ = strategy.Token(ctx) }()
	took := <-stuck.started
	ended := <-stuck.ended
	if d := ended.Sub(took); d > 2*time.Second {
		t.Fatalf("the stuck step take ran %v: no backstop ended it", d)
	}
}

// wantNoneOpen fails unless the profile counts no token operation open.
func wantNoneOpen(t *testing.T, profile *ProfileStore) {
	t.Helper()
	profile.root.mu.Lock()
	defer profile.root.mu.Unlock()
	if n := profile.root.open; n != 0 {
		t.Fatalf("%d token operations still counted open", n)
	}
}

// A start the guest refuses because it holds as many operations as it can
// waits for one to end, and its caller leaves at its deadline. Once they
// end, the next start goes through.
func TestACallerRefusedByAFullGuestLeavesAtItsDeadline(t *testing.T) {
	guestOrSkip(t)
	server, requests, started, release := heldServer(t)
	profile, strategy := heldAccessKey(t, server)
	var wg sync.WaitGroup
	for range maxPaused {
		wg.Go(func() { _, _ = strategy.Token(context.Background()) })
	}
	<-started
	awaitParked(t, profile, maxPaused-1)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := strategy.Token(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a Token refused by a full guest: %v, want the deadline", err)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("it returned after %v", waited)
	}
	close(release)
	wg.Wait()
	if token, err := strategy.Token(context.Background()); err != nil || subject(token) != "1" {
		t.Fatalf("the next Token: %q, %v", subject(token), err)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("%d exchanges, want 1", n)
	}
	wantNoneOpen(t, profile)
}
