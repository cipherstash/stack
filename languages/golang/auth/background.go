package auth

import (
	"context"
	"errors"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
	"weak"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/tetratelabs/wazero/api"
)

// refreshLoops counts the refresh loops running. The tests read it to
// prove that none outlives its strategy.
var refreshLoops atomic.Int32

// minRefreshGap is the least time between two refresh attempts of one
// loop, so a plan that stays due (a caller's refresh still in flight, say)
// cannot spin it.
const minRefreshGap = time.Second

// startRefreshLoop starts the goroutine that refreshes the strategy's
// token ahead of its expiry, by stack-auth's rule (the guest's
// sa_auth_next_refresh): only while the token is in use, and with backoff
// after a failure. Close stops it, as does closing the profile.
//
// The loop holds the strategy weakly, and only while it talks to the
// guest: a strategy its application forgets to close is still collected,
// and its cleanup stops the loop.
func (s *Strategy) startRefreshLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	s.stopLoop = cancel
	s.used = make(chan struct{}, 1)
	s.loopDone = make(chan struct{})
	runtime.AddCleanup(s, func(cancel context.CancelFunc) { cancel() }, cancel)
	refreshLoops.Add(1)
	go refreshLoop(ctx, weak.Make(s), s.used, s.store.root.done, s.loopDone)
}

// signalUse wakes the refresh loop if it is idle: the token was used, so
// its refresh ahead of expiry is due again.
func (s *Strategy) signalUse() {
	select {
	case s.used <- struct{}{}:
	default:
	}
}

func refreshLoop(ctx context.Context, strategy weak.Pointer[Strategy], used <-chan struct{}, closing <-chan struct{}, done chan<- struct{}) {
	defer refreshLoops.Add(-1)
	defer close(done)
	// Nothing to refresh before the first token: wait for a call to get
	// one, rather than ask while that call's exchange holds the strategy.
	if waitFor(ctx, 0, used, closing) == stop {
		return
	}
	var lastAttempt time.Time
	for {
		s := strategy.Value()
		if s == nil {
			return
		}
		at, idle, err := s.nextRefresh(ctx)
		s = nil
		switch {
		case ctx.Err() != nil, errors.Is(err, ErrState):
			return
		case err != nil:
			// Nothing to act on: look again in a minute, or when the token
			// is next used.
			at, idle = time.Now().Add(time.Minute), false
		}
		var wake <-chan struct{}
		var wait time.Duration
		if idle {
			wake = used
		} else {
			wait = max(time.Until(at), minRefreshGap-time.Since(lastAttempt))
		}
		switch waitFor(ctx, wait, wake, closing) {
		case stop:
			return
		case woken:
			continue
		case elapsed:
		}
		if s = strategy.Value(); s == nil {
			return
		}
		lastAttempt = time.Now()
		s.refreshAhead(ctx)
		s = nil
	}
}

type waited int

const (
	stop waited = iota
	woken
	elapsed
)

// waitFor waits until wait has passed (when wake is nil), or until wake
// fires (when it is not), unless ctx ends or the profile closes first.
func waitFor(ctx context.Context, wait time.Duration, wake <-chan struct{}, closing <-chan struct{}) waited {
	var due <-chan time.Time
	if wake == nil {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		due = timer.C
	}
	select {
	case <-ctx.Done():
		return stop
	case <-closing:
		return stop
	case <-wake:
		return woken
	case <-due:
		return elapsed
	}
}

// nextRefresh asks the guest when the token's next refresh ahead of
// expiry is due. idle means not until the token is used again.
func (s *Strategy) nextRefresh(ctx context.Context) (at time.Time, idle bool, err error) {
	out, err := s.store.run(ctx, func(i *instance) api.Function { return i.authNextRefresh }, guest.BufArg([]byte(s.handle)))
	if err != nil {
		return time.Time{}, false, err
	}
	if len(out) == 0 {
		return time.Time{}, true, nil
	}
	secs, err := strconv.ParseInt(string(out), 10, 64)
	if err != nil {
		return time.Time{}, false, errMalformedNextRefresh
	}
	return time.Unix(secs, 0), false, nil
}

var errMalformedNextRefresh = errors.New("auth: the guest's next refresh time is not a number")

// refreshAhead refreshes the token if its refresh is still due. Its
// outcome is the guest's to record: a failure backs the next attempt off,
// and a caller whose token has expired meanwhile gets that failure's
// error. A device session refreshes as Token does, one at a time in the
// process and under the cross-process lock; a caller already refreshing
// one inline is left to it.
func (s *Strategy) refreshAhead(ctx context.Context) {
	refresh := func(ctx context.Context) error {
		out, err := s.store.run(ctx, func(i *instance) api.Function { return i.authRefreshAhead }, guest.BufArg([]byte(s.handle)))
		guest.Wipe(out)
		return err
	}
	if !s.device {
		_ = refresh(ctx)
		return
	}
	if !s.refreshing.TryLock() {
		return
	}
	defer s.refreshing.Unlock()
	path, err := s.store.LockPath(ctx, "auth.json")
	if err != nil {
		return
	}
	// The one request that rotates a credential runs on after Close
	// cancels the loop, for the grace (see refreshGrace).
	_ = withRefreshLock(ctx, path, func() error { return refresh(withRefresh(ctx)) })
}
