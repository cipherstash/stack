package guest

import (
	"context"
	"errors"
	"sync"
	"time"
)

// What a caller's context does to a guest call. A guest instance is shared:
// an encrypt.Client or an auth profile serves every request in a process,
// so one caller's cancellation must end that caller's call and nothing
// else. Three pieces make that so, and every guest package uses all three.
//
//   - The wait for the instance ends with the caller's context ([Lock]). A
//     request whose deadline passes in the queue leaves with the context's
//     error and never reaches the guest.
//   - The guest runs under a context the caller cannot end ([Detach]). A
//     runtime built with WithCloseOnContextDone closes a module whose call
//     context ends, and a closed module is a client gone for everyone. The
//     caller's context still reaches the host functions ([Caller]), so a
//     ZeroKMS request or a token fetch in flight is cancelled, fails as a
//     transport failure, and the guest unwinds through its ordinary error
//     path with its keys intact.
//   - A guest that has not returned [StuckAfter] after its caller's context
//     ended is stuck: the call context Detach returns ends then, with
//     [ErrStuck] as its cause ([Stuck]). That is the backstop for a guest or
//     host function that ignores cancellation, which is a bug, never a
//     closed browser tab. What the backstop does is the guest package's
//     choice. The auth guest's runtime is built with WithCloseOnContextDone,
//     so the runtime interrupts the guest and closes it. The encrypt guest's
//     is not, because that option puts a call back into Go at the top of
//     every loop the guest runs, which costs its cryptography several times
//     over: there the backstop marks the client unusable, so no other caller
//     waits behind the stuck call ([Lock.AcquireUnless]), and the guest is
//     closed if the call ever returns.

// StuckAfter is how long a guest call may go on after its caller's context
// ends before the guest is treated as stuck (see [Stuck]). Once the network
// wait is cancelled, what remains of a call is the guest's own work, which
// takes milliseconds; the margin is wide so that a large batch cancelled
// mid-way still finishes and leaves the instance open.
const StuckAfter = 30 * time.Second

// ErrStuck is the cause of a call context that [Detach]'s backstop ended:
// the call ran on [StuckAfter] after its caller's context ended.
var ErrStuck = errors.New("a call ran on long after its caller's context ended")

// ErrAbandoned is what [Lock.AcquireUnless] returns when its abandon
// channel closes before the lock is free.
var ErrAbandoned = errors.New("guest: the lock's holder is stuck")

// Lock is a guest instance's call lock: one call at a time, as a wasm
// instance is single-threaded, with a wait that ends with the caller's
// context. The zero value is unlocked.
type Lock struct {
	once sync.Once
	ch   chan struct{}
}

func (l *Lock) slot() chan struct{} {
	l.once.Do(func() { l.ch = make(chan struct{}, 1) })
	return l.ch
}

// Acquire takes the lock, or returns ctx's error if ctx ends first. A
// context that has already ended is refused even when the lock is free,
// so a call that would start with nothing to wait for never starts.
func (l *Lock) Acquire(ctx context.Context) error {
	// A nil channel never receives, so nothing abandons this wait.
	return l.AcquireUnless(ctx, nil)
}

// AcquireUnless is [Acquire] that also gives up, with [ErrAbandoned], once
// abandon is closed: for a lock whose holder may be stuck in a guest call
// that cannot be interrupted, so the callers queued behind it, and the ones
// that come later, leave rather than wait on it for ever. A closed abandon
// is refused even when the lock is free. A nil abandon is [Acquire].
func (l *Lock) AcquireUnless(ctx context.Context, abandon <-chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-abandon:
		return ErrAbandoned
	default:
	}
	select {
	case l.slot() <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-abandon:
		return ErrAbandoned
	}
	// More than one case can be ready at once, and select picks any: a
	// context that ended, or a lock abandoned, while the lock was free must
	// not run the call.
	if err := ctx.Err(); err != nil {
		l.Unlock()
		return err
	}
	select {
	case <-abandon:
		l.Unlock()
		return ErrAbandoned
	default:
	}
	return nil
}

// Lock takes the lock with no way out, for Close, which must not be
// skippable.
func (l *Lock) Lock() { l.slot() <- struct{}{} }

// TryLock takes the lock if it is free, without waiting, and reports
// whether it did.
func (l *Lock) TryLock() bool {
	select {
	case l.slot() <- struct{}{}:
		return true
	default:
		return false
	}
}

// Unlock releases the lock.
func (l *Lock) Unlock() { <-l.slot() }

// callerKey carries the caller's context inside the one Detach returns.
type callerKey struct{}

// Detach returns the context a guest call runs under: ctx's values, but not
// its cancellation, so the runtime does not close the module when the
// caller gives up. It ends stuck after ctx does, if the call has not
// finished by then, with [ErrStuck] as its cause: a runtime built with
// WithCloseOnContextDone then closes the module, and [Stuck] reports it to
// a guest package whose runtime is not. done must be called when the call
// returns; it stops the backstop, and ends run with no such cause.
func Detach(ctx context.Context, stuck time.Duration) (run context.Context, done func()) {
	run, cancel := context.WithCancelCause(context.WithValue(context.WithoutCancel(ctx), callerKey{}, ctx))
	var mu sync.Mutex
	var timer *time.Timer
	finished := false
	stop := context.AfterFunc(ctx, func() {
		mu.Lock()
		defer mu.Unlock()
		if !finished {
			timer = time.AfterFunc(stuck, func() { cancel(ErrStuck) })
		}
	})
	return run, func() {
		stop()
		mu.Lock()
		finished = true
		if timer != nil {
			timer.Stop()
		}
		mu.Unlock()
		cancel(nil)
	}
}

// Stuck reports whether run, a context [Detach] returned, was ended by the
// backstop: its call was still running [StuckAfter] after its caller's
// context ended. Once done has been called the answer is final.
func Stuck(run context.Context) bool {
	return errors.Is(context.Cause(run), ErrStuck)
}

// Caller is the caller's context inside a host function: what a request to
// the network or a token source must honour, so the caller's cancellation
// reaches it. Outside a call Detach began, it is ctx itself.
func Caller(ctx context.Context) context.Context {
	if caller, ok := ctx.Value(callerKey{}).(context.Context); ok {
		return caller
	}
	return ctx
}
