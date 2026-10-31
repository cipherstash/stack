package guest

import (
	"context"
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
//   - The guest runs under a context the caller cannot end ([Detach]). The
//     runtime closes a module whose call context ends (the runtimes are
//     built with WithCloseOnContextDone), and a closed module is a client
//     gone for everyone. The caller's context still reaches the host
//     functions ([Caller]), so a ZeroKMS request or a token fetch in flight
//     is cancelled, fails as a transport failure, and the guest unwinds
//     through its ordinary error path with its keys intact.
//   - A guest that has not returned [StuckAfter] after its caller's context
//     ended is closed: the call context Detach returns ends then. That is
//     the backstop for a guest or host function that ignores cancellation,
//     which is a bug, never a closed browser tab.

// StuckAfter is how long a guest call may go on after its caller's context
// ends before the guest is treated as stuck and closed. Once the network
// wait is cancelled, what remains of a call is the guest's own work, which
// takes milliseconds; the margin is wide so that a large batch cancelled
// mid-way still finishes and leaves the instance open.
const StuckAfter = 30 * time.Second

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
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case l.slot() <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	// Both cases can be ready at once, and select picks either: a context
	// that ended while the lock was free must not run the call.
	if err := ctx.Err(); err != nil {
		l.Unlock()
		return err
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
// finished by then, and the runtime then closes the module. done must be
// called when the call returns; it stops the backstop.
func Detach(ctx context.Context, stuck time.Duration) (run context.Context, done func()) {
	run, cancel := context.WithCancel(context.WithValue(context.WithoutCancel(ctx), callerKey{}, ctx))
	var mu sync.Mutex
	var timer *time.Timer
	finished := false
	stop := context.AfterFunc(ctx, func() {
		mu.Lock()
		defer mu.Unlock()
		if !finished {
			timer = time.AfterFunc(stuck, cancel)
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
		cancel()
	}
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
