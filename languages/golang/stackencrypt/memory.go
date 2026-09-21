package stackencrypt

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"

	"github.com/tetratelabs/wazero/experimental"
)

// The guest's linear memory is where every key lives: the client key from
// NewClient on, each keyset's index key once loaded, and each data key for
// the duration of a call. The host owns that memory, so the host decides
// what can happen to it. This allocator supplies the guest's memory from a
// reservation of its own rather than from wazero's default Go slice, so
// that:
//
//   - the buffer never moves. wazero's default grows non-shared memory
//     with append, which copies the whole linear memory — keys included —
//     into a new slice and leaves the old one to the garbage collector,
//     unwiped. Here the declared maximum is reserved up front and growth
//     commits more of the same reservation;
//   - the committed pages are locked where the platform allows, so they
//     are never written to swap;
//   - they are excluded from core dumps where the platform allows (Linux);
//   - the committed range is wiped before it is released, on every
//     release path, so a freed instance leaves nothing behind.
//
// None of this depends on Close running. A process that dies to SIGKILL,
// the OOM killer, a panic on another goroutine or os.Exit leaves its keys
// in memory the kernel will zero before anyone else sees it, and — with
// the lock and the dump exclusion in place — nowhere else. Close still runs
// the guest's own wipe for the orderly path; it is hygiene, not the
// security story.
//
// The lock is best effort by default. RLIMIT_MEMLOCK defaults to 64 KiB on
// many Linux hosts and the guest's memory is larger, so the lock is
// commonly refused, with nothing else lost: the pages can be swapped, and
// on a host with no swap not even that. The refusal is recorded and
// reported through Client.MemoryLocked and Client.MemoryLockError so an
// operator can see it and raise the limit; Config.RequireLockedMemory
// turns it into a NewClient failure.

// lockPolicy is what a refused lock means for an instance.
type lockPolicy uint8

const (
	// bestEffort records a refused lock and carries on with unlocked
	// memory.
	bestEffort lockPolicy = iota
	// strict refuses growth that cannot be locked. The first commit is the
	// exception: wazero cannot instantiate on a nil buffer, so it is
	// granted with the refusal recorded, and newInstance turns that into
	// the ErrMemoryLock the caller asked for.
	strict
)

func policyFor(requireLockedMemory bool) lockPolicy {
	if requireLockedMemory {
		return strict
	}
	return bestEffort
}

// backend is one platform's linear memory behind a memoryAllocator: a
// reservation committed from the front. It is used from the guest's
// goroutine only; the allocator does the bookkeeping other goroutines
// read.
type backend interface {
	// commit grows the memory to size bytes and returns the buffer wazero
	// will use, whose base never changes. A nil buffer means the growth
	// failed. lockErr, when set, is a refused lock on the newly committed
	// range: with a buffer, the range was kept unlocked (best effort);
	// without one, the growth was refused because of it (strict).
	commit(size uint64) (buf []byte, lockErr error)
	// free wipes the committed range and releases the reservation.
	free()
}

// memoryAllocator is the experimental.MemoryAllocator handed to wazero for
// one guest instance, and the experimental.LinearMemory it returns: wazero
// calls Allocate once per memory, and the guest has exactly one. It
// records what the Client reports about the memory, and holds the memory
// mapped while a guest call is in flight (see enter, exit and Free).
type memoryAllocator struct {
	policy lockPolicy

	mu      sync.Mutex
	backing backend
	// fallback is set when the backing is a heap slice rather than a
	// reservation: no lock is possible, growth may copy (and wipes what
	// it abandons).
	fallback bool
	// lockErr is the first refusal that left the guest holding
	// unprotected memory — the reservation, the dump exclusion, a lock on
	// a range that was kept — and never clears: a lock refused once is
	// reported for the life of the instance.
	lockErr error
	// growth is the strict growths refused. It is not lockErr: a refused
	// growth gives its range back before the guest sees it, so every byte
	// the guest holds is still locked and the instance still reports so.
	growth growthRefusal
	// inFlight counts guest calls in progress (see enter and exit);
	// pending records a Free that arrived while one was, to be honoured
	// when the outermost call returns.
	inFlight int
	pending  bool
	// freed is set once the memory is gone, its contents wiped first.
	// Tests read it to observe release paths the caller never sees, such
	// as the cleanup on an unreachable Client.
	freed bool
}

// growthRefusal is the strict growths an allocator has refused: how many,
// and the lock refusal behind the latest. Client.call compares the count
// across a call to name the real cause when the guest reports only a
// failed allocation.
type growthRefusal struct {
	refused uint64
	reason  error
}

func newMemoryAllocator(policy lockPolicy) *memoryAllocator {
	return &memoryAllocator{policy: policy}
}

// Allocate implements experimental.MemoryAllocator.
func (a *memoryAllocator) Allocate(capacity, max uint64) experimental.LinearMemory {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.backing != nil {
		// The guest has one memory; a second would mean wazero's contract
		// changed under us. Refusing here fails instantiation loudly
		// rather than letting two memories share one report.
		panic("stackencrypt: guest memory allocated twice")
	}
	backing, err := reserveMemory(capacity, max, a.policy)
	a.backing = backing
	a.lockErr = err
	_, a.fallback = backing.(*heapMemory)
	return a
}

// Reallocate implements experimental.LinearMemory.
func (a *memoryAllocator) Reallocate(size uint64) []byte {
	buf, lockErr := a.backing.commit(size)
	if lockErr != nil {
		a.mu.Lock()
		if buf == nil {
			// Strict: the range was given back, so nothing unlocked was
			// admitted and the lock report stands.
			a.growth.refused++
			a.growth.reason = lockErr
		} else if a.lockErr == nil {
			a.lockErr = lockErr
		}
		a.mu.Unlock()
	}
	return buf
}

// Free implements experimental.LinearMemory. wazero calls it when the
// module's resources are closed, and that can happen while the guest is
// still running: a call whose context ends during a host import closes
// the module on wazero's watcher goroutine with its resources deferred,
// and the next call into the module — the host import re-entering the
// guest through se_alloc to place its result — closes them. With wazero's
// default allocator that was harmless, the Go slice outlived the module;
// here it would unmap the memory under a guest suspended in the import,
// whose next store then faults in compiled code. So a Free that arrives
// during a call is recorded and performed by the outermost exit, when no
// guest code can be running. A Free with no call in flight is immediate.
func (a *memoryAllocator) Free() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.inFlight > 0 {
		a.pending = true
		return
	}
	a.freeLocked()
}

// enter marks a guest call in progress: the memory must stay mapped until
// the matching exit, whatever wazero asks in between.
func (a *memoryAllocator) enter() {
	a.mu.Lock()
	a.inFlight++
	a.mu.Unlock()
}

// exit ends a guest call and performs a Free that arrived during it.
func (a *memoryAllocator) exit() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.inFlight--
	if a.inFlight == 0 && a.pending {
		a.pending = false
		a.freeLocked()
	}
}

// freeLocked wipes and releases the memory, once. Called with mu held.
func (a *memoryAllocator) freeLocked() {
	if a.freed {
		return
	}
	a.freed = true
	a.backing.free()
}

// lockError is nil while every committed byte is locked (and, on Linux,
// excluded from dumps); otherwise it names what was refused and why.
func (a *memoryAllocator) lockError() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lockErr
}

// growthRefusal is the strict growths refused so far.
func (a *memoryAllocator) growthRefusal() growthRefusal {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.growth
}

// String is the memory's state for a log line: "locked", or the refusal.
// Nothing secret is printed.
func (a *memoryAllocator) String() string {
	if err := a.lockError(); err != nil {
		return fmt.Sprintf("unlocked: %v", err)
	}
	return "locked"
}

// LogValue is the same state for slog: a group with memory_locked and,
// when false, memory_lock_error.
func (a *memoryAllocator) LogValue() slog.Value {
	if err := a.lockError(); err != nil {
		return slog.GroupValue(slog.Bool("memory_locked", false), slog.String("memory_lock_error", err.Error()))
	}
	return slog.GroupValue(slog.Bool("memory_locked", true))
}

func (a *memoryAllocator) isFallback() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fallback
}

func (a *memoryAllocator) isFreed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.freed
}

// heapMemory backs the guest with an ordinary Go slice, for platforms with
// no reservation primitive this package uses and for a reservation that
// failed (a 4 GiB address-space reservation on a 32-bit host, say). It
// keeps two of the four properties above: growth wipes the slice it
// abandons, and free wipes before releasing. It cannot lock or exclude
// from dumps; the allocator carries the reason.
type heapMemory struct {
	buf []byte
	max uint64
}

func newHeapMemory(capacity, max uint64) *heapMemory {
	if capacity > max {
		capacity = max
	}
	if capacity > math.MaxInt {
		capacity = 0
	}
	return &heapMemory{buf: make([]byte, 0, int(capacity)), max: max}
}

func (m *heapMemory) commit(size uint64) ([]byte, error) {
	if size > m.max || size > math.MaxInt {
		return nil, nil
	}
	if size <= uint64(cap(m.buf)) {
		m.buf = m.buf[:size]
		return m.buf, nil
	}
	grown := make([]byte, size)
	copy(grown, m.buf)
	// The abandoned slice held everything the guest had, keys included.
	clear(m.buf[:cap(m.buf)])
	m.buf = grown
	return m.buf, nil
}

func (m *heapMemory) free() {
	clear(m.buf[:cap(m.buf)])
	m.buf = nil
}

// errNoLockSupport is the heap fallback's reason on platforms where this
// package has no lock implementation.
var errNoLockSupport = errors.New("guest memory cannot be locked on this platform")

// memoryLockError wraps a lock refusal as ErrMemoryLock.
func memoryLockError(err error) error {
	return fmt.Errorf("%w: %w", ErrMemoryLock, err)
}

func byteCount(n uint64) string {
	const kib, mib, gib = 1 << 10, 1 << 20, 1 << 30
	switch {
	case n >= gib:
		return fmt.Sprintf("%.1f GiB", float64(n)/gib)
	case n >= mib:
		return fmt.Sprintf("%.1f MiB", float64(n)/mib)
	case n >= kib:
		return fmt.Sprintf("%d KiB", n/kib)
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}
