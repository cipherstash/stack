package stackencrypt

import (
	"errors"
	"fmt"
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

// guestMemory is one instance's linear memory, as this package supplies it
// to wazero: the LinearMemory contract plus what the Client reports about
// it. Reallocate is called by wazero under the Client's lock, and Free
// from wherever wazero closes the module (see observed.Free); lockError is
// read from any goroutine.
type guestMemory interface {
	experimental.LinearMemory
	// lockError is nil while every committed byte is locked (and, on Linux,
	// excluded from dumps); otherwise it names what was refused and why.
	// It never clears: a lock refused once is reported for the life of
	// the instance, even if a later growth locks.
	lockError() error
}

// memoryAllocator is the experimental.MemoryAllocator handed to wazero for
// one guest instance. wazero calls Allocate once per memory, and the guest
// has exactly one, so this is where the Client finds the memory it was
// given.
type memoryAllocator struct {
	// strict refuses growth it cannot lock (see Reallocate in each
	// backend) instead of recording the refusal and carrying on.
	strict bool

	mu  sync.Mutex
	mem guestMemory
	// refusals counts strict growths refused. Client.call compares it
	// across a call to name the real cause when the guest reports only a
	// failed allocation.
	refusals uint64
	// inFlight counts guest calls in progress on this memory (see enter and
	// exit); pending records a Free that arrived while one was, to be
	// honoured when the outermost call returns.
	inFlight int
	pending  bool
	// freed is set once the memory is gone, its contents wiped first.
	// Tests read it to observe release paths the caller never sees, such
	// as the cleanup on an unreachable Client.
	freed bool
}

func newMemoryAllocator(strict bool) *memoryAllocator {
	return &memoryAllocator{strict: strict}
}

// Allocate implements experimental.MemoryAllocator.
func (a *memoryAllocator) Allocate(capacity, max uint64) experimental.LinearMemory {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mem != nil {
		// The guest has one memory; a second would mean wazero's contract
		// changed under us. Refusing here fails instantiation loudly
		// rather than letting two memories share one report.
		panic("stackencrypt: guest memory allocated twice")
	}
	a.mem = &observed{guestMemory: reserveMemory(capacity, max, a.strict), owner: a}
	return a.mem
}

// lockError reports the memory's lock state, or nil before the memory
// exists.
func (a *memoryAllocator) lockError() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mem == nil {
		return nil
	}
	return a.mem.lockError()
}

// growthRefusals counts the strict growths refused so far.
func (a *memoryAllocator) growthRefusals() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.refusals
}

func (a *memoryAllocator) isFreed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.freed
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

// freeLocked wipes and releases the memory. Called with mu held, once.
func (a *memoryAllocator) freeLocked() {
	if a.freed {
		return
	}
	a.freed = true
	a.mem.(*observed).guestMemory.Free()
}

// observed wraps the backend memory so the allocator sees the events the
// Client needs to report: a refused strict growth, and the release.
type observed struct {
	guestMemory
	owner *memoryAllocator
}

func (o *observed) Reallocate(size uint64) []byte {
	buf := o.guestMemory.Reallocate(size)
	if buf == nil && o.owner.strict {
		// In strict mode a nil is a lock refusal (a backend refuses no
		// other growth below the maximum); in best-effort mode it is
		// the maximum, which is the guest's own failure to report.
		o.owner.mu.Lock()
		o.owner.refusals++
		o.owner.mu.Unlock()
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
func (o *observed) Free() {
	o.owner.mu.Lock()
	defer o.owner.mu.Unlock()
	if o.owner.inFlight > 0 {
		o.owner.pending = true
		return
	}
	o.owner.freeLocked()
}

// heapMemory backs the guest with an ordinary Go slice, for platforms with
// no reservation primitive this package uses and for a reservation that
// failed (a 4 GiB address-space reservation on a 32-bit host, say). It
// keeps two of the four properties above: growth wipes the slice it
// abandons, and Free wipes before releasing. It cannot lock or exclude
// from dumps, and says so.
type heapMemory struct {
	buf    []byte
	max    uint64
	reason error
}

// newHeapMemory returns a heap-backed memory whose lockError is reason,
// which must not be nil: a heap memory is never locked.
func newHeapMemory(capacity, max uint64, reason error) *heapMemory {
	if capacity > max {
		capacity = max
	}
	if capacity > math.MaxInt {
		capacity = 0
	}
	return &heapMemory{buf: make([]byte, 0, int(capacity)), max: max, reason: reason}
}

func (m *heapMemory) Reallocate(size uint64) []byte {
	if size > m.max {
		return nil
	}
	if size <= uint64(cap(m.buf)) {
		m.buf = m.buf[:size]
		return m.buf
	}
	grown := make([]byte, size)
	copy(grown, m.buf)
	// The abandoned slice held everything the guest had, keys included.
	clear(m.buf[:cap(m.buf)])
	m.buf = grown
	return m.buf
}

func (m *heapMemory) Free() {
	clear(m.buf[:cap(m.buf)])
	m.buf = nil
}

func (m *heapMemory) lockError() error { return m.reason }

// errNoLockSupport is the heap fallback's reason on platforms where this
// package has no lock implementation.
var errNoLockSupport = errors.New("guest memory cannot be locked on this platform")

// memoryLockError wraps a backend's lock refusal as ErrMemoryLock.
func memoryLockError(err error) error {
	return fmt.Errorf("%w: %w", ErrMemoryLock, err)
}

func byteCount(n uint64) string {
	const kib, mib, gib = 1 << 10, 1 << 20, 1 << 30
	switch {
	case n >= gib && n%gib == 0:
		return fmt.Sprintf("%d GiB", n/gib)
	case n >= mib:
		return fmt.Sprintf("%.1f MiB", float64(n)/mib)
	case n >= kib:
		return fmt.Sprintf("%d KiB", n/kib)
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}
