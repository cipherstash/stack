package encrypt

import (
	"context"
	"crypto/sha256"
	goruntime "runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/experimental"
)

// engineIdle is how long the compiled engine is kept after the last client
// or checker over it closes. One minute is far longer than the gap between
// clients in a program that opens and closes them one after another, such
// as a job that makes a client per task, so that program compiles once. It
// is short enough that a program that stops using clients gets the memory
// back soon. A program that opens a client just after each free compiles
// for about a second once a minute at most.
const engineIdle = time.Minute

// ReleaseEngine frees the compiled engine now, rather than when it has been
// idle for a minute.
//
// The first [NewClient] or [NewChecker] in a process compiles the engine,
// a WebAssembly module, to machine code. That takes about a second. The
// compiled engine is shared: every later client and checker reuses it
// and skips that second. It is kept while any client or checker is open, and
// for one minute after the last one closes, so a program that opens and
// closes clients one after another compiles the engine once. After that
// minute it is freed, and the next client compiles it again.
//
// ReleaseEngine is for a program that knows it has finished with clients
// and wants the memory back at once. It is safe to call more than once,
// and from any goroutine. It never breaks an open client or checker: each
// one goes on working, and the compiled engine is freed when the last of
// them closes. A client opened after ReleaseEngine compiles the engine
// again, unless a client opened before is still open, in which case it
// starts from the compiled engine that client is using.
func ReleaseEngine() { engines.releaseAll() }

// engines is the process's compiled engines, one for each build of the
// guest a client or checker has run.
var engines = &engineCache{idle: engineIdle}

// engineCache keeps each guest build compiled in the shared compilation
// cache while any instance over it is open, and for idle after the last
// one closes.
//
// wazero counts the users of a compiled module in its in-memory cache, and
// deletes the module when the count reaches zero. Each instance's runtime
// is one user while it is open. So when every client has closed, the next
// client would compile the guest again. engineCache adds one user of its
// own: a module compiled on a runtime it keeps, which it closes once the
// build has been idle for idle, or at once on releaseAll. That module is
// never instantiated: every instance still has its own runtime, and reads
// the compiled code from the cache.
type engineCache struct {
	// compileMu makes callers given a build that is not compiled wait for
	// one compile, rather than each compiling it.
	compileMu sync.Mutex

	mu     sync.Mutex
	builds map[[sha256.Size]byte]*sharedEngine
	idle   time.Duration
	// afterFunc runs f once d has passed. Nil is time.AfterFunc; tests
	// replace it to fire the timer themselves.
	afterFunc func(d time.Duration, f func()) stopper
	// compile compiles wasm into the shared cache and returns what frees
	// it. Nil is compileShared; tests replace it to count compiles.
	compile func(ctx context.Context, wasm []byte) (free func(), err error)
}

// stopper is the part of *time.Timer that engineCache uses.
type stopper interface{ Stop() bool }

// sharedEngine is one compiled build and the instances open over it.
type sharedEngine struct {
	key  [sha256.Size]byte
	free func()
	open int
	// idle is the timer that frees the build, while no instance is open.
	idle stopper
	// armed counts the idle timers started, so that a timer that fires
	// after a later acquire has stopped it does nothing.
	armed int
}

// engineLease is one instance's use of a compiled build. A nil lease is
// valid, and its release does nothing.
type engineLease struct {
	cache    *engineCache
	engine   *sharedEngine
	released atomic.Bool
}

// acquire keeps the compiled form of wasm in the shared cache until the
// lease is released, compiling it first if no open instance or idle timer
// keeps it. A compile that fails gives a nil lease: the instance that asked
// then compiles wasm itself, and reports the failure as it always has.
func (c *engineCache) acquire(ctx context.Context, wasm []byte) *engineLease {
	key := sha256.Sum256(wasm)
	if l := c.lease(key); l != nil {
		return l
	}
	c.compileMu.Lock()
	defer c.compileMu.Unlock()
	if l := c.lease(key); l != nil {
		return l
	}
	compile := c.compile
	if compile == nil {
		compile = compileShared
	}
	free, err := compile(ctx, wasm)
	if err != nil {
		return nil
	}
	e := &sharedEngine{key: key, free: free, open: 1}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.builds == nil {
		c.builds = map[[sha256.Size]byte]*sharedEngine{}
	}
	c.builds[key] = e
	return &engineLease{cache: c, engine: e}
}

// lease is a lease on the build with key, if it is compiled.
func (c *engineCache) lease(key [sha256.Size]byte) *engineLease {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.builds[key]
	if !ok {
		return nil
	}
	e.open++
	if e.idle != nil {
		e.idle.Stop()
		e.idle = nil
	}
	return &engineLease{cache: c, engine: e}
}

// release ends the lease. When it was the last open one on its build, the
// build is freed once it has been idle for the cache's idle period. A
// second release does nothing.
func (l *engineLease) release() {
	if l == nil || !l.released.CompareAndSwap(false, true) {
		return
	}
	c, e := l.cache, l.engine
	c.mu.Lock()
	defer c.mu.Unlock()
	e.open--
	// A build releaseAll has already dropped is freed: its lease has
	// nothing left to keep.
	if e.open > 0 || c.builds[e.key] != e {
		return
	}
	e.armed++
	armed := e.armed
	afterFunc := c.afterFunc
	if afterFunc == nil {
		afterFunc = func(d time.Duration, f func()) stopper { return time.AfterFunc(d, f) }
	}
	e.idle = afterFunc(c.idle, func() { c.expire(e, armed) })
}

// expire frees e, if no instance has opened over it since the timer armed
// was started.
func (c *engineCache) expire(e *sharedEngine, armed int) {
	c.mu.Lock()
	if c.builds[e.key] != e || e.open > 0 || e.armed != armed {
		c.mu.Unlock()
		return
	}
	delete(c.builds, e.key)
	e.idle = nil
	c.mu.Unlock()
	e.free()
}

// releaseAll frees every compiled build now. An instance still open over
// one keeps its compiled code, through its own runtime, until it closes.
func (c *engineCache) releaseAll() {
	c.mu.Lock()
	dropped := make([]*sharedEngine, 0, len(c.builds))
	for key, e := range c.builds {
		if e.idle != nil {
			e.idle.Stop()
			e.idle = nil
		}
		delete(c.builds, key)
		dropped = append(dropped, e)
	}
	c.mu.Unlock()
	for _, e := range dropped {
		e.free()
	}
}

// compileShared compiles wasm into the shared compilation cache, on a
// runtime of its own with guestRuntimeConfig, the configuration
// newInstance uses, so the module has the cache entry an instance looks
// up. It compiles the guest's functions on every core: the compiled code
// is the same, and under the race detector the compile takes about ten
// seconds on one core. free closes the module and the runtime, which ends
// this runtime's use of the cache entry.
func compileShared(ctx context.Context, wasm []byte) (free func(), err error) {
	runtime := wazero.NewRuntimeWithConfig(ctx, guestRuntimeConfig())
	compiled, err := runtime.CompileModule(experimental.WithCompilationWorkers(ctx, goruntime.GOMAXPROCS(0)), wasm)
	if err != nil {
		_ = runtime.Close(ctx)
		return nil, err
	}
	return func() {
		// Neither close can fail here. A compiled module's Close always
		// returns nil, and the runtime has no module instantiated in it,
		// which is the only thing its Close reports on. Close takes the
		// background context because the caller's may have ended by now.
		_ = compiled.Close(context.Background())
		_ = runtime.Close(context.Background())
	}, nil
}
