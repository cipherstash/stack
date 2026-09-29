package guest_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cipherstash/cipherstash-suite/bindings/go/internal/guest"
	"github.com/cipherstash/cipherstash-suite/bindings/go/internal/guesttest"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/sys"
)

// The allocator on its own, under the grow probe. What it does for a real
// guest, and what a client reports about it, is tested where the guest is
// embedded (stackencrypt's memory tests).

// The whole point of owning the allocation: growth commits more of one
// reservation, so the buffer's address is the same before and after, and
// the guest's keys are never copied to a new slice.
func TestGuestMemoryDoesNotMoveOnGrowth(t *testing.T) {
	alloc := guest.NewAllocator(guest.BestEffort)
	base, grow, done := guesttest.ProbeMemory(t, alloc)
	defer done()
	if alloc.IsFallback() {
		t.Skipf("heap fallback in use on this host: %v", alloc.LockError())
	}
	t.Logf("lock state on this host: %v", alloc.LockError())
	before := base()
	for _, pages := range []uint32{1, 15, 64} {
		if _, ok := grow(pages); !ok {
			t.Fatalf("grow(%d) refused", pages)
		}
		if after := base(); after != before {
			t.Fatalf("memory moved on grow(%d): %#x -> %#x", pages, before, after)
		}
	}
}

// Free wipes then unmaps: the allocator reports the release, and the
// runtime close is what triggers it.
func TestGuestMemoryIsFreedOnRuntimeClose(t *testing.T) {
	alloc := guest.NewAllocator(guest.BestEffort)
	_, grow, done := guesttest.ProbeMemory(t, alloc)
	if _, ok := grow(3); !ok {
		t.Fatal("grow refused")
	}
	if alloc.IsFreed() {
		t.Fatal("freed before close")
	}
	done()
	if !alloc.IsFreed() {
		t.Fatal("runtime close did not free the guest memory")
	}
}

// The refusal on a growth, from the kernel: with RLIMIT_MEMLOCK at two
// pages the probe's first page locks and a growth by two more cannot.
// Strict refuses the growth and gives the range back, so the page the
// probe holds is still locked and the allocator still says so; the
// refusal is reported on its own, naming the limit.
func TestRequireLockedMemoryRefusesAnUnlockableGrowth(t *testing.T) {
	if !guesttest.HostReserves(t) {
		t.Skip("heap fallback in use on this host: no reservation to lock")
	}
	if !guesttest.InChild(t) {
		return
	}
	const limit = 2 * guesttest.WasmPage
	if err := guesttest.SetMemlockLimit(limit); err != nil {
		t.Fatalf("lowering RLIMIT_MEMLOCK: %v", err)
	}
	alloc := guest.NewAllocator(guest.Strict)
	_, grow, done := guesttest.ProbeMemory(t, alloc)
	defer done()
	if err := alloc.LockError(); err != nil {
		fmt.Printf("case skipped: the first page did not lock under RLIMIT_MEMLOCK=%d: %v\n", limit, err)
		return
	}
	if _, ok := grow(2); ok {
		fmt.Println("case skipped: mlock succeeds past RLIMIT_MEMLOCK")
		return
	}
	if err := alloc.LockError(); err != nil {
		t.Fatalf("a refused growth changed the lock report: %v", err)
	}
	g := alloc.GrowthRefusal()
	if g.Refused != 1 || g.Reason == nil {
		t.Fatalf("GrowthRefusal = %+v; want one, with the refusal", g)
	}
	if !strings.Contains(g.Reason.Error(), "RLIMIT_MEMLOCK") || !strings.Contains(g.Reason.Error(), "needs at least") {
		t.Fatalf("the refusal does not name the limit and the size held: %v", g.Reason)
	}
	fmt.Println("case ok")
}

// A refused growth is the growth's failure, not the memory's: the
// allocator counts it and keeps its reason, and the lock report — nil,
// or whatever this host refused at the start — is exactly what it was.
// Once the growth is let through the report is still unchanged.
func TestRefusedGrowthLeavesTheLockReportAlone(t *testing.T) {
	alloc := guest.NewAllocator(guest.Strict)
	base, grow, done := guesttest.ProbeMemory(t, alloc)
	defer done()
	before := alloc.LockError()
	refusing := guest.RefuseGrowth(alloc, errors.New("refused for the test"))
	at := base()
	if _, ok := grow(1); ok {
		t.Fatal("the refused growth was granted")
	}
	if after := alloc.LockError(); after != before {
		t.Fatalf("the refused growth changed the lock report: %v -> %v", before, after)
	}
	if g := alloc.GrowthRefusal(); g.Refused != 1 || g.Reason != refusing.Reason() {
		t.Fatalf("GrowthRefusal = %+v; want one, with the refusal", g)
	}
	refusing.Allow()
	if _, ok := grow(1); !ok {
		t.Fatal("growth refused once the backend lets it through")
	}
	if after := alloc.LockError(); after != before {
		t.Fatalf("a later growth changed the lock report: %v -> %v", before, after)
	}
	if g := alloc.GrowthRefusal(); g.Refused != 1 {
		t.Fatalf("GrowthRefusal = %+v after a granted growth, want one", g)
	}
	// The heap fallback may copy on growth, and says so; a reservation
	// never does.
	if !alloc.IsFallback() && base() != at {
		t.Fatal("memory moved across the refused growth")
	}
}

// reentrantProbe is a hand-assembled module reproducing the shape of a
// guest's transport import: "run" calls the host function h, then stores
// to memory. h re-enters the guest (as transport_send does through
// se_alloc) with a context that has ended, which is how wazero comes to
// free the module's memory while the guest is suspended in the import:
//
//	(module
//	  (import "env" "h" (func $h))
//	  (memory (export "memory") 1)
//	  (func (export "run") call $h i32.const 0 i32.const 1 i32.store)
//	  (func (export "nop")))
var reentrantProbe = []byte{
	0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type: () -> ()
	0x02, 0x09, 0x01, 0x03, 'e', 'n', 'v', 0x01, 'h', 0x00, 0x00, // import env.h
	0x03, 0x03, 0x02, 0x00, 0x00, // two functions of type 0
	0x05, 0x03, 0x01, 0x00, 0x01, // memory: min 1, no max
	0x07, 0x16, 0x03,
	0x06, 'm', 'e', 'm', 'o', 'r', 'y', 0x02, 0x00,
	0x03, 'r', 'u', 'n', 0x00, 0x01,
	0x03, 'n', 'o', 'p', 0x00, 0x02,
	0x0a, 0x10, 0x02,
	0x0b, 0x00, 0x10, 0x00, 0x41, 0x00, 0x41, 0x01, 0x36, 0x02, 0x00, 0x0b, // run
	0x02, 0x00, 0x0b, // nop
}

// The sequence that crashed in CI: a call's context ends during a host
// import, the import re-enters the guest, and wazero frees the memory in
// that nested call while the outer guest frame is still live and about to
// store. The memory must survive until the outer call has returned; an
// unmapped store here is a fault in compiled code that takes the process
// down, so this test cannot fail gently.
func TestMemoryOutlivesACallClosedDuringAHostImport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	alloc := guest.NewAllocator(guest.BestEffort)
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	defer rt.Close(context.Background())
	var freedDuringImport, nestedFailed bool
	_, err := rt.NewHostModuleBuilder("env").NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module) {
			cancel()
			_, nested := m.ExportedFunction("nop").Call(ctx)
			nestedFailed = nested != nil
			freedDuringImport = alloc.IsFreed()
		}).Export("h").Instantiate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mod, err := rt.InstantiateWithConfig(experimental.WithMemoryAllocator(ctx, alloc), reentrantProbe, wazero.NewModuleConfig())
	if err != nil {
		t.Fatalf("instantiating reentrant probe: %v", err)
	}
	alloc.Enter()
	_, err = mod.ExportedFunction("run").Call(ctx)
	alloc.Exit()
	var exit *sys.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != sys.ExitCodeContextCanceled {
		t.Fatalf("run: %v, want the cancellation exit", err)
	}
	if !nestedFailed {
		t.Fatal("the nested call did not see the closed module")
	}
	if freedDuringImport {
		t.Fatal("memory freed while the guest was suspended in a host import")
	}
	if !alloc.IsFreed() {
		t.Fatal("memory not freed once the outer call returned")
	}
}

// The status table decodes to the shared sentinels, and an unknown code
// is an internal failure that keeps the number.
func TestStatusDecodesToTheSharedSentinels(t *testing.T) {
	want := map[uint32]error{
		guest.StatusAuth:                      guest.ErrAuthentication,
		guest.StatusEncoding:                  guest.ErrEncoding,
		guest.StatusState:                     guest.ErrState,
		guest.StatusInternal:                  guest.ErrInternal,
		guest.StatusKMSUnauthorized:           guest.ErrUnauthorized,
		guest.StatusKMSForbidden:              guest.ErrForbidden,
		guest.StatusKMSNotFound:               guest.ErrNotFound,
		guest.StatusKMSConflict:               guest.ErrConflict,
		guest.StatusKMSTransport:              guest.ErrTransport,
		guest.StatusKMSOther:                  guest.ErrKMS,
		guest.StatusTerm:                      guest.ErrTerm,
		guest.StatusForeignKeyset:             guest.ErrForeignKeyset,
		guest.StatusProfileIO:                 guest.ErrProfileIO,
		guest.StatusProfileJSON:               guest.ErrProfileJSON,
		guest.StatusProfileNotFound:           guest.ErrProfileNotFound,
		guest.StatusProfileInvalidFilename:    guest.ErrInvalidFilename,
		guest.StatusProfileNoCurrentWorkspace: guest.ErrNoCurrentWorkspace,
		guest.StatusProfileInvalidWorkspaceID: guest.ErrInvalidWorkspaceID,
		guest.StatusProfileWorkspaceNotFound:  guest.ErrWorkspaceNotFound,
		guest.StatusAuthInvalidGrant:          guest.ErrAuthInvalidGrant,
		guest.StatusAuthInvalidClient:         guest.ErrAuthInvalidClient,
		guest.StatusAuthUsageLimit:            guest.ErrAuthUsageLimit,
		guest.StatusAuthNotAuthenticated:      guest.ErrAuthNotAuthenticated,
		guest.StatusAuthTransport:             guest.ErrAuthTransport,
		guest.StatusAuthConfig:                guest.ErrAuthConfig,
		guest.StatusAuthOther:                 guest.ErrAuthOther,
		guest.StatusAuthRefreshRequired:       guest.ErrAuthRefreshRequired,
	}
	for code, sentinel := range want {
		if got := guest.StatusError(code); got != sentinel {
			t.Errorf("status %d decoded to %v, want %v", code, got, sentinel)
		}
	}
	unknown := guest.StatusError(99)
	if !errors.Is(unknown, guest.ErrInternal) || !strings.Contains(unknown.Error(), "99") {
		t.Errorf("an unknown status decoded to %v; want ErrInternal naming the code", unknown)
	}
	if _, _, err := guest.PackedResult(uint64(guest.StatusEncoding)); err != guest.ErrEncoding {
		t.Errorf("a packed status decoded to %v, want ErrEncoding", err)
	}
	if ptr, n, err := guest.PackedResult(uint64(0x1234)<<32 | 7); err != nil || ptr != 0x1234 || n != 7 {
		t.Errorf("a packed buffer decoded to (%#x, %d, %v)", ptr, n, err)
	}
}

// The client key never prints its bytes — as a pointer, as a value, or
// inside a struct held either way, under any verb — and is empty once
// wiped.
func TestClientKeyIsOpaqueAndWipes(t *testing.T) {
	material := []byte("key material that must not print")
	key := guest.NewClientKey(material)
	type holder struct {
		ByPointer *guest.ClientKey
		ByValue   guest.ClientKey
	}
	subjects := map[string]any{
		"pointer":           key,
		"value":             *key,
		"struct":            holder{ByPointer: key, ByValue: *key},
		"pointer to struct": &holder{ByPointer: key, ByValue: *key},
	}
	// %d and %x reach a struct's fields without asking a Stringer; only a
	// Formatter answers for them.
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		for name, subject := range subjects {
			out := fmt.Sprintf(verb, subject)
			if strings.Contains(out, "material") || strings.Contains(out, "6d6174657269616c") || strings.Contains(out, "109 97 116") {
				t.Errorf("%s of the %s printed the key: %q", verb, name, out)
			}
		}
	}
	if fmt.Sprint(key) != "ClientKey(***)" || key.String() != "ClientKey(***)" || key.GoString() != "ClientKey(***)" {
		t.Errorf("the redaction is not the documented one: %s", key)
	}
	if string(guest.KeyBytes(key)) != "key material that must not print" {
		t.Fatal("KeyBytes did not return the material")
	}
	key.Wipe()
	if !key.IsZero() || guest.KeyBytes(key) != nil {
		t.Fatal("a wiped key still holds material")
	}
	for _, b := range material {
		if b != 0 {
			t.Fatal("the caller's slice was not wiped")
		}
	}
	key.Wipe() // a second wipe is a no-op
	var none *guest.ClientKey
	if !none.IsZero() || guest.KeyBytes(none) != nil {
		t.Fatal("a nil key is not the empty key")
	}
	if out := fmt.Sprint(none); out != "<nil>" && out != "ClientKey(***)" {
		t.Fatalf("a nil key printed %q", out)
	}
}
