package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/tetratelabs/wazero/api"
)

// Fuzz tests for the credential guest's ABI: its exports called with
// pointer/length pairs a correct host never passes. The rules are
// internal/guest's (hostile.go). `go test` replays the seeds below and the
// corpus under testdata/fuzz on every run; `mise run go:fuzz` fuzzes.
//
// The exports cover the guest's two input shapes, one pair and two
// (export1 and export2 in its abi.rs), over a parser that touches no file
// (sa_auth_validate_crn), one that reads the profile (sa_has_token), and
// two that build paths (sa_workspace_dir, sa_lock_path). None writes to
// the profile, so a fuzzed path cannot change the mounted directory.

const fuzzCRN = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY"

type fuzzAuthExport struct {
	name   string
	fn     func(*instance) api.Function
	layout guest.Layout
	params []guest.Param
}

func bufParams(values ...string) []guest.Param {
	out := make([]guest.Param, len(values))
	for i, v := range values {
		out[i] = guest.Param{Data: []byte(v), IsBuf: true}
	}
	return out
}

var fuzzAuthExports = []fuzzAuthExport{
	{"sa_auth_validate_crn", func(i *instance) api.Function { return i.authValidateCRN }, "p", bufParams(fuzzCRN)},
	{"sa_has_token", func(i *instance) api.Function { return i.hasToken }, "p", bufParams(guestRoot)},
	{"sa_workspace_dir", func(i *instance) api.Function { return i.workspaceDir }, "pp", bufParams(guestRoot, "ZVATKW3VHMFG27DY")},
	{"sa_lock_path", func(i *instance) api.Function { return i.lockPath }, "pp", bufParams(guestRoot, "auth.json")},
}

func newFuzzStore(tb testing.TB, dir string) *ProfileStore {
	tb.Helper()
	if _, err := embeddedGuest(); err != nil {
		tb.Skip(err)
	}
	store, err := Open(context.Background(), dir)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = store.Close() })
	return store
}

// fuzzAuthCall makes one fuzzed call, then checks the instance still
// parses a CRN.
func fuzzAuthCall(store *ProfileStore, which uint8, in guest.FuzzInput) error {
	ctx := context.Background()
	inst := store.root.inst
	x := fuzzAuthExports[int(which)%len(fuzzAuthExports)]
	if err := guest.FuzzCall(ctx, inst.mem, inst.module, inst.exports, x.fn(inst), x.layout, x.params, in, nil); err != nil {
		return errors.Join(errors.New(x.name), err)
	}
	if _, err := guest.Call(ctx, inst.mem, inst.module, inst.exports, inst.authValidateCRN, guest.BufArg([]byte(fuzzCRN))); err != nil {
		return errors.Join(errors.New(x.name+": the instance did not survive the call"), err)
	}
	return nil
}

// FuzzAuthGuestExportPairs calls an export with one (ptr, len) pair
// replaced: the fuzzed bytes in a buffer of their own, a sub-range of that
// buffer, or a pair outside linear memory.
func FuzzAuthGuestExportPairs(f *testing.F) {
	dir := f.TempDir()
	store := newFuzzStore(f, dir)
	for which := range uint8(len(fuzzAuthExports)) {
		x := fuzzAuthExports[which]
		for slot := range uint8(len(x.params)) {
			data := x.params[slot].Data
			f.Add(which, slot, uint8(guest.PairExact), uint32(0), uint32(0), data)
			f.Add(which, slot, uint8(guest.PairInside), uint32(1), uint32(7), data)
			for kind := range uint32(4) {
				f.Add(which, slot, uint8(guest.PairOutside), kind, uint32(0xFFFF_FFFF), []byte(nil))
			}
		}
		// Paths that leave the mount, and bytes that are not UTF-8.
		f.Add(which, uint8(0), uint8(guest.PairExact), uint32(0), uint32(0), []byte("/profile/../../etc"))
		f.Add(which, uint8(1), uint8(guest.PairExact), uint32(0), uint32(0), []byte{0xff, 0xfe, 0x00})
	}
	f.Fuzz(func(t *testing.T, which, slot, mode uint8, a, b uint32, data []byte) {
		in := guest.FuzzInput{Slot: slot, Mode: mode, A: a, B: b, Data: data}
		if err := fuzzAuthCall(store, which, in); err != nil {
			// A broken instance would fail every input after this one.
			store = newFuzzStore(t, dir)
			t.Fatal(err)
		}
	})
}
