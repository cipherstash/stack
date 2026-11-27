// Command wasmtestrun runs a Rust test binary built for wasm32-wasip1 under
// wazero, the Go module's runtime, as cargo's runner
// (CARGO_TARGET_WASM32_WASIP1_RUNNER). It differs from wazero's own CLI in
// one way: it supplies the auth guest's host module, cipherstash_transport,
// with functions that refuse every call, so a test binary that links the
// auth guest's crate instantiates. The tests drive the guest's step loop
// themselves and never call those functions.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wasmtestrun <test.wasm> [args...]")
		return 2
	}
	ctx := context.Background()
	wasm, err := os.ReadFile(os.Args[1]) //nolint:gosec // the test binary cargo names
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, r)
	_, err = r.NewHostModuleBuilder("cipherstash_transport").
		NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32, uint32) int32 { return 1 }).Export("oidc_token_get").
		Instantiate(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	config := wazero.NewModuleConfig().
		WithArgs(append([]string{os.Args[1]}, os.Args[2:]...)...).
		WithStdout(os.Stdout).WithStderr(os.Stderr).
		WithSysWalltime().WithSysNanotime()
	_, err = r.InstantiateWithConfig(ctx, wasm, config)
	var exit *sys.ExitError
	if errors.As(err, &exit) {
		return int(exit.ExitCode())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
