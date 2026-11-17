package encrypttest

import (
	"context"
	"crypto/sha256"
	"embed"
	"fmt"
	"runtime/debug"
	"sync"
	"testing"

	"github.com/cipherstash/stack/languages/golang/encrypt"
	"github.com/cipherstash/stack/languages/golang/encrypt/internal/testclient"
)

// The deterministic-kms test builds of the guest, copied here by `mise run
// wasm:guest:build:deterministic` and `mise run
// wasm:guest:build:eql:deterministic`. They are not committed on main; the
// release workflow commits them on the tag. The directory is embedded so the
// package compiles without them; NewClient reports their absence.
//
//go:embed wasm
var guestFS embed.FS

const (
	guestPath    = "wasm/stack_encrypt_guest_deterministic.wasm"
	eqlGuestPath = "wasm/stack_encrypt_guest_eql_deterministic.wasm"
)

// defaultSeed is the seed NewClient uses without WithSeed. It never
// changes, so values sealed under it in one test process open in another.
var defaultSeed = sha256.Sum256([]byte("github.com/cipherstash/stack/languages/golang/encrypt/encrypttest default seed"))

// A ClientOption configures [NewClient].
type ClientOption func(*clientOptions)

type clientOptions struct {
	seed [32]byte
}

// WithSeed derives every data key from seed in place of the default seed.
// A value sealed under one seed does not open under another, and fails with
// [encrypt.ErrForbidden].
//
// A seed does not keep one test's rows apart from another's in a shared
// table. Search terms depend on the keyset alone, so a query under one seed
// matches rows another seed wrote under the same keyset. Give each test its
// own keyset name for that: every name is a separate keyset.
func WithSeed(seed [32]byte) ClientOption {
	return func(o *clientOptions) { o.seed = seed }
}

// NewClient returns a client for a test that needs no network and no
// CipherStash credentials. It closes the client when the test and its
// subtests finish. It fails the test, and never skips it, when the client
// cannot start.
//
//	func TestSaveUser(t *testing.T) {
//		client := encrypttest.NewClient(t)
//		cipher := client.Keyset(encrypt.KeysetName("tenant-a"))
//
//		rows, err := users.Encrypt(t.Context(), cipher, []users.User{{Email: "ada@example.com"}})
//		if err != nil {
//			t.Fatal(err)
//		}
//		// Store rows in PostgreSQL, query them, then read them back:
//		back, err := users.Decrypt(t.Context(), client, rows)
//	}
//
// The client runs the same engine and generated code as a production
// client. Only the key source differs: each data key derives from a seed and
// from the context the value is sealed under, so the client never calls
// ZeroKMS. An EQL column accepts the values it writes, and its query terms
// match them.
//
// It fails as a production client fails:
//
//   - A cipher bound to one keyset refuses a value sealed under another
//     keyset with [encrypt.ErrForeignKeyset].
//   - A decrypt under a context other than the value's fails with
//     [encrypt.ErrForbidden], as ZeroKMS refuses it.
//   - A row whose context field is not the cipher's context fails with
//     [encrypt.ErrContextMismatch].
//
// Every keyset exists. A keyset selected by a name or an id needs nothing
// created first, and [encrypt.KeysetName]("default") selects the default
// keyset. So a test cannot see [encrypt.ErrNotFound] for a missing keyset,
// or [encrypt.ErrForbidden] for a keyset the client has no grant for. The
// client has no token, so it never returns [encrypt.ErrUnauthorized].
//
// # Seeds
//
// Every client with the default seed opens what any other client with it
// sealed, in any process. So a test that loads fixtures and a test that
// reads them share keys with no setup. The default seed never changes.
// [WithSeed] chooses another. A seed changes the data keys only: search
// terms depend on the keyset alone, so two seeds give a value the same
// terms. To keep tests apart in a shared table, give each its own keyset
// name.
//
// # Not for production
//
// The keys are not secret: anyone with the seed derives every key, and the
// default seed is in this package's source. Never seal real data with this
// client. Nothing it seals opens under a production client, and nothing a
// production client seals opens under it.
//
// Import this package only from _test.go files. Go then links the test
// builds of the engine it embeds into test binaries only. NewClient also
// fails the test outside a test binary, as [testing.Testing] reports.
//
// # Versions
//
// This package is its own module, so a program that never imports it never
// downloads the test builds:
//
//	go get github.com/cipherstash/stack/languages/golang/encrypt/encrypttest@v0.1.0
//
// Require it at the same version as
// github.com/cipherstash/stack/languages/golang. Its test builds match the
// engine host code of that version only, so NewClient, [Contexts] and
// [AssertContexts] fail when the two versions differ. A difference large
// enough to change the SDK's internal packages, which this one imports, fails
// earlier: the test does not compile, with an error that names an internal
// package of the SDK. The fix is the same: require both at one version.
//
// Only a tagged version of this module can be fetched. Between releases its
// go.mod requires the SDK at a placeholder version, replaced by the
// directory in a checkout of the repository; the release commit names the
// version it tags.
//
// # Engine builds
//
// A program whose generated code names an EQL type links package
// [github.com/cipherstash/stack/languages/golang/encrypt/eql]. A production
// client in that program runs the engine build with the EQL types, and a
// client from NewClient runs the test build with them. Otherwise both run
// the build without them.
func NewClient(tb testing.TB, opts ...ClientOption) *encrypt.Client {
	tb.Helper()
	if !testing.Testing() {
		tb.Fatal("encrypttest: NewClient runs only in a test binary, because its keys are not secret")
	}
	if err := versionSkew(); err != nil {
		tb.Fatal(err)
	}
	o := clientOptions{seed: defaultSeed}
	for _, opt := range opts {
		opt(&o)
	}
	built, err := testclient.New(context.Background(), plainTestBuild, eqlTestBuild, o.seed)
	if err != nil {
		tb.Fatalf("encrypttest: %v", err)
	}
	client, ok := built.(*encrypt.Client)
	if !ok {
		if closer, ok := built.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
		tb.Fatalf("encrypttest: the constructor returned %T, not *encrypt.Client", built)
	}
	tb.Cleanup(func() {
		if err := client.Close(); err != nil {
			tb.Errorf("encrypttest: closing the client: %v", err)
		}
	})
	return client
}

const (
	sdkModule  = "github.com/cipherstash/stack/languages/golang"
	thisModule = sdkModule + "/encrypt/encrypttest"
)

// versionSkew is sameVersion over this program's build info, or nil when
// the program carries none.
func versionSkew() error {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	return sameVersion(info)
}

// sameVersion refuses a build in which this module and the SDK module are
// at different versions. A version it cannot know, such as a module
// replaced by a local directory or one built from a checkout, is not
// compared.
func sameVersion(info *debug.BuildInfo) error {
	versions := map[string]string{}
	record := func(m *debug.Module) {
		if m != nil && m.Replace == nil && m.Version != "" && m.Version != "(devel)" {
			versions[m.Path] = m.Version
		}
	}
	record(&info.Main)
	for _, dep := range info.Deps {
		record(dep)
	}
	sdk, okSDK := versions[sdkModule]
	this, okThis := versions[thisModule]
	if okSDK && okThis && sdk != this {
		return fmt.Errorf("encrypttest: this module is at %s and %s is at %s; require both at the same version, for example `go get %s@%s`", this, sdkModule, sdk, thisModule, sdk)
	}
	return nil
}

// The test builds, each read once: embed.FS copies a file on every read,
// and a suite may call NewClient in every test. Package encrypt picks
// between them by the rule it picks its production build by.
var (
	plainTestBuild = sync.OnceValues(func() ([]byte, error) {
		return readTestBuild(guestPath, "wasm:guest:build:deterministic")
	})
	eqlTestBuild = sync.OnceValues(func() ([]byte, error) {
		return readTestBuild(eqlGuestPath, "wasm:guest:build:eql:deterministic")
	})
)

func readTestBuild(path, task string) ([]byte, error) {
	wasm, err := guestFS.ReadFile(path)
	if err != nil {
		return nil, notBuiltError{task: task}
	}
	return wasm, nil
}

// notBuiltError is a test build missing from the module. A released module
// carries both; a checkout of the repository needs the build task run.
type notBuiltError struct{ task string }

func (e notBuiltError) Error() string {
	return "the test build of the engine is not in this module; in a checkout of the repository, run `mise run " + e.task + "`"
}
