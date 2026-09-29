// Package stackauth is the Go binding of the developer profile: the
// directory `stash auth login` writes (~/.cipherstash, or CS_CONFIG_PATH),
// read through the stack-profile crate running unmodified inside a WASI
// guest under wazero (CGO_ENABLED=0), so the on-disk layout is never
// re-derived by hand in Go.
//
// # Shape
//
// A [ProfileStore] is one guest instance over one mounted directory.
// [Resolve] finds the profile directory the way the Rust crate does
// (CS_CONFIG_PATH, then ~/.cipherstash); [Open] takes one;
// [OpenWithoutProfile] mounts nothing, for the access-key and OIDC
// strategies where there is no profile. The guest is given that directory
// and nothing else: no environment, no other path, and no way out through a
// symlink inside it, which the mount refuses to follow. Authentication HTTP
// requests go through the Go host's transport import. Everything the napi
// binding of stack-profile exposes is a method here, named as in Rust: the
// current workspace ([ProfileStore.CurrentWorkspace],
// [ProfileStore.SetCurrentWorkspace], [ProfileStore.ClearCurrentWorkspace]),
// the workspaces on disk ([ProfileStore.ListWorkspaces]), a store scoped to
// one workspace ([ProfileStore.WorkspaceStore],
// [ProfileStore.CurrentWorkspaceStore]), and the typed reads of the files a
// workspace holds: [ProfileStore.SecretKey] hands out the ZeroKMS client key
// as the opaque [ClientKey] that stackencrypt.NewCredentials takes,
// [ProfileStore.Token] the stored access token, [ProfileStore.DeviceIdentity]
// the identity the CLI created. [ProfileStore.Close] releases the guest;
// stores scoped from it are closed with it.
//
// [ProfileStore.TokenSource] is a token source for stackencrypt over the
// stored token: it re-reads auth.json on every call, so a login or refresh
// by the CLI in another terminal is picked up without a restart, and it
// refuses a token at its real expiry with an error naming `stash auth
// login`. For authentication and refresh, use [ProfileStore.AccessKey],
// [ProfileStore.OIDC], [ProfileStore.DeviceSession], or [ProfileStore.Auto].
// Each returns a [Strategy] that implements stackencrypt.TokenSource.
// [OAuth2TokenSource] adapts an existing golang.org/x/oauth2.TokenSource
// into the OIDC provider interface.
//
// # Why a second guest
//
// The crypto guest behind stackencrypt has no filesystem and no
// environment: a bug or compromise inside it cannot read credentials off
// disk. Mounting the profile into it would trade that away, and it is the
// module that handles plaintext and data keys. So the profile lives in its
// own module with its own, smaller blast radius: one directory of
// credentials. ADR-0005 in packages/stack-encrypt/docs/adr records the
// decision and the alternatives.
//
// # What the guest cannot do
//
// WASI preview 1 has no file locking, so the guest takes none. Go holds the
// same cross-process lock as the Rust CLI, on the path [ProfileStore.LockPath]
// names, across each device-session call. The guest re-reads auth.json after
// the lock and saves a rotated token before Go releases it. Creating a device
// identity is native-only in the crate and
// CLI territory; this package only reads one. Files the guest creates are
// mode 0600, which is wazero's create mode rather than the crate's own
// (skipped on wasm32), so a test pins it.
//
// # Memory
//
// The guest's memory holds the client key and the token while a read is
// in flight. It is supplied the way stackencrypt's is — reserved once so it
// never moves, locked in RAM and excluded from core dumps where the
// platform allows, wiped before release, none of it depending on Close
// running — and [ProfileStore.MemoryLocked] reports whether the lock was
// granted. [RequireLockedMemory] makes a refused lock an error from Open.
package stackauth
