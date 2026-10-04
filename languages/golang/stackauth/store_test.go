package stackauth

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cipherstash/stack/languages/golang/internal/guest"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const (
	wsA = "AAAAAAAAAAAAAAAA"
	wsB = "BBBBBBBBBBBBBBBB"

	secretKeyJSON = `{"client_id":"6a70bd18-99ac-4650-b104-37eec3a15b09","client_key":"AAECAwQFBgc="}`
	deviceJSON    = `{"device_instance_id":"0f4a4fd7-4a1a-4c5e-9d3e-7a4c8e3a9c11","device_name":"laptop"}`
)

func authJSON(expiresAt int64) string {
	return fmt.Sprintf(`{"access_token":"tok-%d","refresh_token":"refresh","token_type":"Bearer","expires_at":%d,"region":"ap-southeast-2"}`, expiresAt, expiresAt)
}

// guestOrSkip is the embedded guest, or a skip where it is not built.
func guestOrSkip(t *testing.T) []byte {
	t.Helper()
	wasm, err := embeddedGuest()
	if err != nil {
		t.Skip(err)
	}
	return wasm
}

// profile is a fresh profile directory with two workspaces and the files a
// login writes into the first, opened as a store.
func profile(t *testing.T) (dir string, s *ProfileStore) {
	t.Helper()
	guestOrSkip(t)
	dir = t.TempDir()
	for _, ws := range []string{wsA, wsB} {
		if err := os.MkdirAll(filepath.Join(dir, "workspaces", ws), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(dir, "workspaces", wsA, "secretkey.json"), secretKeyJSON)
	write(t, filepath.Join(dir, "workspaces", wsA, "auth.json"), authJSON(time.Now().Add(time.Hour).Unix()))
	write(t, filepath.Join(dir, "device.json"), deviceJSON)
	s, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return dir, s
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The guest may reach the profile mount and the two named auth host imports.
func TestImportSurfaceIsWASIAndAuthTransport(t *testing.T) {
	ctx := context.Background()
	r := wazero.NewRuntime(ctx)
	defer r.Close(ctx)
	compiled, err := r.CompileModule(ctx, guestOrSkip(t))
	if err != nil {
		t.Fatal(err)
	}
	defer compiled.Close(ctx)
	sawPathOpen := false
	sawTransport := false
	sawOIDC := false
	for _, imp := range compiled.ImportedFunctions() {
		module, name, _ := imp.Import()
		if module == "cipherstash_transport" {
			switch name {
			case "transport_send":
				sawTransport = true
			case "oidc_token_get":
				sawOIDC = true
			default:
				t.Errorf("unexpected auth host import %s", name)
			}
			continue
		}
		if module != "wasi_snapshot_preview1" {
			t.Errorf("guest imports %s::%s, outside the allowed surface", module, name)
			continue
		}
		if strings.HasPrefix(name, "sock_") {
			t.Errorf("guest imports socket function %s", name)
		}
		if name == "path_open" {
			sawPathOpen = true
		}
	}
	if !sawPathOpen {
		t.Error("guest does not import path_open; it cannot be reading a profile")
	}
	if !sawTransport || !sawOIDC {
		t.Errorf("missing auth imports: transport=%t oidc=%t", sawTransport, sawOIDC)
	}
	for _, name := range []string{"se_alloc", "se_dealloc", "sa_shutdown", "sa_current_workspace", "sa_set_current_workspace", "sa_clear_current_workspace", "sa_list_workspaces", "sa_workspace_dir", "sa_lock_path", "sa_secret_key", "sa_token", "sa_has_token", "sa_device_identity", "sa_auth_new", "sa_auth_validate_crn", "sa_auth_token", "sa_auth_refresh", "sa_auth_free"} {
		if _, ok := compiled.ExportedFunctions()[name]; !ok {
			t.Errorf("guest does not export %s", name)
		}
	}
}

func TestOpenRequiresAnExistingDirectory(t *testing.T) {
	guestOrSkip(t)
	ctx := context.Background()
	if _, err := Open(ctx, filepath.Join(t.TempDir(), "missing")); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("Open of a missing directory: %v, want ErrNoProfile", err)
	}
	file := filepath.Join(t.TempDir(), "file")
	write(t, file, "")
	if _, err := Open(ctx, file); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("Open of a file: %v, want ErrNoProfile", err)
	}
}

// Resolve finds the directory the Rust crate would: CS_CONFIG_PATH first.
func TestResolveHonoursConfigPath(t *testing.T) {
	dir, _ := profile(t)
	t.Setenv("CS_CONFIG_PATH", dir)
	s, err := Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Dir() != dir {
		t.Fatalf("Dir = %q, want %q", s.Dir(), dir)
	}
	t.Setenv("CS_CONFIG_PATH", "  ")
	// os.UserHomeDir reads HOME on Unix and USERPROFILE on Windows.
	nohome := filepath.Join(t.TempDir(), "nohome")
	t.Setenv("HOME", nohome)
	t.Setenv("USERPROFILE", nohome)
	if _, err := Resolve(context.Background()); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("Resolve with a blank CS_CONFIG_PATH and no ~/.cipherstash: %v, want ErrNoProfile", err)
	}
	// A non-blank value is used as it is, as the crate uses it: a directory
	// whose name carries whitespace is the directory it names. (Windows
	// trims a trailing space off a directory name itself.)
	if runtime.GOOS != "windows" {
		spaced := filepath.Join(t.TempDir(), " spaced ")
		if err := os.Mkdir(spaced, 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("CS_CONFIG_PATH", spaced)
		s, err := Resolve(context.Background())
		if err != nil {
			t.Fatalf("Resolve with CS_CONFIG_PATH naming a directory with spaces in its name: %v", err)
		}
		defer s.Close()
		if s.Dir() != spaced {
			t.Fatalf("Dir = %q, want the value verbatim, %q", s.Dir(), spaced)
		}
	}
}

func TestWorkspaceSelectionRoundTripsAndLists(t *testing.T) {
	ctx := context.Background()
	_, s := profile(t)
	if _, err := s.CurrentWorkspace(ctx); !errors.Is(err, ErrNoCurrentWorkspace) {
		t.Fatalf("no workspace set: %v, want ErrNoCurrentWorkspace", err)
	}
	if _, err := s.CurrentWorkspaceStore(ctx); !errors.Is(err, ErrNoCurrentWorkspace) {
		t.Fatalf("no workspace set: %v, want ErrNoCurrentWorkspace", err)
	}
	if err := s.SetCurrentWorkspace(ctx, "CCCCCCCCCCCCCCCC"); !errors.Is(err, ErrWorkspaceNotFound) {
		t.Fatalf("setting a workspace with no directory: %v, want ErrWorkspaceNotFound", err)
	}
	if err := s.SetCurrentWorkspace(ctx, "../escape"); !errors.Is(err, ErrInvalidWorkspaceID) {
		t.Fatalf("setting a path as the workspace: %v, want ErrInvalidWorkspaceID", err)
	}
	if err := s.SetCurrentWorkspace(ctx, wsA); err != nil {
		t.Fatal(err)
	}
	if got, err := s.CurrentWorkspace(ctx); err != nil || got != wsA {
		t.Fatalf("CurrentWorkspace = %q, %v; want %q", got, err, wsA)
	}
	ids, err := s.ListWorkspaces(ctx)
	if err != nil || !reflect.DeepEqual(ids, []string{wsA, wsB}) {
		t.Fatalf("ListWorkspaces = %v, %v; want [%s %s]", ids, err, wsA, wsB)
	}
	if err := s.ClearCurrentWorkspace(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CurrentWorkspace(ctx); !errors.Is(err, ErrNoCurrentWorkspace) {
		t.Fatalf("after clearing: %v, want ErrNoCurrentWorkspace", err)
	}
	if err := s.ClearCurrentWorkspace(ctx); err != nil {
		t.Fatalf("clearing twice: %v", err)
	}
}

func TestWorkspaceStoresAreScopedAndShareTheGuest(t *testing.T) {
	ctx := context.Background()
	dir, s := profile(t)
	ws, err := s.WorkspaceStore(ctx, wsA)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "workspaces", wsA); ws.Dir() != want {
		t.Fatalf("workspace Dir = %q, want %q", ws.Dir(), want)
	}
	if s.Dir() != dir {
		t.Fatalf("root Dir = %q, want %q", s.Dir(), dir)
	}
	if _, err := s.WorkspaceStore(ctx, "not-an-id"); !errors.Is(err, ErrInvalidWorkspaceID) {
		t.Fatalf("WorkspaceStore of a bad id: %v, want ErrInvalidWorkspaceID", err)
	}
	// The root holds no secret key; the workspace does.
	if _, _, err := s.SecretKey(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SecretKey at the root: %v, want ErrNotFound", err)
	}
	if err := s.SetCurrentWorkspace(ctx, wsA); err != nil {
		t.Fatal(err)
	}
	current, err := s.CurrentWorkspaceStore(ctx)
	if err != nil || current.Dir() != ws.Dir() {
		t.Fatalf("CurrentWorkspaceStore = %v, %v; want %s", current, err, ws.Dir())
	}
	// One guest: closing the workspace store closes the profile.
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CurrentWorkspace(ctx); !errors.Is(err, ErrState) {
		t.Fatalf("after Close: %v, want ErrState", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("a second Close: %v", err)
	}
}

func TestTypedReadsReturnTheFilesFields(t *testing.T) {
	ctx := context.Background()
	dir, s := profile(t)
	ws, err := s.WorkspaceStore(ctx, wsA)
	if err != nil {
		t.Fatal(err)
	}

	clientID, key, err := ws.SecretKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if clientID != "6a70bd18-99ac-4650-b104-37eec3a15b09" {
		t.Errorf("client id = %q", clientID)
	}
	if string(guest.KeyBytes(key)) != "AAECAwQFBgc=" {
		t.Errorf("client key material = %q, want the file's base64", guest.KeyBytes(key))
	}
	if out := fmt.Sprintf("%v %+v %#v %s", key, key, key, key); strings.Contains(out, "AAECAw") {
		t.Errorf("the key prints its material: %q", out)
	}
	key.Wipe()

	tok, err := ws.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The access token is a credential; a failure names what was wrong
	// with it rather than printing it.
	if !strings.HasPrefix(tok.AccessToken, "tok-") || tok.TokenType != "Bearer" || tok.Region != "ap-southeast-2" {
		t.Errorf("Token: access token has the stub's prefix = %t, type = %q, region = %q",
			strings.HasPrefix(tok.AccessToken, "tok-"), tok.TokenType, tok.Region)
	}
	if !tok.Usable(time.Now()) || tok.ExpiresAt.Before(time.Now().Add(50*time.Minute)) {
		t.Errorf("ExpiresAt = %s, want about an hour away", tok.ExpiresAt)
	}
	if tok.ClientID != "" || tok.DeviceInstanceID != "" {
		t.Errorf("absent optional fields decoded as client_id = %q, device_instance_id = %q", tok.ClientID, tok.DeviceInstanceID)
	}

	identity, err := s.DeviceIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if identity != (DeviceIdentity{DeviceInstanceID: "0f4a4fd7-4a1a-4c5e-9d3e-7a4c8e3a9c11", DeviceName: "laptop"}) {
		t.Errorf("DeviceIdentity = %+v", identity)
	}

	// The other workspace has nothing: not found, not a trap.
	other, err := s.WorkspaceStore(ctx, wsB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Token(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Token of an empty workspace: %v, want ErrNotFound", err)
	}
	// A malformed file is ErrInvalid.
	write(t, filepath.Join(dir, "workspaces", wsB, "auth.json"), "{not json")
	if _, err := other.Token(ctx); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Token from a malformed file: %v, want ErrInvalid", err)
	}
}

// expires_at is a u64 in the crate's file; one past int64 would wrap to a
// time in the past, so it is refused rather than read as expired.
func TestTokenExpiresAtOutOfRangeIsInternal(t *testing.T) {
	ctx := context.Background()
	dir, s := profile(t)
	write(t, filepath.Join(dir, "workspaces", wsA, "auth.json"),
		fmt.Sprintf(`{"access_token":"tok","refresh_token":"refresh","token_type":"Bearer","expires_at":%d}`, uint64(math.MaxInt64)+1))
	ws, err := s.WorkspaceStore(ctx, wsA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ws.Token(ctx); !errors.Is(err, ErrInternal) {
		t.Fatalf("Token: %v, want ErrInternal", err)
	}
}

// The lock file is the crate's sibling `.<filename>.lock`, named by the
// guest and mapped back to the host, never composed here; a filename that
// is a path is refused before any path is built.
func TestLockPathIsTheCratesAndValidated(t *testing.T) {
	ctx := context.Background()
	dir, s := profile(t)
	ws, err := s.WorkspaceStore(ctx, wsA)
	if err != nil {
		t.Fatal(err)
	}
	path, err := ws.LockPath(ctx, "auth.json")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "workspaces", wsA, ".auth.json.lock"); path != want {
		t.Fatalf("LockPath = %q, want %q", path, want)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("naming the lock file created it: %v", err)
	}
	// The host's separator is refused as well as the guest's: on Windows a
	// backslash passes the crate's check (its separator is `/` on wasm32)
	// and would become a path once mapped back to the host.
	for _, bad := range []string{"", ".", "..", "../auth.json", "/etc/auth.json", "a/b", `a\b`, `x\..\..\outside`} {
		if _, err := ws.LockPath(ctx, bad); !errors.Is(err, ErrInvalidFilename) {
			t.Errorf("LockPath(%q) = %v, want ErrInvalidFilename", bad, err)
		}
	}
}

// Two runtime properties the crate does not own on wasm32 and the package
// therefore pins: a file the guest creates is mode 0600 (wazero's create
// mode; the crate's own mode handling is unix-only and skipped), and the
// guest cannot read outside the one directory it was given.
func TestFilesTheGuestCreatesAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix modes on Windows")
	}
	ctx := context.Background()
	dir, s := profile(t)
	if err := s.SetCurrentWorkspace(ctx, wsA); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "current_workspace"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("current_workspace is mode %o, want 0600", mode)
	}
}

func TestTheGuestCannotSeeOutsideTheMount(t *testing.T) {
	ctx := context.Background()
	_, s := profile(t)
	// A perfectly good auth.json, outside the directory the guest was
	// given. Naming its directory to the guest directly — which no method
	// of this package does — must not read it.
	outside := t.TempDir()
	write(t, filepath.Join(outside, "auth.json"), authJSON(time.Now().Add(time.Hour).Unix()))
	escaped := &ProfileStore{root: s.root, dir: outside}
	if _, err := escaped.Token(ctx); err == nil {
		t.Fatal("the guest read a file outside its mount")
	} else if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrIO) {
		t.Fatalf("reading outside the mount: %v, want ErrNotFound or ErrIO", err)
	}
	// The same through the guest's own root: the mount is the only root
	// it has, and `..` above it goes nowhere.
	escaped = &ProfileStore{root: s.root, dir: guestRoot + "/.."}
	if _, err := escaped.DeviceIdentity(ctx); err == nil {
		t.Fatal("the guest read above its mount")
	}
}

// The guest's memory is the shared allocator's: the store reports its lock
// state like a client does, and RequireLockedMemory is honoured.
func TestMemoryStateIsReportedAndStrictIsHonoured(t *testing.T) {
	_, s := profile(t)
	if s.MemoryLocked() != (s.MemoryLockError() == nil) {
		t.Fatal("MemoryLocked and MemoryLockError disagree")
	}
	if err := s.MemoryLockError(); err != nil && !errors.Is(err, ErrMemoryLock) {
		t.Fatalf("MemoryLockError = %v, want ErrMemoryLock or nil", err)
	}
	if !strings.Contains(fmt.Sprint(s), "memory:") {
		t.Fatalf("String = %q, no memory state", s)
	}
	if !s.MemoryLocked() {
		if _, err := Open(context.Background(), s.Dir(), RequireLockedMemory()); !errors.Is(err, ErrMemoryLock) {
			t.Fatalf("RequireLockedMemory under a refused lock: %v, want ErrMemoryLock", err)
		}
	}
}

// A ProfileStore that becomes unreachable without Close is released by
// its cleanup, as a Client is.
func TestUnreachableStoreIsReleased(t *testing.T) {
	dir, _ := profile(t)
	s, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	alloc := s.root.inst.mem
	s = nil
	deadline := time.Now().Add(10 * time.Second)
	for !alloc.IsFreed() {
		if time.Now().After(deadline) {
			t.Fatal("an unreachable store's memory was not released")
		}
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
}

// The guest root this package mounts at is the one the guest builds every
// path under.
func TestGuestRootMatchesTheGuest(t *testing.T) {
	ctx := context.Background()
	_, s := profile(t)
	ws, err := s.WorkspaceStore(ctx, wsA)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ws.dir, guestRoot+"/") {
		t.Fatalf("the guest named %q, not under %q", ws.dir, guestRoot)
	}
	if guest.PolicyFor(false) != guest.BestEffort {
		t.Fatal("the default policy is not best effort")
	}
}

// The mount is confined to the directory it names, symlinks included: a
// symlink inside the profile that leads outside it is refused, for a read
// and for the one write the guest makes, while a symlink that stays inside
// is the file it names. wazero's own directory mount would follow all of
// them with the process's permissions.
func TestASymlinkOutOfTheMountIsRefused(t *testing.T) {
	ctx := context.Background()
	dir, s := profile(t)
	outside := t.TempDir()
	symlink := func(target, link string) {
		t.Helper()
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("cannot create a symlink here: %v", err)
		}
	}

	// A read through a symlinked file: device.json leads outside.
	elsewhere := filepath.Join(outside, "device.json")
	write(t, elsewhere, deviceJSON)
	if err := os.Remove(filepath.Join(dir, "device.json")); err != nil {
		t.Fatal(err)
	}
	symlink(elsewhere, filepath.Join(dir, "device.json"))
	if _, err := s.DeviceIdentity(ctx); err == nil {
		t.Fatal("the guest read a file outside the mount through a symlink")
	} else if !errors.Is(err, ErrIO) {
		t.Fatalf("reading through an escaping symlink: %v, want ErrIO", err)
	}

	// A read through a symlinked directory: workspaces/<id> leads outside.
	escapedWorkspace := filepath.Join(outside, "ws")
	if err := os.Mkdir(escapedWorkspace, 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(escapedWorkspace, "auth.json"), authJSON(time.Now().Add(time.Hour).Unix()))
	const wsC = "CCCCCCCCCCCCCCCC"
	symlink(escapedWorkspace, filepath.Join(dir, "workspaces", wsC))
	ws, err := s.WorkspaceStore(ctx, wsC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ws.Token(ctx); !errors.Is(err, ErrIO) {
		t.Fatalf("reading through an escaping symlinked directory: %v, want ErrIO", err)
	}

	// The one write, through a symlinked file: current_workspace leads to
	// a file outside, which must be left as it was.
	victim := filepath.Join(outside, "victim")
	write(t, victim, "untouched")
	symlink(victim, filepath.Join(dir, "current_workspace"))
	if err := s.SetCurrentWorkspace(ctx, wsA); !errors.Is(err, ErrIO) {
		t.Fatalf("writing through an escaping symlink: %v, want ErrIO", err)
	}
	if got, err := os.ReadFile(victim); err != nil || string(got) != "untouched" {
		t.Fatalf("the guest wrote outside the mount through a symlink: %q, %v", got, err)
	}

	// A symlink that stays inside the mount is the directory it names.
	const wsD = "DDDDDDDDDDDDDDDD"
	symlink(wsA, filepath.Join(dir, "workspaces", wsD))
	same, err := s.WorkspaceStore(ctx, wsD)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := same.Token(ctx); err != nil {
		t.Fatalf("reading through a symlink that stays inside the mount: %v", err)
	}
}

// The profile directory itself may be a symlink — a dotfiles manager's
// usual arrangement — and is opened as the directory it names.
func TestAProfileDirectoryThatIsASymlinkOpens(t *testing.T) {
	ctx := context.Background()
	dir, _ := profile(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	s, err := Open(ctx, link)
	if err != nil {
		t.Fatalf("Open of a symlinked profile directory: %v", err)
	}
	defer s.Close()
	if _, err := s.DeviceIdentity(ctx); err != nil {
		t.Fatalf("reading through a symlinked profile directory: %v", err)
	}
}

// Under RequireLockedMemory a growth the lock limit refuses is reported as
// ErrMemoryLock naming the refusal, as a client reports it, and the store
// stays open with its lock report as it was: the range went back unused.
// (The report is whatever this host gave at Open — locked, or the heap
// fallback's refusal on a 32-bit host — and must not move.)
func TestARefusedGrowthIsReportedAsMemoryLock(t *testing.T) {
	ctx := context.Background()
	_, s := profile(t)
	before := s.MemoryLockError()
	refusing := guest.RefuseGrowth(s.root.inst.mem, errors.New("refused for the test"))
	// Staging a 2 MiB argument into guest memory needs a growth, before the
	// guest can refuse it as a workspace id.
	huge := strings.Repeat("A", 2<<20)
	_, err := s.call(ctx, func(i *instance) api.Function { return i.setCurrentWorkspace }, huge)
	if !errors.Is(err, ErrMemoryLock) || !strings.Contains(err.Error(), "growth refused") || !strings.Contains(err.Error(), refusing.Reason().Error()) {
		t.Fatalf("a call needing a refused growth: %v; want ErrMemoryLock naming the refusal", err)
	}
	if refusing.Refused() == 0 {
		t.Fatal("the guest did not grow; the test proves nothing")
	}
	if after := s.MemoryLockError(); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("a refused growth changed the lock report: %v -> %v", before, after)
	}
	// The store is still open, and grows once it can.
	refusing.Allow()
	if _, err := s.CurrentWorkspace(ctx); !errors.Is(err, ErrNoCurrentWorkspace) {
		t.Fatalf("the next call, growth allowed: %v", err)
	}
}
