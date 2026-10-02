# @cipherstash/profile

[![npm version](https://img.shields.io/npm/v/@cipherstash/profile?style=for-the-badge)](https://www.npmjs.com/package/@cipherstash/profile)
[![Built by CipherStash](https://raw.githubusercontent.com/cipherstash/meta/refs/heads/main/csbadge.svg)](https://cipherstash.com)

 [Website](https://cipherstash.com) | [Docs](https://cipherstash.com/docs) | [Discord](https://discord.com/invite/5qwXUFb6PB)

Native Node.js bindings for managing [CipherStash](https://cipherstash.com) workspace profiles.

Profiles are stored in `~/.cipherstash/` (or the path specified by `CS_CONFIG_PATH`) with per-workspace directories for auth tokens and encryption keys.

## Installation

```bash
npm install @cipherstash/profile
```

Prebuilt native binaries are included for:

- macOS (x64, ARM64)
- Linux (x64 glibc, x64 musl, ARM64 glibc)
- Windows (x64)

## Usage

```js
const { ProfileStore } = require("@cipherstash/profile");

// Open the default profile store (~/.cipherstash)
const store = ProfileStore.resolve();

// Set the active workspace
store.setCurrentWorkspace("E4UMRN47WJNSMAKR");

// List workspaces with local profile data
const workspaces = store.listWorkspaces();
console.log(workspaces); // ["E4UMRN47WJNSMAKR", "JBSWY3DPEHPK3PXP"]

// Get a store scoped to the current workspace
const wsStore = store.currentWorkspaceStore();
console.log(wsStore.dir); // ~/.cipherstash/workspaces/E4UMRN47WJNSMAKR
```

## API

### `ProfileStore.resolve()`

Create a profile store at the default location (`~/.cipherstash`), or the path specified by the `CS_CONFIG_PATH` environment variable.

### `ProfileStore.withDir(dir)`

Create a profile store rooted at the given directory.

### Instance methods

| Method | Description |
|---|---|
| `dir` | The directory path of this profile store |
| `setCurrentWorkspace(id)` | Switch to a workspace. The workspace must already exist on disk (created during login). Throws `WORKSPACE_NOT_FOUND` if not, or `INVALID_WORKSPACE_ID` for malformed IDs. |
| `currentWorkspace()` | Get the current workspace ID (throws if unset) |
| `clearCurrentWorkspace()` | Remove the workspace selection |
| `listWorkspaces()` | List workspace IDs with local profile data |
| `workspaceStore(id)` | Get a store scoped to a specific workspace. Throws `INVALID_WORKSPACE_ID` for malformed IDs. The workspace directory is created on first write. |
| `currentWorkspaceStore()` | Get a store scoped to the current workspace (throws if unset) |

## Error handling

Errors thrown by the native module include a machine-readable `.code` property:

```js
try {
  store.currentWorkspace();
} catch (err) {
  console.error(err.code);    // "NO_CURRENT_WORKSPACE"
  console.error(err.message); // Human-readable description
}
```

### Error codes

| Code | Description |
|---|---|
| `NO_CURRENT_WORKSPACE` | No workspace has been set |
| `INVALID_WORKSPACE_ID` | The workspace ID is not a valid 16-character base32 string |
| `WORKSPACE_NOT_FOUND` | The workspace has no local profile data (not logged in) |
| `NOT_FOUND` | A requested profile file was not found |
| `IO_ERROR` | An I/O error occurred |
| `HOME_DIR_NOT_FOUND` | Could not determine the home directory |

## License

See [LICENSE](https://github.com/cipherstash/cipherstash-suite/blob/main/packages/stack-profile/LICENSE).
