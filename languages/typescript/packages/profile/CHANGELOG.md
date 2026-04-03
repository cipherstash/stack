# Changelog

## 0.35.0

### New Features

- **Multi-workspace profile management** — `ProfileStore` exposes workspace lifecycle operations to Node.js:
  ```ts
  const { ProfileStore } = require("@cipherstash/profile");
  const store = ProfileStore.resolve();

  store.setCurrentWorkspace("E4UMRN47WJNSMAKR");
  const workspaces = store.listWorkspaces();
  const wsStore = store.currentWorkspaceStore();
  ```
- **`ProfileStore.resolve()`** — open the default `~/.cipherstash` profile directory (or `CS_CONFIG_PATH`).
- **`ProfileStore.withDir(path)`** — open a profile store at a custom directory.
- **`setCurrentWorkspace` / `currentWorkspace` / `clearCurrentWorkspace`** — manage the active workspace.
- **`listWorkspaces`** — enumerate workspace IDs with local profile data.
- **`workspaceStore(id)` / `currentWorkspaceStore()`** — get a store scoped to a workspace subdirectory.
- **Error enrichment** — all errors include a machine-readable `.code` property (e.g. `NO_CURRENT_WORKSPACE`).
