// Example: Manage workspaces using the profile store.
//
// The `ProfileStore` manages `~/.cipherstash/` and tracks which
// workspace is currently active. Each workspace gets its own
// subdirectory under `workspaces/<id>/` for auth and key data.
//
// Prerequisites:
//   1. Build the native module:  npm run build
//   2. Log in with the CLI:     stash login
//
// Usage:
//   npx tsx examples/workspace-management.ts

import type { ProfileError } from '../index'
import { ProfileStore } from '../index'

function main() {
  const store = ProfileStore.resolve()
  console.log(`Profile directory: ${store.dir}`)

  // List workspaces that have local profile data.
  const workspaces = store.listWorkspaces()
  console.log(`\nWorkspaces on disk: ${workspaces.length}`)
  for (const id of workspaces) {
    console.log(`  - ${id}`)
  }

  // Show the current workspace (if set).
  try {
    const current = store.currentWorkspace()
    console.log(`\nCurrent workspace: ${current}`)

    // Get a store scoped to the current workspace.
    const wsStore = store.currentWorkspaceStore()
    console.log(`Workspace directory: ${wsStore.dir}`)
  } catch (err) {
    const profileErr = err as ProfileError
    if (profileErr.code === 'NO_CURRENT_WORKSPACE') {
      console.log('\nNo current workspace set. Run `stash login` first.')
    } else {
      throw err
    }
  }
}

main()
