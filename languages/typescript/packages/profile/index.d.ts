/* tslint:disable */
/* eslint-disable */

/** Error codes attached to errors thrown by this package. */
export type ProfileErrorCode =
  | "IO_ERROR"
  | "JSON_ERROR"
  | "HOME_DIR_NOT_FOUND"
  | "NOT_FOUND"
  | "INVALID_FILENAME"
  | "NO_CURRENT_WORKSPACE"
  | "INVALID_WORKSPACE_ID"
  | "UNKNOWN_ERROR";

/** An error thrown by this package, enriched with a machine-readable `.code`. */
export interface ProfileError extends Error {
  code: ProfileErrorCode;
}

/**
 * A directory-scoped profile store for managing workspace profiles.
 *
 * Use `ProfileStore.resolve()` for the default `~/.cipherstash` location,
 * or `ProfileStore.withDir(path)` for a custom directory.
 */
export class ProfileStore {
  /** Create a profile store at the default location (`~/.cipherstash`). */
  static resolve(): ProfileStore;
  /** Create a profile store rooted at the given directory. */
  static withDir(dir: string): ProfileStore;

  /** The directory path of this profile store. */
  get dir(): string;

  /** Set the current workspace. */
  setCurrentWorkspace(workspaceId: string): void;
  /** Return the current workspace ID. Throws if no workspace has been set. */
  currentWorkspace(): string;
  /** Remove the current workspace selection. */
  clearCurrentWorkspace(): void;

  /** List workspace IDs that have profile data on disk. */
  listWorkspaces(): string[];

  /** Return a profile store scoped to a specific workspace directory. */
  workspaceStore(workspaceId: string): ProfileStore;
  /** Return a profile store scoped to the current workspace. Throws if no workspace has been set. */
  currentWorkspaceStore(): ProfileStore;
}
