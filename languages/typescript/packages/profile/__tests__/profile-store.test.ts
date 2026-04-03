import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import type { ProfileStore as ProfileStoreType, ProfileError } from "../index";

const mod = require("../index.js") as typeof import("../index");
const { ProfileStore } = mod;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const WS_A = "AAAAAAAAAAAAAAAA";
const WS_B = "BBBBBBBBBBBBBBBB";

let profileDir: string;

function freshProfileDir(): string {
  return mkdtempSync(join(tmpdir(), "cs-profile-test-"));
}

function store(): InstanceType<typeof ProfileStoreType> {
  return ProfileStore.withDir(profileDir);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ProfileStore", () => {
  beforeEach(() => {
    profileDir = freshProfileDir();
  });

  describe("resolve", () => {
    it("returns a ProfileStore at the default location", () => {
      const s = ProfileStore.resolve();
      expect(s.dir).toBeTruthy();
    });
  });

  describe("withDir", () => {
    it("returns a ProfileStore at the given directory", () => {
      const s = ProfileStore.withDir("/tmp/custom");
      expect(s.dir).toBe("/tmp/custom");
    });
  });

  describe("given no workspace set", () => {
    it("currentWorkspace throws NO_CURRENT_WORKSPACE", () => {
      try {
        store().currentWorkspace();
        expect.unreachable("should have thrown");
      } catch (err) {
        const profileErr = err as ProfileError;
        expect(profileErr).toBeInstanceOf(Error);
        expect(profileErr.code).toBe("NO_CURRENT_WORKSPACE");
      }
    });

    it("currentWorkspaceStore throws NO_CURRENT_WORKSPACE", () => {
      try {
        store().currentWorkspaceStore();
        expect.unreachable("should have thrown");
      } catch (err) {
        const profileErr = err as ProfileError;
        expect(profileErr.code).toBe("NO_CURRENT_WORKSPACE");
      }
    });

    it("listWorkspaces returns empty array", () => {
      expect(store().listWorkspaces()).toEqual([]);
    });

    it("clearCurrentWorkspace succeeds", () => {
      expect(() => store().clearCurrentWorkspace()).not.toThrow();
    });
  });

  describe("given workspace set", () => {
    beforeEach(() => {
      store().setCurrentWorkspace(WS_A);
    });

    it("currentWorkspace returns the workspace ID", () => {
      expect(store().currentWorkspace()).toBe(WS_A);
    });

    it("currentWorkspaceStore returns a scoped store", () => {
      const ws = store().currentWorkspaceStore();
      expect(ws.dir).toBe(join(profileDir, "workspaces", WS_A));
    });

    it("clearCurrentWorkspace removes the selection", () => {
      store().clearCurrentWorkspace();
      try {
        store().currentWorkspace();
        expect.unreachable("should have thrown");
      } catch (err) {
        expect((err as ProfileError).code).toBe("NO_CURRENT_WORKSPACE");
      }
    });
  });

  describe("workspaceStore", () => {
    it("returns a store scoped to the workspace directory", () => {
      const ws = store().workspaceStore(WS_A);
      expect(ws.dir).toBe(join(profileDir, "workspaces", WS_A));
    });

    it("throws INVALID_WORKSPACE_ID for bad input", () => {
      try {
        store().workspaceStore("../escape");
        expect.unreachable("should have thrown");
      } catch (err) {
        expect((err as ProfileError).code).toBe("INVALID_WORKSPACE_ID");
      }
    });
  });

  describe("given multiple workspaces", () => {
    beforeEach(() => {
      const s = store();
      // Create workspace dirs by setting workspace and writing current_workspace
      s.setCurrentWorkspace(WS_A);
      // Touch a file in the workspace dir so it gets created
      s.workspaceStore(WS_A).setCurrentWorkspace(WS_A);
      s.workspaceStore(WS_B).setCurrentWorkspace(WS_B);
    });

    it("listWorkspaces returns sorted workspace IDs", () => {
      expect(store().listWorkspaces()).toEqual([WS_A, WS_B]);
    });

    it("switching workspace changes currentWorkspaceStore", () => {
      const s = store();
      s.setCurrentWorkspace(WS_A);
      expect(s.currentWorkspaceStore().dir).toBe(
        join(profileDir, "workspaces", WS_A),
      );

      s.setCurrentWorkspace(WS_B);
      expect(s.currentWorkspaceStore().dir).toBe(
        join(profileDir, "workspaces", WS_B),
      );
    });
  });
});
