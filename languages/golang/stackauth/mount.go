package stackauth

import (
	"errors"
	"io/fs"
	"os"
	"path"

	experimentalsys "github.com/tetratelabs/wazero/experimental/sys"
	"github.com/tetratelabs/wazero/experimental/sysfs"
	"github.com/tetratelabs/wazero/sys"
)

// confinedFS is the one directory the guest is given, held to that
// directory. wazero's own directory mount joins the guest's path onto the
// host directory and lets the operating system resolve it, symlinks
// included, with the host process's permissions: a profile entry that is
// a symlink to a file elsewhere would read, and a current_workspace that
// is a symlink would write, outside the boundary ADR-0005 draws. Here
// every path the guest names is first resolved by os.Root — which follows
// symlinks only while they stay inside the directory and refuses the ones
// that leave it — and only a path that stays inside reaches the mount.
//
// The check runs before the operation rather than as part of it: os.Root
// answers where the path leads, and wazero's mount then performs the
// operation on the host path. A change to the directory between the two
// is not defended against, deliberately. The profile directory is the
// user's own, and anything able to race a symlink into it can read the
// credentials directly; the boundary here is against what the directory
// contains, not against a concurrent attacker inside it.
type confinedFS struct {
	// FS is wazero's directory mount, which performs every operation.
	experimentalsys.FS
	root *os.Root
}

func newConfinedFS(dir string) (*confinedFS, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &confinedFS{FS: sysfs.DirFS(dir), root: root}, nil
}

// Close releases the directory handle the root holds.
func (c *confinedFS) Close() error { return c.root.Close() }

// confine is the errno an operation on p should fail with instead of
// running, or zero when p resolves inside the directory. p is as wazero
// hands it: relative to the mount, "." for the mount itself. A path that
// does not exist yet is confined when its parent is, which is what a
// create needs; a symlink that leaves the directory, at any component, is
// a refusal, as is a component that is not a directory.
func (c *confinedFS) confine(p string) experimentalsys.Errno {
	_, err := c.root.Stat(p)
	switch {
	case err == nil:
		return 0
	case !errors.Is(err, fs.ErrNotExist):
		return experimentalsys.EACCES
	}
	parent := path.Dir(p)
	if parent == p {
		return 0
	}
	if _, err := c.root.Stat(parent); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return experimentalsys.ENOENT
		}
		return experimentalsys.EACCES
	}
	return 0
}

func (c *confinedFS) OpenFile(p string, flag experimentalsys.Oflag, perm fs.FileMode) (experimentalsys.File, experimentalsys.Errno) {
	if errno := c.confine(p); errno != 0 {
		return nil, errno
	}
	return c.FS.OpenFile(p, flag, perm)
}

func (c *confinedFS) Lstat(p string) (sys.Stat_t, experimentalsys.Errno) {
	if errno := c.confine(p); errno != 0 {
		return sys.Stat_t{}, errno
	}
	return c.FS.Lstat(p)
}

func (c *confinedFS) Stat(p string) (sys.Stat_t, experimentalsys.Errno) {
	if errno := c.confine(p); errno != 0 {
		return sys.Stat_t{}, errno
	}
	return c.FS.Stat(p)
}

func (c *confinedFS) Mkdir(p string, perm fs.FileMode) experimentalsys.Errno {
	if errno := c.confine(p); errno != 0 {
		return errno
	}
	return c.FS.Mkdir(p, perm)
}

func (c *confinedFS) Chmod(p string, perm fs.FileMode) experimentalsys.Errno {
	if errno := c.confine(p); errno != 0 {
		return errno
	}
	return c.FS.Chmod(p, perm)
}

func (c *confinedFS) Rename(from, to string) experimentalsys.Errno {
	if errno := c.confine(from); errno != 0 {
		return errno
	}
	if errno := c.confine(to); errno != 0 {
		return errno
	}
	return c.FS.Rename(from, to)
}

func (c *confinedFS) Rmdir(p string) experimentalsys.Errno {
	if errno := c.confine(p); errno != 0 {
		return errno
	}
	return c.FS.Rmdir(p)
}

func (c *confinedFS) Unlink(p string) experimentalsys.Errno {
	if errno := c.confine(p); errno != 0 {
		return errno
	}
	return c.FS.Unlink(p)
}

func (c *confinedFS) Link(oldPath, newPath string) experimentalsys.Errno {
	if errno := c.confine(oldPath); errno != 0 {
		return errno
	}
	if errno := c.confine(newPath); errno != 0 {
		return errno
	}
	return c.FS.Link(oldPath, newPath)
}

func (c *confinedFS) Symlink(oldPath, linkName string) experimentalsys.Errno {
	if errno := c.confine(linkName); errno != 0 {
		return errno
	}
	return c.FS.Symlink(oldPath, linkName)
}

func (c *confinedFS) Readlink(p string) (string, experimentalsys.Errno) {
	if errno := c.confine(p); errno != 0 {
		return "", errno
	}
	return c.FS.Readlink(p)
}

func (c *confinedFS) Utimens(p string, atim, mtim int64) experimentalsys.Errno {
	if errno := c.confine(p); errno != 0 {
		return errno
	}
	return c.FS.Utimens(p, atim, mtim)
}
