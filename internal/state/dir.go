// Package state resolves the dispatcher state directory. Order:
// $DISPATCHER_HOME, then walk up from cwd looking for .dispatcher/, then
// ~/.dispatcher/. Every resolved dir is enforced to mode 0700 even if it
// pre-existed at a looser mode.
package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const dirName = ".dispatcher"

// Dir resolves the dispatcher state directory, creating it if missing and
// enforcing mode 0700.
func Dir() (string, error) {
	if env := os.Getenv("DISPATCHER_HOME"); env != "" {
		if err := validateHomeOverride(env); err != nil {
			return "", err
		}
		if err := ensureSecureDir(env); err != nil {
			return "", err
		}
		return env, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}

	if cwd, err := os.Getwd(); err == nil {
		if found, ok := findUpward(cwd, home); ok {
			if err := ensureSecureDir(found); err != nil {
				return "", err
			}
			return found, nil
		}
	}

	d := filepath.Join(home, dirName)
	if err := ensureSecureDir(d); err != nil {
		return "", err
	}
	return d, nil
}

// Subdir returns Dir()/name, creating the subdirectory if missing.
func Subdir(name string) (string, error) {
	base, err := Dir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(base, name)
	if err := ensureSecureDir(d); err != nil {
		return "", err
	}
	return d, nil
}

func validateHomeOverride(env string) error {
	if !filepath.IsAbs(env) {
		return fmt.Errorf("DISPATCHER_HOME must be absolute (got %q)", env)
	}
	for _, seg := range strings.Split(env, string(filepath.Separator)) {
		if seg == ".." {
			return fmt.Errorf("DISPATCHER_HOME contains path traversal (got %q)", env)
		}
	}
	return nil
}

// ensureSecureDir creates dir if missing and enforces mode 0700. Symlinks
// to the target are accepted (operators legitimately remap state-dir);
// chmod failure on existing dirs is fatal rather than silently leaking.
func ensureSecureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		info, err = os.Stat(dir)
		if err != nil {
			return fmt.Errorf("stat target of %s: %w", dir, err)
		}
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists but is not a directory", dir)
	}
	// Refuse a directory owned by another user regardless of its mode. A dir that
	// is already 0700 but attacker-owned (pre-created on a shared host, or a
	// symlink resolving to one) must never be trusted for secrets — the old check
	// only ran inside the loose-perms branch and silently trusted this case.
	if ownedByOther(info) {
		return fmt.Errorf("%s is owned by another user; refusing to use it for secrets", dir)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("%s has insecure perms %o and could not be chmodded: %w",
				dir, info.Mode().Perm(), err)
		}
	}
	return nil
}

// findUpward walks parents looking for an existing .dispatcher/ at a
// project root (identified by isProjectRoot markers). Stops at $HOME so
// the global state dir isn't mistaken for project-local.
func findUpward(start, home string) (string, bool) {
	dir := start
	for {
		if dir == home {
			return "", false
		}
		candidate := filepath.Join(dir, dirName)
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate, true
		}
		if isProjectRoot(dir) {
			return "", false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

func isProjectRoot(dir string) bool {
	for _, marker := range []string{".git", "go.mod", "package.json", "pyproject.toml", "Cargo.toml", "dispatcher.yaml", "dispatcher.yml"} {
		if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			return true
		}
	}
	return false
}
