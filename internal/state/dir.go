// Package state resolves the dispatch state directory.
//
// Resolution order:
//  1. $DISPATCH_HOME if set.
//  2. A `.dispatcher/` directory found by walking up from the current working
//     directory (per-project isolation).
//  3. `~/.dispatcher/` as the cross-project fallback.
package state

import (
	"fmt"
	"os"
	"path/filepath"
)

const dirName = ".dispatcher"

// Dir resolves the dispatch state directory, creating it if missing.
func Dir() (string, error) {
	if env := os.Getenv("DISPATCH_HOME"); env != "" {
		if err := os.MkdirAll(env, 0o700); err != nil {
			return "", fmt.Errorf("create $DISPATCH_HOME (%s): %w", env, err)
		}
		return env, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}

	if cwd, err := os.Getwd(); err == nil {
		if found, ok := findUpward(cwd, home); ok {
			return found, nil
		}
	}

	d := filepath.Join(home, dirName)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", d, err)
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
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", fmt.Errorf("create %s: %w", d, err)
	}
	return d, nil
}

// findUpward walks parents looking for a project root, defined as a directory
// containing a project marker (.git, go.mod, package.json, pyproject.toml,
// Cargo.toml, dispatch.yaml) or a .dispatcher/ directory itself. Stops at $HOME
// so the global ~/.dispatcher/ is never mistaken for a project-local one.
// Returns the .dispatcher/ path at that project root if it exists.
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
	for _, marker := range []string{".git", "go.mod", "package.json", "pyproject.toml", "Cargo.toml", "dispatch.yaml", "dispatch.yml"} {
		if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			return true
		}
	}
	return false
}
