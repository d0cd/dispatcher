package workload

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	// maxScanDepth limits recursive directory scanning.
	maxScanDepth = 5
	// maxScanFiles limits the total number of files collected.
	maxScanFiles = 1000
)

// scanSourceFiles collects source files for deep inspection.
// Walks up to maxScanDepth levels deep, skipping common non-source directories
// and directories listed in .dispatchignore.
func scanSourceFiles(root string, extensions []string) []string {
	extSet := make(map[string]bool, len(extensions))
	for _, ext := range extensions {
		extSet[ext] = true
	}

	// Load .dispatchignore
	_, ignored := loadIgnoreFile(root)

	var files []string
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if len(files) >= maxScanFiles {
			return filepath.SkipAll
		}
		if info.IsDir() {
			name := info.Name()
			if shouldSkipDir(name) || ignored[name] {
				return filepath.SkipDir
			}
			// Enforce depth limit
			rel, _ := filepath.Rel(root, path)
			if rel != "." && strings.Count(rel, string(os.PathSeparator)) >= maxScanDepth {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(info.Name())
		if extSet[ext] {
			files = append(files, path)
		}
		return nil
	})

	return files
}

// shouldSkipDir returns true for directories that should not be scanned.
func shouldSkipDir(name string) bool {
	skip := map[string]bool{
		".git":          true,
		".hg":           true,
		".svn":          true,
		"node_modules":  true,
		"vendor":        true,
		".venv":         true,
		"venv":          true,
		"env":           true,
		"__pycache__":   true,
		".tox":          true,
		".mypy_cache":   true,
		".pytest_cache": true,
		".ruff_cache":   true,
		"dist":          true,
		"build":         true,
		"target":        true,
		".next":         true,
		".nuxt":         true,
		".cache":        true,
		".parcel-cache": true,
		".terraform":    true,
		".dispatcher":   true,
		"coverage":      true,
	}
	return skip[name]
}

// LoadIgnorePatterns reads .dispatchignore from a directory and returns
// the patterns as a slice (for rsync --exclude) and a map (for dir skipping).
func LoadIgnorePatterns(root string) ([]string, map[string]bool) {
	patterns, dirMap := loadIgnoreFile(root)
	return patterns, dirMap
}

func loadIgnoreFile(root string) ([]string, map[string]bool) {
	dirMap := map[string]bool{}
	var patterns []string
	data, err := os.ReadFile(filepath.Join(root, ".dispatchignore"))
	if err != nil {
		return patterns, dirMap
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
		normalized := strings.TrimRight(line, "/")
		dirMap[normalized] = true
	}
	return patterns, dirMap
}

// SubWorkload represents a detected workload within a monorepo.
type SubWorkload struct {
	Path    string
	Name    string
	Runtime string
	Kind    string
}

// DetectSubWorkloads looks for multiple workloads in subdirectories.
// Returns nil if the directory appears to be a single project.
func DetectSubWorkloads(root string) []SubWorkload {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}

	var subs []SubWorkload
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if shouldSkipDir(name) {
			continue
		}

		subPath := filepath.Join(root, name)
		if hasProjectMarker(subPath) {
			rt := DetectRuntime(subPath)
			if rt != "unknown" {
				subs = append(subs, SubWorkload{
					Path:    subPath,
					Name:    name,
					Runtime: string(rt),
				})
			}
		}
	}

	// Only return sub-workloads if we found multiple independent projects
	if len(subs) >= 2 {
		return subs
	}
	return nil
}

// hasProjectMarker checks if a directory looks like an independent project.
func hasProjectMarker(path string) bool {
	markers := []string{
		"package.json", "go.mod", "Cargo.toml", "requirements.txt",
		"pyproject.toml", "setup.py", "Gemfile", "pom.xml",
		"build.gradle", "Dockerfile", "Makefile",
	}
	for _, m := range markers {
		if fileExists(filepath.Join(path, m)) {
			return true
		}
	}
	return false
}
