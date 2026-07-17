package workload

import (
	"os"
	"path/filepath"

	"github.com/d0cd/dispatcher/internal/types"
)

// DetectRuntime identifies the primary language/runtime from project files.
func DetectRuntime(path string) types.Runtime {
	// Check signals in priority order
	priorities := []struct {
		file    string
		runtime types.Runtime
	}{
		{"go.mod", types.RuntimeGo},
		{"Cargo.toml", types.RuntimeRust},
		{"package.json", types.RuntimeNode},
		{"requirements.txt", types.RuntimePython},
		{"pyproject.toml", types.RuntimePython},
		{"setup.py", types.RuntimePython},
		{"Pipfile", types.RuntimePython},
		{"pom.xml", types.RuntimeJava},
		{"build.gradle", types.RuntimeJava},
		{"Gemfile", types.RuntimeRuby},
	}

	for _, p := range priorities {
		if fileExists(filepath.Join(path, p.file)) {
			return p.runtime
		}
	}

	// Fall back to checking file extensions
	entries, err := os.ReadDir(path)
	if err != nil {
		return types.RuntimeUnknown
	}

	extMap := map[string]types.Runtime{
		".py":   types.RuntimePython,
		".js":   types.RuntimeNode,
		".ts":   types.RuntimeNode,
		".go":   types.RuntimeGo,
		".rs":   types.RuntimeRust,
		".java": types.RuntimeJava,
		".rb":   types.RuntimeRuby,
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if rt, ok := extMap[ext]; ok {
			return rt
		}
	}

	return types.RuntimeUnknown
}
