package workload

import (
	"os"
	"path/filepath"
	"strings"
)

// DetectEntrypoints finds main files, Dockerfiles, and docker-compose files.
func DetectEntrypoints(path string) []string {
	var entrypoints []string

	candidates := []string{
		"main.py", "app.py", "server.py", "run.py",
		"main.go", "cmd/main.go",
		"main.js", "index.js", "server.js", "app.js",
		"main.ts", "index.ts", "server.ts", "app.ts",
		"Main.java",
		"main.rs",
		"Dockerfile", "Dockerfile.dispatcher",
		"docker-compose.yml", "docker-compose.yaml",
		"compose.yml", "compose.yaml",
	}

	for _, c := range candidates {
		if fileExists(filepath.Join(path, c)) {
			entrypoints = append(entrypoints, c)
		}
	}

	// Check cmd/ subdirectories for Go projects
	cmdDir := filepath.Join(path, "cmd")
	if entries, err := os.ReadDir(cmdDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				mainGo := filepath.Join("cmd", entry.Name(), "main.go")
				if fileExists(filepath.Join(path, mainGo)) {
					if !contains(entrypoints, mainGo) {
						entrypoints = append(entrypoints, mainGo)
					}
				}
			}
		}
	}

	// Check Procfile
	if fileExists(filepath.Join(path, "Procfile")) {
		entrypoints = append(entrypoints, "Procfile")
	}

	// Check Makefile
	if fileExists(filepath.Join(path, "Makefile")) {
		entrypoints = append(entrypoints, "Makefile")
	}

	// Check src/ directory for common patterns
	srcCandidates := []string{
		"src/main.py", "src/app.py", "src/server.py",
		"src/index.js", "src/index.ts", "src/main.ts",
		"src/main.go",
		"src/main.rs", "src/lib.rs",
	}
	for _, c := range srcCandidates {
		if fileExists(filepath.Join(path, c)) {
			if !contains(entrypoints, c) {
				entrypoints = append(entrypoints, c)
			}
		}
	}

	return entrypoints
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
