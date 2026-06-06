package workload

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

// portPatterns match common port binding patterns across languages.
var portPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:port|PORT)\s*[:=]\s*(\d{2,5})`),
	regexp.MustCompile(`\.listen\(\s*(\d{2,5})`),
	regexp.MustCompile(`EXPOSE\s+(\d{2,5})`),
	regexp.MustCompile(`(?:host|bind|addr).*:(\d{2,5})`),
	regexp.MustCompile(`uvicorn.*--port\s+(\d{2,5})`),
	regexp.MustCompile(`gunicorn.*:(\d{2,5})`),
}

// DetectPorts scans project files for port bindings to identify services.
func DetectPorts(path string) []int {
	seen := map[int]bool{}
	var ports []int

	scanFiles := collectScanFiles(path)

	for _, f := range scanFiles {
		found := scanFileForPorts(f)
		for _, p := range found {
			if !seen[p] && p >= 80 && p <= 65535 {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}

	return ports
}

func collectScanFiles(path string) []string {
	// Start with well-known top-level files
	var files []string
	wellKnown := []string{
		"Dockerfile", "docker-compose.yml", "docker-compose.yaml",
		"compose.yml", "compose.yaml",
		".env", ".env.example",
	}
	for _, name := range wellKnown {
		full := filepath.Join(path, name)
		if fileExists(full) {
			files = append(files, full)
		}
	}

	// Recursively scan source files for port patterns
	sourceFiles := scanSourceFiles(path, []string{
		".py", ".go", ".js", ".ts", ".java", ".rb",
		".yaml", ".yml", ".toml", ".json",
	})
	files = append(files, sourceFiles...)

	return files
}

func scanFileForPorts(path string) []int {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var ports []int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		for _, pat := range portPatterns {
			matches := pat.FindStringSubmatch(line)
			if len(matches) >= 2 {
				if p, err := strconv.Atoi(matches[1]); err == nil {
					ports = append(ports, p)
				}
			}
		}
	}

	return ports
}
