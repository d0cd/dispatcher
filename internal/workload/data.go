package workload

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"

	"github.com/d0cd/dispatcher/internal/types"
)

var dataPatterns = []struct {
	pattern *regexp.Regexp
	kind    string
}{
	{regexp.MustCompile(`s3://[a-zA-Z0-9._-]+`), "s3"},
	{regexp.MustCompile(`gs://[a-zA-Z0-9._-]+`), "gcs"},
	{regexp.MustCompile(`(?i)(postgres|postgresql|mysql|mongodb|redis)://`), "database"},
	{regexp.MustCompile(`(?i)mount.*(/data|/mnt|/vol)`), "volume-mount"},
}

// DetectDataRequirements identifies data dependencies in the workload.
func DetectDataRequirements(path string) []types.DataRequirement {
	var reqs []types.DataRequirement
	seen := map[string]bool{}

	// Scan well-known config files at top level
	configFiles := []string{
		".env", ".env.example",
		"docker-compose.yml", "docker-compose.yaml",
		"compose.yml", "compose.yaml",
		"dispatch.yaml",
	}
	for _, name := range configFiles {
		full := filepath.Join(path, name)
		addDataFromFile(full, name, &reqs, seen)
	}

	// Recursively scan source files
	sourceFiles := scanSourceFiles(path, []string{".py", ".go", ".js", ".ts", ".yaml", ".yml"})
	for _, full := range sourceFiles {
		rel, _ := filepath.Rel(path, full)
		if rel == "" {
			rel = filepath.Base(full)
		}
		addDataFromFile(full, rel, &reqs, seen)
	}

	return reqs
}

func addDataFromFile(path, location string, reqs *[]types.DataRequirement, seen map[string]bool) {
	found := scanFileForData(path, location)
	for _, r := range found {
		key := r.Kind + ":" + r.Location + ":" + r.Details
		if !seen[key] {
			seen[key] = true
			*reqs = append(*reqs, r)
		}
	}
}

func scanFileForData(path, location string) []types.DataRequirement {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var reqs []types.DataRequirement
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		for _, dp := range dataPatterns {
			if dp.pattern.MatchString(line) {
				reqs = append(reqs, types.DataRequirement{
					Kind:     dp.kind,
					Location: location,
					Details:  dp.pattern.FindString(line),
				})
			}
		}
	}
	return reqs
}
