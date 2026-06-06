package workload

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"

	"github.com/d0cd/dispatcher/internal/types"
)

var secretPatterns = []struct {
	pattern *regexp.Regexp
	kind    string
}{
	{regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]`), "api-key"},
	{regexp.MustCompile(`(?i)(secret[_-]?key|secretkey)\s*[:=]`), "secret-key"},
	{regexp.MustCompile(`(?i)(database[_-]?url|db[_-]?url|dsn)\s*[:=]`), "database-url"},
	{regexp.MustCompile(`(?i)(password|passwd)\s*[:=]`), "password"},
	{regexp.MustCompile(`(?i)(aws[_-]?access|aws[_-]?secret)`), "aws-credential"},
	{regexp.MustCompile(`(?i)(token|auth[_-]?token)\s*[:=]`), "auth-token"},
	{regexp.MustCompile(`(?i)(private[_-]?key)\s*[:=]`), "private-key"},
}

// DetectSecrets finds references to secrets and credentials in the workload.
func DetectSecrets(path string) []types.SecretRef {
	var refs []types.SecretRef
	seen := map[string]bool{}

	files := []string{".env", ".env.example", ".env.sample"}
	for _, name := range files {
		full := filepath.Join(path, name)
		found := scanFileForSecrets(full, name)
		for _, r := range found {
			key := r.Kind + ":" + r.Name
			if !seen[key] {
				seen[key] = true
				refs = append(refs, r)
			}
		}
	}

	// Scan config files
	configFiles := []string{
		"docker-compose.yml", "docker-compose.yaml",
		"compose.yml", "compose.yaml",
		"dispatcher.yaml",
	}
	for _, name := range configFiles {
		full := filepath.Join(path, name)
		found := scanFileForSecrets(full, name)
		for _, r := range found {
			key := r.Kind + ":" + r.Name
			if !seen[key] {
				seen[key] = true
				refs = append(refs, r)
			}
		}
	}

	return refs
}

func scanFileForSecrets(path, location string) []types.SecretRef {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var refs []types.SecretRef
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		for _, sp := range secretPatterns {
			matches := sp.pattern.FindStringSubmatch(line)
			if len(matches) >= 2 {
				refs = append(refs, types.SecretRef{
					Kind:     sp.kind,
					Location: location,
					Name:     matches[1],
				})
			}
		}
	}
	return refs
}
