package workload

import (
	"bufio"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

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

	// .env.local must be here too: LoadDotEnv loads it and it is exported to the
	// remote, so a secret that lives only there must still be surfaced.
	files := []string{".env", ".env.local", ".env.example", ".env.sample"}
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
	// A credential (e.g. a long JWT or PEM body on one line) can exceed bufio's
	// default 64 KiB token cap, which would otherwise error the scan and silently
	// drop every secret past that line. Raise the cap so long lines are scanned.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		matched := false
		for _, sp := range secretPatterns {
			matches := sp.pattern.FindStringSubmatch(line)
			if len(matches) >= 2 {
				matched = true
				name := matches[1]
				if id := identifierFromLine(line); id != "" {
					name = id
				}
				refs = append(refs, types.SecretRef{
					Kind:     sp.kind,
					Location: location,
					Name:     name,
				})
			}
		}
		// Keyword patterns miss a credential whose variable name carries no
		// tell-tale word (e.g. `FOO=<40-char base64 token>`). Fall back to a
		// high-entropy value check so those aren't invisible.
		if !matched {
			if id, ok := highEntropyAssignment(line); ok {
				refs = append(refs, types.SecretRef{
					Kind:     "high-entropy-value",
					Location: location,
					Name:     id,
				})
			}
		}
	}
	// A truncated scan silently loses secrets; surface it as a single ref so the
	// operator sees the file wasn't fully inspected rather than a false all-clear.
	if scanner.Err() != nil {
		refs = append(refs, types.SecretRef{
			Kind:     "scan-incomplete",
			Location: location,
			Name:     "file could not be fully scanned",
		})
	}
	return refs
}

// entropyValuePattern isolates the value on the right of the first `=`/`:` and
// requires it to be a single base64/hex-like token — URLs, sentences, and paths
// (which contain spaces, `/`, or `.`) are excluded so they don't trip the check.
var entropyValuePattern = regexp.MustCompile(`[:=]\s*["']?([A-Za-z0-9+_/=-]{24,})["']?\s*$`)

// highEntropyAssignment reports whether line assigns a high-entropy token value
// (a likely credential) and returns the assigned identifier. The threshold is
// deliberately conservative — length >= 24 and Shannon entropy >= 3.5 bits/char
// — to keep ordinary config values (versions, hostnames, enums) from flagging.
func highEntropyAssignment(line string) (string, bool) {
	m := entropyValuePattern.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	v := m[1]
	if shannonEntropy(v) < 3.5 {
		return "", false
	}
	// Require a mix of upper, lower, and digit: random base64 credentials have
	// all three, while high-entropy non-secrets (lowercase-hex digests like a
	// `@sha256:` pin, dotted versions) do not — this keeps them from flagging.
	var hasUpper, hasLower, hasDigit bool
	for _, r := range v {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	if !(hasUpper && hasLower && hasDigit) {
		return "", false
	}
	id := identifierFromLine(line)
	if id == "" {
		return "", false
	}
	return id, true
}

// shannonEntropy returns the Shannon entropy of s in bits per character.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]float64{}
	for _, r := range s {
		counts[r]++
	}
	n := float64(len(s))
	var bits float64
	for _, c := range counts {
		p := c / n
		bits -= p * math.Log2(p)
	}
	return bits
}

// identifierFromLine extracts the declared variable name to the left of the
// first ':' or '=' delimiter, mirroring LoadDotEnv's parsing: list prefixes
// ("- ") and surrounding quotes/whitespace are trimmed. Returns "" when the
// line has no such delimiter (e.g. the aws-credential pattern), so callers
// fall back to the matched keyword.
func identifierFromLine(line string) string {
	i := strings.IndexAny(line, ":=")
	if i <= 0 {
		return ""
	}
	id := strings.TrimSpace(line[:i])
	id = strings.TrimPrefix(id, "- ")
	id = strings.TrimSpace(id)
	id = strings.Trim(id, `"'`)
	return id
}
