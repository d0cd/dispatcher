package workload

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadDotEnv parses .env (and .env.local) in dir into a map. Lines are
// KEY=VALUE; comments (#) and blanks are skipped; surrounding quotes are
// stripped. Returns nil map (not an error) when no file is present.
func LoadDotEnv(dir string) (map[string]string, error) {
	out := map[string]string{}
	for _, name := range []string{".env", ".env.local"} {
		path := filepath.Join(dir, name)
		// A repo-supplied .env that is a symlink could point at a host file
		// (e.g. ~/.ssh/id_rsa) whose contents would then be exported into the
		// remote env. Refuse to follow it; a real .env is a regular file.
		if li, err := os.Lstat(path); err == nil && li.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s is a symlink; refusing to read env from it", path)
		}
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			eq := strings.IndexByte(line, '=')
			if eq <= 0 {
				continue
			}
			key := strings.TrimSpace(line[:eq])
			if !isValidEnvKey(key) {
				f.Close()
				return nil, fmt.Errorf("invalid key %q in %s: env var names must match [A-Za-z_][A-Za-z0-9_]*", key, path)
			}
			val := strings.TrimSpace(line[eq+1:])
			val = strings.Trim(val, `"'`)
			out[key] = val
		}
		err = scanner.Err()
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
	}
	return out, nil
}

// IsValidEnvKey reports whether k is a POSIX environment variable name. Exported
// so callers injecting env keys that don't come from .env can apply the same
// boundary check LoadDotEnv applies.
func IsValidEnvKey(k string) bool { return isValidEnvKey(k) }

// isValidEnvKey reports whether k is a POSIX environment variable name
// (^[A-Za-z_][A-Za-z0-9_]*$). Keys are written verbatim into `export <key>=...`
// scripts piped to a remote shell, so a key with shell metacharacters (e.g.
// "FOO; rm -rf /") would be command injection — it must be rejected here, since
// value-quoting cannot protect the left-hand side of an assignment.
func isValidEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
