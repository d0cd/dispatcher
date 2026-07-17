package workload

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectSecrets_EnvLocalIsScanned(t *testing.T) {
	// .env.local is loaded and exported to the remote, so a secret there must be
	// surfaced just like one in .env.
	dir := t.TempDir()
	writeFile(t, dir, ".env.local", "API_KEY=sk-localonly\n")
	kinds := secretKinds(DetectSecrets(dir))
	assert.Contains(t, kinds, "api-key")
}

func TestDetectSecrets_HighEntropyValueWithoutKeyword(t *testing.T) {
	// A credential whose variable name carries no tell-tale keyword is still
	// caught by the entropy fallback; an ordinary low-entropy value is not.
	dir := t.TempDir()
	writeFile(t, dir, ".env", "FOO=Xk7Qp2Lm9Zt4Rw8Bn3Vc6Yj1\nMODE=production\nVERSION=1.2.3\n")
	kinds := secretKinds(DetectSecrets(dir))
	assert.Contains(t, kinds, "high-entropy-value")
	// A base64-ish token is flagged; short/low-entropy values are not.
	for _, r := range DetectSecrets(dir) {
		if r.Kind == "high-entropy-value" {
			assert.NotEqual(t, "MODE", r.Name)
			assert.NotEqual(t, "VERSION", r.Name)
		}
	}
}

func TestDetectSecrets_EnvFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".env", `
API_KEY=sk-abc123
DATABASE_URL=postgres://localhost/mydb
SECRET_KEY=super-secret-value
NORMAL_VAR=not-a-secret
`)

	refs := DetectSecrets(dir)
	kinds := secretKinds(refs)
	assert.Contains(t, kinds, "api-key")
	assert.Contains(t, kinds, "database-url")
	assert.Contains(t, kinds, "secret-key")
}

func TestDetectSecrets_EnvExample(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".env.example", `
API_KEY=
AUTH_TOKEN=
PASSWORD=
`)

	refs := DetectSecrets(dir)
	kinds := secretKinds(refs)
	assert.Contains(t, kinds, "api-key")
	assert.Contains(t, kinds, "auth-token")
	assert.Contains(t, kinds, "password")
}

func TestDetectSecrets_NameIsFullIdentifier(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".env", "STRIPE_API_KEY=x\n")

	refs := DetectSecrets(dir)
	var found bool
	for _, r := range refs {
		if r.Kind == "api-key" {
			assert.Equal(t, "STRIPE_API_KEY", r.Name)
			found = true
		}
	}
	assert.True(t, found, "expected an api-key ref")
}

func TestDetectSecrets_AWSCredentials(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".env", `
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`)

	refs := DetectSecrets(dir)
	kinds := secretKinds(refs)
	assert.Contains(t, kinds, "aws-credential")
}

func TestDetectSecrets_DockerCompose(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "docker-compose.yml", `
services:
  app:
    environment:
      - DATABASE_URL=postgres://db:5432/app
      - API_KEY=${API_KEY}
`)

	refs := DetectSecrets(dir)
	kinds := secretKinds(refs)
	assert.Contains(t, kinds, "database-url")
	assert.Contains(t, kinds, "api-key")
}

func TestDetectSecrets_NoSecrets(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.py", `print("hello world")`)

	refs := DetectSecrets(dir)
	assert.Empty(t, refs)
}

func TestDetectSecrets_Deduplication(t *testing.T) {
	dir := t.TempDir()
	// Same secret in both .env and .env.example
	writeFile(t, dir, ".env", "API_KEY=secret123\n")
	writeFile(t, dir, ".env.example", "API_KEY=\n")

	refs := DetectSecrets(dir)
	// Should have entries from both files (different locations)
	assert.GreaterOrEqual(t, len(refs), 1)
	// But dedup within the same file
	for _, r := range refs {
		assert.NotEmpty(t, r.Kind)
		assert.NotEmpty(t, r.Location)
	}
}

func TestDetectSecrets_PrivateKey(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".env", "PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\n")

	refs := DetectSecrets(dir)
	kinds := secretKinds(refs)
	assert.Contains(t, kinds, "private-key")
}

func TestDetectSecrets_LocationTracking(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".env", "API_KEY=test\n")

	refs := DetectSecrets(dir)
	require.NotEmpty(t, refs)
	assert.Equal(t, ".env", refs[0].Location)
}

func secretKinds(refs []types.SecretRef) []string {
	kinds := make([]string, len(refs))
	for i, r := range refs {
		kinds[i] = r.Kind
	}
	return kinds
}
