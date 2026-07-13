package cloudvm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAgentURL(t *testing.T) {
	require.NoError(t, ValidateAgentURL("https://sharedeus.eus.attest.azure.net"))
	require.NoError(t, ValidateAgentURL("http://10.0.0.5:8443"))

	// A quote closes the `bash -c '...'` literal it is interpolated into.
	assert.Error(t, ValidateAgentURL("https://evil'; touch /pwned #"))
	// Whitespace splits the argument.
	assert.Error(t, ValidateAgentURL("https://x.example/a b"))
	// Command substitution / pipes.
	assert.Error(t, ValidateAgentURL("https://x.example/$(id)"))
	// Non-web scheme.
	assert.Error(t, ValidateAgentURL("ftp://x.example"))
	assert.Error(t, ValidateAgentURL(""))
}
