package secrets

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGet_EnvTakesPrecedenceOverCommand(t *testing.T) {
	SetCommands(map[string][]string{"DISPATCHER_TEST_A": {"printf", "from-command"}})
	t.Cleanup(func() { SetCommands(nil) })
	t.Setenv("DISPATCHER_TEST_A", "from-env")
	assert.Equal(t, "from-env", Get("DISPATCHER_TEST_A"), "an explicit env value must win")
}

func TestGet_RunsCommandWhenUnset(t *testing.T) {
	SetCommands(map[string][]string{"DISPATCHER_TEST_B": {"printf", "the-secret"}})
	t.Cleanup(func() { SetCommands(nil); os.Unsetenv("DISPATCHER_TEST_B") })
	os.Unsetenv("DISPATCHER_TEST_B")
	assert.Equal(t, "the-secret", Get("DISPATCHER_TEST_B"))
	assert.Equal(t, "the-secret", os.Getenv("DISPATCHER_TEST_B"), "resolved value is cached into the env")
}

func TestGet_TrimsTrailingNewline(t *testing.T) {
	SetCommands(map[string][]string{"DISPATCHER_TEST_C": {"sh", "-c", "echo spaced-key"}})
	t.Cleanup(func() { SetCommands(nil); os.Unsetenv("DISPATCHER_TEST_C") })
	os.Unsetenv("DISPATCHER_TEST_C")
	assert.Equal(t, "spaced-key", Get("DISPATCHER_TEST_C"), "trailing newline from echo must be trimmed")
}

func TestGet_FailedCommandYieldsEmpty(t *testing.T) {
	SetCommands(map[string][]string{"DISPATCHER_TEST_D": {"false"}})
	t.Cleanup(func() { SetCommands(nil); os.Unsetenv("DISPATCHER_TEST_D") })
	os.Unsetenv("DISPATCHER_TEST_D")
	assert.Equal(t, "", Get("DISPATCHER_TEST_D"), "a failed command must fail closed to empty, not panic")
}

func TestGet_UnconfiguredYieldsEmpty(t *testing.T) {
	SetCommands(nil)
	os.Unsetenv("DISPATCHER_TEST_E")
	assert.Equal(t, "", Get("DISPATCHER_TEST_E"))
}
