package adapter

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/d0cd/dispatcher/internal/types"
)

func TestRuntimeCommand(t *testing.T) {
	cases := []struct {
		name         string
		rt           types.Runtime
		entrypoint   string
		forContainer bool
		want         []string
	}{
		{"python host uses python3", types.RuntimePython, "app.py", false, []string{"python3", "app.py"}},
		{"python container uses python", types.RuntimePython, "app.py", true, []string{"python", "app.py"}},
		{"node", types.RuntimeNode, "index.js", false, []string{"node", "index.js"}},
		{"go run", types.RuntimeGo, "main.go", false, []string{"go", "run", "main.go"}},
		{"ruby", types.RuntimeRuby, "app.rb", false, []string{"ruby", "app.rb"}},
		{"rust ignores entrypoint (cargo run)", types.RuntimeRust, "ignored", false, []string{"cargo", "run"}},
		{"java", types.RuntimeJava, "Main", false, []string{"java", "Main"}},
		{"unknown runtime runs the entrypoint bare", types.RuntimeUnknown, "./run.sh", false, []string{"./run.sh"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, RuntimeCommand(c.rt, c.entrypoint, c.forContainer))
		})
	}
}

// runtimeCommand is the docker adapter's thin wrapper — always forContainer.
func TestRuntimeCommand_DockerWrapperForcesContainerPython(t *testing.T) {
	assert.Equal(t, []string{"python", "app.py"}, runtimeCommand(types.RuntimePython, "app.py"))
}
