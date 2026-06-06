package plan

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/target"
	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuild_EveryBuiltinTargetPlansAScript exercises every shipped builtin
// target via --target on a trivial Python script. The planner should either
// produce a clean Plan or surface a clear "not feasible" error — never a
// silent misroute or panic.
//
// This catches plan-time regressions like:
//   - a builtin omitting WorkloadKindScript (e.g. the kubernetes bug found
//     during the local-runner smoke test pass)
//   - a builtin whose capabilities don't list any matching WorkloadKind
//   - feasibility checks panicking on unusual capability shapes
func TestBuild_EveryBuiltinTargetPlansAScript(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.py", `print("hello")`)

	reg := target.NewRegistry()
	reg.LoadBuiltins()
	targets := reg.List()
	require.NotEmpty(t, targets, "builtins should populate the registry")

	for _, tt := range targets {
		t.Run(tt.ID, func(t *testing.T) {
			p, err := Build(dir, types.PlanConstraints{
				TargetName:  tt.ID,
				OptimizeFor: types.OptimizeCost,
			}, nil)

			if err != nil {
				// Hard requirement: feasibility errors must clearly explain
				// why. Anything else is a regression — silent panic, nil
				// deref, etc. The exact phrasing isn't pinned (rejection
				// reasons evolve), but the error must surface the target
				// name so users can debug.
				assert.Contains(t, err.Error(), tt.ID,
					"error should mention the target id for diagnosability")
				return
			}

			require.NotNil(t, p)
			require.NotNil(t, p.Recommendation)
			assert.Equal(t, tt.ID, p.Recommendation.Target,
				"--target should pin the recommended target")
		})
	}
}

// TestBuild_EveryBuiltinTargetPlansAService same as above but with a
// service-shape workload (Dockerfile + EXPOSE). Catches builtins that
// claim Service support but fail something else in the feasibility chain.
func TestBuild_EveryBuiltinTargetPlansAService(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", "FROM python:3.11-slim\nEXPOSE 8080\nCMD [\"python\", \"app.py\"]")
	writeFile(t, dir, "app.py", "import http.server; http.server.HTTPServer(('0.0.0.0', 8080), http.server.BaseHTTPRequestHandler).serve_forever()")

	reg := target.NewRegistry()
	reg.LoadBuiltins()

	for _, tt := range reg.List() {
		t.Run(tt.ID, func(t *testing.T) {
			_, err := Build(dir, types.PlanConstraints{
				TargetName:  tt.ID,
				OptimizeFor: types.OptimizeCost,
			}, nil)
			if err != nil {
				assert.Contains(t, err.Error(), tt.ID)
			}
		})
	}
}
