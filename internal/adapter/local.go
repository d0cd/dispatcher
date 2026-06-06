package adapter

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/d0cd/dispatcher/internal/types"
)

// LocalAdapter runs workloads as local processes without Docker.
type LocalAdapter struct{}

// NewLocalAdapter creates a new local process adapter.
func NewLocalAdapter() *LocalAdapter {
	return &LocalAdapter{}
}

func (l *LocalAdapter) ID() string { return "local-process" }

func (l *LocalAdapter) Validate(_ context.Context, w types.WorkloadSpec) (types.ValidationResult, error) {
	v := types.ValidationResult{
		Schema:             types.ValidationPass,
		PackageBuild:       types.ValidationSkipped,
		TargetCapabilities: types.ValidationPass,
		Credentials:        types.ValidationSkipped,
		Quota:              types.ValidationSkipped,
		Network:            types.ValidationPass,
		Policy:             types.ValidationPass,
		CostEstimate:       types.ValidationPass,
		CleanupPlan:        types.ValidationPass,
	}

	if w.Requirements.GPU.Required {
		v.TargetCapabilities = types.ValidationFail
		return v, fmt.Errorf("local process target does not support GPU workloads")
	}

	if w.DetectedKind == types.WorkloadKindService {
		v.TargetCapabilities = types.ValidationWarn
	}

	// Check that the runtime is available
	if bin := runtimeBinary(w.Runtime); bin != "" {
		if _, err := exec.LookPath(bin); err != nil {
			v.TargetCapabilities = types.ValidationFail
			return v, fmt.Errorf("%s runtime not found in PATH", bin)
		}
	}

	return v, nil
}

func (l *LocalAdapter) EstimateCost(_ context.Context, _ types.WorkloadSpec) (types.CostEstimate, error) {
	return types.CostEstimate{
		Value:       0.0,
		Currency:    "USD",
		Confidence:  types.ConfidenceHigh,
		Assumptions: []string{"local execution, zero marginal cost"},
	}, nil
}

func (l *LocalAdapter) Prepare(_ context.Context, p *types.Plan) error {
	w := p.Workload

	// For local process, install dependencies if needed
	switch w.Runtime {
	case types.RuntimePython:
		reqFile := filepath.Join(w.Source.Path, "requirements.txt")
		if _, err := os.Stat(reqFile); err == nil {
			// Check for venv
			venvDir := filepath.Join(w.Source.Path, ".venv")
			if _, err := os.Stat(venvDir); os.IsNotExist(err) {
				// Skip auto-install; just warn
			}
		}
	case types.RuntimeNode:
		nodeModules := filepath.Join(w.Source.Path, "node_modules")
		if _, err := os.Stat(nodeModules); os.IsNotExist(err) {
			pkgJSON := filepath.Join(w.Source.Path, "package.json")
			if _, err := os.Stat(pkgJSON); err == nil {
				// Skip auto-install; just warn
			}
		}
	}

	return nil
}

func (l *LocalAdapter) Execute(ctx context.Context, p *types.Plan) (*RunHandle, error) {
	w := p.Workload

	cmdArgs, err := buildCommand(w)
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Dir = w.Source.Path
	env, err := injectDotEnv(os.Environ(), w.Source.Path)
	if err != nil {
		return nil, err
	}
	cmd.Env = env

	// Capture output via pipe for log persistence
	outR, outW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create output pipe: %w", err)
	}
	cmd.Stdout = outW
	cmd.Stderr = outW

	// Set up process group so we can kill the whole tree
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		outR.Close()
		outW.Close()
		return nil, fmt.Errorf("failed to start process: %w", err)
	}

	ls := &localState{cmd: cmd, started: true, outR: outR, outW: outW}
	ls.logDone = make(chan struct{})

	return &RunHandle{
		ID:       fmt.Sprintf("local-%s-%s", SanitizeName(w.Name), p.Metadata.ID),
		TargetID: "local-process",
		State:    ls,
	}, nil
}

func (l *LocalAdapter) Status(_ context.Context, h *RunHandle) (types.RunState, error) {
	ls := h.State.(*localState)
	err := ls.cmd.Wait()
	// Close write end so the log copy goroutine gets EOF
	if ls.outW != nil {
		ls.outW.Close()
		ls.outW = nil
	}
	// Wait for log copy to finish (only if Logs() was called and started the goroutine)
	if ls.logStarted && ls.logDone != nil {
		<-ls.logDone
	}
	// Close read end
	if ls.outR != nil {
		ls.outR.Close()
		ls.outR = nil
	}
	if err != nil {
		return types.RunStateExecutionFailed, nil
	}
	return types.RunStateCompleted, nil
}

func (l *LocalAdapter) Logs(_ context.Context, h *RunHandle, w io.Writer) error {
	ls := h.State.(*localState)
	if ls.outR != nil && w != nil {
		ls.logStarted = true
		go func() {
			io.Copy(w, ls.outR)
			if ls.logDone != nil {
				close(ls.logDone)
			}
		}()
	}
	return nil
}

func (l *LocalAdapter) Artifacts(_ context.Context, _ *RunHandle) ([]ArtifactRef, error) {
	return nil, nil
}

func (l *LocalAdapter) Terminate(_ context.Context, h *RunHandle) error {
	ls := h.State.(*localState)
	if ls.cmd.Process == nil {
		return nil
	}
	// Kill the process group
	pgid, err := syscall.Getpgid(ls.cmd.Process.Pid)
	if err == nil {
		return syscall.Kill(-pgid, syscall.SIGTERM)
	}
	return ls.cmd.Process.Kill()
}

func (l *LocalAdapter) Cleanup(_ context.Context, _ *RunHandle) (*CleanupResult, error) {
	// Local processes leave no resources to clean up
	return &CleanupResult{Success: true}, nil
}

type localState struct {
	cmd        *exec.Cmd
	started    bool
	outR       *os.File      // read end of output pipe
	outW       *os.File      // write end of output pipe
	logDone    chan struct{}  // closed when log copy goroutine finishes
	logStarted bool          // true after Logs() spawns the goroutine
}

func buildCommand(w types.WorkloadSpec) ([]string, error) {
	// Explicit command takes priority
	if len(w.Command) > 0 {
		return w.Command, nil
	}

	// Build from runtime + entrypoint
	if len(w.Entrypoints) > 0 {
		ep := w.Entrypoints[0]
		// Skip Dockerfiles and compose files as entrypoints
		lower := strings.ToLower(ep)
		if strings.HasPrefix(lower, "dockerfile") || strings.Contains(lower, "compose") {
			// Find next non-docker entrypoint
			for _, e := range w.Entrypoints[1:] {
				l := strings.ToLower(e)
				if !strings.HasPrefix(l, "dockerfile") && !strings.Contains(l, "compose") {
					ep = e
					break
				}
			}
		}
		return RuntimeCommand(w.Runtime, ep, false), nil
	}

	return nil, fmt.Errorf("no command or entrypoint found for local execution")
}

func runtimeBinary(rt types.Runtime) string {
	switch rt {
	case types.RuntimePython:
		return "python3"
	case types.RuntimeNode:
		return "node"
	case types.RuntimeGo:
		return "go"
	case types.RuntimeRuby:
		return "ruby"
	case types.RuntimeRust:
		return "cargo"
	case types.RuntimeJava:
		return "java"
	default:
		return ""
	}
}
