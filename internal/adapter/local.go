package adapter

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	statedir "github.com/d0cd/dispatcher/internal/state"
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
	env, err := injectDotEnv(os.Environ(), w.Source.Path, w.Env)
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

	ls := &localState{cmd: cmd, started: true, outR: outR, outW: outW, sourcePath: w.Source.Path, outputs: w.Outputs}
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

	// Close write end so the log-copy goroutine gets EOF, then wait for it
	// to finish before closing the read end. Mutex serializes against a
	// concurrent Logs() call so we can't observe logStarted=false and miss
	// the wait while Logs is mid-spawn.
	ls.mu.Lock()
	if ls.outW != nil {
		ls.outW.Close()
		ls.outW = nil
	}
	waitFor := ls.logStarted && ls.logDone != nil
	done := ls.logDone
	ls.mu.Unlock()

	if waitFor {
		<-done
	}

	ls.mu.Lock()
	if ls.outR != nil {
		ls.outR.Close()
		ls.outR = nil
	}
	ls.mu.Unlock()

	if err != nil {
		return types.RunStateExecutionFailed, nil
	}
	return types.RunStateCompleted, nil
}

func (l *LocalAdapter) Logs(_ context.Context, h *RunHandle, w io.Writer) error {
	ls := h.State.(*localState)
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.outR == nil || w == nil {
		// Pipe is already closed (Status ran) or no writer — nothing to do.
		return nil
	}
	if ls.logStarted {
		// Logs already started; second caller would race the first.
		return nil
	}
	ls.logStarted = true
	r := ls.outR
	done := ls.logDone
	go func() {
		_, _ = io.Copy(w, r)
		if done != nil {
			close(done)
		}
	}()
	return nil
}

// Artifacts copies the workload's declared outputs from the source dir into
// runs/<run-id>/artifacts/, so a local run's outputs are preserved as a snapshot
// (and are aggregatable when sharded). Output paths are validated against
// absolute/traversal escapes, and symlinks are never followed — the workload is
// arbitrary code and must not be able to snapshot files outside its source tree
// by planting a symlink. A missing output (never produced) is skipped, not an
// error.
func (l *LocalAdapter) Artifacts(_ context.Context, h *RunHandle) ([]ArtifactRef, error) {
	ls, ok := h.State.(*localState)
	if !ok || len(ls.outputs) == 0 {
		return nil, nil
	}
	indexKey := h.RunID
	if indexKey == "" {
		indexKey = h.ID
	}
	destRoot, err := statedir.Subdir(filepath.Join("runs", indexKey, "artifacts"))
	if err != nil {
		return nil, fmt.Errorf("create artifacts dir: %w", err)
	}
	rootAbs, err := filepath.Abs(destRoot)
	if err != nil {
		return nil, err
	}

	var refs []ArtifactRef
	for _, out := range ls.outputs {
		if filepath.IsAbs(out) || strings.Contains(out, "..") {
			continue // defense in depth; config load is the primary gate
		}
		dst := filepath.Join(destRoot, filepath.Clean(out))
		dstAbs, err := filepath.Abs(dst)
		if err != nil || !strings.HasPrefix(dstAbs+string(filepath.Separator), rootAbs+string(filepath.Separator)) {
			continue // escapes the artifacts root
		}
		src := filepath.Join(ls.sourcePath, out)
		info, err := os.Lstat(src)
		if err != nil {
			continue // output not produced by this run
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			continue // a symlinked output could point outside the source tree
		}
		if err := copyPath(src, dst); err != nil {
			return refs, fmt.Errorf("copy output %q: %w", out, err)
		}
		refs = append(refs, ArtifactRef{Name: filepath.Base(out), Path: dst, Size: info.Size()})
	}
	return refs, nil
}

// copyPath copies a file or directory tree from src to dst. Symlinks are never
// followed: a symlinked root is refused and symlinked entries in a walked tree
// are skipped, so a copy can't escape src by dereferencing a link.
func copyPath(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return nil
	}
	if !info.IsDir() {
		return copyFile(src, dst, info.Mode())
	}
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // don't copy a symlink's target out of the tree
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		return copyFile(p, target, fi.Mode())
	})
}

func copyFile(src, dst string, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode.Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// FailureDetails returns the process exit code and (on Unix) signal name.
// Implements FailureReporter.
//
// Local-process can't reliably distinguish OOM from other SIGKILLs without
// reading /sys/fs/cgroup or dmesg — we conservatively set OOMKilled=false
// and let the classifier treat SIGKILL as "possibly transient" instead.
func (l *LocalAdapter) FailureDetails(h *RunHandle) FailureDetails {
	ls, ok := h.State.(*localState)
	if !ok || ls.cmd == nil || ls.cmd.ProcessState == nil {
		return FailureDetails{Message: "process state not available"}
	}
	ps := ls.cmd.ProcessState
	fd := FailureDetails{ExitCode: ps.ExitCode()}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok {
		if ws.Signaled() {
			fd.Signal = ws.Signal().String()
		}
	}
	switch {
	case fd.Signal != "":
		fd.Message = fmt.Sprintf("killed by %s", fd.Signal)
	case fd.ExitCode != 0:
		fd.Message = fmt.Sprintf("exited with code %d", fd.ExitCode)
	}
	return fd
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

// localState carries the running command and its log-pipe plumbing. mu
// serializes Logs()/Status() so a concurrent caller can't read outR after
// Status() has closed it (the race the audit flagged).
type localState struct {
	mu         sync.Mutex
	cmd        *exec.Cmd
	started    bool
	outR       *os.File      // read end of output pipe
	outW       *os.File      // write end of output pipe
	logDone    chan struct{} // closed when log copy goroutine finishes
	logStarted bool          // true after Logs() spawns the goroutine
	sourcePath string        // workload dir, where outputs are produced
	outputs    []string      // workload-relative paths to collect
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
