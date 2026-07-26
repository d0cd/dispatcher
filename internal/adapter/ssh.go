package adapter

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/d0cd/dispatcher/internal/state"
	"github.com/d0cd/dispatcher/internal/types"
)

// runRsync runs rsync. It's a package-level seam so artifact retrieval can be
// tested by capturing argv without a live SSH host.
var runRsync = func(ctx context.Context, args ...string) error {
	return exec.CommandContext(ctx, "rsync", args...).Run()
}

// strictHostKeyChecking pins ssh's StrictHostKeyChecking mode. `accept-new`
// trusts a host's key on first contact (so legitimate first connections work)
// but refuses if a known key later changes — matching internal/cli/recover.go.
const strictHostKeyChecking = "StrictHostKeyChecking=accept-new"

// SSHConfig holds connection details for an SSH target.
type SSHConfig struct {
	Host      string
	User      string
	Port      int
	KeyFile   string
	RemoteDir string
}

// SSHAdapter runs workloads on a remote machine via SSH.
type SSHAdapter struct {
	config SSHConfig
}

// NewSSHAdapter creates a new SSH adapter with the given config.
func NewSSHAdapter(cfg SSHConfig) *SSHAdapter {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.RemoteDir == "" {
		cfg.RemoteDir = "/tmp/dispatcher"
	}
	return &SSHAdapter{config: cfg}
}

func (s *SSHAdapter) ID() string { return "ssh" }

func (s *SSHAdapter) Validate(ctx context.Context, w types.WorkloadSpec) (types.ValidationResult, error) {
	v := types.ValidationResult{
		Schema:             types.ValidationPass,
		PackageBuild:       types.ValidationPass,
		TargetCapabilities: types.ValidationPass,
		Credentials:        types.ValidationSkipped,
		Quota:              types.ValidationSkipped,
		Network:            types.ValidationPass,
		Policy:             types.ValidationPass,
		CostEstimate:       types.ValidationPass,
		CleanupPlan:        types.ValidationPass,
	}

	// Test SSH connectivity
	args := s.sshArgs("-o", "ConnectTimeout=5", "echo", "ok")
	if err := exec.CommandContext(ctx, "ssh", args...).Run(); err != nil {
		v.TargetCapabilities = types.ValidationFail
		return v, fmt.Errorf("SSH connection failed: %w", err)
	}

	if w.Requirements.GPU.Required {
		v.TargetCapabilities = types.ValidationFail
		return v, fmt.Errorf("SSH target does not support GPU workloads")
	}

	return v, nil
}

func (s *SSHAdapter) EstimateCost(_ context.Context, _ types.WorkloadSpec) (types.CostEstimate, error) {
	return types.CostEstimate{
		Value:       0.10,
		Currency:    "USD",
		Confidence:  types.ConfidenceMedium,
		Assumptions: []string{"assumes 1h runtime on existing SSH host"},
	}, nil
}

func (s *SSHAdapter) Prepare(ctx context.Context, p *types.Plan) error {
	w := p.Workload

	// Create remote directory
	mkdirArgs := s.sshArgs("mkdir", "-p", s.config.RemoteDir)
	if err := exec.CommandContext(ctx, "ssh", mkdirArgs...).Run(); err != nil {
		return fmt.Errorf("failed to create remote directory: %w", err)
	}

	// Sync source files via rsync. rsync's `-e` value is re-parsed with
	// shell-like splitting, so any space/metachar in KeyFile would break
	// (or worse, inject) the SSH command. ShellQuote the key path; port
	// is an int and safe as-is.
	dest := fmt.Sprintf("%s@%s:%s/", s.config.User, s.config.Host, s.config.RemoteDir)
	rsyncArgs := []string{"-az", "--delete"}
	if e := rsyncSSHCmd(s.config); e != "" {
		rsyncArgs = append(rsyncArgs, "-e", e)
	}
	rsyncArgs = append(rsyncArgs, w.Source.Path+"/", dest)

	if err := exec.CommandContext(ctx, "rsync", rsyncArgs...).Run(); err != nil {
		return fmt.Errorf("rsync failed: %w", err)
	}

	return nil
}

func (s *SSHAdapter) Execute(ctx context.Context, p *types.Plan) (*RunHandle, error) {
	w := p.Workload

	// Build a bash script that exports the workload's .env and execs the
	// command. Stream it over stdin into `ssh ... bash -s` so the secret
	// values never appear in local or remote process argv (visible via `ps`).
	envExports, err := DotEnvExportScript(w.Source.Path, w.Env)
	if err != nil {
		return nil, err
	}

	var commandLine string
	dir := ShellQuote(s.config.RemoteDir)
	if w.Package.Dockerfile != "" {
		tag := SanitizeName(w.Name)
		// Docker run on the remote: pass env to the container via stdin too,
		// using `--env-file /dev/stdin` so values aren't in the docker argv.
		// We construct two stdin scripts — outer for cd+build, inner for
		// docker via heredoc — keeping all secret material off any argv.
		image := ShellQuote("dispatcher-" + tag + ":latest")
		envFileLines, err := DotEnvFileLines(w.Source.Path, w.Env)
		if err != nil {
			return nil, err
		}
		commandLine = sshDockerRunScript(dir, image, envFileLines)
	} else if len(w.Command) > 0 {
		commandLine = fmt.Sprintf("cd %s\n%sexec %s\n", dir, envExports, ShellQuoteArgs(w.Command))
	} else if len(w.Entrypoints) > 0 {
		cmdParts := runtimeCommand(w.Runtime, w.Entrypoints[0])
		commandLine = fmt.Sprintf("cd %s\n%sexec %s\n", dir, envExports, ShellQuoteArgs(cmdParts))
	} else {
		return nil, fmt.Errorf("no command or entrypoint for SSH execution")
	}

	args := s.sshArgs("bash", "-s")
	cmd := exec.CommandContext(ctx, "ssh", args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("ssh stdin pipe: %w", err)
	}
	// Capture the remote workload's stdout+stderr through a pipe so Logs() can
	// stream it to the run's log. Without this the ssh subprocess inherits no
	// stdio and its output goes to /dev/null. The parent closes its write end
	// after Start so the reader sees EOF when the remote command exits.
	logsR, logsW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("ssh output pipe: %w", err)
	}
	cmd.Stdout = logsW
	cmd.Stderr = logsW
	go func() {
		defer stdin.Close()
		_, _ = io.WriteString(stdin, commandLine)
	}()

	if err := cmd.Start(); err != nil {
		logsR.Close()
		logsW.Close()
		return nil, fmt.Errorf("SSH execution failed: %w", err)
	}
	logsW.Close() // child holds the only remaining write end

	return &RunHandle{
		ID:       fmt.Sprintf("ssh-%s-%s", SanitizeName(w.Name), p.Metadata.ID),
		TargetID: "ssh",
		State:    &sshState{cmd: cmd, outputs: w.Outputs, logs: logsR},
	}, nil
}

// sshDockerRunScript builds the remote bash for the Dockerfile branch: build
// the image, then run it feeding the workload .env via `--env-file /dev/stdin`
// from a heredoc. The heredoc delimiter is SINGLE-QUOTED ('DISPATCHER_ENV_EOF')
// so the remote shell performs no expansion on the env body — a value like
// FOO=$(cmd) or FOO=`cmd` is handed to docker literally instead of executing
// cmd on the host. DotEnvFileLines additionally guarantees no value contains a
// newline or the terminator token. quotedDir and quotedImage must already be
// shell-quoted by the caller.
func sshDockerRunScript(quotedDir, quotedImage, envFileLines string) string {
	return fmt.Sprintf(
		"cd %s\n"+
			"docker build -t %s .\n"+
			"docker run --rm --env-file /dev/stdin %s <<'DISPATCHER_ENV_EOF'\n"+
			"%s"+
			"DISPATCHER_ENV_EOF\n",
		quotedDir, quotedImage, quotedImage, envFileLines,
	)
}

func (s *SSHAdapter) Status(_ context.Context, h *RunHandle) (types.RunState, error) {
	ss := h.State.(*sshState)
	// Drain the output pipe before Wait so a remote command emitting more than the
	// pipe buffer cannot block on write and deadlock cmd.Wait(). On the first
	// attempt Logs() drains it; here we cover the paths where Logs() is skipped.
	drained := ss.startDiscardDrain()
	err := ss.cmd.Wait()
	if drained != nil {
		<-drained
	}
	if err != nil {
		return types.RunStateExecutionFailed, nil
	}
	return types.RunStateCompleted, nil
}

// Logs drains the ssh subprocess's combined stdout/stderr (captured via the
// pipe wired in Execute) to w. It blocks until the remote command exits and the
// pipe reaches EOF, mirroring the docker adapter's `docker logs -f` behavior so
// the executor's streaming loop surfaces remote output. A handle without a live
// pipe (reconstructed outside Execute) is a no-op.
func (s *SSHAdapter) Logs(_ context.Context, h *RunHandle, w io.Writer) error {
	ss, ok := h.State.(*sshState)
	if !ok || ss.logs == nil {
		return nil
	}
	ss.mu.Lock()
	if ss.logStarted {
		ss.mu.Unlock()
		return nil // Status() already claimed the drain
	}
	ss.logStarted = true
	ss.mu.Unlock()
	defer ss.logs.Close()
	_, err := io.Copy(w, ss.logs)
	return err
}

// Artifacts retrieves each workload-declared output path from the remote
// working dir into the run's local artifacts tree via rsync. It mirrors the
// cloud-VM adapter's hardening: output paths that are absolute, contain `..`,
// or would escape the artifacts root are rejected; `--safe-links` blocks a
// workload from planting a symlink to a host file, and `--protect-args` stops
// the remote shell from re-tokenizing the path.
func (s *SSHAdapter) Artifacts(ctx context.Context, h *RunHandle) ([]ArtifactRef, error) {
	ss, ok := h.State.(*sshState)
	if !ok || len(ss.outputs) == 0 {
		return nil, nil
	}

	indexKey := h.RunID
	if indexKey == "" {
		indexKey = h.ID
	}
	dest, err := state.Subdir(filepath.Join("runs", indexKey, "artifacts"))
	if err != nil {
		return nil, fmt.Errorf("create artifacts dir: %w", err)
	}
	rootAbs, err := filepath.Abs(dest)
	if err != nil {
		return nil, fmt.Errorf("resolve artifacts dir: %w", err)
	}

	eArg := rsyncSSHCmd(s.config)

	var refs []ArtifactRef
	var firstErr error
	for _, out := range ss.outputs {
		if filepath.IsAbs(out) || strings.Contains(out, "..") {
			if firstErr == nil {
				firstErr = fmt.Errorf("rejected output path %q (absolute or traversal)", out)
			}
			continue
		}
		remoteSrc := fmt.Sprintf("%s@%s:%s/%s", s.config.User, s.config.Host, s.config.RemoteDir, out)
		localDest := filepath.Join(dest, filepath.Clean(out))
		destAbs, err := filepath.Abs(localDest)
		if err != nil || !strings.HasPrefix(destAbs+string(filepath.Separator), rootAbs+string(filepath.Separator)) {
			if firstErr == nil {
				firstErr = fmt.Errorf("output %q escapes artifacts root", out)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(localDest), 0o700); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("mkdir %s: %w", filepath.Dir(localDest), err)
			}
			continue
		}

		args := []string{"-az", "--safe-links", "--protect-args"}
		if eArg != "" {
			args = append(args, "-e", eArg)
		}
		args = append(args, remoteSrc, localDest)
		if err := runRsync(ctx, args...); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("rsync %s: %w", out, err)
			}
			continue
		}

		_ = filepath.Walk(localDest, func(p string, info os.FileInfo, _ error) error {
			if info == nil || info.IsDir() {
				return nil
			}
			refs = append(refs, ArtifactRef{Name: filepath.Base(p), Path: p, Size: info.Size()})
			return nil
		})
	}
	return refs, firstErr
}

func (s *SSHAdapter) Terminate(ctx context.Context, h *RunHandle) error {
	ss := h.State.(*sshState)
	if ss.cmd.Process != nil {
		return ss.cmd.Process.Kill()
	}
	return nil
}

// FailureDetails reads the local ssh process's exit code. OpenSSH propagates
// the remote command's exit status (when ssh itself succeeds) so for typical
// failures we get the workload's exit code directly. Exit 255 specifically
// means "ssh itself failed" (network glitch, key reject, etc.) — we surface
// that as a SIGKILL-equivalent transient signal so the retry classifier can
// distinguish it from a real workload bug.
func (s *SSHAdapter) FailureDetails(h *RunHandle) FailureDetails {
	ss, ok := h.State.(*sshState)
	if !ok || ss.cmd == nil || ss.cmd.ProcessState == nil {
		return FailureDetails{Message: "ssh process state not available"}
	}
	code := ss.cmd.ProcessState.ExitCode()
	fd := FailureDetails{ExitCode: code}
	switch {
	case code == 255:
		// OpenSSH reserves 255 for transport-level failures: connection
		// refused, host key reject, network timeout. Classify as transient
		// so --retry-transient retries the SSH connection.
		fd.Signal = "SIGKILL"
		fd.Message = "ssh transport failed (exit 255)"
	case code != 0:
		fd.Message = fmt.Sprintf("remote command exited with code %d", code)
	}
	return fd
}

func (s *SSHAdapter) Cleanup(ctx context.Context, _ *RunHandle) (*CleanupResult, error) {
	// Validate RemoteDir before running `rm -rf`. A typo or malicious
	// target config of RemoteDir: "/" (or ".", or "" → which would `rm -rf`
	// the SSH user's $HOME on the remote) would otherwise wipe the host.
	// Require an absolute path with at least two non-empty segments and
	// reject the obvious foot-guns.
	if err := validateRemoteDir(s.config.RemoteDir); err != nil {
		return &CleanupResult{
			Success: false,
			Errors:  []string{fmt.Sprintf("refusing to clean RemoteDir %q: %v", s.config.RemoteDir, err)},
		}, nil
	}
	args := s.sshArgs("rm", "-rf", "--", s.config.RemoteDir)
	if err := exec.CommandContext(ctx, "ssh", args...).Run(); err != nil {
		return &CleanupResult{
			Success: false,
			Errors:  []string{err.Error()},
		}, nil
	}
	return &CleanupResult{
		Success:          true,
		ResourcesCleaned: []string{s.config.RemoteDir},
	}, nil
}

// validateRemoteDir rejects RemoteDir values that would make `rm -rf` a
// foot-gun on the remote host: empty, relative, "/", "/<single-segment>",
// or anything containing `..` segments.
//
// The bar is intentionally conservative — we'd rather refuse a working
// path than nuke someone's $HOME because of a config typo.
func validateRemoteDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("RemoteDir is empty")
	}
	if !strings.HasPrefix(dir, "/") {
		return fmt.Errorf("RemoteDir must be absolute")
	}
	if strings.Contains(dir, "..") {
		return fmt.Errorf("RemoteDir contains traversal")
	}
	// Cleanup passes RemoteDir into `ssh ... rm -rf -- <dir>`, which the remote
	// shell re-tokenizes; a metacharacter or whitespace could start a second
	// command past the `--` guard. Reject anything but ordinary path bytes.
	if strings.ContainsAny(dir, " \t\r\n;&|$`<>(){}[]*?!#~'\"\\") {
		return fmt.Errorf("RemoteDir contains shell metacharacters or whitespace")
	}
	// Count non-empty path segments. "/" → 0, "/tmp" → 1, "/tmp/x" → 2.
	parts := strings.Split(strings.Trim(dir, "/"), "/")
	nonEmpty := 0
	for _, p := range parts {
		if p != "" {
			nonEmpty++
		}
	}
	if nonEmpty < 2 {
		return fmt.Errorf("RemoteDir must have at least two path components (got %q)", dir)
	}
	return nil
}

func (s *SSHAdapter) sshArgs(extraArgs ...string) []string {
	var args []string
	if s.config.KeyFile != "" {
		args = append(args, "-i", s.config.KeyFile)
	}
	args = append(args, "-p", fmt.Sprintf("%d", s.config.Port))
	args = append(args, "-o", strictHostKeyChecking)
	args = append(args, fmt.Sprintf("%s@%s", s.config.User, s.config.Host))
	args = append(args, extraArgs...)
	return args
}

// rsyncSSHCmd builds the `ssh ...` command string for rsync's `-e` option.
// KeyFile is ShellQuoted because rsync re-parses the value with shell-like
// splitting; port is an int and safe as-is. Returns "" when neither a key
// nor a non-default port needs to be specified.
func rsyncSSHCmd(cfg SSHConfig) string {
	if cfg.KeyFile != "" {
		return fmt.Sprintf("ssh -o %s -i %s -p %d", strictHostKeyChecking, ShellQuote(cfg.KeyFile), cfg.Port)
	}
	if cfg.Port != 22 {
		return fmt.Sprintf("ssh -o %s -p %d", strictHostKeyChecking, cfg.Port)
	}
	return ""
}

type sshState struct {
	cmd     *exec.Cmd
	outputs []string
	// logs is the read end of the pipe the ssh subprocess writes its combined
	// stdout/stderr to; Logs() drains it to the run's logWriter. nil for handles
	// reconstructed outside Execute (e.g. Artifacts-only test fixtures).
	logs *os.File
	// mu guards logStarted so Logs() and Status() never both drain the pipe. The
	// first to claim it owns the reader; the other is a no-op.
	mu         sync.Mutex
	logStarted bool
}

// startDiscardDrain starts a goroutine copying the log pipe to io.Discard unless a
// drain (Logs) already claimed it, returning a channel closed when the drain
// finishes (nil if none was started). Without this, cmd.Wait() deadlocks whenever
// the remote command emits more than the ~64 KiB pipe buffer and no Logs()
// consumer drains it (the transient-retry path and the logWriter==nil attempt).
func (ss *sshState) startDiscardDrain() <-chan struct{} {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.logStarted || ss.logs == nil {
		return nil
	}
	ss.logStarted = true
	r := ss.logs
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, r)
		r.Close()
		close(done)
	}()
	return done
}
