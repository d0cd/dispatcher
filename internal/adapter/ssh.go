package adapter

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/d0cd/dispatcher/internal/types"
)

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
	if s.config.KeyFile != "" {
		rsyncArgs = append(rsyncArgs, "-e",
			fmt.Sprintf("ssh -i %s -p %d", ShellQuote(s.config.KeyFile), s.config.Port))
	} else if s.config.Port != 22 {
		rsyncArgs = append(rsyncArgs, "-e", fmt.Sprintf("ssh -p %d", s.config.Port))
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
	envExports, err := DotEnvExportScript(w.Source.Path)
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
		commandLine = fmt.Sprintf(
			"cd %s\n"+
				"docker build -t %s .\n"+
				"docker run --rm --env-file /dev/stdin %s <<DISPATCHER_ENV_EOF\n"+
				"%s"+
				"DISPATCHER_ENV_EOF\n",
			dir, image, image, dotEnvKVLines(envExports),
		)
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
	go func() {
		defer stdin.Close()
		_, _ = io.WriteString(stdin, commandLine)
	}()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("SSH execution failed: %w", err)
	}

	return &RunHandle{
		ID:       fmt.Sprintf("ssh-%s-%s", SanitizeName(w.Name), p.Metadata.ID),
		TargetID: "ssh",
		State:    &sshState{cmd: cmd},
	}, nil
}

// dotEnvKVLines converts the "export K='V'\n..." form produced by
// DotEnvExportScript into bare "K=V\n..." lines suitable for docker's
// --env-file format (which expects no `export` keyword and no shell quoting).
func dotEnvKVLines(exportScript string) string {
	if exportScript == "" {
		return ""
	}
	var out strings.Builder
	for _, line := range strings.Split(exportScript, "\n") {
		line = strings.TrimPrefix(line, "export ")
		if line == "" {
			continue
		}
		// Strip the single-quotes ShellQuote added: KEY='value' → KEY=value
		if eq := strings.IndexByte(line, '='); eq > 0 {
			key := line[:eq]
			val := line[eq+1:]
			val = strings.TrimPrefix(val, "'")
			val = strings.TrimSuffix(val, "'")
			// Re-escape any embedded "'\''" (ShellQuote's escape) → literal "'"
			val = strings.ReplaceAll(val, `'\''`, "'")
			out.WriteString(key)
			out.WriteByte('=')
			out.WriteString(val)
			out.WriteByte('\n')
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.String()
}

func (s *SSHAdapter) Status(_ context.Context, h *RunHandle) (types.RunState, error) {
	ss := h.State.(*sshState)
	if err := ss.cmd.Wait(); err != nil {
		return types.RunStateExecutionFailed, nil
	}
	return types.RunStateCompleted, nil
}

// Logs is a no-op for the SSH adapter. The remote workload's stdout/stderr
// stream directly through the SSH connection to the local process's stdio;
// dispatcher doesn't intercept them, so there's nothing extra to surface here.
// Returning nil (rather than an "unsupported" error) keeps the executor's
// streaming loop working — it tees the ssh subprocess output elsewhere.
func (s *SSHAdapter) Logs(_ context.Context, _ *RunHandle, _ io.Writer) error {
	return nil
}

// Artifacts is unimplemented for SSH targets. The runner has no convention
// for where a remote workload might write artifacts, so we explicitly return
// (nil, nil) — empty list, no error — to signal "no artifacts available"
// rather than failure. A future change could scp a configured directory back.
func (s *SSHAdapter) Artifacts(_ context.Context, _ *RunHandle) ([]ArtifactRef, error) {
	return nil, nil
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
	args = append(args, fmt.Sprintf("%s@%s", s.config.User, s.config.Host))
	args = append(args, extraArgs...)
	return args
}

type sshState struct {
	cmd *exec.Cmd
}
