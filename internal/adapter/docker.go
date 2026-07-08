package adapter

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/types"
)

// DockerAdapter runs workloads using the local Docker daemon.
type DockerAdapter struct{}

// NewDockerAdapter creates a new local Docker adapter.
func NewDockerAdapter() *DockerAdapter {
	return &DockerAdapter{}
}

func (d *DockerAdapter) ID() string { return "local-docker" }

func (d *DockerAdapter) Validate(ctx context.Context, w types.WorkloadSpec) (types.ValidationResult, error) {
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

	// Check Docker is available
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		v.TargetCapabilities = types.ValidationFail
		return v, fmt.Errorf("docker is not available: %w", err)
	}

	if w.Requirements.GPU.Required {
		v.TargetCapabilities = types.ValidationFail
		return v, fmt.Errorf("local docker does not support GPU workloads")
	}

	return v, nil
}

func (d *DockerAdapter) EstimateCost(_ context.Context, _ types.WorkloadSpec) (types.CostEstimate, error) {
	return types.CostEstimate{
		Value:       0.0,
		Currency:    "USD",
		Confidence:  types.ConfidenceHigh,
		Assumptions: []string{"local execution, zero marginal cost"},
	}, nil
}

func (d *DockerAdapter) Prepare(ctx context.Context, p *types.Plan) error {
	w := p.Workload

	if !w.Package.BuildRequired {
		return nil
	}

	if w.Package.Dockerfile != "" {
		tag := fmt.Sprintf("dispatcher-%s:latest", SanitizeName(w.Name))

		// Content-addressed skip: if the existing image was built from the same
		// Dockerfile+source (recorded in a label), the rebuild is a no-op. A
		// digest error falls back to an unconditional build rather than failing.
		digest, err := buildDigest(w.Package.Dockerfile, w.Source.Path)
		if err == nil && dockerImageLabel(ctx, tag, buildContentLabel) == digest {
			return nil
		}

		args := []string{"build", "-t", tag}
		if digest != "" {
			args = append(args, "--label", buildContentLabel+"="+digest)
		}
		args = append(args, "-f", w.Package.Dockerfile, w.Source.Path)
		output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("docker build failed: %s: %w", string(output), err)
		}
		return nil
	}

	// No Dockerfile — for scripts, we'll run directly
	return nil
}

// dockerImageLabel reads a single label off an image via `docker image inspect`,
// or "" if the image or label is absent. Used to decide whether a rebuild can be
// skipped without shelling out to a full build.
func dockerImageLabel(ctx context.Context, tag, label string) string {
	out, err := exec.CommandContext(ctx, "docker", "image", "inspect",
		"--format", fmt.Sprintf("{{index .Config.Labels %q}}", label),
		tag,
	).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (d *DockerAdapter) Execute(ctx context.Context, p *types.Plan) (*RunHandle, error) {
	w := p.Workload
	var args []string

	containerName := fmt.Sprintf("dispatcher-%s-%s", SanitizeName(w.Name), p.Metadata.ID)

	args = append(args, "run", "--name", containerName, "--rm")

	// Add port mappings
	for _, port := range w.Ports {
		args = append(args, "-p", fmt.Sprintf("%d:%d", port, port))
	}

	// Use --env-file to avoid leaking secret values via `ps`-visible argv.
	// The temp file lives only until docker has read it; cleanup runs in a
	// goroutine after the docker CLI has had time to consume it.
	envFile, envCleanup, err := WriteDotEnvFile(w.Source.Path, w.Env)
	if err != nil {
		return nil, err
	}
	if envFile != "" {
		args = append(args, "--env-file", envFile)
	}

	if w.Package.Dockerfile != "" {
		// Use the built image
		tag := fmt.Sprintf("dispatcher-%s:latest", SanitizeName(w.Name))
		args = append(args, tag)
	} else if w.Package.BaseImage != "" {
		// Two flavors converge here:
		//   - Language base image (python:3.11-slim, etc.) — we mount the
		//     workload source so its code is visible to the interpreter.
		//   - Pre-built image (PackageTypeImage from cfg.Image) — the user
		//     is running a packaged tool, NOT their own code. Mounting
		//     source would shadow the image's /app and break it.
		if w.Package.Type != types.PackageTypeImage {
			args = append(args, "-v", w.Source.Path+":/app", "-w", "/app")
		}
		args = append(args, w.Package.BaseImage)
		if len(w.Command) > 0 {
			args = append(args, w.Command...)
		} else if w.Package.Type != types.PackageTypeImage && len(w.Entrypoints) > 0 {
			// Pre-built images use the image's own ENTRYPOINT/CMD; don't
			// override unless the user explicitly set `command:` in yaml.
			args = append(args, runtimeCommand(w.Runtime, w.Entrypoints[0])...)
		}
	} else {
		envCleanup() // no dockerState will be created to own the env temp file
		return nil, fmt.Errorf("no image or base image available")
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	if err := cmd.Start(); err != nil {
		envCleanup()
		return nil, fmt.Errorf("docker run failed: %w", err)
	}

	return &RunHandle{
		ID:       containerName,
		TargetID: "local-docker",
		State: &dockerState{
			cmd:            cmd,
			containerName:  containerName,
			envFileCleanup: envCleanup,
		},
	}, nil
}

func (d *DockerAdapter) Status(ctx context.Context, h *RunHandle) (types.RunState, error) {
	ds := h.State.(*dockerState)
	if ds.cmd.ProcessState != nil && ds.cmd.ProcessState.Exited() {
		if ds.cmd.ProcessState.ExitCode() != 0 {
			return types.RunStateExecutionFailed, nil
		}
		return types.RunStateCompleted, nil
	}

	// Wait for the process
	if err := ds.cmd.Wait(); err != nil {
		return types.RunStateExecutionFailed, nil
	}
	return types.RunStateCompleted, nil
}

func (d *DockerAdapter) Logs(ctx context.Context, h *RunHandle, w io.Writer) error {
	cmd := exec.CommandContext(ctx, "docker", "logs", "-f", h.ID)
	cmd.Stdout = w
	cmd.Stderr = w
	return cmd.Run()
}

func (d *DockerAdapter) Artifacts(_ context.Context, _ *RunHandle) ([]ArtifactRef, error) {
	return nil, nil
}

// FailureDetails reads `docker inspect` to surface ExitCode and the explicit
// OOMKilled flag Docker maintains on container state. Implements
// FailureReporter — a real signal for retry classification.
//
// Best-effort: if `docker inspect` fails (container already removed, daemon
// hiccup), we return a Message-only result rather than failing the run.
func (d *DockerAdapter) FailureDetails(h *RunHandle) FailureDetails {
	// Bounded timeout so a hung docker daemon doesn't stall failure
	// reporting. 10s is generous; docker inspect normally returns in ms.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{.State.ExitCode}}|{{.State.OOMKilled}}|{{.State.Error}}",
		h.ID,
	).Output()
	if err != nil {
		return FailureDetails{Message: "docker inspect unavailable (container may have been removed)"}
	}
	return parseDockerInspect(string(out))
}

// parseDockerInspect turns the `{{.State.ExitCode}}|{{.State.OOMKilled}}|{{.State.Error}}`
// inspect output into FailureDetails. Separated from the exec so the
// classification (OOM→SIGKILL, exit code, secret-truncated message) is testable
// without a docker daemon.
func parseDockerInspect(raw string) FailureDetails {
	parts := strings.SplitN(strings.TrimSpace(raw), "|", 3)
	if len(parts) < 2 {
		return FailureDetails{Message: "docker inspect returned unexpected shape"}
	}
	fd := FailureDetails{}
	if code, err := strconv.Atoi(parts[0]); err == nil {
		fd.ExitCode = code
	}
	fd.OOMKilled = parts[1] == "true"
	if len(parts) == 3 && parts[2] != "" {
		// Truncate so a verbose container error (which may include workload
		// stderr; could contain secrets like "connect failed: password=…")
		// doesn't bleed into logs and persisted run records in full.
		fd.Message = truncateFailureMessage(parts[2])
	}
	switch {
	case fd.OOMKilled:
		fd.Message = "container OOM-killed"
		fd.Signal = "SIGKILL"
	case fd.Message == "" && fd.ExitCode != 0:
		fd.Message = fmt.Sprintf("container exited with code %d", fd.ExitCode)
	}
	return fd
}

func (d *DockerAdapter) Terminate(ctx context.Context, h *RunHandle) error {
	return exec.CommandContext(ctx, "docker", "stop", h.ID).Run()
}

func (d *DockerAdapter) Cleanup(ctx context.Context, h *RunHandle) (*CleanupResult, error) {
	// --rm flag should handle this, but try explicit removal
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", h.ID).Run()

	// Delete the --env-file tempfile created in Execute. By cleanup time
	// docker has already consumed it; we just remove the now-unused secret
	// material so it doesn't linger on disk.
	if ds, ok := h.State.(*dockerState); ok && ds.envFileCleanup != nil {
		ds.envFileCleanup()
		ds.envFileCleanup = nil // idempotent
	}

	return &CleanupResult{
		Success:          true,
		ResourcesCleaned: []string{h.ID},
	}, nil
}

type dockerState struct {
	cmd           *exec.Cmd
	containerName string
	// envFileCleanup removes the temp env file passed via --env-file. Called
	// from Cleanup() rather than a time.Sleep goroutine so we don't leak the
	// file if dispatcher dies between cmd.Start and the timer firing.
	envFileCleanup func()
}

func runtimeCommand(rt types.Runtime, entrypoint string) []string {
	return RuntimeCommand(rt, entrypoint, true)
}
