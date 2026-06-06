package adapter

import (
	"context"
	"fmt"
	"io"
	"os/exec"

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
		// Build from existing Dockerfile
		tag := fmt.Sprintf("dispatcher-%s:latest", SanitizeName(w.Name))
		cmd := exec.CommandContext(ctx, "docker", "build",
			"-t", tag,
			"-f", w.Package.Dockerfile,
			w.Source.Path,
		)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("docker build failed: %s: %w", string(output), err)
		}
		return nil
	}

	// No Dockerfile — for scripts, we'll run directly
	return nil
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

	envArgs, err := DotEnvArgs(w.Source.Path)
	if err != nil {
		return nil, err
	}
	args = append(args, envArgs...)

	if w.Package.Dockerfile != "" {
		// Use the built image
		tag := fmt.Sprintf("dispatcher-%s:latest", SanitizeName(w.Name))
		args = append(args, tag)
	} else if w.Package.BaseImage != "" {
		// Mount source and run with base image
		args = append(args, "-v", w.Source.Path+":/app", "-w", "/app")
		args = append(args, w.Package.BaseImage)
		if len(w.Command) > 0 {
			args = append(args, w.Command...)
		} else if len(w.Entrypoints) > 0 {
			args = append(args, runtimeCommand(w.Runtime, w.Entrypoints[0])...)
		}
	} else {
		return nil, fmt.Errorf("no image or base image available")
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("docker run failed: %w", err)
	}

	return &RunHandle{
		ID:       containerName,
		TargetID: "local-docker",
		State: &dockerState{
			cmd:           cmd,
			containerName: containerName,
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

func (d *DockerAdapter) Terminate(ctx context.Context, h *RunHandle) error {
	return exec.CommandContext(ctx, "docker", "stop", h.ID).Run()
}

func (d *DockerAdapter) Cleanup(ctx context.Context, h *RunHandle) (*CleanupResult, error) {
	// --rm flag should handle this, but try explicit removal
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", h.ID).Run()
	return &CleanupResult{
		Success:          true,
		ResourcesCleaned: []string{h.ID},
	}, nil
}

type dockerState struct {
	cmd           *exec.Cmd
	containerName string
}

func runtimeCommand(rt types.Runtime, entrypoint string) []string {
	return RuntimeCommand(rt, entrypoint, true)
}
