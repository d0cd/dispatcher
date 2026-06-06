package cli

import (
	"fmt"
	"os"
	"os/user"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/approval"
)

var approveCmd = &cobra.Command{
	Use:   "approve <run-id>",
	Short: "Approve a pending policy requirement for a run",
	Long: `Approve a pending policy requirement, unblocking a run that's waiting for
explicit authorization (GPU usage, secrets on external providers, public
endpoints, etc.).

The run process opens a per-run Unix socket while it waits. This command
connects to that socket and delivers the decision; filesystem permissions
(0700 dir, 0600 socket) ensure only the dispatcher user can approve.

Use 'dispatcher list' to find runs in 'awaiting-approval' state. If the
target run has already exited (crash, ctrl-c, completed), this command
returns an error rather than silently succeeding.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return deliverDecision(args[0], approval.DecisionApproved)
	},
}

var denyCmd = &cobra.Command{
	Use:   "deny <run-id>",
	Short: "Deny a pending policy requirement for a run",
	Long: `Deny a pending policy requirement. The run transitions to
'approval-denied' and the executor exits without provisioning resources.

The dispatcher run process must still be active (the gate lives in-process).
Use 'dispatcher list' to find runs in 'awaiting-approval' state.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return deliverDecision(args[0], approval.DecisionDenied)
	},
}

func deliverDecision(runID string, d approval.Decision) error {
	if err := approval.SendDecision(runID, d, currentUser()); err != nil {
		return fmt.Errorf("%s %s: %w", d, runID, err)
	}
	c := color.New(color.FgGreen)
	if d == approval.DecisionDenied {
		c = color.New(color.FgRed)
	}
	c.Fprintf(os.Stderr, "%s %s\n", d, runID)
	return nil
}

// currentUser returns the OS username for the audit decider field. Falls
// back to "unknown" rather than empty so an audit record always names the
// actor — empty strings are how the old codebase swallowed errors.
func currentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "unknown"
}

func init() {
	rootCmd.AddCommand(approveCmd)
	rootCmd.AddCommand(denyCmd)
}
