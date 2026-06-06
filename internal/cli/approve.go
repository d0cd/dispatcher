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
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return resolveApproval(args[0], approval.DecisionApproved)
	},
}

var denyCmd = &cobra.Command{
	Use:   "deny <run-id>",
	Short: "Deny a pending policy requirement for a run",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return resolveApproval(args[0], approval.DecisionDenied)
	},
}

func resolveApproval(runID string, d approval.Decision) error {
	rec, err := approval.Resolve(runID, d, currentUser())
	if err != nil {
		return err
	}
	c := color.New(color.FgGreen)
	if d == approval.DecisionDenied {
		c = color.New(color.FgRed)
	}
	c.Fprintf(os.Stderr, "%s %s\n", d, rec.RunID)
	for _, req := range rec.Requirements {
		fmt.Fprintf(os.Stderr, "  - %s: %s\n", req.Name, req.Reason)
	}
	return nil
}

func currentUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

func init() {
	rootCmd.AddCommand(approveCmd)
	rootCmd.AddCommand(denyCmd)
}
