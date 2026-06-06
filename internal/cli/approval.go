package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"

	"github.com/d0cd/dispatcher/internal/run"
	"github.com/d0cd/dispatcher/internal/types"
)

// terminalApproval prompts the user in the terminal for each required approval.
// Returns nil if all approved, run.ErrApprovalDenied if any denied.
func terminalApproval(approvals []types.PolicyRequirement) error {
	bold := color.New(color.Bold)
	yellow := color.New(color.FgYellow)

	yellow.Fprintln(os.Stderr, "Approval required:")
	fmt.Fprintln(os.Stderr)
	for i, a := range approvals {
		fmt.Fprintf(os.Stderr, "  %d. %s\n", i+1, a.Name)
		fmt.Fprintf(os.Stderr, "     %s\n", a.Reason)
	}
	fmt.Fprintln(os.Stderr)

	bold.Fprint(os.Stderr, "Approve? [y/N] ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return run.ErrApprovalDenied
	}

	input = strings.TrimSpace(strings.ToLower(input))
	if input == "y" || input == "yes" {
		color.New(color.FgGreen).Fprintln(os.Stderr, "Approved.")
		fmt.Fprintln(os.Stderr)
		return nil
	}

	color.New(color.FgRed).Fprintln(os.Stderr, "Denied.")
	return run.ErrApprovalDenied
}
