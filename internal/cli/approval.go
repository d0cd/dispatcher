package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/fatih/color"

	"github.com/d0cd/dispatcher/internal/approval"
	"github.com/d0cd/dispatcher/internal/types"
)

// terminalApproval prompts the operator at the terminal. The decider tag
// captures the OS username so multi-operator shared terminals can't
// produce indistinguishable audit records.
func terminalApproval(approvals []types.PolicyRequirement) (string, error) {
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
		return interactiveDecider(), approval.ErrDenied
	}

	input = strings.TrimSpace(strings.ToLower(input))
	if input == "y" || input == "yes" {
		color.New(color.FgGreen).Fprintln(os.Stderr, "Approved.")
		fmt.Fprintln(os.Stderr)
		return interactiveDecider(), nil
	}

	color.New(color.FgRed).Fprintln(os.Stderr, "Denied.")
	return interactiveDecider(), approval.ErrDenied
}

// yesApproval auto-approves and stamps the audit-distinct "yes-flag:<user>"
// decider so reviewers can see both that --yes was used AND which user
// invoked it.
func yesApproval(approvals []types.PolicyRequirement) (string, error) {
	dim := color.New(color.Faint)
	dim.Fprintln(os.Stderr, "Auto-approving (--yes):")
	for _, a := range approvals {
		dim.Fprintf(os.Stderr, "  • %s — %s\n", a.Name, a.Reason)
	}
	return "yes-flag:" + osUsername(), nil
}

func interactiveDecider() string {
	return "interactive:" + osUsername()
}

func osUsername() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "unknown"
}
