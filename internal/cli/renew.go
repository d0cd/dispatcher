package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/run"
)

var renewCmd = &cobra.Command{
	Use:   "renew <run-id>",
	Short: "Extend a running cloud workload's self-destruct watchdog",
	Long: "Reconnects to a non-terminal cloud run and pushes its watchdog deadline " +
		"forward by the configured TTL, so a healthy detached workload isn't reaped.\n\n" +
		"Run periodically (e.g. from a cron job or systemd timer) to keep an " +
		"unattended long-running workload alive past its watchdog TTL.",
	Args: cobra.ExactArgs(1),
	RunE: runRenew,
}

func runRenew(_ *cobra.Command, args []string) error {
	id := args[0]
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	r, a, err := run.ReconnectToRun(ctx, id, adapterForTarget)
	if err != nil {
		return err
	}
	deadline, err := run.RenewWatchdog(ctx, a, r)
	if err != nil {
		return err
	}
	if _, err := r.Save(); err != nil {
		return fmt.Errorf("watchdog extended but failed to persist run: %w", err)
	}
	fmt.Fprintf(os.Stdout, "Watchdog for %s extended until %s\n", id, deadline.Format("2006-01-02 15:04:05 UTC"))
	return nil
}

func init() {
	rootCmd.AddCommand(renewCmd)
}
