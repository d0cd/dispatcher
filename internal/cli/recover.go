package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/run"
	statedir "github.com/d0cd/dispatcher/internal/state"
)

var recoverFlags struct {
	attach bool
}

var recoverCmd = &cobra.Command{
	Use:   "recover",
	Short: "Inventory cloud VMs whose local run record is missing or stale",
	Long: `Lists every dispatcher-tagged VM across configured cloud providers and
reports what's recoverable. Useful when:

  - Your laptop died mid-run and you need to find still-running VMs.
  - You restored a backup and want to know which runs survived.
  - A 'dispatcher run' was killed mid-flight and you're unsure if the VM
    actually came up.

For each VM the command reports: provider, VM ID, run ID, age, whether the
local run record exists, whether the SSH key is still on disk.

With --attach, recover also runs 'dispatcher status' against each recoverable
run, refreshing live state and (for durable adapters) updating in-memory
handles. Without --attach, recover only reports — it never destroys anything.

To destroy orphaned VMs explicitly, use 'dispatcher gc'.`,
	RunE: runRecover,
}

func init() {
	recoverCmd.Flags().BoolVar(&recoverFlags.attach, "attach", false,
		"after listing, run `dispatcher status` against each recoverable run")
	rootCmd.AddCommand(recoverCmd)
}

func runRecover(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)

	adapters := durableAdapters()
	if len(adapters) == 0 {
		fmt.Fprintln(os.Stderr, "No cloud VM adapters configured (no CLIs installed).")
		return nil
	}

	keyDir, _ := statedir.Subdir("keys")

	total := 0
	attachable := []string{}
	for _, a := range adapters {
		resources, err := a.ListResources(ctx)
		if err != nil {
			dim.Fprintf(os.Stderr, "warning: cannot list resources for %s: %v\n", a.ID(), err)
			continue
		}

		for _, res := range resources {
			total++
			bold.Fprintf(os.Stderr, "\n%s on %s\n", res.ResourceID, res.Provider)
			if res.RunID != "" {
				fmt.Fprintf(os.Stderr, "  run id:        %s\n", res.RunID)
			} else {
				yellow.Fprintln(os.Stderr, "  run id:        (missing tag — provenance unclear)")
			}
			if !res.CreatedAt.IsZero() {
				age := time.Since(res.CreatedAt).Round(time.Second)
				fmt.Fprintf(os.Stderr, "  created:       %s (%s ago)\n",
					res.CreatedAt.Format("2006-01-02 15:04 MST"), age)
			}

			localRecord := false
			if res.RunID != "" {
				if _, err := run.LoadRecord(res.RunID); err == nil {
					green.Fprintln(os.Stderr, "  local record:  yes (run dispatcher status, logs, diagnose)")
					localRecord = true
				} else if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "not found") {
					yellow.Fprintln(os.Stderr, "  local record:  MISSING — workload metadata lost")
				} else {
					yellow.Fprintf(os.Stderr, "  local record:  unreadable (%v)\n", err)
				}
			}

			if res.RunID != "" && keyDir != "" {
				keyPath := filepath.Join(keyDir, "dispatcher-"+res.RunID)
				if _, err := os.Stat(keyPath); err == nil {
					fmt.Fprintf(os.Stderr, "  ssh key:       %s\n", keyPath)
					dim.Fprintf(os.Stderr, "                 ssh -i %s -o StrictHostKeyChecking=accept-new <user>@<ip>\n", keyPath)
				} else {
					yellow.Fprintln(os.Stderr, "  ssh key:       MISSING — cannot SSH in from this machine")
				}
			}

			// Eligible for --attach: must have a local run record AND a
			// run id. Without the local record, status has nothing to
			// refresh; without the id, there's no run to look up.
			if localRecord {
				attachable = append(attachable, res.RunID)
			}
		}
	}

	if total == 0 {
		green.Fprintln(os.Stderr, "No tagged cloud VMs found across configured providers.")
		return nil
	}

	fmt.Fprintln(os.Stderr)
	if recoverFlags.attach && len(attachable) > 0 {
		bold.Fprintf(os.Stderr, "Attaching to %d recoverable run(s)...\n\n", len(attachable))
		for _, id := range attachable {
			bold.Fprintf(os.Stderr, "── %s ──\n", id)
			if err := runStatusByID(id); err != nil {
				yellow.Fprintf(os.Stderr, "  status failed: %v\n", err)
			}
			fmt.Fprintln(os.Stderr)
		}
		return nil
	}

	dim.Fprintln(os.Stderr, "To destroy abandoned VMs: dispatcher gc")
	dim.Fprintln(os.Stderr, "To inspect a recoverable run: dispatcher status <run-id>")
	dim.Fprintln(os.Stderr, "To auto-attach to all recoverable runs: dispatcher recover --attach")
	return nil
}
