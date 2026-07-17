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
	Use:         "recover",
	Annotations: map[string]string{supportsJSON: "true"},
	Short:       "Inventory cloud VMs whose local run record is missing or stale",
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

// recoverEntry is one tagged cloud VM and what dispatcher knows about it.
type recoverEntry struct {
	ResourceID  string    `json:"resourceId"`
	Provider    string    `json:"provider"`
	RunID       string    `json:"runId,omitempty"`
	CreatedAt   time.Time `json:"createdAt,omitempty"`
	LocalRecord string    `json:"localRecord,omitempty"` // yes | missing | unreadable
	SSHKeyPath  string    `json:"sshKeyPath,omitempty"`
	Attachable  bool      `json:"attachable"`
}

func runRecover(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	asJSON := jsonOutput()

	adapters := durableAdaptersFn()
	if len(adapters) == 0 {
		if asJSON {
			return emitJSON(struct {
				Total      int            `json:"total"`
				Attachable []string       `json:"attachable"`
				VMs        []recoverEntry `json:"vms"`
			}{0, []string{}, []recoverEntry{}})
		}
		fmt.Fprintln(os.Stderr, "No cloud VM adapters configured (no CLIs installed).")
		return nil
	}

	keyDir, _ := statedir.Subdir("keys")

	var entries []recoverEntry
	attachable := []string{}
	for _, a := range adapters {
		resources, err := a.ListResources(ctx)
		if err != nil {
			if !asJSON {
				color.New(color.Faint).Fprintf(os.Stderr, "warning: cannot list resources for %s: %v\n", a.ID(), err)
			}
			continue
		}
		for _, res := range resources {
			e := recoverEntry{ResourceID: res.ResourceID, Provider: res.Provider, RunID: res.RunID, CreatedAt: res.CreatedAt}
			if res.RunID != "" {
				// res.RunID is the plan id carried in the VM tag (the adapter is
				// handed a Plan, not a run), so resolve the record by plan id — the
				// record's filename is the distinct run id. attachable must carry
				// that run id so `dispatcher status` can load it.
				if rec, err := run.LoadRecordByPlanID(res.RunID); err == nil {
					e.LocalRecord = "yes"
					e.Attachable = true
					attachable = append(attachable, rec.ID)
				} else if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "not found") {
					e.LocalRecord = "missing"
				} else {
					e.LocalRecord = "unreadable"
				}
				if keyDir != "" {
					keyPath := filepath.Join(keyDir, "dispatcher-"+res.RunID)
					if _, err := os.Stat(keyPath); err == nil {
						e.SSHKeyPath = keyPath
					}
				}
			}
			entries = append(entries, e)
		}
	}

	if asJSON {
		return emitJSON(struct {
			Total      int            `json:"total"`
			Attachable []string       `json:"attachable"`
			VMs        []recoverEntry `json:"vms"`
		}{len(entries), attachable, entries})
	}
	return renderRecover(entries, attachable, keyDir != "")
}

// renderRecover prints the human inventory (and, with --attach, refreshes each
// recoverable run via status).
func renderRecover(entries []recoverEntry, attachable []string, haveKeyDir bool) error {
	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)

	if len(entries) == 0 {
		green.Fprintln(os.Stderr, "No tagged cloud VMs found across configured providers.")
		return nil
	}

	for _, e := range entries {
		bold.Fprintf(os.Stderr, "\n%s on %s\n", e.ResourceID, e.Provider)
		if e.RunID != "" {
			fmt.Fprintf(os.Stderr, "  run id:        %s\n", e.RunID)
		} else {
			yellow.Fprintln(os.Stderr, "  run id:        (missing tag — provenance unclear)")
		}
		if !e.CreatedAt.IsZero() {
			age := time.Since(e.CreatedAt).Round(time.Second)
			fmt.Fprintf(os.Stderr, "  created:       %s (%s ago)\n", e.CreatedAt.Format("2006-01-02 15:04 MST"), age)
		}
		switch e.LocalRecord {
		case "yes":
			green.Fprintln(os.Stderr, "  local record:  yes (run dispatcher status, logs, diagnose)")
		case "missing":
			yellow.Fprintln(os.Stderr, "  local record:  MISSING — workload metadata lost")
		case "unreadable":
			yellow.Fprintln(os.Stderr, "  local record:  unreadable")
		}
		if e.RunID != "" && haveKeyDir {
			if e.SSHKeyPath != "" {
				fmt.Fprintf(os.Stderr, "  ssh key:       %s\n", e.SSHKeyPath)
				dim.Fprintf(os.Stderr, "                 ssh -i %s -o StrictHostKeyChecking=accept-new <user>@<ip>\n", e.SSHKeyPath)
			} else {
				yellow.Fprintln(os.Stderr, "  ssh key:       MISSING — cannot SSH in from this machine")
			}
		}
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
