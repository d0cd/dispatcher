package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/d0cd/dispatcher/internal/attest"
	"github.com/d0cd/dispatcher/internal/confidential"
)

var confidentialCmd = &cobra.Command{
	Use:   "confidential",
	Short: "Manage measured confidential-image pins (the build → capture → pin lifecycle)",
	Long: "Measured confidential runs pin an image and its measurement per cloud " +
		"(GCP container digest, AWS Nitro PCR0, Azure PCR11). These commands manage the " +
		"shared pin registry the run path reads. Measurements are content-addressed, so " +
		"re-capture and re-pin on every image rebuild.",
}

var confidentialPinsCmd = &cobra.Command{
	Use:   "pins",
	Short: "List the current measured-image pins",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		path, err := confidential.DefaultPath()
		if err != nil {
			return err
		}
		reg, err := confidential.Load(path)
		if err != nil {
			return err
		}
		if len(reg.Pins) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "no pins (%s)\n", path)
			return nil
		}
		targets := make([]string, 0, len(reg.Pins))
		for t := range reg.Pins {
			targets = append(targets, string(t))
		}
		sort.Strings(targets)
		for _, t := range targets {
			p := reg.Pins[confidential.Target(t)]
			fmt.Fprintf(cmd.OutOrStdout(), "%-11s %s\n            measurement=%s\n", t, p.Image, p.Measurement)
			for k, v := range p.Extra {
				fmt.Fprintf(cmd.OutOrStdout(), "            %s=%s\n", k, v)
			}
		}
		return nil
	},
}

var confidentialPinFlags struct {
	image       string
	measurement string
	proxy       string
	repoRoot    string
	pins        string
}

var confidentialPinCmd = &cobra.Command{
	Use:   "pin <gcp|aws-nitro|azure-snp>",
	Short: "Set or update a measured-image pin",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target, err := parseTarget(args[0])
		if err != nil {
			return err
		}
		if confidentialPinFlags.image == "" || confidentialPinFlags.measurement == "" {
			return fmt.Errorf("--image and --measurement are required")
		}
		pin := confidential.Pin{
			Image:       confidentialPinFlags.image,
			Measurement: confidentialPinFlags.measurement,
			CapturedAt:  time.Now().UTC().Format(time.RFC3339),
		}
		if confidentialPinFlags.proxy != "" {
			pin.Extra = map[string]string{"proxy": confidentialPinFlags.proxy}
		}
		return savePin(cmd, target, pin, confidentialPinFlags.repoRoot, confidentialPinFlags.pins)
	},
}

var confidentialCaptureFlags struct {
	pin      bool
	eif      string
	image    string
	proxy    string
	repoRoot string
	pins     string
}

var confidentialCaptureCmd = &cobra.Command{
	Use:   "capture <gcp|aws-nitro|azure-snp> <source>",
	Short: "Capture a measurement from a built artifact (and optionally pin it)",
	Long: "Extract the measurement from a build:\n" +
		"  gcp        <image@sha256:…>           the container digest\n" +
		"  aws-nitro  <describe-eif.json path>   PCR0 (also pass --eif/--proxy to pin)\n" +
		"  azure-snp  <http://cvm:8443>          PCR11 from a booted measured CVM (also --image to pin)",
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		target, err := parseTarget(args[0])
		if err != nil {
			return err
		}
		pin, err := captureMeasurement(target, args[1])
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s measurement: %s\n", target, pin.Measurement)
		if !confidentialCaptureFlags.pin {
			fmt.Fprintln(cmd.OutOrStdout(), "(re-run with --pin to record it)")
			return nil
		}
		return savePin(cmd, target, pin, confidentialCaptureFlags.repoRoot, confidentialCaptureFlags.pins)
	},
}

// captureMeasurement extracts the measurement (and image/extras) for a target from
// a build source, ready to pin.
func captureMeasurement(target confidential.Target, source string) (confidential.Pin, error) {
	switch target {
	case confidential.GCP:
		return confidential.CaptureGCP(source)
	case confidential.AWSNitro:
		out, err := os.ReadFile(source)
		if err != nil {
			return confidential.Pin{}, fmt.Errorf("read nitro-cli output: %w", err)
		}
		pcr0, err := confidential.CaptureNitroPCR0(out)
		if err != nil {
			return confidential.Pin{}, err
		}
		pin := confidential.Pin{Image: confidentialCaptureFlags.eif, Measurement: pcr0, CapturedAt: nowRFC3339()}
		if confidentialCaptureFlags.proxy != "" {
			pin.Extra = map[string]string{"proxy": confidentialCaptureFlags.proxy}
		}
		return pin, nil
	case confidential.AzureSNP:
		// Verify the full SEV-SNP + vTPM chain (fresh nonce, AK-bound quote) and derive
		// the hardware-attested PCR11, so a compromised or MITM'd /attest endpoint can't
		// poison the pinned measurement.
		pcr11, launchMeasurement, err := attest.CaptureAzureSNPMeasurement(context.Background(), source)
		if err != nil {
			return confidential.Pin{}, err
		}
		// Pin PCR11 AND the SNP launch measurement — the latter roots the vTPM AK in
		// trusted Azure firmware and is required for a sound verify (see azure_snp.go).
		return confidential.Pin{
			Image:       confidentialCaptureFlags.image,
			Measurement: pcr11,
			Extra:       map[string]string{"launchMeasurement": launchMeasurement},
			CapturedAt:  nowRFC3339(),
		}, nil
	}
	return confidential.Pin{}, fmt.Errorf("unknown target %q", target)
}

var confidentialBuildFlags struct {
	repoRoot string
	eif      string
	proxy    string
	pins     string
}

var confidentialBuildCmd = &cobra.Command{
	Use:   "build <aws-nitro|gcp|azure-snp>",
	Short: "Build a measured image, capture its measurement, and pin it",
	Long: "Runs the per-cloud build, then captures + pins the measurement. The build\n" +
		"is irreducibly per-cloud; only AWS Nitro is a single-host build this wraps.\n" +
		"  aws-nitro  build-eif.sh -> PCR0 -> pin (run on a Nitro instance)\n" +
		"  gcp        no pre-build: the per-run workload container is measured at run time\n" +
		"  azure-snp  multi-host (mkosi -> VHD -> gallery); see docs/confidential-azure-uki.md",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target, err := parseTarget(args[0])
		if err != nil {
			return err
		}
		switch target {
		case confidential.AWSNitro:
			return buildNitro(cmd)
		case confidential.GCP:
			return fmt.Errorf("GCP Confidential Space measures the per-run workload container (agent + workload), " +
				"built and allowlisted during `dispatcher run` — there is no static image to pre-build. " +
				"For a pre-built digest-pinned agent image, use `dispatcher confidential capture gcp <ref>@sha256:<digest> --pin`")
		case confidential.AzureSNP:
			return fmt.Errorf("the Azure measured image is a multi-host build (mkosi → VHD → ConfidentialVm gallery image); " +
				"follow deploy/azure-uki/mkosi/build-and-upload.md, boot a CVM, then " +
				"`dispatcher confidential capture azure-snp http://<cvm>:8443 --image <gallery-id> --pin`")
		}
		return fmt.Errorf("unknown target %q", target)
	},
}

// buildNitro builds the enclave EIF (deploy/nitro/build-eif.sh) on a Nitro host,
// describes it for PCR0, and pins the EIF + PCR0 + proxy. Needs docker + nitro-cli.
func buildNitro(cmd *cobra.Command) error {
	repo := confidentialBuildFlags.repoRoot
	if repo == "" {
		repo = "."
	}
	if confidentialBuildFlags.proxy == "" {
		return fmt.Errorf("--proxy is required (the cross-compiled dispatcher-nitro-proxy path)")
	}
	eif := confidentialBuildFlags.eif
	if eif == "" {
		eif = filepath.Join(repo, "dispatcher-attest-nitro.eif")
	}
	if _, err := exec.LookPath("nitro-cli"); err != nil {
		return fmt.Errorf("nitro-cli not found — run `dispatcher confidential build aws-nitro` on a Nitro-enabled instance (see docs/confidential-nitro.md)")
	}

	fmt.Fprintln(cmd.OutOrStdout(), "building EIF (deploy/nitro/build-eif.sh)…")
	build := exec.Command("bash", filepath.Join(repo, "deploy/nitro/build-eif.sh"))
	build.Env = append(os.Environ(), "EIF="+eif)
	build.Stdout, build.Stderr = cmd.OutOrStderr(), cmd.OutOrStderr()
	if err := build.Run(); err != nil {
		return fmt.Errorf("build-eif.sh: %w", err)
	}

	describe, err := exec.Command("nitro-cli", "describe-eif", "--eif-path", eif).Output()
	if err != nil {
		return fmt.Errorf("nitro-cli describe-eif: %w", err)
	}
	pcr0, err := confidential.CaptureNitroPCR0(describe)
	if err != nil {
		return err
	}
	pin := confidential.Pin{
		Image: eif, Measurement: pcr0, CapturedAt: nowRFC3339(),
		Extra: map[string]string{"proxy": confidentialBuildFlags.proxy},
	}
	return savePin(cmd, confidential.AWSNitro, pin, repo, confidentialBuildFlags.pins)
}

var confidentialCheckFlags struct {
	repoRoot string
	pins     string
}

var confidentialCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Fail if any pinned image's measurement inputs changed since capture (CI drift guard)",
	Long: "Recompute each pin's measurement-input hash (agent source, build config, deps) and\n" +
		"fail if it no longer matches what was recorded at capture — the signal that the\n" +
		"measured image must be rebuilt, re-captured, and re-pinned. Run this in CI so a\n" +
		"routine agent or build change can't silently invalidate a pin. It does not build\n" +
		"images (that needs the per-cloud hosts); it only detects drift.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		// An explicitly requested registry that is absent is an error, not an empty
		// pass — otherwise a mistyped path or a not-yet-committed file reads as
		// "verified". Only the implicit state-dir default may be absent (fresh machine).
		if confidentialCheckFlags.pins != "" {
			if _, err := os.Stat(confidentialCheckFlags.pins); err != nil {
				return fmt.Errorf("pin registry %q not found — commit it or produce it with "+
					"`confidential capture --pin --pins %s` (an absent registry is not an empty pass): %w",
					confidentialCheckFlags.pins, confidentialCheckFlags.pins, err)
			}
		}
		pins := confidentialCheckFlags.pins
		if pins == "" {
			p, err := confidential.DefaultPath()
			if err != nil {
				return err
			}
			pins = p
		}
		return runConfidentialCheck(cmd.OutOrStdout(), confidentialCheckFlags.repoRoot, pins)
	},
}

// runConfidentialCheck loads the pin registry at pinsPath and fails if any pin's
// measurement inputs drifted from repoRoot. A missing registry is a clean pass.
func runConfidentialCheck(out io.Writer, repoRoot, pinsPath string) error {
	if repoRoot == "" {
		repoRoot = "."
	}
	reg, err := confidential.Load(pinsPath)
	if err != nil {
		return err
	}
	stale, err := confidential.CheckPins(reg, repoRoot)
	if err != nil {
		return err
	}
	if len(stale) == 0 {
		fmt.Fprintf(out, "confidential pins current (%s)\n", pinsPath)
		return nil
	}
	names := make([]string, len(stale))
	for i, s := range stale {
		names[i] = string(s.Target)
		fmt.Fprintf(out, "STALE %s: measurement inputs changed since capture\n", s.Target)
	}
	return fmt.Errorf("confidential pin(s) stale [%s] — rebuild the measured image, then re-capture and re-pin (dispatcher confidential build / capture --pin)", strings.Join(names, ", "))
}

// savePin writes pin to the registry (pinsPath, or the state-dir default), first
// recording the target's measurement-inputs hash from repoRoot so a later
// `confidential check` can detect drift. The hashing error is surfaced, not
// swallowed: a pin with no drift baseline is silently exempt from the guard, so if
// the inputs can't be hashed (e.g. repoRoot isn't the source tree) the pin is
// refused rather than saved unprotected. GCP has no static inputs (empty hash, no
// error), which is expected.
func savePin(cmd *cobra.Command, target confidential.Target, pin confidential.Pin, repoRoot, pinsPath string) error {
	if pin.InputsHash == "" {
		h, err := confidential.InputsHash(repoRoot, target)
		if err != nil {
			return fmt.Errorf("record measurement inputs for %s (is --repo-root %q the dispatcher source tree?): %w", target, repoRoot, err)
		}
		pin.InputsHash = h
	}
	path, err := pinsRegistryPath(pinsPath)
	if err != nil {
		return err
	}
	reg, err := confidential.Load(path)
	if err != nil {
		return err
	}
	reg.Set(target, pin)
	if err := reg.Save(path); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "pinned %s = %s (%s)\n", target, pin.Measurement, path)
	return nil
}

// pinsRegistryPath resolves the registry path: the explicit flag, or the state-dir
// default. It is the single place write and check commands agree on a location.
func pinsRegistryPath(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	return confidential.DefaultPath()
}

func parseTarget(s string) (confidential.Target, error) {
	switch confidential.Target(s) {
	case confidential.GCP, confidential.AWSNitro, confidential.AzureSNP:
		return confidential.Target(s), nil
	}
	return "", fmt.Errorf("unknown target %q (want gcp | aws-nitro | azure-snp)", s)
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

func init() {
	confidentialPinCmd.Flags().StringVar(&confidentialPinFlags.image, "image", "", "measured image (container ref / EIF path / gallery image id)")
	confidentialPinCmd.Flags().StringVar(&confidentialPinFlags.measurement, "measurement", "", "the measurement (digest / PCR0 / PCR11)")
	confidentialPinCmd.Flags().StringVar(&confidentialPinFlags.proxy, "proxy", "", "aws-nitro: parent vsock-proxy binary path")
	confidentialPinCmd.Flags().StringVar(&confidentialPinFlags.repoRoot, "repo-root", ".", "the dispatcher source tree to hash measurement inputs from")
	confidentialPinCmd.Flags().StringVar(&confidentialPinFlags.pins, "pins", "", "pin registry to write (default: the state-dir registry)")
	confidentialCaptureCmd.Flags().BoolVar(&confidentialCaptureFlags.pin, "pin", false, "record the captured measurement in the registry")
	confidentialCaptureCmd.Flags().StringVar(&confidentialCaptureFlags.eif, "eif", "", "aws-nitro: the EIF path to pin")
	confidentialCaptureCmd.Flags().StringVar(&confidentialCaptureFlags.image, "image", "", "azure-snp: the gallery image id to pin")
	confidentialCaptureCmd.Flags().StringVar(&confidentialCaptureFlags.proxy, "proxy", "", "aws-nitro: the parent proxy binary path to pin")
	confidentialCaptureCmd.Flags().StringVar(&confidentialCaptureFlags.repoRoot, "repo-root", ".", "the dispatcher source tree to hash measurement inputs from")
	confidentialCaptureCmd.Flags().StringVar(&confidentialCaptureFlags.pins, "pins", "", "pin registry to write (default: the state-dir registry)")
	confidentialBuildCmd.Flags().StringVar(&confidentialBuildFlags.repoRoot, "repo-root", ".", "aws-nitro: the dispatcher source tree (has deploy/nitro/build-eif.sh)")
	confidentialBuildCmd.Flags().StringVar(&confidentialBuildFlags.eif, "eif", "", "aws-nitro: output EIF path (default <repo-root>/dispatcher-attest-nitro.eif)")
	confidentialBuildCmd.Flags().StringVar(&confidentialBuildFlags.proxy, "proxy", "", "aws-nitro: the parent dispatcher-nitro-proxy binary path")
	confidentialBuildCmd.Flags().StringVar(&confidentialBuildFlags.pins, "pins", "", "pin registry to write (default: the state-dir registry)")
	confidentialCheckCmd.Flags().StringVar(&confidentialCheckFlags.repoRoot, "repo-root", ".", "the dispatcher source tree to hash measurement inputs from")
	confidentialCheckCmd.Flags().StringVar(&confidentialCheckFlags.pins, "pins", "", "pin registry to check (default: the state-dir registry)")
	confidentialCmd.AddCommand(confidentialPinsCmd, confidentialPinCmd, confidentialCaptureCmd, confidentialBuildCmd, confidentialCheckCmd)
}
