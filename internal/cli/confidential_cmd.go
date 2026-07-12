package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

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
		return savePin(cmd, target, pin)
	},
}

var confidentialCaptureFlags struct {
	pin   bool
	eif   string
	image string
	proxy string
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
		return savePin(cmd, target, pin)
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
		token, err := fetchAttestToken(source)
		if err != nil {
			return confidential.Pin{}, err
		}
		pcr11, err := confidential.CaptureAzurePCR11(token)
		if err != nil {
			return confidential.Pin{}, err
		}
		return confidential.Pin{Image: confidentialCaptureFlags.image, Measurement: pcr11, CapturedAt: nowRFC3339()}, nil
	}
	return confidential.Pin{}, fmt.Errorf("unknown target %q", target)
}

// fetchAttestToken fetches the agent's /attest evidence bundle from a booted
// measured CVM, so its live PCR11 can be captured.
func fetchAttestToken(endpoint string) (string, error) {
	u := strings.TrimRight(endpoint, "/") + "/attest?nonce=" + url.QueryEscape(strings.Repeat("00", 32))
	resp, err := (&http.Client{Timeout: 45 * time.Second}).Get(u)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("agent /attest returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var r struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Token == "" {
		return "", fmt.Errorf("agent /attest response has no token")
	}
	return r.Token, nil
}

func savePin(cmd *cobra.Command, target confidential.Target, pin confidential.Pin) error {
	path, err := confidential.DefaultPath()
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
	confidentialCaptureCmd.Flags().BoolVar(&confidentialCaptureFlags.pin, "pin", false, "record the captured measurement in the registry")
	confidentialCaptureCmd.Flags().StringVar(&confidentialCaptureFlags.eif, "eif", "", "aws-nitro: the EIF path to pin")
	confidentialCaptureCmd.Flags().StringVar(&confidentialCaptureFlags.image, "image", "", "azure-snp: the gallery image id to pin")
	confidentialCaptureCmd.Flags().StringVar(&confidentialCaptureFlags.proxy, "proxy", "", "aws-nitro: the parent proxy binary path to pin")
	confidentialCmd.AddCommand(confidentialPinsCmd, confidentialPinCmd, confidentialCaptureCmd)
}
