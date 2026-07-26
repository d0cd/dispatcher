package cloudvm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/d0cd/dispatcher/internal/adapter"
)

// OCIProvider implements Provider using the `oci` CLI.
//
// OCI needs several resource OCIDs the other providers auto-resolve — a
// compartment, an availability domain, a subnet (an OCI VCN + subnet must exist),
// and a base image — so they are supplied by the operator via DISPATCHER_OCI_*
// env vars rather than discovered. CreateVM fails closed with a clear message
// when a required one is missing.
type OCIProvider struct {
	region             string
	compartmentID      string
	availabilityDomain string
	subnetID           string
	imageID            string
}

// NewOCIProvider builds an OCI provider. Region may be empty (the CLI's
// configured default region applies); the OCIDs come from the environment.
func NewOCIProvider(region string) *OCIProvider {
	return &OCIProvider{
		region:             region,
		compartmentID:      os.Getenv("DISPATCHER_OCI_COMPARTMENT_ID"),
		availabilityDomain: os.Getenv("DISPATCHER_OCI_AVAILABILITY_DOMAIN"),
		subnetID:           os.Getenv("DISPATCHER_OCI_SUBNET_ID"),
		imageID:            os.Getenv("DISPATCHER_OCI_IMAGE_ID"),
	}
}

func (o *OCIProvider) Name() ProviderID { return ProviderOCI }

// ociFlexSizing returns the OCPU/memory for a Flex shape from the catalog SKU the
// planner selected, so the provisioned box matches what was costed. Falls back to
// 2 OCPU / 16 GB for a shape not in the catalog.
func ociFlexSizing(shape string) (ocpus int, memoryGB float64) {
	for _, inst := range defaultInstances {
		if inst.Provider == ProviderOCI && inst.Name == shape && inst.VCPUs > 0 {
			return inst.VCPUs, inst.MemoryGB
		}
	}
	return 2, 16
}

// ociImageShapeHint augments an OCI launch error that failed on a shape/image
// architecture mismatch with the actionable cause. OCI's raw error ("Shape X is
// not valid for image Y") never says why: the planner may select an ARM shape
// (Ampere A1/A2 — often the cheapest, so the default pick) while
// DISPATCHER_OCI_IMAGE_ID points at an x86 image, or the reverse. Unrelated
// errors pass through unchanged.
func ociImageShapeHint(shape, image string, err error) error {
	if err == nil || !strings.Contains(err.Error(), "not valid for image") {
		return err
	}
	arch := "x86_64"
	if isOCIArmShape(shape) {
		arch = "aarch64 (ARM)"
	}
	return fmt.Errorf("%w\nshape %s needs a %s image; set DISPATCHER_OCI_IMAGE_ID to an image matching the shape architecture (current image %s does not)", err, shape, arch, image)
}

// isOCIArmShape reports whether an OCI shape is Ampere ARM (aarch64). OCI's ARM
// shapes are the A1/A2 families (e.g. VM.Standard.A1.Flex, BM.Standard.A1.160);
// everything else (E-series, standard Intel) is x86_64.
func isOCIArmShape(shape string) bool {
	return strings.Contains(shape, ".A1.") || strings.Contains(shape, ".A2.")
}

// reapByRunTag best-effort destroys any instance carrying this run's
// dispatcher-run-id tag — used to clean up a launch whose OCID we never captured
// (e.g. the blocking --wait-for-state was cancelled after the instance existed).
func (o *OCIProvider) reapByRunTag(tags map[string]string) {
	runID := tags["dispatcher-run-id"]
	if runID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	vms, err := o.ListVMs(ctx, map[string]string{"dispatcher-run-id": runID})
	if err != nil {
		return
	}
	for _, vm := range vms {
		_ = o.DestroyVM(ctx, vm.ID)
	}
}

// SetRegion re-points the provider so create and teardown act on the same region.
func (o *OCIProvider) SetRegion(region string) {
	if region != "" {
		o.region = region
	}
}

// regionArgs adds `--region` only when one is pinned, so an unset region falls
// back to the CLI's configured default rather than passing an empty flag.
func (o *OCIProvider) regionArgs() []string {
	if o.region == "" {
		return nil
	}
	return []string{"--region", o.region}
}

func (o *OCIProvider) CheckCLI(ctx context.Context) error {
	if _, err := exec.LookPath("oci"); err != nil {
		return fmt.Errorf("oci CLI not found: %w", err)
	}
	// A lightweight authenticated call: listing subscribed regions requires a
	// valid config/auth but no compartment.
	if _, err := runCLI(ctx, "oci", append([]string{"iam", "region-subscription", "list"}, o.regionArgs()...)...); err != nil {
		return fmt.Errorf("oci not authenticated (run `oci setup config` / `oci session authenticate`): %w", err)
	}
	return nil
}

// ociShape resolves the compute shape for a VM: the operator's InstanceType, or a
// general-purpose default. OCI is a plain provisioning target — confidential
// execution is not offered (its SEV-SNP reports do not verify against AMD KDS;
// see docs/SECURITY.md) — so there is no platform-config.
func ociShape(opts VMOptions) string {
	if opts.InstanceType != "" {
		return opts.InstanceType
	}
	return "VM.Standard.E4.Flex"
}

func (o *OCIProvider) CreateVM(ctx context.Context, opts VMOptions) (*VMInfo, error) {
	if err := validateLabels(opts.Tags); err != nil {
		return nil, fmt.Errorf("oci tags: %w", err)
	}
	if o.compartmentID == "" || o.availabilityDomain == "" || o.subnetID == "" {
		return nil, fmt.Errorf("oci requires DISPATCHER_OCI_COMPARTMENT_ID, DISPATCHER_OCI_AVAILABILITY_DOMAIN, and DISPATCHER_OCI_SUBNET_ID to be set")
	}
	image := opts.Image
	if image == "" {
		image = o.imageID
	}
	if image == "" {
		return nil, fmt.Errorf("oci requires an image: set DISPATCHER_OCI_IMAGE_ID or the plan's InstanceType image")
	}

	shape := ociShape(opts)

	// Validate the plan/catalog/env-supplied values at the boundary, as every
	// other provider does — a leading '-' or stray metacharacter must not reach
	// the oci argv. Region is optional (empty falls back to the CLI profile).
	if !isSafeArg(shape) || !isSafeArg(image) {
		return nil, fmt.Errorf("oci: shape %q or image %q contains characters outside [a-zA-Z0-9_.:/@-] or is empty/flag-like", shape, image)
	}
	if o.region != "" && !isSafeArg(o.region) {
		return nil, fmt.Errorf("oci: region %q contains characters outside [a-zA-Z0-9_.:/@-] or is flag-like", o.region)
	}

	// SSH key + cloud-init ride in instance metadata. Write the metadata as a
	// file:// input so neither the key nor the (secret-bearing) user-data appears
	// in argv (ps-visible to other users on the host).
	metadata := map[string]string{}
	if opts.SSHKeyPath != "" {
		pub, err := os.ReadFile(opts.SSHKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read ssh pubkey: %w", err)
		}
		metadata["ssh_authorized_keys"] = strings.TrimSpace(string(pub))
	}
	if opts.UserData != "" {
		metadata["user_data"] = base64.StdEncoding.EncodeToString([]byte(opts.UserData))
	}

	args := append([]string{"compute", "instance", "launch"}, o.regionArgs()...)
	args = append(args,
		"--availability-domain", o.availabilityDomain,
		"--compartment-id", o.compartmentID,
		"--shape", shape,
		"--subnet-id", o.subnetID,
		"--image-id", image,
		"--display-name", opts.Name,
		"--assign-public-ip", "true",
		"--wait-for-state", "RUNNING",
		"--output", "json",
	)

	// Spot: launch a preemptible instance that terminates (not just stops) on
	// reclaim, matching the ephemeral-run model on the other clouds so nothing
	// billable is left behind. The config is a fixed constant (no user input).
	if opts.Spot {
		args = append(args, "--preemptible-instance-config",
			`{"preemptionAction": {"type": "TERMINATE", "preserveBootVolume": false}}`)
	}

	// Flex shapes require an explicit OCPU/memory config; bare-metal shapes reject
	// it. Size it from the catalog SKU the planner selected (and costed) so the
	// provisioned box matches what was priced, not a fixed 2/16.
	if strings.HasSuffix(shape, ".Flex") {
		ocpus, memoryGB := ociFlexSizing(shape)
		shapeConfig, _ := json.Marshal(map[string]any{"ocpus": ocpus, "memoryInGBs": memoryGB})
		f, err := adapter.WriteSecureTempFile("dispatcher-oci-shape-*.json", shapeConfig)
		if err != nil {
			return nil, fmt.Errorf("write shape config: %w", err)
		}
		defer os.Remove(f)
		args = append(args, "--shape-config", "file://"+f)
	}

	if len(metadata) > 0 {
		md, _ := json.Marshal(metadata)
		f, err := adapter.WriteSecureTempFile("dispatcher-oci-metadata-*.json", md)
		if err != nil {
			return nil, fmt.Errorf("write metadata: %w", err)
		}
		defer os.Remove(f)
		args = append(args, "--metadata", "file://"+f)
	}

	if len(opts.Tags) > 0 {
		tags, _ := json.Marshal(opts.Tags)
		f, err := adapter.WriteSecureTempFile("dispatcher-oci-tags-*.json", tags)
		if err != nil {
			return nil, fmt.Errorf("write tags: %w", err)
		}
		defer os.Remove(f)
		args = append(args, "--freeform-tags", "file://"+f)
	}

	// Launch is NOT retried: OCI has no idempotency token here, so re-running a
	// launch that already created an instance would provision a second one.
	// `--wait-for-state RUNNING` makes the single call block until the VM is up.
	output, err := runCLI(ctx, "oci", args...)
	if err != nil {
		// launch creates the instance, THEN --wait-for-state blocks until RUNNING.
		// A cancel/timeout during the wait would leave a billable instance behind
		// (its OCID isn't in our output), so reap any instance carrying this run's
		// tag before returning. Best-effort — nothing exists if launch failed early.
		o.reapByRunTag(opts.Tags)
		return nil, ociImageShapeHint(shape, image, wrapExecError("oci compute instance launch", err))
	}

	var launched struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(output, &launched); err != nil {
		return nil, fmt.Errorf("cannot parse oci launch output: %w", err)
	}
	if launched.Data.ID == "" {
		return nil, fmt.Errorf("oci launch returned no instance id")
	}

	ip, err := o.publicIP(ctx, launched.Data.ID)
	if err != nil {
		// The caller's context commonly expires while waiting for the VNIC. Use
		// a fresh bounded cleanup context so a successfully-created instance does
		// not leak merely because the provisioning context was canceled.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if cleanupErr := o.DestroyVM(cleanupCtx, launched.Data.ID); cleanupErr != nil {
			return nil, errors.Join(err, fmt.Errorf("cleanup oci instance %s after public-IP failure: %w", launched.Data.ID, cleanupErr))
		}
		return nil, err
	}

	return &VMInfo{
		ID:        launched.Data.ID,
		IP:        ip,
		State:     VMStateRunning,
		CreatedAt: time.Now().UTC(),
		Tags:      opts.Tags,
	}, nil
}

// publicIP returns the primary VNIC's public IP for an instance. OCI exposes the
// address on the VNIC, not the instance, so it is a separate lookup.
func (o *OCIProvider) publicIP(ctx context.Context, instanceID string) (string, error) {
	pollCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	args := append([]string{"compute", "instance", "list-vnics", "--instance-id", instanceID, "--output", "json"}, o.regionArgs()...)
	for {
		out, err := runCLI(pollCtx, "oci", args...)
		if err == nil {
			var vnics struct {
				Data []struct {
					PublicIP string `json:"public-ip"`
				} `json:"data"`
			}
			if err := json.Unmarshal(out, &vnics); err != nil {
				return "", fmt.Errorf("parse oci vnics: %w", err)
			}
			for _, v := range vnics.Data {
				if v.PublicIP != "" {
					return v.PublicIP, nil
				}
			}
		} else if pollCtx.Err() == nil {
			// VNIC discovery is eventually consistent; retry transient CLI/API
			// failures within the same bounded window.
		} else {
			return "", fmt.Errorf("oci public-IP lookup for %s: %w", instanceID, pollCtx.Err())
		}

		select {
		case <-pollCtx.Done():
			return "", fmt.Errorf("oci instance %s has no public IP after 30s (is the subnet public?): %w", instanceID, pollCtx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (o *OCIProvider) WaitReady(ctx context.Context, _ string, ip string, _ string) error {
	return WaitForSSH(ctx, ip, 5*time.Minute)
}

func (o *OCIProvider) GetVM(ctx context.Context, vmID string) (*VMInfo, error) {
	args := append([]string{"compute", "instance", "get", "--instance-id", vmID, "--output", "json"}, o.regionArgs()...)
	out, err := runCLI(ctx, "oci", args...)
	if err != nil {
		if isVMNotFound(err, vmID) {
			return &VMInfo{ID: vmID, State: VMStateTerminated}, nil
		}
		return nil, wrapExecError("oci compute instance get", err)
	}
	var got struct {
		Data struct {
			ID             string `json:"id"`
			LifecycleState string `json:"lifecycle-state"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		return nil, fmt.Errorf("parse oci instance: %w", err)
	}
	info := &VMInfo{ID: got.Data.ID, State: ociLifecycleState(got.Data.LifecycleState)}
	if info.State == VMStateRunning {
		if ip, err := o.publicIP(ctx, vmID); err == nil {
			info.IP = ip
		}
	}
	return info, nil
}

// ociLifecycleState maps OCI's instance lifecycle-state to the provider-agnostic
// VMState. TERMINATED/TERMINATING are terminal; anything not clearly running is
// treated as pending so a caller polls rather than acting on a half-state.
func ociLifecycleState(s string) VMState {
	switch strings.ToUpper(s) {
	case "RUNNING":
		return VMStateRunning
	case "TERMINATED", "TERMINATING":
		return VMStateTerminated
	case "STOPPING", "STOPPED":
		return VMStateStopping
	default:
		return VMStatePending
	}
}

func (o *OCIProvider) DestroyVM(ctx context.Context, vmID string) error {
	args := append([]string{"compute", "instance", "terminate", "--instance-id", vmID, "--force"}, o.regionArgs()...)
	if _, err := runCLI(ctx, "oci", args...); err != nil {
		if isVMNotFound(err, vmID) {
			return nil
		}
		return fmt.Errorf("oci compute instance terminate failed: %w", err)
	}
	return nil
}

func (o *OCIProvider) ListVMs(ctx context.Context, tags map[string]string) ([]VMInfo, error) {
	if err := validateLabels(tags); err != nil {
		return nil, fmt.Errorf("oci selector: %w", err)
	}
	if o.compartmentID == "" {
		return nil, fmt.Errorf("oci requires DISPATCHER_OCI_COMPARTMENT_ID to list instances")
	}
	args := append([]string{"compute", "instance", "list", "--compartment-id", o.compartmentID, "--output", "json"}, o.regionArgs()...)
	out, err := runCLI(ctx, "oci", args...)
	if err != nil {
		return nil, wrapExecError("oci compute instance list", err)
	}
	var listed struct {
		Data []struct {
			ID             string            `json:"id"`
			DisplayName    string            `json:"display-name"`
			LifecycleState string            `json:"lifecycle-state"`
			FreeformTags   map[string]string `json:"freeform-tags"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &listed); err != nil {
		return nil, fmt.Errorf("parse oci instance list: %w", err)
	}
	var vms []VMInfo
	for _, inst := range listed.Data {
		if ociLifecycleState(inst.LifecycleState) == VMStateTerminated {
			continue
		}
		if !tagsMatch(inst.FreeformTags, tags) {
			continue
		}
		vms = append(vms, VMInfo{
			ID:    inst.ID,
			Name:  inst.DisplayName,
			State: ociLifecycleState(inst.LifecycleState),
			Tags:  inst.FreeformTags,
		})
	}
	return vms, nil
}

// tagsMatch reports whether every selector tag is present with the same value in
// have. An empty selector matches everything.
func tagsMatch(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}
