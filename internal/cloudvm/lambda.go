package cloudvm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// LambdaProvider implements Provider against the Lambda Cloud REST API
// (https://cloud.lambdalabs.com/api/v1). It is dispatcher's first HTTP-native
// provider — the others shell out to a vendor CLI — so the transport is a seam
// (p.do) that tests stub without a live account.
//
// Lambda's model shapes a few decisions:
//   - Auth is an Authorization: Bearer <api-key> header (the API's recommended
//     scheme; it also accepts HTTP Basic for backward compatibility).
//   - Instances carry no arbitrary tags, only a name. dispatcher encodes the run
//     id into the name ("dispatcher-<run-id>") and recovers it for tag-based
//     lookups (gc, adopt), synthesising the tag map GetVM/ListVMs return.
//   - SSH keys are account-registered by name and referenced at launch (like
//     Hetzner); the per-run public key is uploaded on create and deleted on
//     destroy.
//
// Known limitations (provisioning-only first cut, mirroring the OCI rollout):
//   - No per-run SSH firewall (AllowSSHFrom is not enforced): Lambda's firewall
//     API is account-global, not per-instance.
//   - The launch API takes no user-data, so the in-VM self-destruct watchdog
//     can't be injected; a dead dispatcher relies on `dispatcher gc` to reap by
//     name rather than an in-VM TTL backstop.
type LambdaProvider struct {
	apiKey        string
	defaultRegion string
	baseURL       string
	do            func(*http.Request) (*http.Response, error)
}

// NewLambdaProvider builds a Lambda Cloud provider. The API key comes from
// DISPATCHER_LAMBDA_API_KEY; region defaults to us-east-1 when unset.
func NewLambdaProvider(region string) *LambdaProvider {
	if region == "" {
		region = "us-east-1"
	}
	return &LambdaProvider{
		apiKey:        os.Getenv("DISPATCHER_LAMBDA_API_KEY"),
		defaultRegion: region,
		baseURL:       "https://cloud.lambda.ai/api/v1",
		do:            http.DefaultClient.Do,
	}
}

func (l *LambdaProvider) Name() ProviderID { return ProviderLambda }

// lambdaInstance is the subset of Lambda's instance object dispatcher consumes.
type lambdaInstance struct {
	ID           string                `json:"id"`
	Name         string                `json:"name"`
	IP           string                `json:"ip"`
	Status       string                `json:"status"` // booting | active | unhealthy | terminating | terminated
	SSHKeyNames  []string              `json:"ssh_key_names"`
	Region       struct{ Name string } `json:"region"`
	InstanceType struct{ Name string } `json:"instance_type"`
}

// lambdaDo issues a JSON request to the Lambda API and decodes the "data"
// envelope into out (may be nil). A non-2xx response is returned as an error
// carrying the API's error message so callers surface the real complaint.
func (l *LambdaProvider) lambdaDo(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, l.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+l.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := l.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Error struct {
				Code, Message, Suggestion string
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := strings.TrimSpace(e.Error.Message + " " + e.Error.Suggestion)
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
		}
		return &lambdaAPIError{status: resp.StatusCode, message: msg}
	}
	if out == nil {
		return nil
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("parse lambda response: %w", err)
	}
	return json.Unmarshal(env.Data, out)
}

// lambdaAPIError carries the HTTP status so callers (GetVM) can distinguish a
// 404 (instance gone) from other failures.
type lambdaAPIError struct {
	status  int
	message string
}

func (e *lambdaAPIError) Error() string {
	return fmt.Sprintf("lambda api %d: %s", e.status, e.message)
}

func (l *LambdaProvider) CheckCLI(ctx context.Context) error {
	if l.apiKey == "" {
		return fmt.Errorf("lambda: DISPATCHER_LAMBDA_API_KEY is not set")
	}
	// A cheap authenticated GET confirms the key works before we try to launch.
	if err := l.lambdaDo(ctx, http.MethodGet, "/instance-types", nil, nil); err != nil {
		return fmt.Errorf("lambda: API key rejected or unreachable: %w", err)
	}
	return nil
}

func (l *LambdaProvider) CreateVM(ctx context.Context, opts VMOptions) (*VMInfo, error) {
	region := opts.Region
	if region == "" {
		region = l.defaultRegion
	}
	instanceType := opts.InstanceType
	if instanceType == "" {
		// A GPU box is the whole point of Lambda; pin a type via the planner
		// rather than guessing a default that may be unavailable in-region.
		return nil, fmt.Errorf("lambda: no instance type resolved (set one via the plan; Lambda has no safe default)")
	}
	if err := validateVMArgs(region, instanceType, "ubuntu"); err != nil {
		return nil, fmt.Errorf("lambda: %w", err)
	}

	runID := opts.Tags["dispatcher-run-id"]
	name := lambdaInstanceName(runID, opts.Name)

	// Register the per-run public key by name, then launch referencing it.
	keyName := name
	if opts.SSHKeyPath != "" {
		if err := l.ensureSSHKey(ctx, keyName, opts.SSHKeyPath); err != nil {
			return nil, err
		}
	}

	var launched struct {
		InstanceIDs []string `json:"instance_ids"`
	}
	err := l.lambdaDo(ctx, http.MethodPost, "/instance-operations/launch", map[string]any{
		"region_name":        region,
		"instance_type_name": instanceType,
		"ssh_key_names":      []string{keyName},
		"name":               name,
		"quantity":           1,
	}, &launched)
	if err != nil {
		// Launch failed; don't leak the key we just uploaded.
		l.deleteSSHKey(context.Background(), keyName)
		return nil, fmt.Errorf("lambda launch: %w", err)
	}
	if len(launched.InstanceIDs) == 0 {
		l.deleteSSHKey(context.Background(), keyName)
		return nil, fmt.Errorf("lambda launch returned no instance id")
	}
	id := launched.InstanceIDs[0]

	// Poll until the instance has a public IP (Lambda assigns it shortly after
	// booting), mirroring AWS's waitForIP so the adapter gets a dialable address.
	ip, err := l.waitForIP(ctx, id)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_ = l.DestroyVM(cleanupCtx, id)
		return nil, err
	}

	return &VMInfo{
		ID:        id,
		Name:      name,
		IP:        ip,
		SSHUser:   "ubuntu",
		State:     VMStateRunning,
		CreatedAt: time.Now().UTC(),
		Tags:      lambdaTags(name),
	}, nil
}

// waitForIP polls GetVM until the instance reports a public IP or the context /
// a bounded deadline expires.
func (l *LambdaProvider) waitForIP(ctx context.Context, id string) (string, error) {
	deadline := time.Now().Add(5 * time.Minute)
	for {
		vm, err := l.GetVM(ctx, id)
		if err != nil {
			return "", err
		}
		if vm.State == VMStateTerminated {
			return "", fmt.Errorf("lambda instance %s terminated before it got an IP", id)
		}
		if vm.IP != "" {
			return vm.IP, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("lambda instance %s did not get an IP within the deadline", id)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func (l *LambdaProvider) WaitReady(ctx context.Context, _ string, ip string, _ string) error {
	return WaitForSSH(ctx, ip, 5*time.Minute)
}

func (l *LambdaProvider) GetVM(ctx context.Context, vmID string) (*VMInfo, error) {
	var inst lambdaInstance
	err := l.lambdaDo(ctx, http.MethodGet, "/instances/"+vmID, nil, &inst)
	if err != nil {
		var apiErr *lambdaAPIError
		if errors.As(err, &apiErr) && apiErr.status == http.StatusNotFound {
			return &VMInfo{ID: vmID, State: VMStateTerminated}, nil
		}
		return nil, fmt.Errorf("lambda get instance: %w", err)
	}
	return &VMInfo{
		ID:      inst.ID,
		Name:    inst.Name,
		IP:      inst.IP,
		SSHUser: "ubuntu",
		State:   lambdaState(inst.Status),
		Tags:    lambdaTags(inst.Name),
	}, nil
}

func (l *LambdaProvider) DestroyVM(ctx context.Context, vmID string) error {
	// Recover the name (→ ssh-key name) before terminating so the per-run key can
	// be deleted afterward; best-effort if the instance is already gone.
	keyName := ""
	if vm, err := l.GetVM(ctx, vmID); err == nil {
		keyName = vm.Name
	}
	err := l.lambdaDo(ctx, http.MethodPost, "/instance-operations/terminate", map[string]any{
		"instance_ids": []string{vmID},
	}, nil)
	if err != nil {
		var apiErr *lambdaAPIError
		if !(errors.As(err, &apiErr) && apiErr.status == http.StatusNotFound) {
			return fmt.Errorf("lambda terminate: %w", err)
		}
	}
	if keyName != "" {
		l.deleteSSHKey(ctx, keyName)
	}
	return nil
}

func (l *LambdaProvider) ListVMs(ctx context.Context, tags map[string]string) ([]VMInfo, error) {
	var insts []lambdaInstance
	if err := l.lambdaDo(ctx, http.MethodGet, "/instances", nil, &insts); err != nil {
		return nil, fmt.Errorf("lambda list instances: %w", err)
	}
	// Lambda has no server-side tag filter, so match on the encoded name locally.
	wantRun := tags["dispatcher-run-id"]
	var vms []VMInfo
	for _, inst := range insts {
		if !strings.HasPrefix(inst.Name, lambdaNamePrefix) {
			continue
		}
		if wantRun != "" && inst.Name != lambdaInstanceName(wantRun, "") {
			continue
		}
		vms = append(vms, VMInfo{
			ID:      inst.ID,
			Name:    inst.Name,
			IP:      inst.IP,
			SSHUser: "ubuntu",
			State:   lambdaState(inst.Status),
			Tags:    lambdaTags(inst.Name),
		})
	}
	return vms, nil
}

// ensureSSHKey registers the per-run public key under keyName, tolerating an
// "already exists" from a retry.
func (l *LambdaProvider) ensureSSHKey(ctx context.Context, keyName, pubKeyPath string) error {
	pub, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("lambda read ssh pubkey: %w", err)
	}
	err = l.lambdaDo(ctx, http.MethodPost, "/ssh-keys", map[string]any{
		"name":       keyName,
		"public_key": strings.TrimSpace(string(pub)),
	}, nil)
	if err != nil {
		var apiErr *lambdaAPIError
		// 400/409 with an "exists" message means a prior attempt uploaded it.
		if errors.As(err, &apiErr) && strings.Contains(strings.ToLower(apiErr.message), "exist") {
			return nil
		}
		return fmt.Errorf("lambda add ssh key: %w", err)
	}
	return nil
}

// deleteSSHKey removes the per-run key by name. Best-effort: Lambda's delete is
// by key id, so resolve the name→id first; a missing key is not an error.
func (l *LambdaProvider) deleteSSHKey(ctx context.Context, keyName string) {
	var keys []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := l.lambdaDo(ctx, http.MethodGet, "/ssh-keys", nil, &keys); err != nil {
		return
	}
	for _, k := range keys {
		if k.Name == keyName {
			_ = l.lambdaDo(ctx, http.MethodDelete, "/ssh-keys/"+k.ID, nil, nil)
			return
		}
	}
}

const lambdaNamePrefix = "dispatcher-"

// lambdaInstanceName encodes the run id (or a fallback name) into the instance
// name so tag-based lookups can recover it.
func lambdaInstanceName(runID, fallback string) string {
	if runID != "" {
		return lambdaNamePrefix + runID
	}
	return lambdaNamePrefix + fallback
}

// lambdaTags synthesises the tag map dispatcher expects from an encoded name, so
// gc/adopt (which key off dispatcher-run-id) work against a provider with no
// native tags.
func lambdaTags(name string) map[string]string {
	tags := map[string]string{"dispatcher": "true"}
	if runID := strings.TrimPrefix(name, lambdaNamePrefix); runID != name {
		tags["dispatcher-run-id"] = runID
	}
	return tags
}

// lambdaState maps a Lambda instance status to a dispatcher VMState.
func lambdaState(status string) VMState {
	switch status {
	case "active":
		return VMStateRunning
	case "booting", "":
		return VMStatePending
	case "terminating":
		return VMStateStopping
	case "terminated":
		return VMStateTerminated
	default: // unhealthy, unknown
		return VMStateError
	}
}
