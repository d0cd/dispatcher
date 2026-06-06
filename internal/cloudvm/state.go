package cloudvm

import (
	"encoding/json"
	"time"
)

// CloudVMState is the serializable adapter state for cloud VM runs.
// It implements adapter.SerializableState so it survives CLI restarts.
type CloudVMState struct {
	Provider   ProviderID `json:"provider"`
	VMID       string     `json:"vmId"`
	IP         string     `json:"ip"`
	SSHKeyPath string     `json:"sshKeyPath"`
	// KnownHostsPath is the path to a known_hosts file populated by
	// ssh-keyscan immediately after the VM became SSH-reachable. Subsequent
	// SSH calls use it with StrictHostKeyChecking=yes to prevent MITM on
	// reconnects. Empty for legacy state files / first connection.
	KnownHostsPath string    `json:"knownHostsPath,omitempty"`
	SSHUser        string    `json:"sshUser"`
	SSHPort        int       `json:"sshPort"`
	Region         string    `json:"region"`
	InstanceType   string    `json:"instanceType"`
	RemoteDir      string    `json:"remoteDir"`
	LogPath        string    `json:"logPath"`
	WorkloadPID    int       `json:"workloadPid,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	// LastExitCode is populated by Status() once the workload finishes by
	// SSH-reading the runner's exit-code file. Empty (0 + LastExitCodeRead
	// false) until then. Used by FailureDetails to surface the actual
	// workload exit code — without this, CloudVM Status would say
	// "Completed" for both real successes and real failures.
	LastExitCode     int  `json:"lastExitCode,omitempty"`
	LastExitCodeRead bool `json:"lastExitCodeRead,omitempty"`
	// SSHKeyManaged distinguishes dispatcher-generated per-run keys (true,
	// Cleanup removes them) from provider-supplied identity files (false,
	// e.g. Lima's ~/.lima/_config/user — must NOT be removed).
	SSHKeyManaged bool `json:"sshKeyManaged,omitempty"`
	// SSHWrapper is the path to a per-run shell script that invokes ssh
	// with the pinned identity, port, and known_hosts already baked in
	// (shell-quoted at write time). rsync uses it as `-e <wrapper>` so the
	// rsync -e value is just one filesystem path and no per-call quoting
	// is needed. Cleanup removes it.
	SSHWrapper string `json:"sshWrapper,omitempty"`
	// Outputs lists workload-relative paths under RemoteDir that should be
	// rsynced back before VM destruction. Persisted with state so reconnected
	// runs (CLI restart, watchdog rescue) still know what to retrieve.
	Outputs []string `json:"outputs,omitempty"`
}

// MarshalHandleState implements adapter.SerializableState.
func (s *CloudVMState) MarshalHandleState() (json.RawMessage, error) {
	return json.Marshal(s)
}

// UnmarshalCloudVMState deserializes a CloudVMState from JSON.
func UnmarshalCloudVMState(raw json.RawMessage) (*CloudVMState, error) {
	var s CloudVMState
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
