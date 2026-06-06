package cloudvm

import (
	"encoding/json"
	"time"
)

// CloudVMState is the serializable adapter state for cloud VM runs.
// It implements adapter.SerializableState so it survives CLI restarts.
type CloudVMState struct {
	Provider     ProviderID `json:"provider"`
	VMID         string     `json:"vmId"`
	IP           string     `json:"ip"`
	SSHKeyPath   string     `json:"sshKeyPath"`
	SSHUser      string     `json:"sshUser"`
	SSHPort      int        `json:"sshPort"`
	Region       string     `json:"region"`
	InstanceType string     `json:"instanceType"`
	RemoteDir    string     `json:"remoteDir"`
	LogPath      string     `json:"logPath"`
	WorkloadPID  int        `json:"workloadPid,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
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
