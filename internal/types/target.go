package types

// TargetKind classifies a target.
type TargetKind string

const (
	TargetKindLocal      TargetKind = "local"
	TargetKindLocalVM    TargetKind = "local-vm"
	TargetKindDocker     TargetKind = "docker"
	TargetKindSSH        TargetKind = "ssh"
	TargetKindKubernetes TargetKind = "kubernetes"
	TargetKindCloudVM    TargetKind = "cloud-vm"
	TargetKindModal      TargetKind = "modal"
	TargetKindE2B        TargetKind = "e2b"
)

// GPUCapability describes GPU support on a target.
type GPUCapability struct {
	Supported bool     `yaml:"supported" json:"supported"`
	Models    []string `yaml:"models,omitempty" json:"models,omitempty"`
}

// NetworkingCapability describes networking features.
type NetworkingCapability struct {
	PublicEndpoint  bool `yaml:"publicEndpoint" json:"publicEndpoint"`
	PrivateVPCAccess bool `yaml:"privateVpcAccess" json:"privateVpcAccess"`
	StaticEgressIP  bool `yaml:"staticEgressIp" json:"staticEgressIp"`
}

// AccountingCapability describes cost tracking support.
type AccountingCapability struct {
	CostEstimate  bool   `yaml:"costEstimate" json:"costEstimate"`
	ActualBilling bool   `yaml:"actualBilling" json:"actualBilling"`
	RateCard      string `yaml:"rateCard,omitempty" json:"rateCard,omitempty"`
}

// IsolationCapability describes isolation levels.
type IsolationCapability struct {
	Levels []string `yaml:"levels,omitempty" json:"levels,omitempty"`
}

// ObservabilityCapability describes logging/metrics support.
type ObservabilityCapability struct {
	Logs      bool `yaml:"logs" json:"logs"`
	Metrics   bool `yaml:"metrics" json:"metrics"`
	Artifacts bool `yaml:"artifacts" json:"artifacts"`
}

// Capabilities describes what a target can do.
type Capabilities struct {
	WorkloadKinds  []WorkloadKind          `yaml:"workloadKinds" json:"workloadKinds"`
	Resources      ResourceCapability      `yaml:"resources" json:"resources"`
	Networking     NetworkingCapability    `yaml:"networking" json:"networking"`
	Accounting     AccountingCapability    `yaml:"accounting" json:"accounting"`
	Isolation      IsolationCapability     `yaml:"isolation" json:"isolation"`
	Observability  ObservabilityCapability `yaml:"observability" json:"observability"`
	NotSupported   []string               `yaml:"notSupported,omitempty" json:"notSupported,omitempty"`
}

// ResourceCapability describes compute resources available.
type ResourceCapability struct {
	CPU    bool          `yaml:"cpu" json:"cpu"`
	Memory bool          `yaml:"memory" json:"memory"`
	GPU    GPUCapability `yaml:"gpu" json:"gpu"`
}

// SSHTargetConfig holds SSH connection details for SSH targets.
type SSHTargetConfig struct {
	Host    string `yaml:"host" json:"host"`
	User    string `yaml:"user" json:"user"`
	Port    int    `yaml:"port,omitempty" json:"port,omitempty"`
	KeyFile string `yaml:"keyFile,omitempty" json:"keyFile,omitempty"`
}

// TargetConfig defines a configured execution target.
type TargetConfig struct {
	ID           string           `yaml:"id" json:"id"`
	Kind         TargetKind       `yaml:"kind" json:"kind"`
	Enabled      bool             `yaml:"enabled" json:"enabled"`
	Capabilities Capabilities     `yaml:"capabilities" json:"capabilities"`
	SSH          *SSHTargetConfig `yaml:"ssh,omitempty" json:"ssh,omitempty"`
}
