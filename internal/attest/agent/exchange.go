package agent

// Payload and Result are the confidential-exchange wire types carried over the
// attested TLS session (internal/attest/atls): dispatcher delivers a Payload to
// the verified in-TEE agent and the agent returns a Result over the same session.
// []byte fields are base64 in JSON. The session's attestation binding is what makes
// the untrusted channel safe (R9) — there is no separate payload sealing.

// Payload is what dispatcher delivers to the agent over the attested session.
type Payload struct {
	Command     []string `json:"command"`
	DotEnv      []byte   `json:"dotenv,omitempty"`
	SourceTarGz []byte   `json:"source_tar_gz,omitempty"`
	Outputs     []string `json:"outputs,omitempty"`
}

// Result is what the agent returns over the attested session once the workload
// has finished.
type Result struct {
	ExitCode     int    `json:"exit_code"`
	Stdout       []byte `json:"stdout,omitempty"`
	Stderr       []byte `json:"stderr,omitempty"`
	OutputsTarGz []byte `json:"outputs_tar_gz,omitempty"`
}
