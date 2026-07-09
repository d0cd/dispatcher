package cloudvm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGCPSSHKeysValue(t *testing.T) {
	// GCP metadata binds the key to a login user as "<user>:<pubkey>"; trailing
	// newline from the .pub file must be stripped.
	assert.Equal(t, "dispatcher:ssh-ed25519 AAAATEST comment",
		gcpSSHKeysValue("dispatcher", "ssh-ed25519 AAAATEST comment\n"))
}

// A GCP create must publish dispatcher's per-run public key via ssh-keys
// metadata; without it the VM comes up with no way for dispatcher to log in.
func TestGCPCreateVM_InjectsSSHKeyMetadata(t *testing.T) {
	binDir := t.TempDir()
	argvFile := filepath.Join(binDir, "argv")
	stub := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"" + argvFile + "\"\n" +
		"cat <<'JSON'\n[{\"name\":\"n\",\"networkInterfaces\":[{\"accessConfigs\":[{\"natIP\":\"1.2.3.4\"}]}]}]\nJSON\n"
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "gcloud"), []byte(stub), 0o755))
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	pub := filepath.Join(t.TempDir(), "k.pub")
	require.NoError(t, os.WriteFile(pub, []byte("ssh-ed25519 AAAATEST comment\n"), 0o600))

	_, err := NewGCPProvider("proj", "us-central1-a").CreateVM(context.Background(),
		VMOptions{Name: "n", SSHKeyPath: pub, SSHUser: "dispatcher",
			Tags: map[string]string{"dispatcher": "true"}})
	require.NoError(t, err)

	data, _ := os.ReadFile(argvFile)
	assert.Contains(t, string(data), "--metadata-from-file", "create must pass metadata files")
	assert.Contains(t, string(data), "ssh-keys=", "create must publish the ssh-keys metadata")
}

// The default GCP image family must actually exist in ubuntu-os-cloud. Ubuntu
// 24.04 publishes arch-suffixed families (ubuntu-2404-lts-amd64), so the bare
// "ubuntu-2404-lts" is not a resolvable family and create fails.
func TestGCPCreateVM_DefaultImageFamilyResolvable(t *testing.T) {
	binDir := t.TempDir()
	argvFile := filepath.Join(binDir, "argv")
	stub := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"" + argvFile + "\"\n" +
		"cat <<'JSON'\n[{\"name\":\"n\",\"networkInterfaces\":[{\"accessConfigs\":[{\"natIP\":\"1.2.3.4\"}]}]}]\nJSON\n"
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "gcloud"), []byte(stub), 0o755))
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, err := NewGCPProvider("proj", "us-central1-a").CreateVM(context.Background(),
		VMOptions{Name: "n", Tags: map[string]string{"dispatcher": "true"}})
	require.NoError(t, err)

	data, _ := os.ReadFile(argvFile)
	assert.Contains(t, string(data), "ubuntu-2404-lts-amd64",
		"default image family must be the real arch-suffixed 24.04 family")
}

// A confidential VM with no explicit instance type must default to a
// TEE-capable machine family — e2-medium rejects --confidential-compute-type
// and --min-cpu-platform, so the generic default can't be used for confidential.
func TestGCPCreateVM_ConfidentialDefaultsToCapableMachine(t *testing.T) {
	binDir := t.TempDir()
	argvFile := filepath.Join(binDir, "argv")
	stub := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"" + argvFile + "\"\n" +
		"cat <<'JSON'\n[{\"name\":\"n\",\"networkInterfaces\":[{\"accessConfigs\":[{\"natIP\":\"1.2.3.4\"}]}]}]\nJSON\n"
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "gcloud"), []byte(stub), 0o755))
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, err := NewGCPProvider("proj", "us-central1-a").CreateVM(context.Background(),
		VMOptions{Name: "n", ConfidentialType: "sev-snp", Tags: map[string]string{"dispatcher": "true"}})
	require.NoError(t, err)

	data, _ := os.ReadFile(argvFile)
	assert.Contains(t, string(data), "--machine-type n2d-standard-2", "SEV-SNP needs an AMD n2d")
	assert.NotContains(t, string(data), "e2-medium", "must not fall back to the non-confidential default")
}

// GPUs can't live-migrate, so GCP rejects a GPU machine type unless
// --maintenance-policy=TERMINATE is set. A plain CPU VM must NOT get it.
func TestGCPCreateVM_GPUMachineGetsTerminatePolicy(t *testing.T) {
	newStub := func(t *testing.T) string {
		binDir := t.TempDir()
		argvFile := filepath.Join(binDir, "argv")
		stub := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"" + argvFile + "\"\n" +
			"cat <<'JSON'\n[{\"name\":\"n\",\"networkInterfaces\":[{\"accessConfigs\":[{\"natIP\":\"1.2.3.4\"}]}]}]\nJSON\n"
		require.NoError(t, os.WriteFile(filepath.Join(binDir, "gcloud"), []byte(stub), 0o755))
		t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
		return argvFile
	}

	t.Run("gpu machine gets TERMINATE", func(t *testing.T) {
		argvFile := newStub(t)
		_, err := NewGCPProvider("proj", "us-central1-a").CreateVM(context.Background(),
			VMOptions{Name: "n", InstanceType: "g2-standard-4", Tags: map[string]string{"dispatcher": "true"}})
		require.NoError(t, err)
		data, _ := os.ReadFile(argvFile)
		assert.Contains(t, string(data), "--maintenance-policy=TERMINATE")
	})

	t.Run("cpu machine does not", func(t *testing.T) {
		argvFile := newStub(t)
		_, err := NewGCPProvider("proj", "us-central1-a").CreateVM(context.Background(),
			VMOptions{Name: "n", InstanceType: "e2-medium", Tags: map[string]string{"dispatcher": "true"}})
		require.NoError(t, err)
		data, _ := os.ReadFile(argvFile)
		assert.NotContains(t, string(data), "--maintenance-policy=TERMINATE")
	})
}

// A GPU machine needs the NVIDIA driver; when the operator supplies a
// driver-baked image via DISPATCHER_GCP_GPU_IMAGE, GPU creates use it (from the
// current project), not the stock ubuntu-os-cloud family.
func TestGCPCreateVM_GPUImageOverride(t *testing.T) {
	binDir := t.TempDir()
	argvFile := filepath.Join(binDir, "argv")
	stub := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"" + argvFile + "\"\n" +
		"cat <<'JSON'\n[{\"name\":\"n\",\"networkInterfaces\":[{\"accessConfigs\":[{\"natIP\":\"1.2.3.4\"}]}]}]\nJSON\n"
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "gcloud"), []byte(stub), 0o755))
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DISPATCHER_GCP_GPU_IMAGE", "dispatcher-gpu-l4")

	_, err := NewGCPProvider("proj", "us-central1-a").CreateVM(context.Background(),
		VMOptions{Name: "n", InstanceType: "g2-standard-4", Tags: map[string]string{"dispatcher": "true"}})
	require.NoError(t, err)

	data, _ := os.ReadFile(argvFile)
	assert.Contains(t, string(data), "--image dispatcher-gpu-l4", "GPU create uses the driver-baked image")
	assert.NotContains(t, string(data), "ubuntu-os-cloud", "a current-project image must not carry --image-project ubuntu-os-cloud")
}

func TestAWSInstanceType_ConfidentialDefaultsToCapable(t *testing.T) {
	// t3 does not support SEV-SNP; a confidential VM with no explicit type must
	// default to an SEV-SNP-capable family.
	assert.Equal(t, "t3.micro", awsInstanceType(VMOptions{}))
	assert.Equal(t, "m6a.large", awsInstanceType(VMOptions{ConfidentialType: "sev-snp"}))
	assert.Equal(t, "c5.large", awsInstanceType(VMOptions{InstanceType: "c5.large", ConfidentialType: "sev-snp"}),
		"an explicit instance type is respected")
}

func TestAWSSGName(t *testing.T) {
	assert.Equal(t, "dispatcher-run-abc",
		awsSGName(VMOptions{Tags: map[string]string{"dispatcher-run-id": "run_abc"}}))
	// Falls back to the VM name when no run id tag is present.
	assert.Equal(t, "dispatcher-myvm", awsSGName(VMOptions{Name: "myvm"}))
}

func TestAWSUserDataWithSSHKey(t *testing.T) {
	out := awsUserDataWithSSHKey("#!/bin/sh\necho hi\n", "ubuntu", "ssh-ed25519 AAAATEST comment\n")
	assert.Contains(t, out, "#!/bin/sh", "original boot script is preserved")
	assert.Contains(t, out, "/home/ubuntu/.ssh/authorized_keys", "key is installed for the login user")
	assert.Contains(t, out, "ssh-ed25519 AAAATEST comment", "the public key is present")
}

// An AWS create must fold dispatcher's public key into the boot user-data so the
// instance authorizes the per-run key (AWS has no metadata channel like GCP).
func TestAWSCreateVM_InjectsSSHKeyIntoUserData(t *testing.T) {
	binDir := t.TempDir()
	argvFile := filepath.Join(binDir, "argv")
	// Record argv and, for run-instances, echo the user-data file's contents so
	// the test can confirm the key was folded in. Return minimal JSON.
	stub := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"" + argvFile + "\"\n" +
		"for a in \"$@\"; do case \"$a\" in file://*) cat \"${a#file://}\" >> \"" + argvFile + "\";; esac; done\n" +
		"case \"$*\" in\n" +
		"  *describe-instances*) echo '{\"Reservations\":[{\"Instances\":[{\"InstanceId\":\"i-1\",\"PublicIpAddress\":\"1.2.3.4\",\"State\":{\"Name\":\"running\"}}]}]}' ;;\n" +
		"  *) echo '{\"Instances\":[{\"InstanceId\":\"i-1\"}]}' ;;\n" +
		"esac\n"
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "aws"), []byte(stub), 0o755))
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	pub := filepath.Join(t.TempDir(), "k.pub")
	require.NoError(t, os.WriteFile(pub, []byte("ssh-ed25519 AAAATEST comment\n"), 0o600))

	// getVMInRegion/waitForIP will fail against the stub; we only care that
	// run-instances captured the folded-in key, so ignore the overall error.
	_, _ = NewAWSProvider("us-east-1").CreateVM(context.Background(),
		VMOptions{Name: "n", Image: "ami-123", InstanceType: "t3.micro",
			SSHKeyPath: pub, SSHUser: "ubuntu", UserData: "#!/bin/sh\necho hi\n",
			Tags: map[string]string{"dispatcher": "true"}})

	data, _ := os.ReadFile(argvFile)
	assert.Contains(t, string(data), "ssh-ed25519 AAAATEST comment", "user-data must carry the per-run key")
}
