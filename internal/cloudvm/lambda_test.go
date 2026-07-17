package cloudvm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lambdaStub routes a request by method + path suffix to a canned response,
// standing in for the Lambda API so the provider is exercised without a network.
type lambdaStub struct {
	t        *testing.T
	handler  func(method, path string, body []byte) (int, string)
	requests []string // "METHOD path" log for assertions
}

func (s *lambdaStub) do(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	s.requests = append(s.requests, req.Method+" "+req.URL.Path)
	// The stub relies on Basic auth being set so a regression that drops it fails.
	if _, _, ok := req.BasicAuth(); !ok {
		s.t.Fatalf("request %s %s missing basic auth", req.Method, req.URL.Path)
	}
	status, payload := s.handler(req.Method, req.URL.Path, body)
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(payload)),
		Header:     make(http.Header),
	}, nil
}

func newLambdaTestProvider(t *testing.T, handler func(method, path string, body []byte) (int, string)) (*LambdaProvider, *lambdaStub) {
	stub := &lambdaStub{t: t, handler: handler}
	p := &LambdaProvider{
		apiKey:        "test-key",
		defaultRegion: "us-east-1",
		baseURL:       "https://cloud.lambdalabs.com/api/v1",
		do:            stub.do,
	}
	return p, stub
}

func TestLambdaCreateVM_UploadsKeyLaunchesAndResolvesIP(t *testing.T) {
	dir := t.TempDir()
	pub := filepath.Join(dir, "id.pub")
	require.NoError(t, os.WriteFile(pub, []byte("ssh-ed25519 AAAA test\n"), 0o600))

	var launchBody map[string]any
	p, _ := newLambdaTestProvider(t, func(method, path string, body []byte) (int, string) {
		switch {
		case method == http.MethodPost && strings.HasSuffix(path, "/ssh-keys"):
			return 200, `{"data":{"id":"key-1","name":"dispatcher-run_abc"}}`
		case method == http.MethodPost && strings.HasSuffix(path, "/instance-operations/launch"):
			_ = json.Unmarshal(body, &launchBody)
			return 200, `{"data":{"instance_ids":["inst-9"]}}`
		case method == http.MethodGet && strings.HasSuffix(path, "/instances/inst-9"):
			return 200, `{"data":{"id":"inst-9","name":"dispatcher-run_abc","ip":"203.0.113.7","status":"active"}}`
		default:
			t.Fatalf("unexpected call %s %s", method, path)
			return 500, ""
		}
	})

	vm, err := p.CreateVM(context.Background(), VMOptions{
		Name:         "job",
		InstanceType: "gpu_1x_a100",
		Region:       "us-west-1",
		SSHKeyPath:   pub,
		Tags:         map[string]string{"dispatcher-run-id": "run_abc"},
	})
	require.NoError(t, err)
	assert.Equal(t, "inst-9", vm.ID)
	assert.Equal(t, "203.0.113.7", vm.IP)
	assert.Equal(t, "ubuntu", vm.SSHUser)
	assert.Equal(t, VMStateRunning, vm.State)
	assert.Equal(t, "run_abc", vm.Tags["dispatcher-run-id"])

	// The launch encodes the run id into the name and references the per-run key.
	assert.Equal(t, "dispatcher-run_abc", launchBody["name"])
	assert.Equal(t, "gpu_1x_a100", launchBody["instance_type_name"])
	assert.Equal(t, "us-west-1", launchBody["region_name"])
	assert.Equal(t, []any{"dispatcher-run_abc"}, launchBody["ssh_key_names"])
}

func TestLambdaCreateVM_RejectsMissingInstanceType(t *testing.T) {
	p, _ := newLambdaTestProvider(t, func(string, string, []byte) (int, string) {
		t.Fatal("no API call should be made without an instance type")
		return 500, ""
	})
	_, err := p.CreateVM(context.Background(), VMOptions{Name: "x", Tags: map[string]string{"dispatcher-run-id": "r"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "instance type")
}

func TestLambdaGetVM_NotFoundIsTerminated(t *testing.T) {
	p, _ := newLambdaTestProvider(t, func(method, path string, _ []byte) (int, string) {
		return 404, `{"error":{"code":"instance-not-found","message":"no such instance"}}`
	})
	vm, err := p.GetVM(context.Background(), "gone")
	require.NoError(t, err, "a 404 is a definitive terminated state, not an error")
	assert.Equal(t, VMStateTerminated, vm.State)
}

func TestLambdaGetVM_OtherErrorPropagates(t *testing.T) {
	p, _ := newLambdaTestProvider(t, func(method, path string, _ []byte) (int, string) {
		return 500, `{"error":{"message":"boom"}}`
	})
	_, err := p.GetVM(context.Background(), "x")
	require.Error(t, err, "a 500 must not be mistaken for a terminated VM")
}

func TestLambdaListVMs_FiltersByEncodedRunID(t *testing.T) {
	p, _ := newLambdaTestProvider(t, func(method, path string, _ []byte) (int, string) {
		return 200, `{"data":[
			{"id":"a","name":"dispatcher-run_1","ip":"1.1.1.1","status":"active"},
			{"id":"b","name":"dispatcher-run_2","ip":"2.2.2.2","status":"active"},
			{"id":"c","name":"someone-elses-box","ip":"3.3.3.3","status":"active"}
		]}`
	})
	// Filter to one run.
	vms, err := p.ListVMs(context.Background(), map[string]string{"dispatcher-run-id": "run_2"})
	require.NoError(t, err)
	require.Len(t, vms, 1)
	assert.Equal(t, "b", vms[0].ID)
	assert.Equal(t, "run_2", vms[0].Tags["dispatcher-run-id"])

	// The unmanaged box is never returned even for a broad dispatcher-only query.
	all, err := p.ListVMs(context.Background(), map[string]string{"dispatcher": "true"})
	require.NoError(t, err)
	require.Len(t, all, 2)
}

func TestLambdaDestroyVM_TerminatesAndDeletesKey(t *testing.T) {
	deletedKey := false
	p, _ := newLambdaTestProvider(t, func(method, path string, _ []byte) (int, string) {
		switch {
		case method == http.MethodGet && strings.HasSuffix(path, "/instances/inst-9"):
			return 200, `{"data":{"id":"inst-9","name":"dispatcher-run_abc","status":"active"}}`
		case method == http.MethodPost && strings.HasSuffix(path, "/instance-operations/terminate"):
			return 200, `{"data":{"terminated_instances":[{"id":"inst-9"}]}}`
		case method == http.MethodGet && strings.HasSuffix(path, "/ssh-keys"):
			return 200, `{"data":[{"id":"key-1","name":"dispatcher-run_abc"}]}`
		case method == http.MethodDelete && strings.HasSuffix(path, "/ssh-keys/key-1"):
			deletedKey = true
			return 200, `{"data":{}}`
		default:
			t.Fatalf("unexpected call %s %s", method, path)
			return 500, ""
		}
	})
	require.NoError(t, p.DestroyVM(context.Background(), "inst-9"))
	assert.True(t, deletedKey, "the per-run ssh key must be deleted on teardown")
}

func TestLambdaCheckCLI_RequiresAPIKey(t *testing.T) {
	p := &LambdaProvider{apiKey: "", baseURL: "x", do: http.DefaultClient.Do}
	err := p.CheckCLI(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DISPATCHER_LAMBDA_API_KEY")
}

func TestLambdaPureHelpers(t *testing.T) {
	assert.Equal(t, "dispatcher-run_x", lambdaInstanceName("run_x", "ignored"))
	assert.Equal(t, "dispatcher-fallback", lambdaInstanceName("", "fallback"))
	assert.Equal(t, "run_x", lambdaTags("dispatcher-run_x")["dispatcher-run-id"])
	assert.Equal(t, "true", lambdaTags("dispatcher-run_x")["dispatcher"])
	_, hasRun := lambdaTags("external-box")["dispatcher-run-id"]
	assert.False(t, hasRun, "a name without the prefix carries no run id")

	assert.Equal(t, VMStateRunning, lambdaState("active"))
	assert.Equal(t, VMStatePending, lambdaState("booting"))
	assert.Equal(t, VMStateStopping, lambdaState("terminating"))
	assert.Equal(t, VMStateTerminated, lambdaState("terminated"))
	assert.Equal(t, VMStateError, lambdaState("unhealthy"))
}
