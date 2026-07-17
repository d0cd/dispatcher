package workload

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInputPreflightClient_BlocksSSRFTargets(t *testing.T) {
	client := NewInputPreflightClient(2 * time.Second)
	// The dialer must refuse loopback and the cloud metadata service even though
	// they're reachable, closing the SSRF vector on repo-controlled input URLs.
	for _, url := range []string{
		"http://127.0.0.1:1/x",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]:1/x",
	} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		require.NoError(t, err)
		_, err = client.Do(req)
		require.Error(t, err, "expected %s to be blocked", url)
		assert.Contains(t, err.Error(), "disallowed")
	}
}

func TestIsBlockedInputHost(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.1", "::1", "fe80::1", "0.0.0.0"} {
		assert.True(t, isBlockedInputHost(net.ParseIP(ip)), "%s should be blocked", ip)
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34"} {
		assert.False(t, isBlockedInputHost(net.ParseIP(ip)), "%s should be allowed", ip)
	}
}

func TestInputRefs_ParsesEnvContract(t *testing.T) {
	refs := InputRefs(map[string]string{
		"DISPATCHER_INPUT_GENOME": "https://store.example/genome.fa.gz abc123",
		"DISPATCHER_INPUT_PANEL":  "https://store.example/panel.bed", // no digest
		"DISPATCHER_INPUT_LOCAL":  "/data/local.txt",                 // not a URL → ignored
		"UNRELATED":               "https://store.example/other",     // wrong key → ignored
	})
	require.Len(t, refs, 2, "only http(s) DISPATCHER_INPUT_* vars are input refs")

	byKey := map[string]InputRef{}
	for _, r := range refs {
		byKey[r.EnvKey] = r
	}
	assert.Equal(t, "https://store.example/genome.fa.gz", byKey["DISPATCHER_INPUT_GENOME"].URI)
	assert.Equal(t, "abc123", byKey["DISPATCHER_INPUT_GENOME"].SHA256)
	assert.Equal(t, "", byKey["DISPATCHER_INPUT_PANEL"].SHA256, "digest is optional")
}

// A source that advertises an object but returns 403 on the object itself must
// fail the run BEFORE provisioning — as a definitive source error, not transport.
func TestPreflightInputs_ForbiddenIsSourceError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	err := PreflightInputs(context.Background(), []InputRef{{EnvKey: "DISPATCHER_INPUT_X", URI: srv.URL}}, srv.Client())
	require.Error(t, err)
	var se *InputSourceError
	require.True(t, errors.As(err, &se), "a 4xx must be an InputSourceError, not transport")
	assert.Equal(t, http.StatusForbidden, se.Status)
}

func TestPreflightInputs_ReachableSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Honor the bounded Range read.
		assert.NotEmpty(t, r.Header.Get("Range"), "preflight must do a bounded Range read, not a full GET")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()

	err := PreflightInputs(context.Background(), []InputRef{{EnvKey: "DISPATCHER_INPUT_X", URI: srv.URL}}, srv.Client())
	assert.NoError(t, err, "a reachable object passes preflight")
}

// A 5xx or a network failure is transport (possibly transient), recorded
// separately from a definitive source rejection.
func TestPreflightInputs_ServerErrorIsTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	err := PreflightInputs(context.Background(), []InputRef{{EnvKey: "DISPATCHER_INPUT_X", URI: srv.URL}}, srv.Client())
	require.Error(t, err)
	var te *InputTransportError
	assert.True(t, errors.As(err, &te), "a 5xx must be a transport error, not a source error")
}
