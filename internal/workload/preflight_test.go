package workload

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
