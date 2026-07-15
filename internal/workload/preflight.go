package workload

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// inputEnvPrefix marks a workload env var as a large-immutable-input reference:
// its value is "<uri>" or "<uri> <sha256>". The workload fetches and digest-
// verifies the object on the VM; dispatcher only preflights that the source is
// reachable, so a 403/404 fails the run BEFORE a paid VM is provisioned. This
// rides on the existing workload environment — there is no new config type, and
// the same env var the workload reads is the one dispatcher checks.
const inputEnvPrefix = "DISPATCHER_INPUT"

// preflightRangeEnd is the last byte the bounded Range read requests — enough to
// confirm the object serves content without downloading it.
const preflightRangeEnd = 0

// InputRef is a parsed large-immutable-input reference.
type InputRef struct {
	EnvKey string
	URI    string
	SHA256 string // optional; verified by the workload on arrival, not by the preflight
}

// InputRefs extracts input references from a workload's environment (its .env
// merged with any spec-level env): every DISPATCHER_INPUT* var whose value begins
// with an http(s) URI. A digest, when present, is the second whitespace-separated
// field. Non-URL values (e.g. a local path) are not fetch references and skipped.
func InputRefs(env map[string]string) []InputRef {
	var refs []InputRef
	for k, v := range env {
		if !strings.HasPrefix(k, inputEnvPrefix) {
			continue
		}
		fields := strings.Fields(v)
		if len(fields) == 0 {
			continue
		}
		uri := fields[0]
		if !strings.HasPrefix(uri, "http://") && !strings.HasPrefix(uri, "https://") {
			continue
		}
		ref := InputRef{EnvKey: k, URI: uri}
		if len(fields) > 1 {
			ref.SHA256 = fields[1]
		}
		refs = append(refs, ref)
	}
	return refs
}

// InputSourceError is a definitive source failure (HTTP 4xx / gone, or a
// malformed URI): the object is not fetchable, so a retry won't help — fail the
// run before provisioning and fix the source or credentials.
type InputSourceError struct {
	Ref    InputRef
	Status int // 0 for a malformed URI
}

func (e *InputSourceError) Error() string {
	if e.Status == 0 {
		return fmt.Sprintf("input %s (%s) is not a valid URL — fix the reference before running", e.Ref.EnvKey, e.Ref.URI)
	}
	return fmt.Sprintf("input %s (%s) is not fetchable: HTTP %d — fix the source or credentials before running", e.Ref.EnvKey, e.Ref.URI, e.Status)
}

// InputTransportError is a transport-level failure (timeout, connection reset,
// 5xx): possibly transient, recorded separately from a definitive source
// rejection so the operator can tell "the source said no" from "couldn't reach it".
type InputTransportError struct {
	Ref InputRef
	Err error
}

func (e *InputTransportError) Error() string {
	return fmt.Sprintf("input %s (%s) could not be reached (transport, may be transient): %v", e.Ref.EnvKey, e.Ref.URI, e.Err)
}

// HTTPDoer is the seam for the preflight's HTTP client (a real *http.Client in
// production, a stub in tests).
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// PreflightInputs does a bounded Range read of each input URI to confirm the
// source is actually fetchable before expensive compute — catching the case
// where an index advertises an object but the object itself returns 403. A 4xx
// (or malformed URI) is an InputSourceError (definitive); a 5xx or a network
// failure is an InputTransportError (possibly transient). Presigned/public URLs
// authenticate via the URL itself; auth-header inputs are out of scope for now.
func PreflightInputs(ctx context.Context, refs []InputRef, client HTTPDoer) error {
	for _, ref := range refs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ref.URI, nil)
		if err != nil {
			return &InputSourceError{Ref: ref, Status: 0}
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", preflightRangeEnd))

		resp, err := client.Do(req)
		if err != nil {
			return &InputTransportError{Ref: ref, Err: err}
		}
		resp.Body.Close()

		switch {
		case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusPartialContent:
			// reachable
		case resp.StatusCode >= 400 && resp.StatusCode < 500:
			return &InputSourceError{Ref: ref, Status: resp.StatusCode}
		default: // 5xx and any other non-2xx
			return &InputTransportError{Ref: ref, Err: fmt.Errorf("HTTP %d", resp.StatusCode)}
		}
	}
	return nil
}
