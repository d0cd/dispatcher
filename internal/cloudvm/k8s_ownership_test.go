package cloudvm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d0cd/dispatcher/internal/adapter"
)

// K8s Jobs are reaped only by gc (no watchdog), so this ownership guard is the
// sole boundary protecting a non-dispatcher Job. The guard returns before any
// kubectl call, so this test never shells out.
func TestK8sAdapter_DestroyResource_RefusesUnowned(t *testing.T) {
	a := NewK8sAdapter("default")
	err := a.DestroyResource(context.Background(),
		adapter.ResourceInfo{ResourceID: "someone-elses-job", Kind: adapter.ResourceInstance})
	require.Error(t, err, "a Job dispatcher doesn't own must be refused")
	assert.Contains(t, err.Error(), "not dispatcher-owned")
}
