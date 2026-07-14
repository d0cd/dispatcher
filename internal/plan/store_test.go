package plan

import (
	"testing"
	"time"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveAndLoad(t *testing.T) {
	// Use a temp dir as HOME so we don't pollute the real home
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	p := &types.Plan{
		APIVersion: "dispatcher.dev/v1",
		Kind:       "Plan",
		Metadata: types.PlanMetadata{
			ID:        "plan_test_1",
			CreatedAt: time.Now().UTC(),
			CreatedBy: "test",
		},
		Workload: types.WorkloadSpec{
			Name:         "test-workload",
			DetectedKind: types.WorkloadKindScript,
			Runtime:      types.RuntimePython,
		},
		Recommendation: &types.Recommendation{
			Target:  "local-docker",
			Runtime: "local-docker",
			EstimatedCost: types.CostEstimate{
				Value:      0.0,
				Currency:   "USD",
				Confidence: types.ConfidenceHigh,
			},
		},
	}

	path, err := Save(p)
	require.NoError(t, err)
	assert.FileExists(t, path)

	loaded, err := Load("plan_test_1")
	require.NoError(t, err)
	assert.Equal(t, p.Metadata.ID, loaded.Metadata.ID)
	assert.Equal(t, p.Workload.Name, loaded.Workload.Name)
	assert.Equal(t, p.Recommendation.Target, loaded.Recommendation.Target)
}

func TestLoadNotFound(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	_, err := Load("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
