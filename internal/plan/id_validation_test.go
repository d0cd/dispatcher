package plan

import (
	"testing"

	"github.com/d0cd/dispatcher/internal/types"
	"github.com/stretchr/testify/assert"
)

func TestValidatePlanID(t *testing.T) {
	cases := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"valid generated id", "plan_abc123", false},
		{"empty id", "", true},
		{"traversal", "../../etc/passwd", true},
		{"forward slash", "plan/abc", true},
		{"backslash", `plan\abc`, true},
		{"dot dot mid", "plan..abc", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validatePlanID(c.id)
			if c.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSave_RejectsTraversalID(t *testing.T) {
	p := &types.Plan{Metadata: types.PlanMetadata{ID: "../../etc/passwd"}}
	_, err := Save(p)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "traversal")
}

func TestLoad_RejectsTraversalID(t *testing.T) {
	_, err := Load("../../etc/passwd")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "traversal")
}
