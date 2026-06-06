package run

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateRunID_RejectsTraversal(t *testing.T) {
	cases := []struct {
		name string
		id   string
		want bool // true = should be rejected
	}{
		{"valid generated id", "run_abc123", false},
		{"empty", "", true},
		{"path separator", "../etc/passwd", true},
		{"windows separator", `..\etc\passwd`, true},
		{"dot dot", "run..123", true},
		{"forward slash in middle", "run/abc", true},
		{"trailing path traversal", "run_abc/..", true},
		{"valid with underscore", "run_abc_xyz", false},
		{"valid hex", "run_a1b2c3d4", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateRunID(c.id)
			if c.want {
				assert.Error(t, err, "%q should be rejected", c.id)
				if err != nil {
					// Error message should be precise enough that a security
					// auditor can spot what was rejected and why.
					msg := err.Error()
					assert.True(t,
						strings.Contains(msg, "empty") ||
							strings.Contains(msg, "path separator") ||
							strings.Contains(msg, "traversal"),
						"error message should explain rejection: %q", msg)
				}
			} else {
				assert.NoError(t, err, "%q should be accepted", c.id)
			}
		})
	}
}

func TestLoadRecord_RejectsTraversalID(t *testing.T) {
	// LoadRecord must refuse to build a path from an attacker-controlled ID.
	_, err := LoadRecord("../../../etc/passwd")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "traversal")
}
