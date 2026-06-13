package cli

import (
	"runtime/debug"
	"testing"
)

func TestResolveVersion(t *testing.T) {
	tests := []struct {
		name    string
		ldflags string
		info    *debug.BuildInfo
		ok      bool
		want    string
	}{
		{
			name:    "explicit ldflags wins over build info",
			ldflags: "v1.2.3",
			info:    &debug.BuildInfo{Main: debug.Module{Version: "v0.2.0"}},
			ok:      true,
			want:    "v1.2.3",
		},
		{
			name:    "go install tag used when ldflags unset",
			ldflags: "dev",
			info:    &debug.BuildInfo{Main: debug.Module{Version: "v0.2.0"}},
			ok:      true,
			want:    "v0.2.0",
		},
		{
			name:    "local build reports dev",
			ldflags: "dev",
			info:    &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
			ok:      true,
			want:    "dev",
		},
		{
			name:    "no build info reports dev",
			ldflags: "dev",
			info:    nil,
			ok:      false,
			want:    "dev",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveVersion(tt.ldflags, tt.info, tt.ok); got != tt.want {
				t.Errorf("resolveVersion(%q, ...) = %q, want %q", tt.ldflags, got, tt.want)
			}
		})
	}
}
