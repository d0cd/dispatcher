package workload

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/d0cd/dispatcher/internal/types"
)

// GPU framework indicators in import statements or config files.
var gpuFrameworks = map[string]string{
	"torch":        "pytorch",
	"tensorflow":   "tensorflow",
	"jax":          "jax",
	"cupy":         "cupy",
	"cuda":         "cuda",
	"nvidia":       "nvidia",
	"triton":       "triton",
	"onnxruntime":  "onnxruntime",
}

// DetectGPURequirements scans imports and configs for GPU framework usage.
func DetectGPURequirements(path string) types.GPURequirement {
	req := types.GPURequirement{}

	// Check Python requirements files
	reqFiles := []string{
		"requirements.txt", "pyproject.toml", "setup.py", "Pipfile",
	}
	for _, name := range reqFiles {
		full := filepath.Join(path, name)
		if fw := scanFileForGPU(full); fw != "" {
			req.Required = true
			req.Count = 1
			req.Framework = fw
			return req
		}
	}

	// Recursively scan source files for GPU imports
	sourceFiles := scanSourceFiles(path, []string{".py", ".go", ".rs", ".java"})
	for _, f := range sourceFiles {
		if fw := scanFileForGPU(f); fw != "" {
			req.Required = true
			req.Count = 1
			req.Framework = fw
			return req
		}
	}

	return req
}

func scanFileForGPU(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		for keyword, framework := range gpuFrameworks {
			if strings.Contains(line, keyword) {
				return framework
			}
		}
	}
	return ""
}
