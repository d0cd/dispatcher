package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// RunAgent starts the in-TEE Confidential Space agent HTTP server on addr. It
// uses the container-launcher teeserver for attestation tokens and the default
// exec runner for the workload. This is the entrypoint the dispatcher-attest
// binary (the measured container) calls.
func RunAgent(addr, audience string) error {
	return RunServerATLS(addr, csAttestFunc(csTeeserverSocket, audience))
}

// defaultRunner extracts the sealed source into a scratch workdir, runs the
// workload command with the delivered environment, and tars the requested
// outputs back. Everything it touches came in sealed to this TEE's channel key.
func defaultRunner(ctx context.Context, p Payload) Result {
	if len(p.Command) == 0 {
		return Result{ExitCode: -1, Stderr: []byte("empty command")}
	}
	dir, err := os.MkdirTemp("", "dispatcher-workload-*")
	if err != nil {
		return Result{ExitCode: -1, Stderr: []byte("workdir: " + err.Error())}
	}
	defer os.RemoveAll(dir)

	if len(p.SourceTarGz) > 0 {
		if err := UnTarGz(p.SourceTarGz, dir); err != nil {
			return Result{ExitCode: -1, Stderr: []byte("extract source: " + err.Error())}
		}
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, p.Command[0], p.Command[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), parseDotEnv(p.DotEnv)...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	code := 0
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = -1
			stderr.WriteString("\n" + err.Error())
		}
	}

	res := Result{ExitCode: code, Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if len(p.Outputs) > 0 {
		if blob, terr := TarGz(dir, p.Outputs); terr == nil {
			res.OutputsTarGz = blob
		}
	}
	return res
}

// parseDotEnv turns raw KEY=VALUE lines into an environment slice, skipping
// blanks and #-comments. Values are taken verbatim (no shell expansion).
func parseDotEnv(b []byte) []string {
	var env []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsRune(line, '=') {
			env = append(env, line)
		}
	}
	return env
}

// TarGz packs the given paths (relative to baseDir) into a gzip'd tar.
func TarGz(baseDir string, paths []string) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, p := range paths {
		root := filepath.Join(baseDir, p)
		err := filepath.Walk(root, func(file string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(baseDir, file)
			if err != nil {
				return err
			}
			hdr, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			hdr.Name = filepath.ToSlash(rel)
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			if info.Mode().IsRegular() {
				f, err := os.Open(file)
				if err != nil {
					return err
				}
				defer f.Close()
				if _, err := io.Copy(tw, f); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnTarGz extracts a gzip'd tar into dir, refusing any entry whose path escapes
// dir (tar traversal defense).
func UnTarGz(blob []byte, dir string) error {
	gz, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		return err
	}
	defer gz.Close()

	rootAbs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dir, hdr.Name)
		targetAbs, err := filepath.Abs(target)
		if err != nil {
			return err
		}
		if targetAbs != rootAbs && !strings.HasPrefix(targetAbs, rootAbs+string(filepath.Separator)) {
			return fmt.Errorf("tar entry %q escapes extraction root", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, io.LimitReader(tr, 512<<20)); err != nil {
				_ = f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
	}
	return nil
}
