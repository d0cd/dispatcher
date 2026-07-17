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
		blob, terr := TarGz(dir, p.Outputs)
		if terr != nil {
			// The workload itself succeeded; don't fail the run over a packing
			// error, but surface it instead of silently returning no outputs.
			res.Stderr = append(res.Stderr, []byte("\n[dispatcher] output packing error: "+terr.Error())...)
		}
		res.OutputsTarGz = blob
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

// TarGz packs the given paths (relative to baseDir) into a gzip'd tar. A path
// that escapes baseDir (absolute or via "..") is rejected — the Outputs list is
// caller-supplied and must not be able to read files outside the workload dir.
// A path that simply doesn't exist is skipped (a missing optional output must
// not discard the outputs that do exist).
func TarGz(baseDir string, paths []string) ([]byte, error) {
	baseAbs, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, p := range paths {
		root := filepath.Join(baseDir, p)
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			return nil, err
		}
		if rootAbs != baseAbs && !strings.HasPrefix(rootAbs, baseAbs+string(filepath.Separator)) {
			return nil, fmt.Errorf("output path %q escapes workload dir", p)
		}
		if _, err := os.Lstat(rootAbs); errors.Is(err, os.ErrNotExist) {
			continue
		}
		err = filepath.Walk(root, func(file string, info os.FileInfo, err error) error {
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

// Extraction bounds: the source archive is delivered over the attested channel
// but is still untrusted input, so cap the aggregate decompressed size and the
// entry count to make a decompression bomb a bounded failure rather than an
// enclave-filesystem exhaustion.
const (
	maxExtractTotal = int64(2) << 30 // 2 GiB aggregate across all files
	maxTarEntries   = 100_000
)

// UnTarGz extracts a gzip'd tar into dir. It refuses any entry (file, dir, or
// link) whose resolved path escapes dir, bounds the entry count and aggregate
// size, detects truncated files, and handles sym/hardlinks explicitly rather
// than silently dropping them.
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
	// withinRoot reports whether an absolute path stays inside the extraction root.
	withinRoot := func(abs string) bool {
		return abs == rootAbs || strings.HasPrefix(abs, rootAbs+string(filepath.Separator))
	}

	tr := tar.NewReader(gz)
	var total int64
	var entries int
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		entries++
		if entries > maxTarEntries {
			return fmt.Errorf("archive has too many entries (>%d)", maxTarEntries)
		}
		target := filepath.Join(dir, hdr.Name)
		targetAbs, err := filepath.Abs(target)
		if err != nil {
			return err
		}
		if !withinRoot(targetAbs) {
			return fmt.Errorf("tar entry %q escapes extraction root", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if hdr.Size < 0 {
				return fmt.Errorf("tar entry %q has negative size", hdr.Name)
			}
			total += hdr.Size
			if total > maxExtractTotal {
				return fmt.Errorf("archive exceeds max extracted size (%d bytes)", maxExtractTotal)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return err
			}
			// CopyN with the declared size detects a short read (truncation)
			// instead of silently writing a partial file.
			if _, err := io.CopyN(f, tr, hdr.Size); err != nil {
				_ = f.Close()
				return fmt.Errorf("extract %q: %w", hdr.Name, err)
			}
			if err := f.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink, tar.TypeLink:
			// Resolve the link target and refuse anything pointing outside root.
			var linkAbs string
			if hdr.Typeflag == tar.TypeSymlink && !filepath.IsAbs(hdr.Linkname) {
				linkAbs = filepath.Join(filepath.Dir(targetAbs), hdr.Linkname)
			} else {
				linkAbs = filepath.Join(rootAbs, hdr.Linkname)
			}
			if abs, err := filepath.Abs(linkAbs); err != nil || !withinRoot(abs) {
				return fmt.Errorf("link entry %q target escapes extraction root", hdr.Name)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if hdr.Typeflag == tar.TypeSymlink {
				if err := os.Symlink(hdr.Linkname, target); err != nil {
					return err
				}
			} else if err := os.Link(filepath.Join(rootAbs, hdr.Linkname), target); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported tar entry type %d for %q", hdr.Typeflag, hdr.Name)
		}
	}
	return nil
}
