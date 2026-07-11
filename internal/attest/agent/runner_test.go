package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTarGz_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("world"), 0o644))

	blob, err := TarGz(dir, []string{"a.txt", "sub"})
	require.NoError(t, err)

	out := t.TempDir()
	require.NoError(t, UnTarGz(blob, out))

	a, err := os.ReadFile(filepath.Join(out, "a.txt"))
	require.NoError(t, err)
	assert.Equal(t, "hello", string(a))
	b, err := os.ReadFile(filepath.Join(out, "sub", "b.txt"))
	require.NoError(t, err)
	assert.Equal(t, "world", string(b))
}

func TestUnTarGz_RejectsTraversal(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "../evil.txt", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg}))
	_, _ = tw.Write([]byte("bad"))
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	err := UnTarGz(buf.Bytes(), t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "escapes")
}

func TestDefaultRunner_RunsCommandWithSourceAndEnv(t *testing.T) {
	src := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, "run.sh"),
		[]byte("#!/bin/sh\necho \"hi $NAME\"\necho result > out.txt\n"), 0o755))
	blob, err := TarGz(src, []string{"run.sh"})
	require.NoError(t, err)

	res := defaultRunner(context.Background(), Payload{
		Command:     []string{"sh", "run.sh"},
		SourceTarGz: blob,
		DotEnv:      []byte("NAME=world\n# a comment\n"),
		Outputs:     []string{"out.txt"},
	})

	assert.Equal(t, 0, res.ExitCode)
	assert.Contains(t, string(res.Stdout), "hi world")

	out := t.TempDir()
	require.NoError(t, UnTarGz(res.OutputsTarGz, out))
	got, err := os.ReadFile(filepath.Join(out, "out.txt"))
	require.NoError(t, err)
	assert.Equal(t, "result\n", string(got))
}

func TestDefaultRunner_CapturesNonZeroExit(t *testing.T) {
	res := defaultRunner(context.Background(), Payload{Command: []string{"sh", "-c", "exit 7"}})
	assert.Equal(t, 7, res.ExitCode)
}

func TestDefaultRunner_EmptyCommandFails(t *testing.T) {
	res := defaultRunner(context.Background(), Payload{})
	assert.NotEqual(t, 0, res.ExitCode)
}
