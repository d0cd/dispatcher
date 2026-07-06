package adapter

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// buildContentLabel is the Docker image label that records the content digest a
// dispatcher image was built from, so Prepare can skip rebuilding when the
// source is unchanged.
const buildContentLabel = "dispatcher.content"

// buildDigest computes a content digest over the Dockerfile and the source tree
// (file paths + contents), used as a build-cache key. `.git` / `.dispatcher`
// churn is ignored. It hashes file contents, not metadata, so an edit that
// keeps a file the same size still busts the cache.
func buildDigest(dockerfilePath, sourceDir string) (string, error) {
	h := sha256.New()

	df, err := os.ReadFile(dockerfilePath)
	if err != nil {
		return "", fmt.Errorf("read dockerfile: %w", err)
	}
	io.WriteString(h, "dockerfile\x00")
	h.Write(df)

	err = filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".dispatcher":
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		io.WriteString(h, "\x00file\x00"+rel+"\x00")
		h.Write(content)
		return nil
	})
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil))[:12], nil
}
