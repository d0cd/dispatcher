package adapter

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
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
	hashChunk(h, []byte("dockerfile"))
	hashChunk(h, df)

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
		hashChunk(h, []byte(rel))
		hashChunk(h, content)
		return nil
	})
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil))[:12], nil
}

// hashChunk feeds a length-prefixed field into h so that no field's bytes can be
// confused with a subsequent field — without the length prefix, file content
// containing the old inline delimiter could impersonate another file entry and
// collide two distinct source trees to the same digest.
func hashChunk(h hash.Hash, b []byte) {
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(b)))
	h.Write(lenBuf[:])
	h.Write(b)
}
