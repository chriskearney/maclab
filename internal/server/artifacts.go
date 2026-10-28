package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const artifactChunkBytes = 1 << 20

type artifactTemp interface {
	io.ReadWriteSeeker
	Name() string
	Fd() uintptr
	Sync() error
	Close() error
}

// Per-call operations let tests exercise I/O failures without global hooks.
type artifactDisk struct {
	create  func(string) (artifactTemp, error)
	drop    func(artifactTemp) error
	rename  func(string, string) error
	syncDir func(string) error
}

func artifactDiskOps() artifactDisk {
	return artifactDisk{
		create: func(dir string) (artifactTemp, error) { return os.CreateTemp(dir, ".upload-*") },
		drop:   dropArtifactCache,
		rename: os.Rename,
		syncDir: func(dir string) error {
			f, err := os.Open(dir)
			if err != nil {
				return err
			}
			return errors.Join(f.Sync(), f.Close())
		},
	}
}

// Sync each bounded write rather than leaving a whole package in delalloc.
// This does not repair an unhealthy filesystem: any I/O error refuses upload.
type artifactChunkWriter struct{ file artifactTemp }

func (w artifactChunkWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p[:min(len(p), artifactChunkBytes)]
		n, err := w.file.Write(chunk)
		total += n
		if err == nil && n != len(chunk) {
			err = io.ErrShortWrite
		}
		if err == nil {
			err = w.file.Sync()
		}
		if err != nil {
			return total, err
		}
		p = p[n:]
	}
	return total, nil
}

// writeVerifiedArtifact closes the file on every path. A hash is returned only
// after synced writes, cache eviction and a complete on-file size/hash readback.
func writeVerifiedArtifact(file artifactTemp, body io.Reader, drop func(artifactTemp) error) (sha string, size int64, err error) {
	defer func() {
		err = errors.Join(err, file.Close())
		if err != nil {
			sha, size = "", 0
		}
	}()
	buffer := make([]byte, artifactChunkBytes)
	incoming := sha256.New()
	size, err = io.CopyBuffer(io.MultiWriter(artifactChunkWriter{file}, incoming), body, buffer)
	if err != nil {
		return "", 0, fmt.Errorf("artifact write/sync: %w", err)
	}
	if size == 0 {
		if err = file.Sync(); err != nil {
			return "", 0, fmt.Errorf("empty artifact sync: %w", err)
		}
	}
	if err = drop(file); err != nil {
		return "", 0, fmt.Errorf("artifact cache eviction: %w", err)
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return "", 0, fmt.Errorf("artifact readback seek: %w", err)
	}
	stored := sha256.New()
	var readSize int64
	readSize, err = io.CopyBuffer(stored, file, buffer)
	if err != nil {
		return "", 0, fmt.Errorf("artifact readback: %w", err)
	}
	sha = hex.EncodeToString(incoming.Sum(nil))
	if readSize != size || hex.EncodeToString(stored.Sum(nil)) != sha {
		return "", 0, fmt.Errorf("artifact readback differs from upload: wrote %d, read %d", size, readSize)
	}
	return sha, size, nil
}

func storeArtifactIn(dir string, body io.Reader, disk artifactDisk) (string, int64, error) {
	file, err := disk.create(dir)
	if err != nil {
		return "", 0, err
	}
	defer os.Remove(file.Name())
	sha, size, err := writeVerifiedArtifact(file, body, disk.drop)
	if err != nil {
		return "", 0, err
	}
	// Replace a same-name CAS object only with the newly verified body; its
	// existence alone is not evidence that the old bytes are correct.
	if err := disk.rename(file.Name(), filepath.Join(dir, sha)); err != nil {
		return "", 0, fmt.Errorf("artifact commit rename: %w", err)
	}
	if err := disk.syncDir(dir); err != nil {
		return "", 0, fmt.Errorf("artifact commit directory sync: %w", err)
	}
	return sha, size, nil
}
