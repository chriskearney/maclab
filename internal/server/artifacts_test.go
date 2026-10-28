package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var errArtifactIO = errors.New("synthetic artifact I/O failure")

type artifactFaultFile struct {
	file                    *os.File
	fault                   string
	maxWrite, syncs, closes int
}

func (f *artifactFaultFile) Name() string { return f.file.Name() }
func (f *artifactFaultFile) Fd() uintptr  { return f.file.Fd() }
func (f *artifactFaultFile) Read(p []byte) (int, error) {
	if f.fault == "read" {
		return 0, errArtifactIO
	}
	return f.file.Read(p)
}
func (f *artifactFaultFile) Seek(offset int64, whence int) (int64, error) {
	if f.fault == "seek" {
		return 0, errArtifactIO
	}
	return f.file.Seek(offset, whence)
}
func (f *artifactFaultFile) Write(p []byte) (int, error) {
	f.maxWrite = max(f.maxWrite, len(p))
	if f.fault == "write" {
		return 0, errArtifactIO
	}
	if f.fault == "short-write" {
		return f.file.Write(p[:len(p)-1])
	}
	return f.file.Write(p)
}
func (f *artifactFaultFile) Sync() error {
	f.syncs++
	if f.fault == "sync" || (f.fault == "second-sync" && f.syncs == 2) {
		return errArtifactIO
	}
	return f.file.Sync()
}
func (f *artifactFaultFile) Close() error {
	f.closes++
	err := f.file.Close()
	if f.fault == "close" {
		return errors.Join(err, errArtifactIO)
	}
	return err
}

func artifactTestDisk(t *testing.T, fault string) (artifactDisk, **artifactFaultFile) {
	t.Helper()
	disk := artifactDiskOps()
	var file *artifactFaultFile
	disk.create = func(dir string) (artifactTemp, error) {
		f, err := os.CreateTemp(dir, ".upload-*")
		if err != nil {
			return nil, err
		}
		file = &artifactFaultFile{file: f, fault: fault}
		return file, nil
	}
	return disk, &file
}

func artifactSHA(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func TestArtifactBoundedDurableStore(t *testing.T) {
	for _, size := range []int{0, 2*artifactChunkBytes + 19} {
		dir := t.TempDir()
		body := bytes.Repeat([]byte{0x5a}, size)
		disk, file := artifactTestDisk(t, "")
		// bytes.Reader.WriteTo may pass the entire body in one Write call:
		// bounded allocation must hold even when io.Copy uses that fast path.
		sha, gotSize, err := storeArtifactIn(dir, bytes.NewReader(body), disk)
		if err != nil || sha != artifactSHA(body) || gotSize != int64(size) {
			t.Fatalf("size %d: sha=%s bytes=%d err=%v", size, sha, gotSize, err)
		}
		wantSyncs := max(1, (size+artifactChunkBytes-1)/artifactChunkBytes)
		if (*file).maxWrite > artifactChunkBytes || (*file).syncs != wantSyncs || (*file).closes != 1 {
			t.Fatalf("size %d: file %+v", size, *file)
		}
		stored, err := os.ReadFile(filepath.Join(dir, sha))
		if err != nil || !bytes.Equal(stored, body) {
			t.Fatalf("stored bytes differ: %v", err)
		}
	}
}

func TestArtifactStorageFailuresNeverCommit(t *testing.T) {
	for _, fault := range []string{"write", "short-write", "sync", "second-sync", "close", "seek", "read", "drop", "hash-mismatch", "size-mismatch"} {
		t.Run(fault, func(t *testing.T) {
			dir := t.TempDir()
			body := bytes.Repeat([]byte{0x42}, artifactChunkBytes+7)
			disk, file := artifactTestDisk(t, fault)
			drop := disk.drop
			disk.drop = func(f artifactTemp) error {
				switch fault {
				case "drop":
					return errArtifactIO
				case "hash-mismatch":
					if _, err := (*file).file.WriteAt([]byte{0}, 0); err != nil {
						return err
					}
				case "size-mismatch":
					if err := (*file).file.Truncate(int64(len(body) - 1)); err != nil {
						return err
					}
				}
				if fault == "hash-mismatch" || fault == "size-mismatch" {
					if err := (*file).file.Sync(); err != nil {
						return err
					}
				}
				return drop(f)
			}
			renamed := false
			disk.rename = func(string, string) error { renamed = true; return nil }
			sha, size, err := storeArtifactIn(dir, bytes.NewReader(body), disk)
			if err == nil || sha != "" || size != 0 || renamed || (*file).closes != 1 {
				t.Fatalf("sha=%q bytes=%d err=%v renamed=%t closes=%d", sha, size, err, renamed, (*file).closes)
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 0 {
				t.Fatalf("failed upload left files: %v", entries)
			}
		})
	}
}

func TestArtifactCommitFailuresNeverReportSuccess(t *testing.T) {
	for _, phase := range []string{"rename", "directory-sync"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			disk, _ := artifactTestDisk(t, "")
			if phase == "rename" {
				disk.rename = func(string, string) error { return errArtifactIO }
			} else {
				disk.syncDir = func(string) error { return errArtifactIO }
			}
			sha, size, err := storeArtifactIn(dir, strings.NewReader("verified body"), disk)
			if !errors.Is(err, errArtifactIO) || sha != "" || size != 0 {
				t.Fatalf("sha=%q bytes=%d err=%v", sha, size, err)
			}
		})
	}
}

func TestArtifactReplacesCorruptSameNameOnlyAfterVerification(t *testing.T) {
	dir := t.TempDir()
	body := []byte("correct body")
	path := filepath.Join(dir, artifactSHA(body))
	if err := os.WriteFile(path, []byte("corrupt old body"), 0o600); err != nil {
		t.Fatal(err)
	}
	disk, _ := artifactTestDisk(t, "sync")
	if _, _, err := storeArtifactIn(dir, bytes.NewReader(body), disk); err == nil {
		t.Fatal("sync failure accepted")
	}
	if stored, _ := os.ReadFile(path); string(stored) != "corrupt old body" {
		t.Fatal("unverified upload replaced existing CAS object")
	}
	if _, _, err := storeArtifactIn(dir, bytes.NewReader(body), artifactDiskOps()); err != nil {
		t.Fatal(err)
	}
	if stored, _ := os.ReadFile(path); !bytes.Equal(stored, body) {
		t.Fatal("verified upload did not replace corrupt object")
	}
}

type artifactBrokenReader struct{}

func (artifactBrokenReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestArtifactHTTPFailureDoesNotReturnSHA(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "artifacts"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{DataDir: dir}}
	for _, handler := range []http.HandlerFunc{s.hPutArtifact, s.hBuilderArtifact} {
		recorder := httptest.NewRecorder()
		handler(recorder, httptest.NewRequest(http.MethodPost, "/api/artifacts", artifactBrokenReader{}))
		if recorder.Code != http.StatusInternalServerError || strings.Contains(recorder.Body.String(), `"sha256"`) {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
	}
}
