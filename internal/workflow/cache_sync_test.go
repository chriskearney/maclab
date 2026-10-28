package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func cacheSyncFixture(t *testing.T, size int) (*Runner, Pin, []byte) {
	t.Helper()
	dir := t.TempDir()
	raw := make([]byte, size)
	for i := range raw {
		raw[i] = byte(i*31 + i/251)
	}
	source := filepath.Join(dir, "source")
	if err := os.WriteFile(source, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return &Runner{Dir: dir}, Pin{Path: source, SHA256: Hash(raw), Bytes: int64(len(raw))}, raw
}
func noCacheAdoption(t *testing.T, r *Runner, p Pin) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(r.Dir, "cache", p.SHA256)); !os.IsNotExist(err) {
		t.Fatalf("failed cache adopted: %v", err)
	}
	partial, err := filepath.Glob(filepath.Join(r.Dir, "cache", ".cache-*"))
	if err != nil || len(partial) != 0 {
		t.Fatalf("temporary cache retained: %v %v", partial, err)
	}
}
func TestCacheSyncEveryMiBAndFinalReadback(t *testing.T) {
	r, p, raw := cacheSyncFixture(t, 2*cacheSyncBytes+17)
	var offsets []int64
	out, err := r.cacheWithSync(context.Background(), p, func(f *os.File) error {
		at, e := f.Seek(0, io.SeekCurrent)
		if e != nil {
			return e
		}
		offsets = append(offsets, at)
		return f.Sync()
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(offsets, []int64{cacheSyncBytes, 2 * cacheSyncBytes, int64(len(raw))}) {
		t.Fatalf("unbounded/missing sync: %v", offsets)
	}
	var got struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Bytes  int64  `json:"bytes"`
		Reused bool   `json:"reused"`
	}
	if err = json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(got.Path)
	if err != nil || !bytes.Equal(actual, raw) || got.SHA256 != p.SHA256 || got.Bytes != p.Bytes || got.Reused {
		t.Fatalf("cache identity/readback differs: %v", err)
	}
	if err = verifyPin(p); err != nil {
		t.Fatal("original changed", err)
	}
}
func TestCacheChunkSyncFailureAbortsWithoutAdoptionOrRetry(t *testing.T) {
	r, p, _ := cacheSyncFixture(t, 3*cacheSyncBytes+19)
	calls := 0
	out, err := r.cacheWithSync(context.Background(), p, func(f *os.File) error { calls++; return syscall.EIO })
	if !errors.Is(err, syscall.EIO) || out != nil || calls != 1 {
		t.Fatalf("sync failure retried/ignored: %v %d %s", err, calls, out)
	}
	noCacheAdoption(t, r, p)
	if err = verifyPin(p); err != nil {
		t.Fatal("source changed", err)
	}
}
func TestCacheFinalSyncFailureStillAborts(t *testing.T) {
	r, p, _ := cacheSyncFixture(t, cacheSyncBytes+7)
	calls := 0
	out, err := r.cacheWithSync(context.Background(), p, func(f *os.File) error {
		calls++
		if calls == 2 {
			return syscall.EIO
		}
		return f.Sync()
	})
	if !errors.Is(err, syscall.EIO) || out != nil || calls != 2 {
		t.Fatalf("final sync missing/ignored: %v %d", err, calls)
	}
	noCacheAdoption(t, r, p)
}
func TestCacheBadSourceHashNeverAdopted(t *testing.T) {
	r, p, _ := cacheSyncFixture(t, cacheSyncBytes+7)
	p.SHA256 = Hash([]byte("wrong"))
	out, err := r.cache(context.Background(), p)
	if err == nil || out != nil {
		t.Fatal("wrong hash adopted")
	}
	noCacheAdoption(t, r, p)
}
func TestCacheExistingObjectRevalidatedWithoutRewrite(t *testing.T) {
	r, p, _ := cacheSyncFixture(t, cacheSyncBytes+7)
	if _, err := r.cache(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(r.Dir, "cache", p.SHA256)
	before, err := os.Lstat(dst)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	out, err := r.cacheWithSync(context.Background(), p, func(f *os.File) error { calls++; return syscall.EIO })
	if err != nil || calls != 0 {
		t.Fatalf("existing bytes rewritten: %v %d", err, calls)
	}
	after, _ := os.Lstat(dst)
	if !same(before, after) || !bytes.Contains(out, []byte(`"reused":true`)) {
		t.Fatal("reuse identity/receipt differs")
	}
	if err = os.WriteFile(dst, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = r.cache(context.Background(), p); err == nil {
		t.Fatal("corrupt cache silently replaced")
	}
	bad, _ := os.ReadFile(dst)
	if string(bad) != "corrupt" {
		t.Fatal("corrupt evidence overwritten")
	}
}
